import os
import json
import hmac
import hashlib
import io
import logging
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, request, send_from_directory, send_file
from pymongo import MongoClient, ASCENDING, DESCENDING


# ============================================================
# Configuration
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
MONGODB_URI = os.getenv("MONGODB_URI", "").strip()
OWNER_ID = int(os.getenv("OWNER_ID", "0") or 0)

VERIFY_HOST = os.getenv("VERIFY_HOST", "0.0.0.0")
VERIFY_PORT = int(os.getenv("VERIFY_PORT", os.getenv("PORT", "8081")))

# initData freshness. 15 minutes is a sensible verification window.
INITDATA_MAX_AGE = int(os.getenv("INITDATA_MAX_AGE", "900"))

# Exact-device banned match auto-ban switch. Kept under the old env name for backward compatibility.
AUTO_BAN_HIGH_RISK = os.getenv("AUTO_BAN_HIGH_RISK", "true").lower() in {
    "1", "true", "yes", "on"
}

# Trust reverse-proxy headers only when your deployment actually uses them.
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "true").lower() in {
    "1", "true", "yes", "on"
}

# Number of prior matching records inspected per verification.
MATCH_LIMIT = max(5, min(int(os.getenv("MATCH_LIMIT", "40")), 100))

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is required.")
if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is required.")


# ============================================================
# Logging / Mongo
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - verification - %(levelname)s - %(message)s",
)
logger = logging.getLogger("verification")

mongo = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=10000)
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "afk_db").strip() or "afk_db"
db = mongo[MONGO_DB_NAME]

verification_events = db.verification_events
verification_actions = db.verification_actions
ip_geo_cache = db.verification_ip_geo_cache
verification_groups = db.verification_groups
verification_pending = db.verification_pending
verification_settings = db.verification_settings
verification_exceptions = db.verification_exceptions

# Helpful indexes. These collections are separate from the existing AFK bot.
verification_events.create_index([("telegram_user_id", ASCENDING), ("created_at", DESCENDING)])
verification_events.create_index([("fingerprint", ASCENDING), ("created_at", DESCENDING)])
verification_events.create_index([("ip", ASCENDING), ("created_at", DESCENDING)])
verification_events.create_index([("group_ids", ASCENDING)])
verification_events.create_index([("decision", ASCENDING), ("created_at", DESCENDING)])
verification_actions.create_index([("telegram_user_id", ASCENDING), ("created_at", DESCENDING)])
ip_geo_cache.create_index([("ip", ASCENDING)], unique=True)


# ============================================================
# Flask
# ============================================================

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent


# ============================================================
# Dynamic verification-group configuration
# ============================================================

def get_verification_group_ids():
    return [
        int(doc["chat_id"])
        for doc in verification_groups.find({"enabled": {"$ne": False}}, {"chat_id": 1}).sort("added_at", ASCENDING)
        if doc.get("chat_id") is not None
    ]

def is_configured_group(group_id: int) -> bool:
    return verification_groups.find_one({"chat_id": int(group_id), "enabled": {"$ne": False}}) is not None

def is_verification_exception(user_id: int) -> bool:
    return verification_exceptions.find_one({
        "user_id": int(user_id),
        "enabled": {"$ne": False},
    }) is not None


# ============================================================
# Telegram helpers
# ============================================================

def telegram_api(method: str, payload: Optional[dict] = None, timeout: int = 12):
    """Call Telegram Bot API without starting another Pyrogram client."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = urllib.parse.urlencode(payload or {}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            body = json.loads(res.read().decode("utf-8"))
    except Exception as e:
        logger.warning("Telegram API %s failed: %s", method, e)
        return {"ok": False, "description": str(e)}

    return body

def delete_group_verification_prompt(group_id: int, user_id: int):
    """Best-effort cleanup of the temporary group verification prompt."""
    pending = verification_pending.find_one({
        "group_id": int(group_id),
        "user_id": int(user_id),
    })
    if not pending:
        return {"ok": False, "description": "pending record not found"}
    chat_id = pending.get("group_verify_prompt_chat_id") or pending.get("group_id")
    message_id = pending.get("group_verify_prompt_message_id")
    if not chat_id or not message_id:
        return {"ok": False, "description": "no group verification prompt"}
    result = telegram_api("deleteMessage", {
        "chat_id": int(chat_id),
        "message_id": int(message_id),
    })
    if result.get("ok"):
        verification_pending.update_one(
            {"_id": pending["_id"]},
            {"$set": {
                "group_verify_prompt_deleted": True,
                "group_verify_prompt_deleted_at": datetime.now(timezone.utc),
            }},
        )
    return result



def get_chat_member(group_id: int, user_id: int):
    return telegram_api(
        "getChatMember",
        {"chat_id": group_id, "user_id": user_id},
    )


def get_group_title(group_id: int) -> str:
    """Best-effort Telegram group title lookup for user-facing verification messages."""
    try:
        result = telegram_api("getChat", {"chat_id": group_id})
        if result.get("ok"):
            title = str((result.get("result") or {}).get("title") or "").strip()
            if title:
                return title
    except Exception:
        pass
    return "this group"


def get_group_photo_bytes(group_id: int):
    """Fetch the configured group's current Telegram photo without exposing BOT_TOKEN to the browser."""
    try:
        chat = telegram_api("getChat", {"chat_id": group_id})
        if not chat.get("ok"):
            return None, None

        photo = (chat.get("result") or {}).get("photo") or {}
        file_id = photo.get("big_file_id") or photo.get("small_file_id")
        if not file_id:
            return None, None

        file_result = telegram_api("getFile", {"file_id": file_id})
        if not file_result.get("ok"):
            return None, None
        file_path = str((file_result.get("result") or {}).get("file_path") or "").strip()
        if not file_path:
            return None, None

        # Telegram's download URL contains the bot token, so download it here and proxy bytes to the Mini App.
        url = f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_path}"
        with urllib.request.urlopen(url, timeout=12) as res:
            data = res.read()
            content_type = res.headers.get_content_type() or "image/jpeg"
        return data, content_type
    except Exception as e:
        logger.warning("Could not fetch group photo for %s: %s", group_id, e)
        return None, None


def is_banned_in_group(group_id: int, user_id: int):
    result = get_chat_member(group_id, user_id)
    if not result.get("ok"):
        return False, None

    member = result.get("result") or {}
    # Bot API returns "kicked" for banned users.
    return member.get("status") == "kicked", member


def decline_join_request(group_id: int, user_id: int):
    """Explicitly remove a pending join request before/while banning.

    Telegram can keep a join request visible even after banChatMember. If an
    admin later approves that stale request, the user may still get admitted.
    Declining it closes that approval path.
    """
    return telegram_api(
        "declineChatJoinRequest",
        {
            "chat_id": group_id,
            "user_id": user_id,
        },
    )


def ban_user(group_id: int, user_id: int):
    return telegram_api(
        "banChatMember",
        {
            "chat_id": group_id,
            "user_id": user_id,
            "revoke_messages": "true",
        },
    )


def decline_and_ban_user(group_id: int, user_id: int):
    """Close any pending join request, then ban the user."""
    decline_result = decline_join_request(group_id, user_id)
    ban_result = ban_user(group_id, user_id)
    return decline_result, ban_result


def unmute_user_in_group(group_id: int, user_id: int):
    """Fully remove member-level restrictions after successful verification.

    Explicitly grant every ordinary ChatPermissions flag instead of copying
    the group's defaults, because copying a false default can leave the user
    partially muted even after verification.
    """
    permissions = {
        "can_send_messages": True,
        "can_send_audios": True,
        "can_send_documents": True,
        "can_send_photos": True,
        "can_send_videos": True,
        "can_send_video_notes": True,
        "can_send_voice_notes": True,
        "can_send_polls": True,
        "can_send_other_messages": True,
        "can_add_web_page_previews": True,
        "can_change_info": True,
        "can_invite_users": True,
        "can_pin_messages": True,
        "can_manage_topics": True,
    }

    return telegram_api(
        "restrictChatMember",
        {
            "chat_id": group_id,
            "user_id": user_id,
            "permissions": json.dumps(permissions, separators=(",", ":")),
            "use_independent_chat_permissions": True,
        },
    )


def send_owner_message(text: str, reply_markup: Optional[dict] = None):
    if not OWNER_ID:
        return {"ok": False, "description": "OWNER_ID not configured"}

    payload = {
        "chat_id": OWNER_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup, separators=(",", ":"))

    return telegram_api("sendMessage", payload)


# ============================================================
# Telegram Mini App initData validation
# ============================================================

def validate_init_data(init_data: str):
    if not init_data:
        return False, "missing_init_data", None

    try:
        parsed_pairs = urllib.parse.parse_qsl(
            init_data,
            keep_blank_values=True,
            strict_parsing=True,
        )
        parsed = dict(parsed_pairs)
    except Exception:
        return False, "invalid_init_data", None

    received_hash = parsed.pop("hash", None)
    if not received_hash:
        return False, "missing_hash", None

    data_check_string = "\n".join(
        f"{key}={value}"
        for key, value in sorted(parsed.items())
    )

    secret_key = hmac.new(
        b"WebAppData",
        BOT_TOKEN.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    expected_hash = hmac.new(
        secret_key,
        data_check_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_hash, received_hash):
        return False, "bad_signature", None

    try:
        auth_date = int(parsed.get("auth_date", "0"))
    except ValueError:
        return False, "bad_auth_date", None

    now = int(time.time())
    if auth_date <= 0 or abs(now - auth_date) > INITDATA_MAX_AGE:
        return False, "expired_init_data", None

    try:
        user = json.loads(parsed.get("user", "{}"))
        user_id = int(user["id"])
    except Exception:
        return False, "missing_user", None

    return True, None, {
        "user": user,
        "user_id": user_id,
        "auth_date": auth_date,
        "query_id": parsed.get("query_id"),
    }


# ============================================================
# IP / approximate location
# ============================================================

def client_ip():
    if TRUST_PROXY_HEADERS:
        cf = (request.headers.get("CF-Connecting-IP") or "").strip()
        if cf:
            return cf

        xff = (request.headers.get("X-Forwarded-For") or "").strip()
        if xff:
            return xff.split(",")[0].strip()

        real_ip = (request.headers.get("X-Real-IP") or "").strip()
        if real_ip:
            return real_ip

    return (request.remote_addr or "").strip()


def approximate_ip_location(ip: str):
    """
    Returns coarse city/state/country-level IP location.
    This is approximate network geolocation, not GPS.
    """
    if not ip:
        return {
            "city": None,
            "region": None,
            "country": None,
            "country_code": None,
            "asn": None,
            "org": None,
        }

    cached = ip_geo_cache.find_one({"ip": ip})
    if cached:
        return {
            "city": cached.get("city"),
            "region": cached.get("region"),
            "country": cached.get("country"),
            "country_code": cached.get("country_code"),
            "asn": cached.get("asn"),
            "org": cached.get("org"),
        }

    result = {
        "city": None,
        "region": None,
        "country": None,
        "country_code": None,
        "asn": None,
        "org": None,
    }

    try:
        safe_ip = urllib.parse.quote(ip, safe=":")
        url = f"https://ipwho.is/{safe_ip}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "AFKVerification/1.0"},
        )
        with urllib.request.urlopen(req, timeout=4) as res:
            data = json.loads(res.read().decode("utf-8"))

        if data.get("success", True):
            conn = data.get("connection") or {}
            result = {
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "country_code": data.get("country_code"),
                "asn": conn.get("asn"),
                "org": conn.get("org") or conn.get("isp"),
            }
    except Exception as e:
        logger.info("IP location lookup failed for %s: %s", ip, e)

    try:
        ip_geo_cache.update_one(
            {"ip": ip},
            {
                "$set": {
                    "ip": ip,
                    **result,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
            upsert=True,
        )
    except Exception:
        pass

    return result


def location_text(doc: dict):
    geo = doc.get("geo") or {}
    parts = [
        geo.get("city"),
        geo.get("region"),
        geo.get("country"),
    ]
    return ", ".join(str(x) for x in parts if x) or "Unknown"


def same_ip_autoban_enabled() -> bool:
    """Read the bot-managed same-IP policy live from MongoDB. Default is OFF."""
    try:
        doc = verification_settings.find_one({"_id": "same_ip_auto_ban"})
        return bool(doc.get("enabled", False)) if doc else False
    except Exception as e:
        logger.warning("Could not read same-IP auto-ban setting: %s", e)
        return False


# ============================================================
# Risk matching
# ============================================================

def candidate_matches(current_user_id: int, fingerprint: str, ip: str):
    """
    Pull only exact fingerprint/IP candidates. We do not auto-ban from IP alone.
    """
    clauses = []
    if fingerprint:
        clauses.append({"fingerprint": fingerprint})
    if ip:
        clauses.append({"ip": ip})

    if not clauses:
        return []

    cursor = verification_events.find(
        {
            "telegram_user_id": {"$ne": current_user_id},
            "$or": clauses,
        }
    ).sort("created_at", DESCENDING).limit(MATCH_LIMIT)

    return list(cursor)


def same_ip_matches_for_current_user(current_user_id: int, ip: str):
    """Return recent verification records for OTHER Telegram IDs on the exact same IP.

    Same-IP matches are review signals only. They never auto-ban a user.
    """
    if not ip:
        return []

    cursor = verification_events.find(
        {
            "telegram_user_id": {"$ne": int(current_user_id)},
            "ip": ip,
        }
    ).sort("created_at", DESCENDING).limit(MATCH_LIMIT)

    result = []
    seen = set()
    for doc in cursor:
        uid = int(doc.get("telegram_user_id", 0) or 0)
        if not uid or uid in seen:
            continue
        seen.add(uid)
        result.append(doc)
    return result



def banned_same_ip_matches_for_current_user(current_user_id: int, ip: str, target_group_id: int):
    """Return same-IP historical IDs that are CURRENTLY banned in THIS target group.

    A ban in some other verification group must never cause an automatic ban
    in the group the current user is trying to join.
    """
    results = []
    seen = set()
    target_group_id = int(target_group_id)

    for old in same_ip_matches_for_current_user(current_user_id, ip):
        old_user_id = int(old.get("telegram_user_id", 0) or 0)
        if not old_user_id or old_user_id in seen:
            continue
        seen.add(old_user_id)

        banned, member = is_banned_in_group(target_group_id, old_user_id)
        if not banned:
            continue

        item = dict(old)
        item["banned_group_id"] = target_group_id
        item["ban_member"] = member
        results.append(item)

    return results


def banned_matches_for_current_user(
    current_user_id: int,
    fingerprint: str,
    ip: str,
    device: dict,
    target_group_id: int,
):
    """
    Return prior Telegram IDs that used the exact same device fingerprint and
    are currently banned in THIS target verification group.

    IP and browser fields are retained only for logs/diagnostics. They never
    cause an automatic ban by themselves.
    """
    matches = []
    seen = set()

    for old in candidate_matches(current_user_id, fingerprint, ip):
        old_user_id = int(old.get("telegram_user_id", 0) or 0)
        if not old_user_id or old_user_id in seen:
            continue
        seen.add(old_user_id)

        fp_same = bool(
            fingerprint
            and old.get("fingerprint")
            and old.get("fingerprint") == fingerprint
        )

        # Core policy: only an exact same-device fingerprint can link the IDs.
        # Same IP, location, user-agent, screen, etc. are NOT enough.
        if not fp_same:
            continue

        ip_same = bool(ip and old.get("ip") and old.get("ip") == ip)
        old_device = old.get("device") or {}
        supporting = {
            "user_agent": bool(device.get("user_agent") and old_device.get("user_agent") == device.get("user_agent")),
            "screen": bool(device.get("screen") and old_device.get("screen") == device.get("screen")),
            "timezone": bool(device.get("timezone") and old_device.get("timezone") == device.get("timezone")),
            "language": bool(device.get("language") and old_device.get("language") == device.get("language")),
        }

        group_id = int(target_group_id)
        banned, member = is_banned_in_group(group_id, old_user_id)
        if not banned:
            continue

        matches.append({
            "group_id": group_id,
            "matched_user_id": old_user_id,
            "score": 100,
            "level": "high",
            "reason": "same device fingerprint + matched Telegram ID is banned in this group",
            "fingerprint_same": True,
            "ip_same": ip_same,
            "supporting": supporting,
            "old_event": old,
            "member": member,
        })

    matches.sort(key=lambda x: x["score"], reverse=True)
    return matches


# ============================================================
# Owner notification
# ============================================================

def h(value):
    """Minimal HTML escaping for Telegram HTML messages."""
    return (
        str(value if value is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def short_fp(fp: str):
    if not fp:
        return "N/A"
    return f"{fp[:12]}…{fp[-8:]}" if len(fp) > 24 else fp


def notify_high_risk(current_doc: dict, match: dict, ban_results: list):
    old = match["old_event"]

    cur_name = current_doc.get("name") or "Unknown"
    old_name = old.get("name") or "Unknown"

    cur_username = current_doc.get("username")
    old_username = old.get("username")

    cur_user_label = (
        f"{cur_name}" + (f" (@{cur_username})" if cur_username else "")
    )
    old_user_label = (
        f"{old_name}" + (f" (@{old_username})" if old_username else "")
    )

    ban_lines = []
    for item in ban_results:
        ban_lines.append(
            f"• <code>{item['group_id']}</code>: "
            + ("✅ banned" if item["ok"] else f"❌ {h(item.get('error', 'failed'))}")
        )

    text = (
        "🚨 <b>High-Risk Verification Match</b>\n\n"
        f"<b>Risk:</b> {match['score']}/100 — {h(match['reason'])}\n\n"

        "<b>Current user</b>\n"
        f"👤 {h(cur_user_label)}\n"
        f"🆔 <code>{current_doc['telegram_user_id']}</code>\n"
        f"🌐 IP: <code>{h(current_doc.get('ip') or 'N/A')}</code>\n"
        f"📍 Approx: {h(location_text(current_doc))}\n"
        f"🧩 Fingerprint: <code>{h(short_fp(current_doc.get('fingerprint')))}</code>\n\n"

        "<b>Matched banned user</b>\n"
        f"👤 {h(old_user_label)}\n"
        f"🆔 <code>{old.get('telegram_user_id')}</code>\n"
        f"🌐 IP: <code>{h(old.get('ip') or 'N/A')}</code>\n"
        f"📍 Approx: {h(location_text(old))}\n"
        f"🧩 Fingerprint: <code>{h(short_fp(old.get('fingerprint')))}</code>\n"
        f"🚫 Banned in group: <code>{match['group_id']}</code>\n\n"

        "<b>Automatic action</b>\n"
        + ("\n".join(ban_lines) if ban_lines else "No ban action.")
    )

    send_owner_message(text)



def format_verification_identity_details(doc: dict, *, include_ban_group: bool = False) -> str:
    """Full admin-facing verification details for comparison/review."""
    name = doc.get("name") or "Unknown"
    username = doc.get("username")
    label = name + (f" (@{username})" if username else "")
    device = doc.get("device") or {}

    fingerprint = doc.get("fingerprint") or "N/A"
    ip = doc.get("ip") or "N/A"

    lines = [
        f"👤 {h(label)}",
        f"🆔 <code>{int(doc.get('telegram_user_id', 0) or 0)}</code>",
        f"🌐 IP: <code>{h(ip)}</code>",
        f"📍 Approx: {h(location_text(doc))}",
        f"🧩 Fingerprint: <code>{h(fingerprint)}</code>",
    ]

    # Device/browser signals help the admin compare two same-IP users.
    if device.get("platform"):
        lines.append(f"💻 Platform: <code>{h(device.get('platform'))}</code>")
    if device.get("screen"):
        lines.append(f"🖥 Screen: <code>{h(device.get('screen'))}</code>")
    if device.get("timezone"):
        lines.append(f"🕒 Timezone: <code>{h(device.get('timezone'))}</code>")
    if device.get("language"):
        lines.append(f"🌐 Language: <code>{h(device.get('language'))}</code>")
    if device.get("hardware_concurrency") not in (None, ""):
        lines.append(f"⚙️ CPU Threads: <code>{h(device.get('hardware_concurrency'))}</code>")
    if device.get("max_touch_points") not in (None, ""):
        lines.append(f"👆 Touch Points: <code>{h(device.get('max_touch_points'))}</code>")
    if device.get("user_agent"):
        ua = str(device.get("user_agent"))
        if len(ua) > 220:
            ua = ua[:217] + "..."
        lines.append(f"🧭 User-Agent: <code>{h(ua)}</code>")

    if include_ban_group and doc.get("banned_group_id"):
        lines.append(f"🚫 Banned in: <code>{int(doc.get('banned_group_id'))}</code>")

    return "\n".join(lines)


def notify_same_ip_autoban(current_doc: dict, ip_matches: list, ban_result: dict):
    """Inform the owner with full current + matched-user details."""
    group_id = int(current_doc.get("target_group_id") or 0)
    group_name = get_group_title(group_id)

    matched_blocks = []
    for idx, old in enumerate(ip_matches[:8], start=1):
        matched_blocks.append(
            f"<b>Matched banned ID #{idx}</b>\n"
            + format_verification_identity_details(old, include_ban_group=True)
        )

    action_text = (
        "✅ Ban applied"
        if ban_result.get("ok")
        else f"⚠️ Ban failed: {h(ban_result.get('description') or 'Unknown error')}"
    )

    text = (
        "🚫 <b>Same-IP Auto-Ban Alert</b>\n\n"
        f"<b>Group:</b> {h(group_name)} (<code>{group_id}</code>)\n\n"
        "<b>Current user</b>\n"
        + format_verification_identity_details(current_doc)
        + "\n\n"
        f"<b>Banned IDs linked to this IP:</b> {len(ip_matches)}\n\n"
        + ("\n\n".join(matched_blocks) if matched_blocks else "None")
        + "\n\n<b>Decision:</b> Same-IP Auto Ban is ON and at least one linked ID is currently banned in this same group.\n"
        + action_text
    )
    return send_owner_message(text)


def notify_same_ip_review(current_doc: dict, ip_matches: list, event_id):
    """Alert the owner with full details and leave the request pending for a manual decision."""
    group_id = int(current_doc.get("target_group_id") or 0)
    group_name = get_group_title(group_id)

    matched_blocks = []
    for idx, old in enumerate(ip_matches[:8], start=1):
        matched_blocks.append(
            f"<b>Other ID on same IP #{idx}</b>\n"
            + format_verification_identity_details(old)
        )

    text = (
        "⚠️ <b>Same-IP Verification Alert</b>\n\n"
        f"<b>Group:</b> {h(group_name)} (<code>{group_id}</code>)\n\n"
        "<b>Current user</b>\n"
        + format_verification_identity_details(current_doc)
        + "\n\n"
        f"<b>Other IDs previously seen on this IP:</b> {len(ip_matches)}\n\n"
        + ("\n\n".join(matched_blocks) if matched_blocks else "None")
        + "\n\n<b>Decision required:</b> Same IP alone does not auto-ban this user. Compare the details above and choose an action."
    )

    keyboard = {
        "inline_keyboard": [[
            {"text": "✅ Approve", "callback_data": f"vipok:{group_id}:{current_doc['telegram_user_id']}"},
            {"text": "🚫 Ban", "callback_data": f"vipban:{group_id}:{current_doc['telegram_user_id']}"},
        ]]
    }
    return send_owner_message(text, reply_markup=keyboard)


# ============================================================
# Routes
# ============================================================

@app.get("/")
@app.get("/verify")
def verify_page():
    return send_from_directory(BASE_DIR, "verify.html")


@app.get("/group-photo")
def group_photo():
    try:
        group_id = int(request.args.get("group_id") or 0)
    except Exception:
        group_id = 0

    # Never proxy arbitrary Telegram chat photos. Only configured verification groups are allowed.
    if not group_id or not is_configured_group(group_id):
        return ("", 404)

    data, content_type = get_group_photo_bytes(group_id)
    if not data:
        return ("", 404)

    return send_file(
        io.BytesIO(data),
        mimetype=content_type or "image/jpeg",
        max_age=300,
        conditional=True,
    )


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "verification"})


@app.post("/api/verify")
def verify_api():
    payload = request.get_json(silent=True) or {}

    try:
        target_group_id = int(payload.get("group_id") or 0)
    except Exception:
        target_group_id = 0
    if not target_group_id or not is_configured_group(target_group_id):
        return jsonify({
            "ok": False,
            "status": "failed",
            "message": "This verification group is not configured.",
        }), 400

    ok, err, init = validate_init_data(str(payload.get("initData") or ""))
    if not ok:
        return jsonify({
            "ok": False,
            "status": "failed",
            "message": "Verification could not be completed.",
            "code": err,
        }), 401

    telegram_user = init["user"]
    telegram_user_id = init["user_id"]

    # One verification per active join cycle. Re-opening/re-clicking the same
    # Web App must not create more verification events or rerun anti-fraud
    # checks. A fresh join request resets this record back to `pending`.
    pending_doc = verification_pending.find_one({
        "group_id": target_group_id,
        "user_id": telegram_user_id,
    })
    if not pending_doc:
        return jsonify({
            "ok": False,
            "status": "no_active_request",
            "group_name": get_group_title(target_group_id),
            "message": "No active verification request was found. Please send a new join request first.",
        }), 409

    pending_status = str(pending_doc.get("status") or "")
    if pending_status in {
        "approved",
        "approved_exception",
        "approved_manual_ip_review",
        "verified_waiting_approval",
    }:
        return jsonify({
            "ok": True,
            "status": "already_verified",
            "group_name": get_group_title(target_group_id),
            "message": "You are already verified for this group. Verification will be required again only after you leave and send a new join request.",
        }), 200

    if pending_status == "manual_review_ip":
        return jsonify({
            "ok": True,
            "status": "manual_review",
            "group_name": get_group_title(target_group_id),
            "message": "Your verification is already under administrator review. Please wait for approval.",
        }), 200

    if pending_status != "pending":
        return jsonify({
            "ok": False,
            "status": "no_active_request",
            "group_name": get_group_title(target_group_id),
            "message": "This verification request is no longer active. Please send a new join request to verify again.",
        }), 409

    # Never trust telegram_user_id sent separately by browser.
    claimed_id = payload.get("telegram_user_id")
    try:
        if claimed_id is not None and int(claimed_id) != telegram_user_id:
            return jsonify({
                "ok": False,
                "status": "failed",
                "message": "Verification could not be completed.",
            }), 401
    except Exception:
        return jsonify({
            "ok": False,
            "status": "failed",
            "message": "Verification could not be completed.",
        }), 401

    fingerprint = str(payload.get("fingerprint") or "").strip().lower()
    if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
        return jsonify({
            "ok": False,
            "status": "failed",
            "message": "Verification could not be completed.",
        }), 400

    ip = client_ip()
    geo = approximate_ip_location(ip)

    first_name = str(telegram_user.get("first_name") or "").strip()
    last_name = str(telegram_user.get("last_name") or "").strip()
    name = " ".join(x for x in [first_name, last_name] if x).strip() or "Unknown"

    device = {
        "user_agent": str(payload.get("user_agent") or "")[:1000],
        "screen": str(payload.get("screen") or "")[:100],
        "timezone": str(payload.get("timezone") or "")[:100],
        "language": str(payload.get("language") or "")[:100],
        "platform": str(payload.get("platform") or "")[:100],
        "hardware_concurrency": payload.get("hardware_concurrency"),
        "max_touch_points": payload.get("max_touch_points"),
    }

    current_doc = {
        "telegram_user_id": telegram_user_id,
        "name": name,
        "username": telegram_user.get("username"),
        "is_premium": telegram_user.get("is_premium"),
        "fingerprint": fingerprint,
        "ip": ip,
        "geo": geo,
        "device": device,
        "group_ids": get_verification_group_ids(),
        "target_group_id": target_group_id,
        "auth_date": init["auth_date"],
        "created_at": datetime.now(timezone.utc),
        "decision": "pending",
    }

    # Owner-managed exception: authentication/fingerprint collection still happens,
    # but anti-fraud device/IP matching is bypassed for this Telegram user ID.
    # The join request is approved normally after valid Telegram Mini App verification.
    if is_verification_exception(telegram_user_id):
        current_doc["decision"] = "verified_exception"
        current_doc["risk_level"] = "exception"
        current_doc["risk_score"] = 0
        current_doc["exception_bypass"] = True

        inserted = verification_events.insert_one(current_doc)
        approve_result = telegram_api(
            "approveChatJoinRequest",
            {"chat_id": target_group_id, "user_id": telegram_user_id},
        )
        approved = bool(approve_result.get("ok"))
        unmute_result = unmute_user_in_group(target_group_id, telegram_user_id)
        unmuted = bool(unmute_result.get("ok"))
        access_restored = approved or unmuted
        if access_restored:
            delete_group_verification_prompt(target_group_id, telegram_user_id)

        verification_actions.insert_one({
            "event_id": inserted.inserted_id,
            "telegram_user_id": telegram_user_id,
            "group_id": target_group_id,
            "action": "approve_exception",
            "approve_ok": approved,
            "approve_error": approve_result.get("description"),
            "unmute_ok": unmuted,
            "unmute_error": unmute_result.get("description"),
            "created_at": datetime.now(timezone.utc),
        })
        verification_pending.update_one(
            {"group_id": target_group_id, "user_id": telegram_user_id},
            {"$set": {
                "status": "approved_exception" if access_restored else "verified_waiting_approval",
                "verified_at": datetime.now(timezone.utc),
                "verification_event_id": inserted.inserted_id,
                "exception_bypass": True,
                "muted_unverified": False if unmuted else None,
                "unmuted_at": datetime.now(timezone.utc) if unmuted else None,
            }},
            upsert=True,
        )

        if access_restored:
            return jsonify({
                "ok": True,
                "status": "approved",
                "group_name": get_group_title(target_group_id),
                "message": "Verification completed successfully. Your group access has been restored.",
            }), 200
        return jsonify({
            "ok": True,
            "status": "verified_waiting_approval",
            "group_name": get_group_title(target_group_id),
            "message": "Verification completed successfully. Your join request is waiting for approval.",
        }), 200

    matches = banned_matches_for_current_user(
        current_user_id=telegram_user_id,
        fingerprint=fingerprint,
        ip=ip,
        device=device,
        target_group_id=target_group_id,
    )

    best = matches[0] if matches else None
    banned_device_match = bool(best)

    if banned_device_match and AUTO_BAN_HIGH_RISK:
        ban_results = []
        decline_result, result = decline_and_ban_user(target_group_id, telegram_user_id)
        ban_results.append({
            "group_id": target_group_id,
            "ok": bool(result.get("ok")),
            "error": result.get("description"),
            "join_request_declined": bool(decline_result.get("ok")),
            "decline_error": decline_result.get("description"),
        })

        current_doc["decision"] = "auto_banned"
        current_doc["risk_level"] = "high"
        current_doc["risk_score"] = best["score"]
        current_doc["match_reason"] = best["reason"]
        current_doc["matched_user_id"] = best["matched_user_id"]
        current_doc["matched_group_id"] = best["group_id"]
        current_doc["ban_results"] = ban_results

        inserted = verification_events.insert_one(current_doc)

        verification_actions.insert_one({
            "event_id": inserted.inserted_id,
            "telegram_user_id": telegram_user_id,
            "action": "auto_ban_high_risk",
            "matched_user_id": best["matched_user_id"],
            "risk_score": best["score"],
            "reason": best["reason"],
            "ban_results": ban_results,
            "created_at": datetime.now(timezone.utc),
        })

        try:
            notify_high_risk(current_doc, best, ban_results)
        except Exception as e:
            logger.exception("Owner notification failed: %s", e)

        verification_pending.update_one(
            {"group_id": target_group_id, "user_id": telegram_user_id},
            {"$set": {"status": "auto_banned", "verified_at": datetime.now(timezone.utc)}},
            upsert=True,
        )

        # Keep user-facing response generic.
        return jsonify({
            "ok": False,
            "status": "restricted",
            "group_name": get_group_title(target_group_id),
            "message": "We found suspicious activity during verification. Please contact the group administrator.",
        }), 403

    # Same-IP behavior is controlled live by the bot owner via /ipban.
    # IMPORTANT: same IP alone NEVER auto-bans.
    # ON  -> auto-ban only when at least one historical ID on this exact IP is
    #        currently banned in THIS SAME target group.
    # OFF -> every same-IP match stays pending for manual owner review.
    ip_matches = same_ip_matches_for_current_user(telegram_user_id, ip)
    banned_ip_matches = banned_same_ip_matches_for_current_user(telegram_user_id, ip, target_group_id)
    if banned_ip_matches and same_ip_autoban_enabled():
        decline_result, ban_result = decline_and_ban_user(target_group_id, telegram_user_id)
        current_doc["decision"] = "auto_banned_same_ip_banned_link"
        current_doc["risk_level"] = "ip_banned_link"
        current_doc["risk_score"] = 100
        current_doc["match_reason"] = "same IP is linked to a Telegram ID that is currently banned in this group"
        current_doc["same_ip_user_ids"] = [
            int(x.get("telegram_user_id", 0) or 0) for x in ip_matches
            if x.get("telegram_user_id")
        ]
        current_doc["same_ip_banned_user_ids"] = sorted({
            int(x.get("telegram_user_id", 0) or 0) for x in banned_ip_matches
            if x.get("telegram_user_id")
        })
        current_doc["same_ip_banned_groups"] = sorted({
            int(x.get("banned_group_id", 0) or 0) for x in banned_ip_matches
            if x.get("banned_group_id")
        })
        current_doc["ban_results"] = [{
            "group_id": target_group_id,
            "ok": bool(ban_result.get("ok")),
            "error": ban_result.get("description"),
            "join_request_declined": bool(decline_result.get("ok")),
            "decline_error": decline_result.get("description"),
        }]

        inserted = verification_events.insert_one(current_doc)
        verification_actions.insert_one({
            "event_id": inserted.inserted_id,
            "telegram_user_id": telegram_user_id,
            "group_id": target_group_id,
            "action": "auto_ban_same_ip_banned_link",
            "same_ip_user_ids": current_doc["same_ip_user_ids"],
            "ban_result": current_doc["ban_results"][0],
            "created_at": datetime.now(timezone.utc),
        })
        verification_pending.update_one(
            {"group_id": target_group_id, "user_id": telegram_user_id},
            {"$set": {
                "status": "auto_banned_same_ip_banned_link",
                "verified_at": datetime.now(timezone.utc),
                "verification_event_id": inserted.inserted_id,
                "same_ip_user_ids": current_doc["same_ip_user_ids"],
            }},
            upsert=True,
        )

        try:
            notify_same_ip_autoban(current_doc, banned_ip_matches, current_doc["ban_results"][0])
        except Exception as e:
            logger.exception("Same-IP auto-ban owner notification failed: %s", e)

        return jsonify({
            "ok": False,
            "status": "restricted",
            "group_name": get_group_title(target_group_id),
            "message": "We found suspicious activity during verification. Please contact the group administrator.",
        }), 403

    # If the same IP is linked to an ID banned in THIS group but /ipban is OFF,
    # keep it for manual review. Same IP alone is harmless and must auto-approve.
    if banned_ip_matches:
        current_doc["decision"] = "manual_review_ip_banned_link"
        current_doc["risk_level"] = "review"
        current_doc["risk_score"] = 0
        current_doc["match_reason"] = "same IP is linked to an ID banned in this group; auto-ban is OFF"
        current_doc["same_ip_user_ids"] = [
            int(x.get("telegram_user_id", 0) or 0) for x in ip_matches
            if x.get("telegram_user_id")
        ]
        current_doc["same_ip_banned_user_ids"] = sorted({
            int(x.get("telegram_user_id", 0) or 0) for x in banned_ip_matches
            if x.get("telegram_user_id")
        })

        inserted = verification_events.insert_one(current_doc)
        verification_actions.insert_one({
            "event_id": inserted.inserted_id,
            "telegram_user_id": telegram_user_id,
            "group_id": target_group_id,
            "action": "manual_review_same_ip_banned_link",
            "same_ip_user_ids": current_doc["same_ip_user_ids"],
            "same_ip_banned_user_ids": current_doc["same_ip_banned_user_ids"],
            "created_at": datetime.now(timezone.utc),
        })

        verification_pending.update_one(
            {"group_id": target_group_id, "user_id": telegram_user_id},
            {"$set": {
                "status": "manual_review_ip",
                "verified_at": datetime.now(timezone.utc),
                "verification_event_id": inserted.inserted_id,
                "same_ip_user_ids": current_doc["same_ip_user_ids"],
                "same_ip_banned_user_ids": current_doc["same_ip_banned_user_ids"],
            }},
            upsert=True,
        )

        try:
            notify_same_ip_review(current_doc, banned_ip_matches, inserted.inserted_id)
        except Exception as e:
            logger.exception("Same-IP banned-link owner notification failed: %s", e)

        return jsonify({
            "ok": True,
            "status": "manual_review",
            "group_name": get_group_title(target_group_id),
            "message": "Verification submitted for administrator review. Please wait for approval.",
        }), 200

    # Same IP with no banned linked ID in this group is only informational.
    # Record it for audit, but do NOT alert the owner and do NOT block approval.
    if ip_matches:
        current_doc["same_ip_user_ids"] = [
            int(x.get("telegram_user_id", 0) or 0) for x in ip_matches
            if x.get("telegram_user_id")
        ]
        current_doc["same_ip_note"] = "same IP seen, but no linked ID is banned in this group"

    # No banned device match and no banned same-IP link: approve.
    current_doc["decision"] = "verified"
    current_doc["risk_level"] = best["level"] if best else "none"
    current_doc["risk_score"] = best["score"] if best else 0

    if best:
        current_doc["match_reason"] = best["reason"]
        current_doc["matched_user_id"] = best["matched_user_id"]
        current_doc["matched_group_id"] = best["group_id"]

    inserted = verification_events.insert_one(current_doc)

    approve_result = telegram_api(
        "approveChatJoinRequest",
        {"chat_id": target_group_id, "user_id": telegram_user_id},
    )
    approved = bool(approve_result.get("ok"))
    unmute_result = unmute_user_in_group(target_group_id, telegram_user_id)
    unmuted = bool(unmute_result.get("ok"))
    access_restored = approved or unmuted
    if access_restored:
        delete_group_verification_prompt(target_group_id, telegram_user_id)
    verification_pending.update_one(
        {"group_id": target_group_id, "user_id": telegram_user_id},
        {"$set": {
            "status": "approved" if access_restored else "verified_waiting_approval",
            "verified_at": datetime.now(timezone.utc),
            "verification_event_id": inserted.inserted_id,
            "approval_error": None if approved else approve_result.get("description"),
            "muted_unverified": False if unmuted else None,
            "unmuted_at": datetime.now(timezone.utc) if unmuted else None,
        }},
        upsert=True,
    )

    verification_actions.insert_one({
        "event_id": inserted.inserted_id,
        "telegram_user_id": telegram_user_id,
        "group_id": target_group_id,
        "action": "approve_join_request" if access_restored else "join_approval_failed",
        "error": None if access_restored else approve_result.get("description"),
        "unmute_ok": unmuted,
        "unmute_error": unmute_result.get("description"),
        "created_at": datetime.now(timezone.utc),
    })

    return jsonify({
        "ok": True,
        "status": "verified",
        "approved": access_restored,
        "message": (
            "Verification completed successfully. Your group access has been restored."
            if access_restored else
            "Verification completed successfully. Your join request is waiting for approval."
        ),
    })


if __name__ == "__main__":
    logger.info(
        "Verification server starting on %s:%s for groups %s",
        VERIFY_HOST,
        VERIFY_PORT,
        get_verification_group_ids(),
    )
    app.run(
        host=VERIFY_HOST,
        port=VERIFY_PORT,
        threaded=True,
    )
