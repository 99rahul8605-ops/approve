import os
import re
import json
import html
import asyncio
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from typing import Optional

from pyrogram import Client, filters, enums, idle
from pyrogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery, WebAppInfo, ChatPermissions
from motor.motor_asyncio import AsyncIOMotorClient

from verification_server import app as web_app, VERIFY_HOST, VERIFY_PORT

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("verification-bot")

BOT_TOKEN = (os.getenv("BOT_TOKEN") or "").strip()
API_ID = int((os.getenv("API_ID") or "0").strip())
API_HASH = (os.getenv("API_HASH") or "").strip()
BOT_USERNAME = (os.getenv("BOT_USERNAME") or "").strip().lstrip("@")
MONGODB_URI = (os.getenv("MONGODB_URI") or "").strip()
MONGO_DB_NAME = (os.getenv("MONGO_DB_NAME") or "afk_db").strip() or "afk_db"
OWNER_ID = int((os.getenv("OWNER_ID") or "0").strip())
VERIFY_URL = (os.getenv("VERIFY_URL") or os.getenv("RENDER_EXTERNAL_URL") or "").strip().rstrip("/")
VERIFICATION_REMINDER_SECONDS = int((os.getenv("VERIFICATION_REMINDER_SECONDS") or "240").strip())

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is required")
if not API_ID or not API_HASH:
    raise RuntimeError("API_ID and API_HASH are required")
if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is required")
if not OWNER_ID:
    raise RuntimeError("OWNER_ID is required")

bot = Client(
    "verification_bot",
    api_id=API_ID,
    api_hash=API_HASH,
    bot_token=BOT_TOKEN,
)

mongo = AsyncIOMotorClient(MONGODB_URI)
db = mongo[MONGO_DB_NAME]
verification_groups = db.verification_groups
verification_pending = db.verification_pending
verification_events = db.verification_events
verification_actions = db.verification_actions
verification_settings = db.verification_settings
verification_exceptions = db.verification_exceptions


def owner_only(user_id: int) -> bool:
    return int(user_id or 0) == OWNER_ID


async def get_verification_groups():
    return await verification_groups.find({"enabled": {"$ne": False}}).sort("added_at", 1).to_list(length=500)


async def add_verification_group(chat_id: int, title: str):
    await verification_groups.update_one(
        {"chat_id": int(chat_id)},
        {"$set": {
            "chat_id": int(chat_id),
            "title": title or str(chat_id),
            "enabled": True,
            "added_at": datetime.now(),
        }},
        upsert=True,
    )


async def remove_verification_group(chat_id: int):
    await verification_groups.delete_one({"chat_id": int(chat_id)})
    await verification_pending.delete_many({"group_id": int(chat_id), "status": "pending"})


async def get_group_name(group_id: int) -> str:
    try:
        chat = await bot.get_chat(int(group_id))
        title = getattr(chat, "title", None) or "this group"
        await verification_groups.update_one({"chat_id": int(group_id)}, {"$set": {"title": title}})
        return title
    except Exception:
        doc = await verification_groups.find_one({"chat_id": int(group_id)})
        return (doc or {}).get("title") or "this group"


def verification_url(group_id: int) -> str:
    return f"{VERIFY_URL}/verify?group_id={int(group_id)}"


async def get_same_ip_autoban_enabled() -> bool:
    doc = await verification_settings.find_one({"_id": "same_ip_auto_ban"})
    return bool(doc.get("enabled", False)) if doc else False


async def set_same_ip_autoban_enabled(enabled: bool):
    await verification_settings.update_one(
        {"_id": "same_ip_auto_ban"},
        {"$set": {"enabled": bool(enabled), "updated_at": datetime.now(), "updated_by": OWNER_ID}},
        upsert=True,
    )


VERIFIED_PENDING_STATUSES = {
    "approved",
    "approved_exception",
    "approved_manual_ip_review",
    "verified_waiting_approval",
}


async def mute_unverified_member(group_id: int, user_id: int) -> bool:
    """Mute a member who entered a protected group before completing verification."""
    try:
        await bot.restrict_chat_member(
            int(group_id),
            int(user_id),
            permissions=ChatPermissions(can_send_messages=False),
        )
        return True
    except Exception as e:
        logger.warning("Could not mute unverified member %s in %s: %s", user_id, group_id, e)
        return False


async def fully_unmute_member(group_id: int, user_id: int) -> bool:
    """Fully restore a verified member's ordinary group permissions.

    Do not copy the group's current default permissions here: if any default
    flag is false, that can leave a previously-muted member partially
    restricted. Instead explicitly clear the member-level restriction by
    granting every non-admin permission exposed by Pyrogram 2.x.
    """
    try:
        permissions = ChatPermissions(
            can_send_messages=True,
            can_send_media_messages=True,
            can_send_polls=True,
            can_send_other_messages=True,
            can_add_web_page_previews=True,
            can_change_info=True,
            can_invite_users=True,
            can_pin_messages=True,
        )
        await bot.restrict_chat_member(
            int(group_id),
            int(user_id),
            permissions=permissions,
        )
        return True
    except Exception as e:
        logger.warning("Could not fully unmute verified member %s in %s: %s", user_id, group_id, e)
        return False


def bot_deep_link(group_id: int, user_id: int) -> str:
    username = BOT_USERNAME.strip().lstrip("@")
    if not username:
        return ""
    return f"https://t.me/{username}?start=verify_{int(group_id)}_{int(user_id)}"


async def resolve_target_user(message: Message):
    """Resolve reply, numeric Telegram ID, or @username/username for owner commands."""
    if message.reply_to_message and message.reply_to_message.from_user:
        return message.reply_to_message.from_user

    if len(message.command) <= 1:
        return None

    raw = str(message.command[1] or "").strip()
    if not raw:
        return None

    try:
        if raw.lstrip("-").isdigit():
            return await bot.get_users(int(raw))

        username = raw if raw.startswith("@") else f"@{raw}"
        return await bot.get_users(username)
    except Exception:
        return None


def user_display(user) -> str:
    if not user:
        return "Unknown"
    name = (getattr(user, "first_name", None) or "User").strip()
    username = getattr(user, "username", None)
    return name + (f" (@{username})" if username else "")


async def send_join_verification_dm(join_request, group_name: str, group_id: int) -> bool:
    user_id = int(join_request.from_user.id)
    user_chat_id = getattr(join_request, "user_chat_id", None)
    url = verification_url(group_id)
    text = (
        "🔐 Verification Required\n\n"
        f"Group: {group_name}\n\n"
        "Verification is compulsory to be approved in this group.\n\n"
        "✅ Secure device verification\n"
        "⚡ Takes only a few seconds\n\n"
        "Tap the button below to continue."
    )
    button_text = f"✅ Verify for {group_name}"[:64]

    if user_chat_id:
        payload = {
            "chat_id": int(user_chat_id),
            "text": text,
            "reply_markup": {"inline_keyboard": [[{"text": button_text, "web_app": {"url": url}}]]},
        }

        def do_send():
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")

        try:
            status, body = await asyncio.to_thread(do_send)
            if 200 <= int(status) < 300:
                logger.info("Verification DM sent to %s for group %s", user_id, group_id)
                return True
            logger.warning("Verification DM Bot API failed [%s]: %s", status, body)
        except Exception as e:
            logger.warning("Temporary join-request DM failed for %s: %s", user_id, e)

    try:
        await bot.send_message(
            user_id,
            text,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(button_text, web_app=WebAppInfo(url=url))]]),
        )
        return True
    except Exception as e:
        logger.warning("Private DM fallback failed for %s: %s", user_id, e)
        return False


async def send_verification_reminder(pending: dict) -> bool:
    """Send one reminder while Telegram's temporary join-request DM is still valid.

    Telegram only exposes the temporary requester chat for about five minutes.
    The reminder loop therefore defaults to 240 seconds (4 minutes), leaving
    enough margin for scheduler/network delay. The delay is configurable via
    VERIFICATION_REMINDER_SECONDS.
    """
    user_id = int(pending.get("user_id") or 0)
    group_id = int(pending.get("group_id") or 0)
    user_chat_id = pending.get("user_chat_id")
    if not user_id or not group_id or not VERIFY_URL:
        return False

    group_name = pending.get("group_title") or await get_group_name(group_id)
    url = verification_url(group_id)
    text = (
        "⏰ Verification Reminder\n\n"
        f"Group: {group_name}\n\n"
        "You have not completed your verification yet.\n"
        "Verification is compulsory to be approved in this group.\n\n"
        "Tap the button below to verify now."
    )
    button_text = f"✅ Verify for {group_name}"[:64]

    if user_chat_id:
        payload = {
            "chat_id": int(user_chat_id),
            "text": text,
            "reply_markup": {"inline_keyboard": [[{"text": button_text, "web_app": {"url": url}}]]},
        }

        def do_send():
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")

        try:
            status, body = await asyncio.to_thread(do_send)
            if 200 <= int(status) < 300:
                logger.info("Verification reminder sent via temporary chat to %s for group %s", user_id, group_id)
                return True
            logger.warning("Verification reminder Bot API failed [%s]: %s", status, body)
        except Exception as e:
            logger.warning("Temporary reminder DM failed for %s: %s", user_id, e)

    try:
        await bot.send_message(
            user_id,
            text,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(button_text, web_app=WebAppInfo(url=url))]]),
        )
        logger.info("Verification reminder sent to %s for group %s", user_id, group_id)
        return True
    except Exception as e:
        if "PEER_ID_INVALID" in str(e):
            logger.info("Verification reminder fallback unavailable for %s (user has not opened the bot in PM yet).", user_id)
        else:
            logger.warning("Verification reminder fallback failed for %s: %s", user_id, e)
        return False


async def verification_reminder_loop():
    """Persistently send one reminder before the temporary DM window expires."""
    while True:
        try:
            cutoff = datetime.now() - timedelta(seconds=VERIFICATION_REMINDER_SECONDS)
            cursor = verification_pending.find({
                "status": "pending",
                "requested_at": {"$lte": cutoff},
                "reminder_attempted": {"$ne": True},
            }).sort("requested_at", 1).limit(100)

            async for pending in cursor:
                # Claim the reminder atomically so multiple loop iterations or
                # duplicate workers do not send it twice.
                claim = await verification_pending.update_one(
                    {
                        "_id": pending["_id"],
                        "status": "pending",
                        "reminder_attempted": {"$ne": True},
                    },
                    {"$set": {
                        "reminder_attempted": True,
                        "reminder_attempted_at": datetime.now(),
                    }},
                )
                if claim.modified_count == 0:
                    continue

                sent = await send_verification_reminder(pending)
                await verification_pending.update_one(
                    {"_id": pending["_id"]},
                    {"$set": {
                        "reminder_sent": bool(sent),
                        "reminder_sent_at": datetime.now() if sent else None,
                    }},
                )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.exception("Verification reminder loop error: %s", e)

        await asyncio.sleep(15)


def help_text(is_owner: bool) -> str:
    text = (
        "🔐 **Verification Bot**\n\n"
        "This bot verifies join requests before approving users into protected groups.\n\n"
        "**User command:**\n"
        "• `/verify` — Open your pending group verification\n"
    )
    if is_owner:
        text += (
            "\n**Admin Commands:**\n"
            "• `/addverifygroup` — Enable verification in the current group\n"
            "• `/removeverifygroup` — Remove current group from verification\n"
            "• `/removeverifygroup <group_id>` — Remove by ID\n"
            "• `/verifygroups` — List protected groups\n"
            "• `/ipban` — Manage linked-account auto-ban policy for the same group\n"
            "• `/addexception <user_id>` — Add anti-fraud exception\n"
            "• `/removeexception <user_id>` — Remove exception\n"
            "• `/verifyexceptions` — List exceptions\n"
            "• `/info <user_id>` — View Telegram + verification/device details\n\n"
            "Exception users are not restricted by the group message guard; verification can still be completed normally."
        )
    return text


@bot.on_message(filters.command("start"))
async def start_cmd(_, message: Message):
    uid = int(message.from_user.id if message.from_user else 0)
    payload = message.command[1] if len(message.command) > 1 else ""
    m = re.fullmatch(r"verify_(-?\d+)_(\d+)", payload or "")
    if m:
        gid, target_uid = int(m.group(1)), int(m.group(2))
        if uid != target_uid:
            await message.reply_text("❌ This verification link is not for your account.")
            return
        pending = await verification_pending.find_one({"group_id": gid, "user_id": uid})
        if not pending:
            await message.reply_text("❌ No pending verification was found for this group.")
            return
        if pending.get("status") in VERIFIED_PENDING_STATUSES:
            await fully_unmute_member(gid, uid)
            await message.reply_text("✅ You are already verified for this group.")
            return
        name = await get_group_name(gid)
        await message.reply_text(
            "🔐 **Verification Required**\n\n"
            f"**Group:** {name}\n\n"
            "You joined before completing verification, so messaging is temporarily restricted.\n"
            "Complete verification below to restore full access.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(f"✅ Verify for {name}"[:64], web_app=WebAppInfo(url=verification_url(gid)))
            ]]),
        )
        return
    await message.reply_text(help_text(owner_only(uid)))


@bot.on_message(filters.command("help"))
async def help_cmd(_, message: Message):
    await message.reply_text(help_text(owner_only(message.from_user.id if message.from_user else 0)))


@bot.on_message(filters.command("addverifygroup") & filters.user(OWNER_ID))
async def add_group_cmd(_, message: Message):
    if message.chat.type not in (enums.ChatType.GROUP, enums.ChatType.SUPERGROUP):
        await message.reply_text("Add me to the target group as an admin, then run /addverifygroup there.")
        return
    try:
        me = await bot.get_me()
        member = await bot.get_chat_member(message.chat.id, me.id)
        if member.status not in (enums.ChatMemberStatus.ADMINISTRATOR, enums.ChatMemberStatus.OWNER):
            await message.reply_text("❌ Make me an admin first. I need permission to approve join requests and ban users.")
            return
    except Exception:
        await message.reply_text("❌ I could not verify my admin permissions in this group.")
        return
    await add_verification_group(message.chat.id, message.chat.title or str(message.chat.id))
    await message.reply_text(
        f"✅ **Verification enabled**\n\nGroup: **{message.chat.title or message.chat.id}**\nID: `{message.chat.id}`\n\n"
        "New join requests will be sent to verification before approval."
    )


@bot.on_message(filters.command("removeverifygroup") & filters.user(OWNER_ID))
async def remove_group_cmd(_, message: Message):
    gid = None
    if message.chat.type in (enums.ChatType.GROUP, enums.ChatType.SUPERGROUP):
        gid = int(message.chat.id)
    elif len(message.command) > 1:
        try:
            gid = int(message.command[1])
        except Exception:
            pass
    if gid is None:
        await message.reply_text("Use /removeverifygroup inside the group, or /removeverifygroup <group_id> in DM.")
        return
    doc = await verification_groups.find_one({"chat_id": gid})
    if not doc:
        await message.reply_text("❌ That group is not in the verification list.")
        return
    await remove_verification_group(gid)
    await message.reply_text(f"✅ Removed **{doc.get('title') or gid}** (`{gid}`) from verification.")


@bot.on_message(filters.command("verifygroups") & filters.user(OWNER_ID))
async def list_groups_cmd(_, message: Message):
    rows = await get_verification_groups()
    if not rows:
        await message.reply_text("No verification groups added yet. Run /addverifygroup inside a group.")
        return
    lines = ["🔐 **Verification Groups**", ""]
    for i, row in enumerate(rows, 1):
        lines.append(f"{i}. **{row.get('title') or row['chat_id']}** — `{row['chat_id']}`")
    await message.reply_text("\n".join(lines))


@bot.on_message(filters.command(["ipban", "ipautoban"]) & filters.user(OWNER_ID))
async def ipban_cmd(_, message: Message):
    enabled = await get_same_ip_autoban_enabled()
    await message.reply_text(
        "🌐 **Network Match Auto Ban**\n\n"
        f"Status: **{'🟢 ON' if enabled else '🔴 OFF'}**\n\n"
        "ON → auto-ban only if a linked account is currently banned in this same group.\n"
        "Same IP with no ID banned in this group → auto-approve after verification.\n"
        "OFF → linked-account matches tied to a banned ID in this group go to manual review.\n\n"
        "Exact-device + banned-ID protection remains active separately.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("✅ Turn ON", callback_data="vipsetting:ipban:on"),
            InlineKeyboardButton("❌ Turn OFF", callback_data="vipsetting:ipban:off"),
        ]]),
    )


@bot.on_callback_query(filters.regex(r"^vipsetting:ipban:(on|off)$"))
async def ipban_toggle(_, query: CallbackQuery):
    if not owner_only(query.from_user.id if query.from_user else 0):
        await query.answer("Owner only.", show_alert=True)
        return
    enabled = (query.data or "").endswith(":on")
    await set_same_ip_autoban_enabled(enabled)
    await query.message.edit_text(
        "🌐 **Network Match Auto Ban**\n\n"
        f"Status: **{'🟢 ON' if enabled else '🔴 OFF'}**\n\n"
        "ON → auto-ban only if a linked account is currently banned in this same group.\n"
        "Same IP with no ID banned in this group → auto-approve after verification.\n"
        "OFF → linked-account matches tied to a banned ID in this group wait for manual review.\n\n"
        "Exact-device + banned-ID protection remains active separately.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("✅ Turn ON", callback_data="vipsetting:ipban:on"),
            InlineKeyboardButton("❌ Turn OFF", callback_data="vipsetting:ipban:off"),
        ]]),
    )
    await query.answer("Setting updated.")



def _info_dt(value) -> str:
    if not value:
        return "N/A"
    try:
        return value.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value)


def _info_location(doc: dict) -> str:
    geo = (doc or {}).get("geo") or {}
    parts = [
        geo.get("city"),
        geo.get("region"),
        geo.get("country"),
    ]
    return ", ".join(str(x) for x in parts if x) or "Unknown"


def _info_user_label_from_event(doc: dict) -> str:
    name = str((doc or {}).get("name") or "Unknown")
    username = (doc or {}).get("username")
    return name + (f" (@{username})" if username else "")


async def _linked_verification_ids(user_id: int, field: str, value, limit: int = 10):
    if not value:
        return []

    cursor = verification_events.find(
        {
            "telegram_user_id": {"$ne": int(user_id)},
            field: value,
        }
    ).sort("created_at", -1)

    rows = await cursor.to_list(length=100)
    result = []
    seen = set()
    for row in rows:
        uid = int(row.get("telegram_user_id", 0) or 0)
        if not uid or uid in seen:
            continue
        seen.add(uid)
        result.append(row)
        if len(result) >= limit:
            break
    return result


async def _send_html_chunks(message: Message, text_value: str):
    """Telegram messages are capped; split long /info output on line boundaries."""
    max_len = 3900
    if len(text_value) <= max_len:
        await message.reply_text(
            text_value,
            parse_mode=enums.ParseMode.HTML,
            disable_web_page_preview=True,
        )
        return

    lines = text_value.splitlines()
    chunks = []
    current = ""
    for line in lines:
        candidate = current + ("\n" if current else "") + line
        if len(candidate) > max_len and current:
            chunks.append(current)
            current = line
        else:
            current = candidate
    if current:
        chunks.append(current)

    for chunk in chunks:
        await message.reply_text(
            chunk,
            parse_mode=enums.ParseMode.HTML,
            disable_web_page_preview=True,
        )


@bot.on_message(filters.command("info") & filters.user(OWNER_ID))
async def user_info_cmd(_, message: Message):
    """Owner-only Telegram + verification audit lookup.

    Supports numeric Telegram UID as requested, and also reply / @username for convenience.
    """
    user = await resolve_target_user(message)
    if not user:
        await message.reply_text(
            "Usage:\n"
            "<code>/info 123456789</code>\n"
            "<code>/info @username</code>\n"
            "or reply to a user's message with <code>/info</code>.",
            parse_mode=enums.ParseMode.HTML,
        )
        return

    uid = int(user.id)

    latest_event = await verification_events.find_one(
        {"telegram_user_id": uid},
        sort=[("created_at", -1)],
    )
    events = await verification_events.find(
        {"telegram_user_id": uid}
    ).sort("created_at", -1).to_list(length=10)

    pending_rows = await verification_pending.find(
        {"user_id": uid}
    ).sort("requested_at", -1).to_list(length=100)

    exception = await verification_exceptions.find_one(
        {"user_id": uid, "enabled": {"$ne": False}}
    )

    total_events = await verification_events.count_documents({"telegram_user_id": uid})
    total_actions = await verification_actions.count_documents({"telegram_user_id": uid})

    full_name = " ".join(
        x for x in [
            getattr(user, "first_name", None),
            getattr(user, "last_name", None),
        ] if x
    ).strip() or "Unknown"
    username = getattr(user, "username", None)

    lines = [
        "👤 <b>User Info</b>",
        "",
        f"<b>Name:</b> {html.escape(full_name)}",
        f"<b>Username:</b> @{html.escape(username)}" if username else "<b>Username:</b> —",
        f"<b>UID:</b> <code>{uid}</code>",
        f"<b>Bot:</b> {'Yes' if getattr(user, 'is_bot', False) else 'No'}",
        f"<b>Premium:</b> {'Yes' if getattr(user, 'is_premium', False) else 'No'}",
        f"<b>Verified account:</b> {'Yes' if getattr(user, 'is_verified', False) else 'No'}",
        f"<b>Scam flag:</b> {'Yes' if getattr(user, 'is_scam', False) else 'No'}",
        f"<b>Fake flag:</b> {'Yes' if getattr(user, 'is_fake', False) else 'No'}",
        f"<b>Exception:</b> {'✅ Yes' if exception else '❌ No'}",
        "",
        "📊 <b>Verification Summary</b>",
        f"<b>Total verification events:</b> {total_events}",
        f"<b>Total recorded actions:</b> {total_actions}",
    ]

    if latest_event:
        device = latest_event.get("device") or {}
        fingerprint = latest_event.get("fingerprint") or "N/A"
        ip = latest_event.get("ip") or "N/A"
        lines += [
            "",
            "🧾 <b>Latest Verification</b>",
            f"<b>Decision:</b> {html.escape(str(latest_event.get('decision') or 'N/A'))}",
            f"<b>Risk:</b> {html.escape(str(latest_event.get('risk_level') or 'none'))}"
            f" ({html.escape(str(latest_event.get('risk_score', 0)))})",
            f"<b>Group:</b> <code>{int(latest_event.get('target_group_id', 0) or 0)}</code>",
            f"<b>Network ID:</b> <code>{html.escape(str(ip))}</code>",
            f"<b>Approx:</b> {html.escape(_info_location(latest_event))}",
            f"<b>Device ID:</b> <code>{html.escape(str(fingerprint))}</code>",
            f"<b>Platform:</b> <code>{html.escape(str(device.get('platform') or 'N/A'))}</code>",
            f"<b>Screen:</b> <code>{html.escape(str(device.get('screen') or 'N/A'))}</code>",
            f"<b>Timezone:</b> <code>{html.escape(str(device.get('timezone') or 'N/A'))}</code>",
            f"<b>Language:</b> <code>{html.escape(str(device.get('language') or 'N/A'))}</code>",
            f"<b>CPU Threads:</b> <code>{html.escape(str(device.get('hardware_concurrency') if device.get('hardware_concurrency') is not None else 'N/A'))}</code>",
            f"<b>Touch Points:</b> <code>{html.escape(str(device.get('max_touch_points') if device.get('max_touch_points') is not None else 'N/A'))}</code>",
            f"<b>Verified at:</b> {_info_dt(latest_event.get('created_at'))}",
        ]
        ua = str(device.get("user_agent") or "N/A")
        if len(ua) > 450:
            ua = ua[:447] + "..."
        lines.append(f"<b>User-Agent:</b> <code>{html.escape(ua)}</code>")

        same_device = await _linked_verification_ids(uid, "fingerprint", fingerprint, limit=10)
        same_ip = await _linked_verification_ids(uid, "ip", ip, limit=10)

        lines += ["", f"🧩 <b>Related device IDs ({len(same_device)}):</b>"]
        if same_device:
            for row in same_device:
                other_uid = int(row.get("telegram_user_id", 0) or 0)
                label = _info_user_label_from_event(row)
                lines.append(
                    f"• {html.escape(label)} — <code>{other_uid}</code>"
                    f" | {html.escape(str(row.get('decision') or 'N/A'))}"
                )
        else:
            lines.append("• None detected")

        lines += ["", f"🌐 <b>Related network IDs ({len(same_ip)}):</b>"]
        if same_ip:
            for row in same_ip:
                other_uid = int(row.get("telegram_user_id", 0) or 0)
                label = _info_user_label_from_event(row)
                fp = str(row.get("fingerprint") or "N/A")
                short_fp = fp if len(fp) <= 24 else f"{fp[:12]}…{fp[-8:]}"
                lines.append(
                    f"• {html.escape(label)} — <code>{other_uid}</code>"
                    f" | FP <code>{html.escape(short_fp)}</code>"
                    f" | {html.escape(str(row.get('decision') or 'N/A'))}"
                )
        else:
            lines.append("• None detected")
    else:
        lines += ["", "ℹ️ <b>No completed Mini App verification event found.</b>"]

    if pending_rows:
        lines += ["", "🏷️ <b>Protected Group Records</b>"]
        shown = 0
        seen_groups = set()
        group_docs = {
            int(row.get("chat_id")): row
            for row in await get_verification_groups()
            if row.get("chat_id") is not None
        }

        for pending in pending_rows:
            gid = int(pending.get("group_id", 0) or 0)
            if not gid or gid in seen_groups:
                continue
            seen_groups.add(gid)
            shown += 1

            title = (group_docs.get(gid) or {}).get("title") or pending.get("group_title") or str(gid)
            status = str(pending.get("status") or "unknown")
            live_status = "unknown"
            try:
                member = await bot.get_chat_member(gid, uid)
                member_status = getattr(member, "status", None)
                live_status = getattr(member_status, "value", None) or str(member_status or "unknown")
            except Exception:
                # Not a current member / inaccessible / never admitted.
                live_status = "not member or unavailable"

            lines.append(
                f"• <b>{html.escape(str(title))}</b> (<code>{gid}</code>)\n"
                f"  DB: <code>{html.escape(status)}</code> | Telegram: <code>{html.escape(live_status)}</code>"
            )
            if shown >= 25:
                remaining = len(seen_groups) - shown
                if remaining > 0:
                    lines.append(f"• …and {remaining} more")
                break
    else:
        lines += ["", "🏷️ <b>No protected-group verification records found.</b>"]

    if events:
        lines += ["", "🕘 <b>Recent Verification History</b>"]
        for event in events[:5]:
            gid = int(event.get("target_group_id", 0) or 0)
            decision = str(event.get("decision") or "N/A")
            created = _info_dt(event.get("created_at"))
            lines.append(
                f"• <code>{gid}</code> — {html.escape(decision)} — {html.escape(created)}"
            )

    await _send_html_chunks(message, "\n".join(lines))


@bot.on_message(filters.command("addexception") & filters.user(OWNER_ID))
async def add_exception_cmd(_, message: Message):
    user = await resolve_target_user(message)
    if not user:
        await message.reply_text(
            "Usage:\n"
            "`/addexception 123456789`\n"
            "`/addexception @username`\n"
            "`/addexception username`\n"
            "or reply to a user's message with `/addexception`."
        )
        return

    uid = int(user.id)
    await verification_exceptions.update_one(
        {"user_id": uid},
        {"$set": {
            "user_id": uid,
            "username": getattr(user, "username", None),
            "name": user_display(user),
            "enabled": True,
            "added_at": datetime.now(),
            "added_by": OWNER_ID,
        }},
        upsert=True,
    )

    # If this user had already been restricted by the unverified-message guard,
    # clear that restriction immediately across protected groups.
    unmuted_groups = 0
    pending_rows = await verification_pending.find(
        {"user_id": uid, "muted_unverified": True}
    ).to_list(length=200)
    for row in pending_rows:
        gid = int(row.get("group_id", 0) or 0)
        if not gid:
            continue
        try:
            if await fully_unmute_member(gid, uid):
                unmuted_groups += 1
        except Exception as e:
            logger.debug("Could not clear exception-user restriction for %s in %s: %s", uid, gid, e)

        # Remove an old verification-guard prompt if one was posted in the group.
        try:
            await delete_group_verification_prompt(row)
        except Exception as e:
            logger.debug("Could not clear exception-user verification prompt for %s in %s: %s", uid, gid, e)

        await verification_pending.update_one(
            {"_id": row["_id"]},
            {"$set": {
                "muted_unverified": False,
                "exception_guard_bypass": True,
                "exception_guard_bypass_at": datetime.now(),
            }},
        )

    note = f"\n✅ Group restriction cleared in {unmuted_groups} group(s)." if unmuted_groups else ""
    await message.reply_text(
        f"✅ Exception added for **{user_display(user)}** — `{uid}`.\n"
        "Verification remains available, but this user will not be muted or have messages removed by the group guard."
        + note
    )


@bot.on_message(filters.command("removeexception") & filters.user(OWNER_ID))
async def remove_exception_cmd(_, message: Message):
    user = await resolve_target_user(message)
    if not user:
        await message.reply_text(
            "Usage:\n"
            "`/removeexception 123456789`\n"
            "`/removeexception @username`\n"
            "`/removeexception username`\n"
            "or reply to a user's message with `/removeexception`."
        )
        return

    uid = int(user.id)
    result = await verification_exceptions.delete_one({"user_id": uid})
    await message.reply_text(
        ("✅ Removed" if result.deleted_count else "ℹ️ Not found")
        + f" exception for **{user_display(user)}** — `{uid}`."
    )


@bot.on_message(filters.command("verifyexceptions") & filters.user(OWNER_ID))
async def list_exceptions_cmd(_, message: Message):
    rows = await verification_exceptions.find({"enabled": {"$ne": False}}).sort("added_at", 1).to_list(length=500)
    if not rows:
        await message.reply_text("No verification exceptions configured.")
        return
    lines = ["🛡️ **Verification Exceptions**", ""]
    for i, row in enumerate(rows, 1):
        uid = int(row.get("user_id", 0) or 0)
        try:
            u = await bot.get_users(uid)
            name = (u.first_name or "User") + (f" (@{u.username})" if u.username else "")
            lines.append(f"{i}. {name} — `{uid}`")
        except Exception:
            lines.append(f"{i}. `{uid}`")
    await message.reply_text("\n".join(lines))


@bot.on_chat_join_request()
async def on_join_request(_, join_request):
    gid = int(join_request.chat.id)
    group = await verification_groups.find_one({"chat_id": gid, "enabled": {"$ne": False}})
    if not group:
        return

    uid = int(join_request.from_user.id)
    # Every NEW join request starts a fresh verification cycle. This is the
    # only normal way an already-verified user becomes eligible to verify again.
    await verification_pending.update_one(
        {"group_id": gid, "user_id": uid},
        {
            "$set": {
                "group_id": gid,
                "group_title": join_request.chat.title or group.get("title") or str(gid),
                "user_id": uid,
                "status": "pending",
                "requested_at": datetime.now(),
                "user_chat_id": int(getattr(join_request, "user_chat_id", 0) or 0) or None,
                "reminder_attempted": False,
                "reminder_sent": False,
                "group_verify_prompt_sent": False,
                "muted_unverified": False,
            },
            "$inc": {"verification_cycle": 1},
            "$unset": {
                "verified_at": "",
                "verification_event_id": "",
                "reviewed_at": "",
                "reviewed_by": "",
                "approval_error": "",
                "unmuted_at": "",
                "same_ip_user_ids": "",
            },
        },
        upsert=True,
    )

    if not VERIFY_URL:
        logger.warning("VERIFY_URL is empty. Set VERIFY_URL or deploy on Render where RENDER_EXTERNAL_URL is available.")
        return

    name = join_request.chat.title or group.get("title") or "this group"
    sent = await send_join_verification_dm(join_request, name, gid)
    await verification_pending.update_one(
        {"group_id": gid, "user_id": uid},
        {"$set": {"dm_sent": bool(sent), "dm_attempted_at": datetime.now()}},
    )


@bot.on_chat_member_updated()
async def track_member_leave(_, update):
    """Invalidate a completed verification when the user leaves a protected group.

    A future join request will create a fresh pending cycle and require verification again.
    """
    try:
        gid = int(update.chat.id)
        group = await verification_groups.find_one({"chat_id": gid, "enabled": {"$ne": False}})
        if not group:
            return

        old_member = getattr(update, "old_chat_member", None)
        new_member = getattr(update, "new_chat_member", None)
        user = getattr(new_member, "user", None) or getattr(old_member, "user", None)
        if not user or getattr(user, "is_bot", False):
            return
        uid = int(user.id)

        old_status = getattr(old_member, "status", None)
        new_status = getattr(new_member, "status", None)
        active_statuses = {
            enums.ChatMemberStatus.MEMBER,
            enums.ChatMemberStatus.RESTRICTED,
            enums.ChatMemberStatus.ADMINISTRATOR,
            enums.ChatMemberStatus.OWNER,
        }
        left_statuses = {enums.ChatMemberStatus.LEFT, enums.ChatMemberStatus.BANNED}
        if old_status not in active_statuses or new_status not in left_statuses:
            return

        pending = await verification_pending.find_one({"group_id": gid, "user_id": uid})
        if not pending:
            return
        status = str(pending.get("status") or "")
        # Preserve actual ban decisions; they are security records, not ordinary leaves.
        if status.startswith("banned") or status.startswith("auto_banned"):
            return
        if status in VERIFIED_PENDING_STATUSES or status == "manual_review_ip":
            await verification_pending.update_one(
                {"_id": pending["_id"]},
                {"$set": {
                    "status": "left_requires_reverification",
                    "left_at": datetime.now(),
                    "group_verify_prompt_sent": False,
                    "reminder_attempted": False,
                    "reminder_sent": False,
                }},
            )
            logger.info("Verification invalidated after leave: user=%s group=%s", uid, gid)
    except Exception as e:
        logger.debug("Could not process chat-member leave update: %s", e)


@bot.on_message(filters.group & ~filters.service & ~filters.me)
async def guard_unverified_group_member(_, message: Message):
    """If another admin admits an unverified requester, mute them on first message and send a targeted verify prompt."""
    if not message.from_user or message.from_user.is_bot:
        return
    gid = int(message.chat.id)
    group = await verification_groups.find_one({"chat_id": gid, "enabled": {"$ne": False}})
    if not group:
        return

    uid = int(message.from_user.id)
    try:
        member = await bot.get_chat_member(gid, uid)
        if member.status in (enums.ChatMemberStatus.ADMINISTRATOR, enums.ChatMemberStatus.OWNER):
            return
    except Exception:
        pass

    pending = await verification_pending.find_one({"group_id": gid, "user_id": uid})
    if not pending:
        return

    # Exception users are never muted and their group messages are never deleted.
    # They may still complete the normal verification flow for join approval, but
    # this guard must not restrict them after an admin has admitted them.
    exception = await verification_exceptions.find_one(
        {"user_id": uid, "enabled": {"$ne": False}}
    )
    if exception:
        if pending.get("muted_unverified"):
            await fully_unmute_member(gid, uid)
            await verification_pending.update_one(
                {"_id": pending["_id"]},
                {"$set": {
                    "muted_unverified": False,
                    "exception_guard_bypass": True,
                    "exception_guard_bypass_at": datetime.now(),
                }},
            )
        return

    status = str(pending.get("status") or "pending")
    if status in VERIFIED_PENDING_STATUSES or status.startswith("banned") or status.startswith("auto_banned"):
        return

    muted = await mute_unverified_member(gid, uid)
    if muted:
        try:
            await message.delete()
        except Exception as e:
            logger.debug("Could not delete pre-verification message from %s in %s: %s", uid, gid, e)
    now = datetime.now()
    await verification_pending.update_one(
        {"_id": pending["_id"]},
        {"$set": {
            "muted_unverified": bool(muted),
            "muted_at": now if muted else pending.get("muted_at"),
            "admitted_before_verification": True,
        }},
    )

    # Avoid spamming the group if the handler sees more than one update before the mute takes effect.
    claim = await verification_pending.update_one(
        {"_id": pending["_id"], "group_verify_prompt_sent": {"$ne": True}},
        {"$set": {"group_verify_prompt_sent": True, "group_verify_prompt_sent_at": now}},
    )
    if claim.modified_count == 0:
        return

    deep_link = bot_deep_link(gid, uid)
    if not deep_link:
        logger.warning("BOT_USERNAME unavailable; cannot create private deep-link verification prompt.")
        return
    name = html.escape(message.from_user.first_name or "User")
    user_mention = f'<a href="tg://user?id={uid}">{name}</a>'
    prompt_msg = await message.reply_text(
        f"🔐 <b>Verification Required for {user_mention}</b>\n\n"
        "You must complete verification before you can send messages in this group.\n"
        "Tap the button below to continue in private chat.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("✅ Verify in Private Chat", url=deep_link)
        ]]),
        parse_mode=enums.ParseMode.HTML,
    )
    # Save the verification prompt so it can be removed automatically after
    # successful verification/manual approval, keeping the group clean.
    await verification_pending.update_one(
        {"_id": pending["_id"]},
        {"$set": {
            "group_verify_prompt_message_id": int(prompt_msg.id),
            "group_verify_prompt_chat_id": gid,
        }},
    )


@bot.on_message(filters.command("verify"))
async def verify_cmd(_, message: Message):
    if message.chat.type != enums.ChatType.PRIVATE:
        await message.reply_text("🔐 Open this bot in private chat and send /verify.")
        return
    if not VERIFY_URL:
        await message.reply_text("❌ Verification URL is not configured yet.")
        return

    uid = int(message.from_user.id)
    pending = await verification_pending.find_one(
        {"user_id": uid},
        sort=[("requested_at", -1)],
    )
    if not pending:
        await message.reply_text(
            "ℹ️ You do not have an active verification request.\n\n"
            "Send a join request to a protected group first."
        )
        return

    status = str(pending.get("status") or "")
    gid = int(pending["group_id"])
    name = await get_group_name(gid)

    if status in VERIFIED_PENDING_STATUSES:
        await fully_unmute_member(gid, uid)
        await message.reply_text(
            f"✅ You are already verified for **{name}**.\n\n"
            "You only need to verify again after leaving the group and sending a new join request."
        )
        return

    if status == "manual_review_ip":
        await message.reply_text(
            f"⏳ Your verification for **{name}** is already under administrator review.\n\n"
            "You do not need to verify again."
        )
        return

    if status != "pending":
        await message.reply_text(
            f"ℹ️ There is no active verification request for **{name}**.\n\n"
            "Send a new join request to start verification again."
        )
        return
    await message.reply_text(
        "🔐 **Verification Required**\n\n"
        f"**Group:** {name}\n\n"
        "Verification is compulsory to be approved in this group.\n\n"
        "✅ Secure device verification\n"
        "⚡ Takes only a few seconds\n\n"
        "Tap the button below to continue.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton(f"✅ Verify for {name}"[:64], web_app=WebAppInfo(url=verification_url(gid)))
        ]]),
    )


async def delete_group_verification_prompt(pending: dict) -> bool:
    """Delete the one-off verification prompt posted in the group, if present."""
    if not pending:
        return False
    gid = pending.get("group_verify_prompt_chat_id") or pending.get("group_id")
    mid = pending.get("group_verify_prompt_message_id")
    if not gid or not mid:
        return False
    try:
        await bot.delete_messages(int(gid), int(mid))
        await verification_pending.update_one(
            {"_id": pending["_id"]},
            {"$set": {
                "group_verify_prompt_deleted": True,
                "group_verify_prompt_deleted_at": datetime.now(),
            }}
        )
        return True
    except Exception as e:
        logger.debug("Could not delete verification prompt %s in %s: %s", mid, gid, e)
        return False


@bot.on_callback_query(filters.regex(r"^vip(ok|ban):(-?\d+):(\d+)$"))
async def manual_ip_review(_, query: CallbackQuery):
    if not owner_only(query.from_user.id if query.from_user else 0):
        await query.answer("Owner only.", show_alert=True)
        return
    m = re.match(r"^vip(ok|ban):(-?\d+):(\d+)$", query.data or "")
    if not m:
        await query.answer("Invalid action.", show_alert=True)
        return
    action, graw, uraw = m.groups()
    gid, uid = int(graw), int(uraw)
    pending = await verification_pending.find_one({"group_id": gid, "user_id": uid, "status": "manual_review_ip"})
    if not pending:
        await query.answer("Already processed or no longer pending.", show_alert=True)
        return

    now = datetime.now()
    if action == "ok":
        try:
            await bot.approve_chat_join_request(gid, uid)
        except Exception as e:
            # The user may already have been admitted by another admin.
            logger.info("Join approval during same-IP review returned %s; attempting unmute in case user is already a member.", e)
        unmuted = await fully_unmute_member(gid, uid)
        await delete_group_verification_prompt(pending)
        new_status = "approved_manual_ip_review"
        action_name = "manual_approve_same_ip"
        result_text = "✅ Manually approved after network review." + (" User unmuted." if unmuted else "")
    else:
        try:
            try:
                await bot.decline_chat_join_request(gid, uid)
            except Exception as e:
                logger.warning("Could not decline request before ban: %s", e)
            await bot.ban_chat_member(gid, uid)
        except Exception as e:
            await query.answer(f"Ban failed: {e}", show_alert=True)
            return
        new_status = "banned_manual_ip_review"
        action_name = "manual_ban_same_ip"
        result_text = "🚫 Manually banned after network review."

    await verification_pending.update_one(
        {"_id": pending["_id"], "status": "manual_review_ip"},
        {"$set": {"status": new_status, "reviewed_at": now, "reviewed_by": OWNER_ID}},
    )
    event_id = pending.get("verification_event_id")
    if event_id:
        await verification_events.update_one(
            {"_id": event_id},
            {"$set": {"decision": new_status, "reviewed_at": now, "reviewed_by": OWNER_ID}},
        )
    await verification_actions.insert_one({
        "event_id": event_id,
        "telegram_user_id": uid,
        "group_id": gid,
        "action": action_name,
        "reviewed_by": OWNER_ID,
        "created_at": now,
    })
    try:
        await query.message.edit_text((query.message.text or "") + f"\n\n{result_text}")
    except Exception:
        pass
    await query.answer("Done.")


def run_web():
    web_app.run(host=VERIFY_HOST, port=VERIFY_PORT, threaded=True, use_reloader=False)


async def main():
    global BOT_USERNAME
    threading.Thread(target=run_web, daemon=True).start()
    await bot.start()
    me = await bot.get_me()
    if not BOT_USERNAME:
        BOT_USERNAME = (me.username or "").strip().lstrip("@")
    logger.info("Verification bot started as @%s | web=%s | db=%s", me.username, VERIFY_URL or "auto/missing", MONGO_DB_NAME)
    reminder_task = asyncio.create_task(verification_reminder_loop())
    try:
        await idle()
    finally:
        reminder_task.cancel()
        try:
            await reminder_task
        except asyncio.CancelledError:
            pass
    await bot.stop()


if __name__ == "__main__":
    # Pyrogram binds its Client to the event loop that exists when the Client
    # is created. asyncio.run() creates a different loop, which can cause
    # "Future attached to a different loop" during handler shutdown.
    # Run main() through Pyrogram so start/handlers/idle/stop share one loop.
    bot.run(main())
