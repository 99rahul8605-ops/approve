import os
import re
import json
import asyncio
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional

from pyrogram import Client, filters, enums, idle
from pyrogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery, WebAppInfo
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


def target_user_id(message: Message) -> Optional[int]:
    if message.reply_to_message and message.reply_to_message.from_user:
        return int(message.reply_to_message.from_user.id)
    if len(message.command) > 1:
        try:
            return int(message.command[1])
        except Exception:
            return None
    return None


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
            "• `/ipban` — Same-IP auto-ban ON/OFF\n"
            "• `/addexception <user_id>` — Add anti-fraud exception\n"
            "• `/removeexception <user_id>` — Remove exception\n"
            "• `/verifyexceptions` — List exceptions\n\n"
            "Exceptions still complete verification; only device/IP anti-fraud checks are skipped."
        )
    return text


@bot.on_message(filters.command("start"))
async def start_cmd(_, message: Message):
    await message.reply_text(help_text(owner_only(message.from_user.id if message.from_user else 0)))


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
        "🌐 **Same-IP Auto Ban**\n\n"
        f"Status: **{'🟢 ON' if enabled else '🔴 OFF'}**\n\n"
        "ON → same-IP match automatically bans the new requester.\n"
        "OFF → same-IP match is sent to you for manual Approve / Ban review.\n\n"
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
        "🌐 **Same-IP Auto Ban**\n\n"
        f"Status: **{'🟢 ON' if enabled else '🔴 OFF'}**\n\n"
        "ON → same-IP match automatically bans the new requester.\n"
        "OFF → same-IP match waits for manual Approve / Ban review.\n\n"
        "Exact-device + banned-ID protection remains active separately.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("✅ Turn ON", callback_data="vipsetting:ipban:on"),
            InlineKeyboardButton("❌ Turn OFF", callback_data="vipsetting:ipban:off"),
        ]]),
    )
    await query.answer("Setting updated.")


@bot.on_message(filters.command("addexception") & filters.user(OWNER_ID))
async def add_exception_cmd(_, message: Message):
    uid = target_user_id(message)
    if not uid:
        await message.reply_text("Usage: `/addexception <user_id>` or reply to a user's message with `/addexception`.")
        return
    await verification_exceptions.update_one(
        {"user_id": uid},
        {"$set": {"user_id": uid, "enabled": True, "added_at": datetime.now(), "added_by": OWNER_ID}},
        upsert=True,
    )
    await message.reply_text(f"✅ Exception added for `{uid}`. Verification remains compulsory; anti-fraud device/IP checks are skipped.")


@bot.on_message(filters.command("removeexception") & filters.user(OWNER_ID))
async def remove_exception_cmd(_, message: Message):
    uid = target_user_id(message)
    if not uid:
        await message.reply_text("Usage: `/removeexception <user_id>` or reply to a user's message with `/removeexception`.")
        return
    result = await verification_exceptions.delete_one({"user_id": uid})
    await message.reply_text(("✅ Removed" if result.deleted_count else "ℹ️ Not found") + f" exception for `{uid}`.")


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
    await verification_pending.update_one(
        {"group_id": gid, "user_id": uid},
        {"$set": {
            "group_id": gid,
            "group_title": join_request.chat.title or group.get("title") or str(gid),
            "user_id": uid,
            "status": "pending",
            "requested_at": datetime.now(),
        }},
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


@bot.on_message(filters.command("verify"))
async def verify_cmd(_, message: Message):
    if message.chat.type != enums.ChatType.PRIVATE:
        await message.reply_text("🔐 Open this bot in private chat and send /verify.")
        return
    if not VERIFY_URL:
        await message.reply_text("❌ Verification URL is not configured yet.")
        return
    pending = await verification_pending.find_one(
        {"user_id": int(message.from_user.id), "status": {"$in": ["pending", "manual_review_ip"]}},
        sort=[("requested_at", -1)],
    )
    if pending:
        gid = int(pending["group_id"])
    else:
        groups = await get_verification_groups()
        if not groups:
            await message.reply_text("❌ No verification group has been configured yet.")
            return
        gid = int(groups[0]["chat_id"])
    name = await get_group_name(gid)
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
            await query.answer(f"Approval failed: {e}", show_alert=True)
            return
        new_status = "approved_manual_ip_review"
        action_name = "manual_approve_same_ip"
        result_text = "✅ Manually approved after same-IP review."
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
        result_text = "🚫 Manually banned after same-IP review."

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
    threading.Thread(target=run_web, daemon=True).start()
    await bot.start()
    me = await bot.get_me()
    logger.info("Verification bot started as @%s | web=%s | db=%s", me.username, VERIFY_URL or "auto/missing", MONGO_DB_NAME)
    await idle()
    await bot.stop()


if __name__ == "__main__":
    # Pyrogram binds its Client to the event loop that exists when the Client
    # is created. asyncio.run() creates a different loop, which can cause
    # "Future attached to a different loop" during handler shutdown.
    # Run main() through Pyrogram so start/handlers/idle/stop share one loop.
    bot.run(main())
