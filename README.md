# Standalone Telegram Verification Bot

This package contains only the verification system. It does not contain AFK, force-AFK, stats, broadcast, or auto-delete features.

## Features

- Bot-managed verification groups: `/addverifygroup`, `/removeverifygroup`, `/verifygroups`
- Join-request DM with the target group's live Telegram title
- Telegram Mini App verification
- Target group's Telegram profile photo displayed on the verification page
- Exact-device + currently banned linked account => decline pending request, then auto-ban
- Same-IP match => owner manual review by default
- Optional same-IP auto-ban toggle via `/ipban`
- Verification exceptions via `/addexception`, `/removeexception`, `/verifyexceptions`
- Suspicious user-facing block screen does not disclose linked-account details
- Manual review Approve/Ban buttons for the owner
- Group join request is declined before any ban, preventing stale approval
- MongoDB persistence
- Single Render Web Service; `RENDER_EXTERNAL_URL` is used automatically as the verification URL

## Required environment variables

`BOT_TOKEN`, `API_ID`, `API_HASH`, `MONGODB_URI`, `OWNER_ID`.

`BOT_USERNAME` is optional for most flows but recommended. `VERIFY_URL` is not needed on Render because `RENDER_EXTERNAL_URL` is detected automatically.

Default database name is `afk_db` for backward compatibility with existing verification records. Change `MONGO_DB_NAME` if you want an isolated database.

## Group setup

1. Add the new verification bot to the target group.
2. Make it admin with permission to approve join requests and ban/restrict users.
3. As `OWNER_ID`, run `/addverifygroup` inside the group.
4. Make sure the group uses join requests.

## Admin commands

- `/addverifygroup`
- `/removeverifygroup`
- `/removeverifygroup <group_id>`
- `/verifygroups`
- `/ipban`
- `/addexception <user_id>` or reply with `/addexception`
- `/removeexception <user_id>` or reply with `/removeexception`
- `/verifyexceptions`

Normal users only see the user-facing verification help and `/verify` flow.

## Admitted-before-verification guard

If another group admin approves a join request before the requester verifies, the bot now catches the member on their first group message, mutes them, and posts a targeted **Verify in Private Chat** button. The deep-link is bound to that Telegram user ID, so another member cannot use it for themselves. After successful verification, the bot restores the group's normal member permissions automatically. The triggering unverified message is also deleted when the bot has permission to delete messages.

For this feature, keep the bot as group admin with **Restrict Members** and **Delete Messages** permissions in addition to join-request approval rights.
