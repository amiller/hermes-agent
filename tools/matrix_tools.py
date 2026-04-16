"""LLM-callable Matrix tools.

These tools wrap the live Matrix gateway adapter when Hermes is connected to
Matrix. They are intentionally thin wrappers around the existing
``MatrixAdapter`` public APIs so the tool layer does NOT duplicate Matrix SDK
logic.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from typing import Any, Optional

from tools.registry import registry

logger = logging.getLogger(__name__)

_adapter: Optional[Any] = None
_adapter_lock = threading.Lock()

_MAX_EMOJI_LEN = 32
_MAX_REASON_LEN = 500
_MAX_NAME_LEN = 255
_MAX_TOPIC_LEN = 1000
_MAX_STATUS_LEN = 255
_MAX_MIME_TYPE_LEN = 128
_MAX_FILE_PATH_LEN = 4096
_ALLOWED_PRESETS = frozenset(("private_chat", "public_chat", "trusted_private_chat"))
_TOOL_RETRY_ATTEMPTS = 3
_TOOL_RETRY_DELAY_SECONDS = 0.5


def set_matrix_adapter(adapter: Optional[Any]) -> None:
    """Bind the currently connected Matrix adapter for tool use."""
    global _adapter
    with _adapter_lock:
        _adapter = adapter


def _check_matrix_connected() -> bool:
    """Return True only when a live Matrix adapter instance is available."""
    with _adapter_lock:
        return _adapter is not None


def _ensure_adapter() -> Any:
    with _adapter_lock:
        adapter = _adapter
    if adapter is None:
        raise RuntimeError("Matrix adapter is not connected")
    return adapter


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from a sync tool handler."""
    adapter = _ensure_adapter()
    adapter_loop = getattr(adapter, "_loop", None)
    if adapter_loop is not None and adapter_loop.is_running():
        future = asyncio.run_coroutine_threadsafe(coro, adapter_loop)
        try:
            return future.result(timeout=30)
        except TimeoutError:
            future.cancel()
            raise

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result(timeout=30)

    return asyncio.run(coro)


def _run_async_retry(async_fn: Any, *args: Any, attempts: int = _TOOL_RETRY_ATTEMPTS, delay_seconds: float = _TOOL_RETRY_DELAY_SECONDS, **kwargs: Any) -> Any:
    """Run an adapter coroutine with light retry for transient homeserver failures."""
    last_exc: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            return _run_async(async_fn(*args, **kwargs))
        except TimeoutError:
            raise
        except Exception as exc:
            last_exc = exc
            if attempt >= attempts:
                break
            logger.warning(
                "Matrix tools: %s failed on attempt %d/%d; retrying in %.1fs",
                getattr(async_fn, "__name__", repr(async_fn)),
                attempt,
                attempts,
                delay_seconds,
            )
            import time
            time.sleep(delay_seconds * attempt)
    assert last_exc is not None
    raise last_exc


def _json_error(message: str) -> str:
    return json.dumps({"error": message}, ensure_ascii=False)


def _handle_send_reaction(args: dict, **_kw) -> str:
    room_id = str(args.get("room_id", "")).strip()
    event_id = str(args.get("event_id", "")).strip()
    emoji = str(args.get("emoji", "")).strip()

    if not room_id or not room_id.startswith("!"):
        return _json_error("room_id is required and must start with '!'")
    if not event_id or not event_id.startswith("$"):
        return _json_error("event_id is required and must start with '$'")
    if not emoji:
        return _json_error("emoji is required and must be non-empty")
    if len(emoji) > _MAX_EMOJI_LEN:
        return _json_error(f"emoji must be at most {_MAX_EMOJI_LEN} characters")

    try:
        adapter = _ensure_adapter()
        reaction_event_id = _run_async_retry(adapter.send_reaction, room_id, event_id, emoji)
        return json.dumps({"success": bool(reaction_event_id), "reaction_event_id": reaction_event_id}, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_send_reaction error: %s", exc)
        return _json_error(f"Failed to send reaction: {exc}")


def _handle_redact_message(args: dict, **_kw) -> str:
    room_id = str(args.get("room_id", "")).strip()
    event_id = str(args.get("event_id", "")).strip()
    reason = str(args.get("reason", ""))[:_MAX_REASON_LEN]

    if not room_id or not room_id.startswith("!"):
        return _json_error("room_id is required and must start with '!'")
    if not event_id or not event_id.startswith("$"):
        return _json_error("event_id is required and must start with '$'")

    try:
        adapter = _ensure_adapter()
        ok = _run_async_retry(adapter.redact_message, room_id, event_id, reason=reason)
        return json.dumps({"success": bool(ok)}, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_redact_message error: %s", exc)
        return _json_error(f"Failed to redact message: {exc}")


def _handle_create_room(args: dict, **_kw) -> str:
    name = str(args.get("name", ""))[:_MAX_NAME_LEN]
    topic = str(args.get("topic", ""))[:_MAX_TOPIC_LEN]
    invite = args.get("invite", [])
    is_direct = bool(args.get("is_direct", False))
    preset = str(args.get("preset", "private_chat"))

    if invite and not isinstance(invite, list):
        return _json_error("invite must be a list of user IDs")
    for user_id in invite or []:
        if not isinstance(user_id, str) or not user_id.startswith("@"):
            return _json_error(f"Invalid user ID in invite list: {user_id!r}")
    if preset not in _ALLOWED_PRESETS:
        return _json_error(f"Invalid preset: {preset!r}. Must be one of: {', '.join(sorted(_ALLOWED_PRESETS))}")
    if preset == "public_chat" and os.getenv("MATRIX_ALLOW_PUBLIC_ROOMS", "").lower() not in ("true", "1", "yes"):
        return _json_error("Public room creation is disabled by default. Set MATRIX_ALLOW_PUBLIC_ROOMS=true to allow.")

    try:
        adapter = _ensure_adapter()
        room_id = _run_async_retry(adapter.create_room, name=name, topic=topic, invite=invite, is_direct=is_direct, preset=preset)
        if not room_id:
            return json.dumps({"success": False, "error": "Room creation failed"}, ensure_ascii=False)
        return json.dumps({"success": True, "room_id": room_id}, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_create_room error: %s", exc)
        return _json_error(f"Failed to create room: {exc}")


def _handle_invite_user(args: dict, **_kw) -> str:
    room_id = str(args.get("room_id", "")).strip()
    user_id = str(args.get("user_id", "")).strip()

    if not room_id or not room_id.startswith("!"):
        return _json_error("room_id is required and must start with '!'")
    if not user_id or not user_id.startswith("@"):
        return _json_error("user_id is required and must start with '@'")

    try:
        adapter = _ensure_adapter()
        ok = _run_async_retry(adapter.invite_user, room_id, user_id)
        return json.dumps({"success": bool(ok)}, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_invite_user error: %s", exc)
        return _json_error(f"Failed to invite user: {exc}")


def _handle_fetch_history(args: dict, **_kw) -> str:
    room_id = str(args.get("room_id", "")).strip()
    limit = args.get("limit", 50)
    start = str(args.get("start", "")).strip()

    if not room_id or not room_id.startswith("!"):
        return _json_error("room_id is required and must start with '!'")
    if not isinstance(limit, int) or limit < 1:
        limit = 50
    limit = min(limit, 200)

    try:
        adapter = _ensure_adapter()
        messages = _run_async_retry(adapter.fetch_room_history, room_id, limit=limit, start=start)
        return json.dumps({"count": len(messages), "messages": messages}, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_fetch_history error: %s", exc)
        return _json_error(f"Failed to fetch history: {exc}")


def _handle_set_presence(args: dict, **_kw) -> str:
    state = str(args.get("state", "")).strip().lower()
    status_msg = str(args.get("status_msg", ""))[:_MAX_STATUS_LEN]

    if state not in ("online", "offline", "unavailable"):
        return _json_error(f"Invalid state: {state!r}. Must be 'online', 'offline', or 'unavailable'")

    try:
        adapter = _ensure_adapter()
        ok = _run_async_retry(adapter.set_presence, state=state, status_msg=status_msg)
        return json.dumps({"success": bool(ok)}, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_set_presence error: %s", exc)
        return _json_error(f"Failed to set presence: {exc}")


def _handle_upload_media(args: dict, **_kw) -> str:
    """Upload a file to the Matrix homeserver and return its mxc:// URI."""
    file_path = str(args.get("file_path", "")).strip()
    mime_type = str(args.get("mime_type", "")).strip() or None

    if not file_path:
        return _json_error("file_path is required")
    if len(file_path) > _MAX_FILE_PATH_LEN:
        return _json_error(f"file_path must be at most {_MAX_FILE_PATH_LEN} characters")
    if mime_type and len(mime_type) > _MAX_MIME_TYPE_LEN:
        return _json_error(f"mime_type must be at most {_MAX_MIME_TYPE_LEN} characters")

    from pathlib import Path
    p = Path(file_path)
    if not p.exists():
        return _json_error(f"File not found: {file_path}")

    try:
        adapter = _ensure_adapter()
        client = adapter._client
        import mimetypes
        if not mime_type:
            mime_type = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
        data = p.read_bytes()
        mxc_url = _run_async_retry(client.upload_media, data, mime_type=mime_type, filename=p.name)
        return json.dumps({"mxc_url": str(mxc_url)}, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_upload_media error: %s", exc)
        return _json_error(f"Failed to upload media: {exc}")


def _handle_set_profile(args: dict, **_kw) -> str:
    """Set display name and/or avatar URL for the bot's Matrix account."""
    display_name = args.get("display_name")
    avatar_mxc = str(args.get("avatar_mxc", "")).strip() or None

    if display_name is not None:
        display_name = str(display_name).strip()[:_MAX_NAME_LEN]
    if avatar_mxc and not avatar_mxc.startswith("mxc://"):
        return _json_error("avatar_mxc must start with 'mxc://'")

    try:
        adapter = _ensure_adapter()
        client = adapter._client
        ok = True
        if display_name is not None:
            _run_async_retry(client.set_displayname, display_name)
        if avatar_mxc:
            from mautrix.types import ContentURI
            _run_async_retry(client.set_avatar_url, ContentURI(avatar_mxc))
        return json.dumps({"ok": ok}, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_set_profile error: %s", exc)
        return _json_error(f"Failed to set profile: {exc}")


def _handle_get_state(args: dict, **_kw) -> str:
    """Get a state event from a Matrix room."""
    room_id = str(args.get("room_id", "")).strip()
    event_type = str(args.get("event_type", "")).strip()
    state_key = str(args.get("state_key", "")).strip()

    if not room_id or not room_id.startswith("!"):
        return _json_error("room_id is required and must start with '!'")
    if not event_type:
        return _json_error("event_type is required")

    try:
        adapter = _ensure_adapter()
        client = adapter._client
        from mautrix.types import RoomID
        # Pass event_type as string and let client handle EventType conversion
        state_event = _run_async_retry(client.get_state_event, RoomID(room_id), event_type, state_key or "")
        content = {}
        if hasattr(state_event, "content"):
            content = dict(state_event.content) if isinstance(state_event.content, dict) else {}
        elif hasattr(state_event, "serialize"):
            content = state_event.serialize()
        elif isinstance(state_event, dict):
            content = state_event
        return json.dumps(content, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_get_state error: %s", exc)
        return _json_error(f"Failed to get state: {exc}")


def _handle_put_state(args: dict, **_kw) -> str:
    """Send a state event to a Matrix room."""
    room_id = str(args.get("room_id", "")).strip()
    event_type = str(args.get("event_type", "")).strip()
    content = args.get("content", {})
    state_key = str(args.get("state_key", "")).strip()

    if not room_id or not room_id.startswith("!"):
        return _json_error("room_id is required and must start with '!'")
    if not event_type:
        return _json_error("event_type is required")
    if not isinstance(content, dict):
        return _json_error("content must be a dictionary")

    try:
        adapter = _ensure_adapter()
        client = adapter._client
        from mautrix.types import RoomID
        # Pass event_type as string and let client handle EventType conversion
        event_id = _run_async_retry(client.send_state_event, RoomID(room_id), event_type, content, state_key or "")
        return json.dumps({"event_id": str(event_id)}, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_put_state error: %s", exc)
        return _json_error(f"Failed to put state: {exc}")


def _handle_create_room_enhanced(args: dict, **_kw) -> str:
    """Create a Matrix room with optional encryption and retention policies."""
    name = str(args.get("name", ""))[:_MAX_NAME_LEN]
    topic = str(args.get("topic", ""))[:_MAX_TOPIC_LEN]
    invite = args.get("invite", [])
    is_direct = bool(args.get("is_direct", False))
    encrypted = bool(args.get("encrypted", True))
    preset = str(args.get("preset", "private_chat"))
    retention_max_lifetime_ms = args.get("retention_max_lifetime_ms")
    history_visibility = str(args.get("history_visibility", "shared"))

    if invite and not isinstance(invite, list):
        return _json_error("invite must be a list of user IDs")
    for user_id in invite or []:
        if not isinstance(user_id, str) or not user_id.startswith("@"):
            return _json_error(f"Invalid user ID in invite list: {user_id!r}")
    if preset not in _ALLOWED_PRESETS:
        return _json_error(f"Invalid preset: {preset!r}. Must be one of: {', '.join(sorted(_ALLOWED_PRESETS))}")
    if preset == "public_chat" and os.getenv("MATRIX_ALLOW_PUBLIC_ROOMS", "").lower() not in ("true", "1", "yes"):
        return _json_error("Public room creation is disabled by default. Set MATRIX_ALLOW_PUBLIC_ROOMS=true to allow.")
    if retention_max_lifetime_ms is not None:
        if not isinstance(retention_max_lifetime_ms, int) or retention_max_lifetime_ms < 0:
            return _json_error("retention_max_lifetime_ms must be a non-negative integer")

    try:
        adapter = _ensure_adapter()
        client = adapter._client
        from mautrix.types import RoomID, UserID, RoomCreatePreset

        initial_state = []
        if encrypted:
            initial_state.append({
                "type": "m.room.encryption",
                "state_key": "",
                "content": {"algorithm": "m.megolm.v1.aes-sha2"}
            })
        if retention_max_lifetime_ms is not None:
            initial_state.append({
                "type": "m.room.retention",
                "state_key": "",
                "content": {"max_lifetime": retention_max_lifetime_ms}
            })

        preset_enum = {
            "private_chat": RoomCreatePreset.PRIVATE,
            "public_chat": RoomCreatePreset.PUBLIC,
            "trusted_private_chat": RoomCreatePreset.TRUSTED_PRIVATE,
        }.get(preset, RoomCreatePreset.PRIVATE)
        invitees = [UserID(u) for u in (invite or [])]

        room_id = _run_async_retry(
            client.create_room,
            name=name or None,
            topic=topic or None,
            invitees=invitees,
            is_direct=is_direct,
            preset=preset_enum,
            initial_state=initial_state,
            room_version=None
        )
        room_id_str = str(room_id)
        adapter._joined_rooms.add(room_id_str)
        return json.dumps({"success": True, "room_id": room_id_str}, ensure_ascii=False)
    except Exception as exc:
        logger.error("matrix_create_room_enhanced error: %s", exc)
        return _json_error(f"Failed to create room: {exc}")


def _handle_get_account_data(args: dict, **_kw) -> str:
    """Get account data for the current user, returning None if not found."""
    event_type = str(args.get("event_type", "")).strip()

    if not event_type:
        return _json_error("event_type is required")

    try:
        adapter = _ensure_adapter()
        client = adapter._client

        # Use direct async call instead of retry to handle MNotFound gracefully
        async def _get_with_no_retry():
            try:
                resp = await client.get_account_data(event_type)
                content = {}
                if hasattr(resp, "content"):
                    content = dict(resp.content) if isinstance(resp.content, dict) else {}
                elif hasattr(resp, "serialize"):
                    content = resp.serialize()
                elif isinstance(resp, dict):
                    content = resp
                return json.dumps(content, ensure_ascii=False)
            except Exception as exc:
                # Check for MNotFound (account data not set)
                if "MNotFound" in str(exc) or "not found" in str(exc).lower():
                    return json.dumps(None, ensure_ascii=False)
                raise

        return _run_async(_get_with_no_retry())
    except Exception as exc:
        logger.error("matrix_get_account_data error: %s", exc)
        return _json_error(f"Failed to get account data: {exc}")


registry.register(
    name="matrix_send_reaction",
    toolset="matrix",
    schema={
        "name": "matrix_send_reaction",
        "description": "Send an emoji reaction to a specific message in a Matrix room.",
        "parameters": {
            "type": "object",
            "properties": {
                "room_id": {"type": "string", "description": "Matrix room ID starting with '!'."},
                "event_id": {"type": "string", "description": "Target Matrix event ID starting with '$'."},
                "emoji": {"type": "string", "description": "Emoji reaction to apply."},
            },
            "required": ["room_id", "event_id", "emoji"],
        },
    },
    handler=_handle_send_reaction,
    check_fn=_check_matrix_connected,
)

registry.register(
    name="matrix_redact_message",
    toolset="matrix",
    schema={
        "name": "matrix_redact_message",
        "description": "Redact a Matrix event from a room.",
        "parameters": {
            "type": "object",
            "properties": {
                "room_id": {"type": "string"},
                "event_id": {"type": "string"},
                "reason": {"type": "string", "description": "Optional reason for redaction."},
            },
            "required": ["room_id", "event_id"],
        },
    },
    handler=_handle_redact_message,
    check_fn=_check_matrix_connected,
)

registry.register(
    name="matrix_create_room",
    toolset="matrix",
    schema={
        "name": "matrix_create_room",
        "description": "Create a Matrix room. Public room creation is gated by MATRIX_ALLOW_PUBLIC_ROOMS. For ad-hoc raw API access, the bot's MATRIX_ACCESS_TOKEN is in process env (use os.environ); do not scrape /proc/1/environ.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "topic": {"type": "string"},
                "invite": {"type": "array", "items": {"type": "string"}},
                "is_direct": {"type": "boolean"},
                "preset": {"type": "string", "enum": ["private_chat", "public_chat"]},
            },
            "required": [],
        },
    },
    handler=_handle_create_room,
    check_fn=_check_matrix_connected,
)

registry.register(
    name="matrix_invite_user",
    toolset="matrix",
    schema={
        "name": "matrix_invite_user",
        "description": "Invite a user to a Matrix room.",
        "parameters": {
            "type": "object",
            "properties": {
                "room_id": {"type": "string"},
                "user_id": {"type": "string"},
            },
            "required": ["room_id", "user_id"],
        },
    },
    handler=_handle_invite_user,
    check_fn=_check_matrix_connected,
)

registry.register(
    name="matrix_fetch_history",
    toolset="matrix",
    schema={
        "name": "matrix_fetch_history",
        "description": "Fetch recent message history from a Matrix room using the adapter's existing history API.",
        "parameters": {
            "type": "object",
            "properties": {
                "room_id": {"type": "string"},
                "limit": {"type": "integer", "description": "Maximum messages to return (1-200)."},
                "start": {"type": "string", "description": "Optional pagination token."},
            },
            "required": ["room_id"],
        },
    },
    handler=_handle_fetch_history,
    check_fn=_check_matrix_connected,
)

registry.register(
    name="matrix_set_presence",
    toolset="matrix",
    schema={
        "name": "matrix_set_presence",
        "description": "Set Matrix presence to online, offline, or unavailable.",
        "parameters": {
            "type": "object",
            "properties": {
                "state": {"type": "string", "enum": ["online", "offline", "unavailable"]},
                "status_msg": {"type": "string"},
            },
            "required": ["state"],
        },
    },
    handler=_handle_set_presence,
    check_fn=_check_matrix_connected,
)


registry.register(
    name="matrix_upload_media",
    toolset="matrix",
    schema={
        "name": "matrix_upload_media",
        "description": "Upload a file to the Matrix homeserver and return its mxc:// URI.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Local file path to upload."},
                "mime_type": {"type": "string", "description": "Optional MIME type. If not provided, guessed from file extension."},
            },
            "required": ["file_path"],
        },
    },
    handler=_handle_upload_media,
    check_fn=_check_matrix_connected,
)


registry.register(
    name="matrix_set_profile",
    toolset="matrix",
    schema={
        "name": "matrix_set_profile",
        "description": "Set display name and/or avatar URL for the bot's Matrix account.",
        "parameters": {
            "type": "object",
            "properties": {
                "display_name": {"type": "string", "description": "Optional display name to set."},
                "avatar_mxc": {"type": "string", "description": "Optional mxc:// URL to set as avatar (e.g., from matrix_upload_media)."},
            },
            "required": [],
        },
    },
    handler=_handle_set_profile,
    check_fn=_check_matrix_connected,
)


registry.register(
    name="matrix_get_state",
    toolset="matrix",
    schema={
        "name": "matrix_get_state",
        "description": "Get a state event from a Matrix room.",
        "parameters": {
            "type": "object",
            "properties": {
                "room_id": {"type": "string", "description": "Matrix room ID starting with '!'."},
                "event_type": {"type": "string", "description": "Event type to fetch (e.g., 'm.room.name', 'm.room.encryption')."},
                "state_key": {"type": "string", "description": "Optional state key (defaults to empty string)."},
            },
            "required": ["room_id", "event_type"],
        },
    },
    handler=_handle_get_state,
    check_fn=_check_matrix_connected,
)


registry.register(
    name="matrix_put_state",
    toolset="matrix",
    schema={
        "name": "matrix_put_state",
        "description": "Send a state event to a Matrix room.",
        "parameters": {
            "type": "object",
            "properties": {
                "room_id": {"type": "string", "description": "Matrix room ID starting with '!'."},
                "event_type": {"type": "string", "description": "Event type to set (e.g., 'com.example.test')."},
                "content": {"type": "object", "description": "State event content as a dictionary."},
                "state_key": {"type": "string", "description": "Optional state key (defaults to empty string)."},
            },
            "required": ["room_id", "event_type", "content"],
        },
    },
    handler=_handle_put_state,
    check_fn=_check_matrix_connected,
)


registry.register(
    name="matrix_create_room_enhanced",
    toolset="matrix",
    schema={
        "name": "matrix_create_room_enhanced",
        "description": "Create a Matrix room with optional encryption and retention policies. Public room creation is gated by MATRIX_ALLOW_PUBLIC_ROOMS. For ad-hoc raw API access, the bot's MATRIX_ACCESS_TOKEN is in process env (use os.environ); do not scrape /proc/1/environ.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "topic": {"type": "string"},
                "invite": {"type": "array", "items": {"type": "string"}},
                "is_direct": {"type": "boolean"},
                "encrypted": {"type": "boolean", "description": "Enable end-to-end encryption (default: true)."},
                "preset": {"type": "string", "enum": ["private_chat", "public_chat", "trusted_private_chat"]},
                "retention_max_lifetime_ms": {"type": "integer", "description": "Optional retention max lifetime in milliseconds."},
                "history_visibility": {"type": "string", "enum": ["invited", "joined", "shared", "world_readable"], "description": "Room history visibility (default: 'shared')."},
            },
            "required": [],
        },
    },
    handler=_handle_create_room_enhanced,
    check_fn=_check_matrix_connected,
)


registry.register(
    name="matrix_get_account_data",
    toolset="matrix",
    schema={
        "name": "matrix_get_account_data",
        "description": "Get account data for the current user. Returns None if the account data type is not set.",
        "parameters": {
            "type": "object",
            "properties": {
                "event_type": {"type": "string", "description": "Account data event type to fetch (e.g., 'm.direct', 'com.example.data')."},
            },
            "required": ["event_type"],
        },
    },
    handler=_handle_get_account_data,
    check_fn=_check_matrix_connected,
)
