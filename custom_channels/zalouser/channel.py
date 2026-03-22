# -*- coding: utf-8 -*-
"""
Zalo Personal Channel for CoPaw (v2 — rebuilt from scratch).

Uses a Node.js bridge subprocess (zca-js) to automate a personal Zalo account.
Communication happens via stdin/stdout JSON-line protocol.

WARNING: Unofficial integration using reverse-engineered API.
Using Zalo automation may result in account suspension or ban.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from agentscope_runtime.engine.schemas.agent_schemas import (
    ContentType,
    FileContent,
    ImageContent,
    TextContent,
    VideoContent,
)

try:
    from copaw.app.channels.base import (
        BaseChannel,
        OnReplySent,
        OutgoingContentPart,
        ProcessHandler,
    )
    from copaw.app.channels.utils import file_url_to_local_path
except ImportError:
    from copaw.app.channels.base import (
        BaseChannel,
        OnReplySent,
        ProcessHandler,
    )

    OutgoingContentPart = Any

    def file_url_to_local_path(url: str):
        """Fallback if utils not available."""
        if url and url.startswith("file://"):
            from urllib.parse import urlparse
            from urllib.request import url2pathname
            return url2pathname(urlparse(url).path)
        return url if url and not url.startswith("http") else None

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────
ZALO_TEXT_LIMIT = 2000
_BRIDGE_DIR = Path(__file__).parent
_BRIDGE_SCRIPT = _BRIDGE_DIR / "bridge.mjs"
_DEFAULT_STATE_DIR = Path("~/.copaw/zalouser").expanduser()
_TYPING_INTERVAL_S = 4
_TYPING_TIMEOUT_S = 180
_NPM_CMD = "npm.cmd" if sys.platform == "win32" else "npm"


class ZaloBridge:
    """Hardened Node.js bridge subprocess manager.

    Handles:
    - Subprocess lifecycle (start/stop)
    - JSON-line protocol (send_command/reply)
    - Event emitter (on/off/emit)
    - Health checks (ping every N seconds)
    - Crash recovery (auto-restart with exponential backoff)
    - Stderr reader (logs Node.js errors)
    """

    def __init__(
        self,
        state_dir: str = "",
        health_check_interval: int = 30,
        max_restart_attempts: int = 5,
    ):
        self._state_dir = (
            Path(state_dir).expanduser() if state_dir else _DEFAULT_STATE_DIR
        )
        self._health_check_interval = health_check_interval
        self._max_restart_attempts = max_restart_attempts

        self._process: Optional[asyncio.subprocess.Process] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None
        self._health_task: Optional[asyncio.Task] = None
        self._pending: Dict[str, asyncio.Future] = {}
        self._event_handlers: Dict[str, List[Any]] = {}
        self._ready = asyncio.Event()
        self._running = False

        # Crash recovery state
        self._restart_count = 0
        self._health_fail_count = 0

    @property
    def is_running(self) -> bool:
        return self._running and self._process is not None

    # ─── Event Emitter ────────────────────────────────────────

    def on(self, event: str, handler):
        self._event_handlers.setdefault(event, []).append(handler)

    def off(self, event: str, handler):
        handlers = self._event_handlers.get(event, [])
        if handler in handlers:
            handlers.remove(handler)

    def _emit(self, event: str, data: Any):
        for handler in self._event_handlers.get(event, []):
            try:
                result = handler(data)
                if asyncio.iscoroutine(result):
                    asyncio.create_task(result)
            except Exception:
                logger.exception(
                    "zalouser bridge event handler error: %s", event
                )

    # ─── Subprocess Lifecycle ─────────────────────────────────

    async def start(self):
        if self._running:
            return

        self._state_dir.mkdir(parents=True, exist_ok=True)

        if not _BRIDGE_SCRIPT.exists():
            raise FileNotFoundError(
                f"Bridge script not found: {_BRIDGE_SCRIPT}"
            )

        # Auto-install npm deps
        node_modules = _BRIDGE_DIR / "node_modules"
        if not node_modules.exists():
            logger.info("zalouser: installing npm dependencies...")
            proc = await asyncio.create_subprocess_exec(
                _NPM_CMD,
                "install",
                "--production",
                cwd=str(_BRIDGE_DIR),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(
                    f"npm install failed: {stderr.decode()}"
                )

        self._process = await asyncio.create_subprocess_exec(
            "node",
            str(_BRIDGE_SCRIPT),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(_BRIDGE_DIR),
        )

        self._running = True
        self._reader_task = asyncio.create_task(self._read_loop())
        self._stderr_task = asyncio.create_task(self._stderr_reader())

        try:
            await asyncio.wait_for(self._ready.wait(), timeout=10)
        except asyncio.TimeoutError:
            logger.error("zalouser: bridge did not become ready in 10s")
            await self.stop()
            raise RuntimeError("Bridge startup timeout")

        # Start health checks
        if self._health_check_interval > 0:
            self._health_task = asyncio.create_task(
                self._health_check_loop()
            )

        self._restart_count = 0
        logger.info(
            "zalouser: bridge started (pid=%s)", self._process.pid
        )

    async def stop(self):
        self._running = False

        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except (asyncio.CancelledError, Exception):
                pass
            self._health_task = None

        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
            self._reader_task = None

        if self._stderr_task:
            self._stderr_task.cancel()
            try:
                await self._stderr_task
            except (asyncio.CancelledError, Exception):
                pass
            self._stderr_task = None

        if self._process:
            try:
                self._process.stdin.write(
                    json.dumps(
                        {"cmd": "shutdown", "id": "shutdown"}
                    ).encode()
                    + b"\n"
                )
                await self._process.stdin.drain()
            except Exception:
                pass

            try:
                await asyncio.wait_for(
                    self._process.wait(), timeout=5
                )
            except (asyncio.TimeoutError, Exception):
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()
        self._ready.clear()

    # ─── Protocol I/O ─────────────────────────────────────────

    async def _read_loop(self):
        try:
            while self._running and self._process:
                line = await self._process.stdout.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode().strip())
                except json.JSONDecodeError:
                    continue

                if "event" in msg:
                    event = msg["event"]
                    data = msg.get("data", {})
                    if event == "ready":
                        self._ready.set()
                    self._emit(event, data)
                    continue

                msg_id = msg.get("id")
                if msg_id and msg_id in self._pending:
                    fut = self._pending.pop(msg_id)
                    if not fut.done():
                        fut.set_result(msg)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("zalouser: bridge read loop error")
        finally:
            if self._running:
                self._running = False
                asyncio.create_task(self._crash_handler())

    async def _stderr_reader(self):
        try:
            while self._running and self._process:
                line = await self._process.stderr.readline()
                if not line:
                    break
                text = line.decode().strip()
                if text:
                    logger.warning("zalouser bridge stderr: %s", text)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def send_command(
        self, cmd: str, timeout: float = 30, **kwargs
    ) -> Dict[str, Any]:
        if not self._process or not self._running:
            raise RuntimeError("Bridge not running")

        msg_id = str(uuid.uuid4())[:8]
        payload = {"cmd": cmd, "id": msg_id, **kwargs}

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._pending[msg_id] = fut

        try:
            self._process.stdin.write(
                json.dumps(payload).encode() + b"\n"
            )
            await self._process.stdin.drain()
        except Exception as e:
            self._pending.pop(msg_id, None)
            raise RuntimeError(f"Failed to send command: {e}")

        try:
            result = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(msg_id, None)
            raise TimeoutError(
                f"Command {cmd} timed out after {timeout}s"
            )

        if not result.get("ok"):
            raise RuntimeError(
                result.get("error", f"Command {cmd} failed")
            )

        return result.get("data", {})

    # ─── Health Check ─────────────────────────────────────────

    async def _health_check_loop(self):
        try:
            while self._running:
                await asyncio.sleep(self._health_check_interval)
                if not self._running:
                    break
                try:
                    await self.send_command("ping", timeout=10)
                    self._health_fail_count = 0
                except Exception:
                    self._health_fail_count += 1
                    logger.warning(
                        "zalouser: health check failed (%d/3)",
                        self._health_fail_count,
                    )
                    if self._health_fail_count >= 3:
                        logger.error(
                            "zalouser: 3 consecutive health check "
                            "failures, restarting bridge"
                        )
                        self._running = False
                        asyncio.create_task(self._crash_handler())
                        break
        except asyncio.CancelledError:
            pass

    # ─── Crash Recovery ───────────────────────────────────────

    async def _crash_handler(self):
        if self._restart_count >= self._max_restart_attempts:
            logger.error(
                "zalouser: max restart attempts (%d) reached, "
                "giving up",
                self._max_restart_attempts,
            )
            return

        self._restart_count += 1
        backoff = min(2 ** self._restart_count, 30)
        logger.info(
            "zalouser: restarting bridge in %ds "
            "(attempt %d/%d)",
            backoff,
            self._restart_count,
            self._max_restart_attempts,
        )
        await asyncio.sleep(backoff)

        try:
            await self.stop()
            await self.start()
            self._emit("restarted", {"attempt": self._restart_count})
        except Exception:
            logger.exception("zalouser: bridge restart failed")
            asyncio.create_task(self._crash_handler())


class ZaloUserChannel(BaseChannel):
    """
    Zalo Personal channel for CoPaw (v2).

    Uses zca-js via a Node.js bridge subprocess to automate a personal
    Zalo account. Supports text, images, files, stickers.

    WARNING: Unofficial integration — may result in account suspension.
    """

    channel = "zalouser"
    uses_manager_queue = True

    def __init__(
        self,
        process: ProcessHandler,
        enabled: bool = False,
        state_dir: str = "",
        bot_prefix: str = "",
        show_typing: bool = True,
        on_reply_sent: OnReplySent = None,
        show_tool_details: bool = True,
        filter_tool_messages: bool = False,
        filter_thinking: bool = False,
        dm_policy: str = "open",
        group_policy: str = "open",
        allow_from: Optional[list] = None,
        deny_message: str = "",
        require_mention: bool = False,
        health_check_interval: int = 30,
        max_restart_attempts: int = 5,
    ):
        super().__init__(
            process,
            on_reply_sent=on_reply_sent,
            show_tool_details=show_tool_details,
            filter_tool_messages=filter_tool_messages,
            filter_thinking=filter_thinking,
            dm_policy=dm_policy,
            group_policy=group_policy,
            allow_from=allow_from,
            deny_message=deny_message,
            require_mention=require_mention,
        )
        self.enabled = enabled
        self._state_dir = state_dir
        self.bot_prefix = bot_prefix
        self._show_typing = show_typing
        self._bridge = ZaloBridge(
            state_dir=state_dir,
            health_check_interval=health_check_interval,
            max_restart_attempts=max_restart_attempts,
        )
        self._typing_tasks: Dict[str, asyncio.Task] = {}
        self._connected = False

    # ─── Factory Methods ──────────────────────────────────────

    @classmethod
    def from_env(
        cls,
        process: ProcessHandler,
        on_reply_sent: OnReplySent = None,
    ) -> "ZaloUserChannel":
        allow_from_env = os.getenv("ZALOUSER_ALLOW_FROM", "")
        allow_from = (
            [s.strip() for s in allow_from_env.split(",") if s.strip()]
            if allow_from_env
            else []
        )
        return cls(
            process=process,
            enabled=os.getenv("ZALOUSER_CHANNEL_ENABLED", "0") == "1",
            state_dir=os.getenv("ZALOUSER_STATE_DIR", ""),
            bot_prefix=os.getenv("ZALOUSER_BOT_PREFIX", ""),
            show_typing=os.getenv("ZALOUSER_SHOW_TYPING", "1") == "1",
            on_reply_sent=on_reply_sent,
            dm_policy=os.getenv("ZALOUSER_DM_POLICY", "open"),
            group_policy=os.getenv("ZALOUSER_GROUP_POLICY", "open"),
            allow_from=allow_from,
            deny_message=os.getenv("ZALOUSER_DENY_MESSAGE", ""),
            require_mention=os.getenv(
                "ZALOUSER_REQUIRE_MENTION", "0"
            )
            == "1",
            health_check_interval=int(
                os.getenv("ZALOUSER_HEALTH_CHECK_INTERVAL", "30")
            ),
            max_restart_attempts=int(
                os.getenv("ZALOUSER_MAX_RESTART_ATTEMPTS", "5")
            ),
        )

    @classmethod
    def from_config(
        cls,
        process: ProcessHandler,
        config: Any,
        on_reply_sent: OnReplySent = None,
        show_tool_details: bool = True,
        filter_tool_messages: bool = False,
        filter_thinking: bool = False,
    ) -> "ZaloUserChannel":
        if isinstance(config, dict):
            c = config
        else:
            c = (
                config.model_dump()
                if hasattr(config, "model_dump")
                else vars(config)
            )

        def _get(key: str, default=""):
            val = c.get(key, default)
            return (val or "").strip() if isinstance(val, str) else val

        show_typing = c.get("show_typing")
        if show_typing is None:
            show_typing = True

        return cls(
            process=process,
            enabled=bool(c.get("enabled", False)),
            state_dir=_get("state_dir"),
            bot_prefix=_get("bot_prefix"),
            show_typing=show_typing,
            on_reply_sent=on_reply_sent,
            show_tool_details=show_tool_details,
            filter_tool_messages=c.get(
                "filter_tool_messages", filter_tool_messages
            ),
            filter_thinking=c.get(
                "filter_thinking", filter_thinking
            ),
            dm_policy=c.get("dm_policy") or "open",
            group_policy=c.get("group_policy") or "open",
            allow_from=c.get("allow_from") or [],
            deny_message=c.get("deny_message") or "",
            require_mention=c.get("require_mention", False),
            health_check_interval=int(
                c.get("health_check_interval", 30)
            ),
            max_restart_attempts=int(
                c.get("max_restart_attempts", 5)
            ),
        )

    # ─── Session Resolution ───────────────────────────────────

    def resolve_session_id(
        self,
        sender_id: str,
        channel_meta: Optional[dict] = None,
    ) -> str:
        meta = channel_meta or {}
        thread_id = meta.get("thread_id")
        is_group = meta.get("is_group", False)
        if thread_id:
            prefix = "group" if is_group else "dm"
            return f"zalouser:{prefix}:{thread_id}"
        return f"zalouser:dm:{sender_id}"

    def get_to_handle_from_request(self, request: Any) -> str:
        meta = getattr(request, "channel_meta", None) or {}
        thread_id = meta.get("thread_id")
        if thread_id:
            return str(thread_id)
        sid = getattr(request, "session_id", "")
        if sid.startswith("zalouser:"):
            parts = sid.split(":", 2)
            if len(parts) >= 3:
                return parts[2]
            return parts[-1]
        return getattr(request, "user_id", "") or ""

    def to_handle_from_target(
        self, *, user_id: str, session_id: str
    ) -> str:
        if session_id.startswith("zalouser:"):
            parts = session_id.split(":", 2)
            if len(parts) >= 3:
                return parts[2]
            return parts[-1]
        return user_id

    # ─── Inbound Message Handling ─────────────────────────────

    def _on_message(self, data: dict):
        thread_id = data.get("threadId", "")
        is_group = data.get("isGroup", False)
        sender_id = data.get("senderId", "")
        sender_name = data.get("senderName") or ""
        group_name = data.get("groupName") or ""
        content = data.get("content", "")
        attachments = data.get("attachments") or []
        timestamp_ms = data.get("timestampMs", 0)
        msg_id = data.get("msgId")
        cli_msg_id = data.get("cliMsgId")
        was_mentioned = data.get("wasExplicitlyMentioned", False)
        has_any_mention = data.get("hasAnyMention", False)

        if not content and not attachments:
            return
        if not sender_id:
            return

        # Access control
        allowed, error_msg = self._check_allowlist(
            sender_id, is_group
        )
        if not allowed:
            logger.info(
                "zalouser allowlist blocked: sender=%s is_group=%s",
                sender_id,
                is_group,
            )
            asyncio.create_task(
                self._send_rejection(thread_id, error_msg, is_group)
            )
            return

        meta = {
            "thread_id": thread_id,
            "sender_id": sender_id,
            "sender_name": sender_name,
            "is_group": is_group,
            "group_name": group_name,
            "timestamp_ms": timestamp_ms,
            "msg_id": msg_id,
            "cli_msg_id": cli_msg_id,
            "bot_mentioned": was_mentioned,
            "has_any_mention": has_any_mention,
        }

        if not self._check_group_mention(is_group, meta):
            return

        # Build content_parts
        content_parts = []
        if content:
            content_parts.append(
                TextContent(type=ContentType.TEXT, text=content)
            )

        for att in attachments:
            att_type = (att.get("type") or "").lower()
            url = att.get("url") or ""
            if not url:
                continue
            if att_type == "image":
                content_parts.append(
                    ImageContent(
                        type=ContentType.IMAGE, image_url=url
                    )
                )
            elif att_type == "video":
                content_parts.append(
                    VideoContent(
                        type=ContentType.VIDEO, video_url=url
                    )
                )
            elif att_type == "file":
                content_parts.append(
                    FileContent(
                        type=ContentType.FILE,
                        file_url=url,
                        filename=att.get("filename", ""),
                    )
                )
            # Stickers: skip for now (no ContentType for stickers)

        native = {
            "channel_id": self.channel,
            "sender_id": sender_id,
            "content_parts": content_parts,
            "meta": meta,
        }

        if self._enqueue is not None:
            if self._show_typing:
                self._start_typing(thread_id, is_group)
            self._enqueue(native)
        else:
            logger.warning(
                "zalouser: _enqueue not set, message dropped"
            )

    async def _send_rejection(
        self, thread_id: str, message: str, is_group: bool
    ):
        try:
            await self._bridge.send_command(
                "send_message",
                threadId=thread_id,
                text=message,
                isGroup=is_group,
            )
        except Exception:
            logger.debug(
                "zalouser: failed to send rejection to %s",
                thread_id,
            )

    def build_agent_request_from_native(
        self, native_payload: Any
    ) -> Any:
        payload = (
            native_payload
            if isinstance(native_payload, dict)
            else {}
        )
        channel_id = payload.get("channel_id") or self.channel
        sender_id = payload.get("sender_id") or ""
        content_parts = payload.get("content_parts") or []
        meta = payload.get("meta") or {}
        session_id = self.resolve_session_id(sender_id, meta)
        user_id = str(meta.get("sender_id") or sender_id)
        request = self.build_agent_request_from_user_content(
            channel_id=channel_id,
            sender_id=sender_id,
            session_id=session_id,
            content_parts=content_parts,
            channel_meta=meta,
        )
        request.user_id = user_id
        request.channel_meta = meta
        return request

    # ─── Outbound: Text ───────────────────────────────────────

    def _chunk_text(self, text: str) -> List[str]:
        if not text or len(text) <= ZALO_TEXT_LIMIT:
            return [text] if text else []
        chunks = []
        rest = text
        while rest:
            if len(rest) <= ZALO_TEXT_LIMIT:
                chunks.append(rest)
                break
            chunk = rest[:ZALO_TEXT_LIMIT]
            last_nl = chunk.rfind("\n")
            if last_nl > ZALO_TEXT_LIMIT // 2:
                chunk = chunk[: last_nl + 1]
            else:
                last_space = chunk.rfind(" ")
                if last_space > ZALO_TEXT_LIMIT // 2:
                    chunk = chunk[: last_space + 1]
            chunks.append(chunk)
            rest = rest[len(chunk):].lstrip("\n ")
        return chunks

    async def send(
        self,
        to_handle: str,
        text: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.enabled or not self._bridge.is_running:
            return

        meta = meta or {}
        thread_id = meta.get("thread_id") or to_handle
        is_group = meta.get("is_group", False)

        if not thread_id:
            logger.warning(
                "zalouser send: no thread_id in to_handle or meta"
            )
            return

        self._stop_typing(thread_id)

        chunks = self._chunk_text(text)
        for chunk in chunks:
            try:
                await self._bridge.send_command(
                    "send_message",
                    threadId=thread_id,
                    text=chunk,
                    isGroup=is_group,
                    timeout=30,
                )
            except Exception:
                logger.exception("zalouser: send_message failed")

    # ─── Outbound: Media ──────────────────────────────────────

    async def send_content_parts(
        self,
        to_handle: str,
        parts: List[OutgoingContentPart],
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Override: split text and media into separate sends."""
        meta = meta or {}

        # Merge text/refusal parts
        text_parts = []
        media_parts = []
        for part in parts:
            pt = getattr(part, "type", None)
            if pt in (ContentType.TEXT, ContentType.REFUSAL):
                text_parts.append(
                    getattr(part, "text", "")
                    or getattr(part, "refusal", "")
                )
            else:
                media_parts.append(part)

        merged_text = "\n".join(t for t in text_parts if t).strip()
        if merged_text:
            await self.send(to_handle, merged_text, meta)

        for part in media_parts:
            await self.send_media(to_handle, part, meta)

    async def send_media(
        self,
        to_handle: str,
        part: OutgoingContentPart,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.enabled or not self._bridge.is_running:
            return

        meta = meta or {}
        thread_id = meta.get("thread_id") or to_handle
        is_group = meta.get("is_group", False)
        part_type = getattr(part, "type", None)

        # Extract URL and determine send command
        url = None
        send_cmd = "send_file"  # default fallback

        if part_type == ContentType.IMAGE:
            url = getattr(part, "image_url", None)
            send_cmd = "send_image"
        elif part_type == ContentType.VIDEO:
            url = getattr(part, "video_url", None)
            send_cmd = "send_file"  # videos via send_file
        elif part_type == ContentType.FILE:
            url = (
                getattr(part, "file_url", None)
                or getattr(part, "file_id", None)
            )
            send_cmd = "send_file"
        elif part_type == ContentType.AUDIO:
            url = getattr(part, "data", None)
            send_cmd = "send_file"

        if not url:
            return

        # Resolve to local path using CoPaw's utility
        local_path = file_url_to_local_path(url)

        # For local files, send directly to bridge
        if local_path and os.path.exists(local_path):
            await self._send_local_media(
                send_cmd, thread_id, local_path, is_group
            )
        elif url.startswith("http://") or url.startswith(
            "https://"
        ):
            # Download HTTP URL to temp file, send, then cleanup
            await self._download_and_send_media(
                send_cmd, thread_id, url, is_group
            )
        else:
            # Unknown scheme — send as text link fallback
            await self.send(
                to_handle, f"[Media: {url}]", meta
            )

    async def _send_local_media(
        self,
        send_cmd: str,
        thread_id: str,
        local_path: str,
        is_group: bool,
    ) -> None:
        try:
            kwargs = {
                "threadId": thread_id,
                "filePath": local_path,
                "isGroup": is_group,
            }
            if send_cmd == "send_image":
                kwargs["caption"] = ""
            await self._bridge.send_command(
                send_cmd, timeout=60, **kwargs
            )
        except Exception:
            logger.exception(
                "zalouser: %s failed for %s",
                send_cmd,
                local_path,
            )

    async def _download_and_send_media(
        self,
        send_cmd: str,
        thread_id: str,
        url: str,
        is_group: bool,
    ) -> None:
        """Download HTTP URL to temp file and send via bridge."""
        media_dir = self._bridge._state_dir / "media"
        media_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = None
        try:
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=60
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()

                # Determine extension from URL or content-type
                ext = Path(url.split("?")[0]).suffix or ""
                if not ext:
                    ct = resp.headers.get("content-type", "")
                    if "image" in ct:
                        ext = ".jpg"
                    elif "video" in ct:
                        ext = ".mp4"
                    else:
                        ext = ".bin"

                with tempfile.NamedTemporaryFile(
                    dir=str(media_dir),
                    suffix=ext,
                    delete=False,
                ) as tmp:
                    tmp.write(resp.content)
                    tmp_path = tmp.name

            await self._send_local_media(
                send_cmd, thread_id, tmp_path, is_group
            )
        except Exception:
            logger.exception(
                "zalouser: download+send failed for %s", url
            )
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # ─── Typing Indicators ────────────────────────────────────

    def _start_typing(
        self, thread_id: str, is_group: bool = False
    ):
        if not self._show_typing:
            return
        self._stop_typing(thread_id)
        self._typing_tasks[thread_id] = asyncio.create_task(
            self._typing_loop(thread_id, is_group)
        )

    def _stop_typing(self, thread_id: str):
        task = self._typing_tasks.pop(thread_id, None)
        if task and not task.done():
            task.cancel()

    async def _typing_loop(
        self, thread_id: str, is_group: bool = False
    ):
        try:
            deadline = (
                asyncio.get_running_loop().time() + _TYPING_TIMEOUT_S
            )
            while self._bridge.is_running:
                try:
                    await self._bridge.send_command(
                        "send_typing",
                        threadId=thread_id,
                        isGroup=is_group,
                        timeout=5,
                    )
                except Exception:
                    pass
                await asyncio.sleep(_TYPING_INTERVAL_S)
                if asyncio.get_running_loop().time() >= deadline:
                    break
        except asyncio.CancelledError:
            pass
        finally:
            if (
                self._typing_tasks.get(thread_id)
                is asyncio.current_task()
            ):
                self._typing_tasks.pop(thread_id, None)

    # ─── Lifecycle ────────────────────────────────────────────

    async def start(self) -> None:
        if not self.enabled:
            logger.debug(
                "zalouser: channel disabled (enabled=false)"
            )
            return

        try:
            await self._bridge.start()

            self._bridge.on("message", self._on_message)
            self._bridge.on("error", self._on_bridge_error)
            self._bridge.on(
                "disconnected", self._on_bridge_disconnect
            )
            self._bridge.on(
                "restarted", self._on_bridge_restarted
            )

            try:
                result = await self._bridge.send_command(
                    "login",
                    stateDir=str(self._state_dir),
                    timeout=20,
                )
                self._connected = True
                logger.info(
                    "zalouser: logged in (userId=%s)",
                    result.get("userId", "unknown"),
                )

                await self._bridge.send_command("start_listener")
                logger.info(
                    "zalouser: channel started and listening"
                )
            except Exception as e:
                logger.warning(
                    "zalouser: no saved session, QR login "
                    "required. Error: %s",
                    e,
                )
                logger.info(
                    "zalouser: channel started but not "
                    "authenticated. Use QR login."
                )

        except Exception:
            logger.exception("zalouser: failed to start channel")

    async def stop(self) -> None:
        if not self.enabled:
            return

        for tid in list(self._typing_tasks):
            self._stop_typing(tid)

        await self._bridge.stop()
        self._connected = False
        logger.info("zalouser: channel stopped")

    def _on_bridge_error(self, data: dict):
        msg = data.get("message", "Unknown error")
        logger.error("zalouser bridge error: %s", msg)

    def _on_bridge_disconnect(self, data: dict):
        code = data.get("code", -1)
        reason = data.get("reason", "unknown")
        logger.warning(
            "zalouser: disconnected (code=%s, reason=%s)",
            code,
            reason,
        )
        self._connected = False

    async def _on_bridge_restarted(self, data: dict):
        """Re-login and restart listener after bridge crash recovery."""
        try:
            result = await self._bridge.send_command(
                "login",
                stateDir=str(self._state_dir),
                timeout=20,
            )
            self._connected = True
            logger.info(
                "zalouser: reconnected after restart (userId=%s)",
                result.get("userId", "unknown"),
            )
            await self._bridge.send_command("start_listener")
            logger.info("zalouser: listener restarted")
        except Exception as e:
            logger.error(
                "zalouser: failed to reconnect after restart: %s",
                e,
            )
            self._connected = False
