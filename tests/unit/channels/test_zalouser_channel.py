# -*- coding: utf-8 -*-
# pylint: disable=protected-access
"""Unit tests for Zalo Personal (zalouser) channel."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from agentscope_runtime.engine.schemas.agent_schemas import (
    ContentType,
    ImageContent,
    TextContent,
)

from custom_channels.zalouser.channel import (
    ZaloBridge,
    ZaloUserChannel,
    ZALO_TEXT_LIMIT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_channel(**overrides: Any) -> ZaloUserChannel:
    """Create a ZaloUserChannel with dummy process handler."""

    async def _noop_process(_request):
        yield  # pragma: no cover

    defaults = {
        "process": _noop_process,
        "enabled": True,
        "state_dir": "/tmp/test_zalouser",
        "bot_prefix": "",
        "show_typing": False,
    }
    defaults.update(overrides)
    ch = ZaloUserChannel(**defaults)
    # Mock the bridge so no subprocess is spawned
    ch._bridge = MagicMock(spec=ZaloBridge)
    ch._bridge.is_running = True
    ch._bridge.send_command = AsyncMock(return_value={})
    return ch


# ===================================================================
# resolve_session_id
# ===================================================================


class TestResolveSessionId:
    def test_dm_with_thread_id(self):
        ch = _make_channel()
        result = ch.resolve_session_id(
            "sender123", {"thread_id": "thread456", "is_group": False}
        )
        assert result == "zalouser:dm:thread456"

    def test_group_with_thread_id(self):
        ch = _make_channel()
        result = ch.resolve_session_id(
            "sender123", {"thread_id": "group789", "is_group": True}
        )
        assert result == "zalouser:group:group789"

    def test_fallback_to_sender_id(self):
        ch = _make_channel()
        result = ch.resolve_session_id("sender123", {})
        assert result == "zalouser:dm:sender123"

    def test_none_meta(self):
        ch = _make_channel()
        result = ch.resolve_session_id("sender123", None)
        assert result == "zalouser:dm:sender123"


# ===================================================================
# _chunk_text
# ===================================================================


class TestChunkText:
    def test_short_text_no_split(self):
        ch = _make_channel()
        assert ch._chunk_text("hello") == ["hello"]

    def test_empty_text(self):
        ch = _make_channel()
        assert ch._chunk_text("") == []

    def test_none_text(self):
        ch = _make_channel()
        assert ch._chunk_text(None) == []

    def test_exact_limit(self):
        ch = _make_channel()
        text = "a" * ZALO_TEXT_LIMIT
        assert ch._chunk_text(text) == [text]

    def test_over_limit_splits_at_newline(self):
        ch = _make_channel()
        # Create text with a newline near the middle
        part1 = "a" * (ZALO_TEXT_LIMIT - 100)
        part2 = "b" * 200
        text = part1 + "\n" + part2
        chunks = ch._chunk_text(text)
        assert len(chunks) == 2
        assert chunks[0] == part1 + "\n"

    def test_over_limit_splits_at_space(self):
        ch = _make_channel()
        # No newlines, has spaces
        part1 = "word " * (ZALO_TEXT_LIMIT // 5 - 10)
        part2 = "more " * 50
        text = part1 + part2
        chunks = ch._chunk_text(text)
        assert len(chunks) >= 2
        for chunk in chunks:
            assert len(chunk) <= ZALO_TEXT_LIMIT + 10  # some slack


# ===================================================================
# get_to_handle_from_request
# ===================================================================


class TestGetToHandleFromRequest:
    def test_from_meta_thread_id(self):
        ch = _make_channel()
        request = MagicMock()
        request.channel_meta = {"thread_id": "t123"}
        assert ch.get_to_handle_from_request(request) == "t123"

    def test_from_session_id_fallback(self):
        ch = _make_channel()
        request = MagicMock()
        request.channel_meta = {}
        request.session_id = "zalouser:dm:user456"
        assert ch.get_to_handle_from_request(request) == "user456"

    def test_no_meta_no_session(self):
        ch = _make_channel()
        request = MagicMock()
        request.channel_meta = None
        request.session_id = ""
        request.user_id = "fallback_uid"
        assert ch.get_to_handle_from_request(request) == "fallback_uid"


# ===================================================================
# to_handle_from_target
# ===================================================================


class TestToHandleFromTarget:
    def test_dm_session(self):
        ch = _make_channel()
        result = ch.to_handle_from_target(
            user_id="u1", session_id="zalouser:dm:thread789"
        )
        assert result == "thread789"

    def test_group_session(self):
        ch = _make_channel()
        result = ch.to_handle_from_target(
            user_id="u1", session_id="zalouser:group:grp123"
        )
        assert result == "grp123"

    def test_non_zalouser_session(self):
        ch = _make_channel()
        result = ch.to_handle_from_target(
            user_id="fallback_uid", session_id="other:thing"
        )
        assert result == "fallback_uid"


# ===================================================================
# from_config
# ===================================================================


class TestFromConfig:
    def test_from_dict_config(self):
        async def _noop(_req):
            yield

        config = {
            "enabled": True,
            "state_dir": "/custom/path",
            "bot_prefix": "[BOT]",
            "show_typing": False,
            "dm_policy": "allowlist",
            "group_policy": "open",
            "allow_from": ["user1", "user2"],
            "deny_message": "Not allowed",
            "require_mention": True,
        }
        ch = ZaloUserChannel.from_config(process=_noop, config=config)
        assert ch.enabled is True
        assert ch._state_dir == "/custom/path"
        assert ch.bot_prefix == "[BOT]"
        assert ch._show_typing is False
        assert ch.dm_policy == "allowlist"
        assert ch.require_mention is True

    def test_from_dict_defaults(self):
        async def _noop(_req):
            yield

        ch = ZaloUserChannel.from_config(process=_noop, config={})
        assert ch.enabled is False
        assert ch._show_typing is True
        assert ch.dm_policy == "open"


# ===================================================================
# from_env
# ===================================================================


class TestFromEnv:
    @patch.dict(
        "os.environ",
        {
            "ZALOUSER_CHANNEL_ENABLED": "1",
            "ZALOUSER_STATE_DIR": "/env/path",
            "ZALOUSER_BOT_PREFIX": "[ENV]",
            "ZALOUSER_SHOW_TYPING": "0",
            "ZALOUSER_DM_POLICY": "allowlist",
            "ZALOUSER_ALLOW_FROM": "u1,u2,u3",
            "ZALOUSER_REQUIRE_MENTION": "1",
        },
    )
    def test_from_env_vars(self):
        async def _noop(_req):
            yield

        ch = ZaloUserChannel.from_env(process=_noop)
        assert ch.enabled is True
        assert ch._state_dir == "/env/path"
        assert ch.bot_prefix == "[ENV]"
        assert ch._show_typing is False
        assert ch.dm_policy == "allowlist"
        assert set(ch.allow_from) == {"u1", "u2", "u3"}
        assert ch.require_mention is True


# ===================================================================
# _on_message
# ===================================================================


class TestOnMessage:
    def test_text_message_enqueues(self):
        ch = _make_channel()
        enqueued = []
        ch._enqueue = enqueued.append

        ch._on_message(
            {
                "threadId": "t123",
                "isGroup": False,
                "senderId": "s456",
                "senderName": "John",
                "content": "Hello!",
                "attachments": [],
                "timestampMs": 1711100000000,
                "msgId": "m1",
                "wasExplicitlyMentioned": False,
            }
        )

        assert len(enqueued) == 1
        native = enqueued[0]
        assert native["channel_id"] == "zalouser"
        assert native["sender_id"] == "s456"

    def test_empty_content_skipped(self):
        ch = _make_channel()
        enqueued = []
        ch._enqueue = enqueued.append

        ch._on_message(
            {
                "threadId": "t123",
                "senderId": "s456",
                "content": "",
                "attachments": [],
            }
        )

        assert len(enqueued) == 0

    def test_no_sender_skipped(self):
        ch = _make_channel()
        enqueued = []
        ch._enqueue = enqueued.append

        ch._on_message({"threadId": "t123", "senderId": "", "content": "hi"})
        assert len(enqueued) == 0

    def test_group_mention_gated(self):
        ch = _make_channel(require_mention=True)
        enqueued = []
        ch._enqueue = enqueued.append

        # Group message without mention -> should be dropped
        ch._on_message(
            {
                "threadId": "g123",
                "isGroup": True,
                "senderId": "s456",
                "content": "hello",
                "attachments": [],
                "wasExplicitlyMentioned": False,
            }
        )
        assert len(enqueued) == 0

    def test_group_mention_passes(self):
        ch = _make_channel(require_mention=True)
        enqueued = []
        ch._enqueue = enqueued.append

        ch._on_message(
            {
                "threadId": "g123",
                "isGroup": True,
                "senderId": "s456",
                "content": "hello bot",
                "attachments": [],
                "wasExplicitlyMentioned": True,
            }
        )
        assert len(enqueued) == 1

    def test_message_with_image_attachment(self):
        ch = _make_channel()
        enqueued = []
        ch._enqueue = enqueued.append

        ch._on_message(
            {
                "threadId": "t123",
                "isGroup": False,
                "senderId": "s456",
                "content": "Look at this",
                "attachments": [
                    {
                        "type": "image",
                        "url": "https://example.com/img.jpg",
                        "thumbnailUrl": "https://example.com/thumb.jpg",
                    }
                ],
                "timestampMs": 1711100000000,
                "msgId": "m2",
                "wasExplicitlyMentioned": False,
            }
        )

        assert len(enqueued) == 1
        native = enqueued[0]
        parts = native["content_parts"]
        # Should have TextContent + ImageContent
        types = [p.type for p in parts]
        assert ContentType.TEXT in types
        assert ContentType.IMAGE in types

    def test_allowlist_blocks_unauthorized(self):
        ch = _make_channel(dm_policy="allowlist", allow_from=["allowed_user"])
        enqueued = []
        ch._enqueue = enqueued.append
        ch._bridge.send_command = AsyncMock()

        ch._on_message(
            {
                "threadId": "t123",
                "isGroup": False,
                "senderId": "blocked_user",
                "content": "hello",
                "attachments": [],
            }
        )
        assert len(enqueued) == 0


# ===================================================================
# build_agent_request_from_native
# ===================================================================


class TestBuildAgentRequestFromNative:
    def test_basic_text_request(self):
        ch = _make_channel()
        native = {
            "channel_id": "zalouser",
            "sender_id": "s123",
            "content_parts": [TextContent(type=ContentType.TEXT, text="hi")],
            "meta": {
                "thread_id": "t456",
                "sender_id": "s123",
                "is_group": False,
            },
        }
        req = ch.build_agent_request_from_native(native)
        assert req is not None
        assert req.user_id == "s123"
        assert req.channel_meta["thread_id"] == "t456"

    def test_non_dict_payload(self):
        ch = _make_channel()
        req = ch.build_agent_request_from_native("invalid")
        assert req is not None  # should not raise


# ===================================================================
# send
# ===================================================================


class TestSend:
    @pytest.mark.asyncio
    async def test_send_text(self):
        ch = _make_channel()
        ch._bridge.send_command = AsyncMock(return_value={"ok": True})
        await ch.send("t123", "Hello!", {"thread_id": "t123", "is_group": False})
        ch._bridge.send_command.assert_called_once()
        call = ch._bridge.send_command.call_args
        assert call[0][0] == "send_message"

    @pytest.mark.asyncio
    async def test_send_disabled_noop(self):
        ch = _make_channel(enabled=False)
        ch._bridge.send_command = AsyncMock()
        await ch.send("t123", "Hello!")
        ch._bridge.send_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_no_thread_id_noop(self):
        ch = _make_channel()
        ch._bridge.send_command = AsyncMock()
        await ch.send("", "Hello!", {})
        ch._bridge.send_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_stops_typing(self):
        ch = _make_channel()
        ch._bridge.send_command = AsyncMock(return_value={"ok": True})
        ch._typing_tasks["t123"] = MagicMock()
        ch._typing_tasks["t123"].done.return_value = False
        await ch.send("t123", "Hello!", {"thread_id": "t123"})
        # Typing task should have been cancelled
        ch._typing_tasks.get("t123", MagicMock()).cancel.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_long_text_chunked(self):
        ch = _make_channel()
        ch._bridge.send_command = AsyncMock(return_value={"ok": True})
        # Text over ZALO_TEXT_LIMIT should be chunked
        long_text = "a " * (ZALO_TEXT_LIMIT + 100)
        await ch.send("t123", long_text, {"thread_id": "t123"})
        assert ch._bridge.send_command.call_count >= 2
        for call in ch._bridge.send_command.call_args_list:
            assert len(call.kwargs.get("text", "")) <= ZALO_TEXT_LIMIT + 10


# ===================================================================
# send_content_parts
# ===================================================================


class TestSendContentParts:
    @pytest.mark.asyncio
    async def test_splits_text_and_media(self):
        ch = _make_channel()
        ch._bridge.send_command = AsyncMock(return_value={"ok": True})
        ch._bridge._state_dir = Path("/tmp/test_zalouser")

        parts = [
            TextContent(type=ContentType.TEXT, text="Hello!"),
            ImageContent(
                type=ContentType.IMAGE,
                image_url="file:///tmp/test.jpg",
            ),
        ]
        meta = {"thread_id": "t123", "is_group": False}

        with patch("os.path.exists", return_value=True):
            await ch.send_content_parts("t123", parts, meta)

        # Should have sent text and then attempted media
        calls = ch._bridge.send_command.call_args_list
        cmds = [c[0][0] for c in calls]
        assert "send_message" in cmds

    @pytest.mark.asyncio
    async def test_text_only_no_media(self):
        ch = _make_channel()
        ch._bridge.send_command = AsyncMock(return_value={"ok": True})

        parts = [
            TextContent(type=ContentType.TEXT, text="Just text"),
        ]
        meta = {"thread_id": "t123", "is_group": False}
        await ch.send_content_parts("t123", parts, meta)

        ch._bridge.send_command.assert_called_once()
        assert ch._bridge.send_command.call_args[0][0] == "send_message"


# ===================================================================
# send_media
# ===================================================================


class TestSendMedia:
    @pytest.mark.asyncio
    async def test_send_local_image(self):
        ch = _make_channel()
        ch._bridge.send_command = AsyncMock(return_value={"ok": True})
        ch._bridge._state_dir = Path("/tmp/test_zalouser")

        part = ImageContent(
            type=ContentType.IMAGE,
            image_url="file:///tmp/test.jpg",
        )
        meta = {"thread_id": "t123", "is_group": False}

        with patch("os.path.exists", return_value=True):
            await ch.send_media("t123", part, meta)

        ch._bridge.send_command.assert_called_once()
        call = ch._bridge.send_command.call_args
        assert call[0][0] == "send_image"

    @pytest.mark.asyncio
    async def test_send_http_url_downloads(self):
        ch = _make_channel()
        ch._bridge.send_command = AsyncMock(return_value={"ok": True})
        ch._bridge._state_dir = Path("/tmp/test_zalouser")

        part = ImageContent(
            type=ContentType.IMAGE,
            image_url="https://example.com/photo.jpg",
        )
        meta = {"thread_id": "t123", "is_group": False}

        # Mock httpx download
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"fake image data"
        mock_resp.headers = {"content-type": "image/jpeg"}
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            await ch.send_media("t123", part, meta)

        # Should have called bridge to send the downloaded file
        assert ch._bridge.send_command.called

    @pytest.mark.asyncio
    async def test_no_url_noop(self):
        ch = _make_channel()
        ch._bridge.send_command = AsyncMock()

        part = ImageContent(type=ContentType.IMAGE, image_url="")
        meta = {"thread_id": "t123"}
        await ch.send_media("t123", part, meta)
        ch._bridge.send_command.assert_not_called()
