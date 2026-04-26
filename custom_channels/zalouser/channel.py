"""
Zalo Personal Account Channel for QwenPaw

Pure Python implementation - no Node.js bridge required.
Based on reverse-engineered Zalo Web protocol.

Architecture:
    QwenPaw (Python)
        |
        v
    ZaloUserChannel (BaseChannel subclass)
        | aiohttp WebSocket/HTTP
        v
    Zalo Servers
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import gzip
import hashlib
import json
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import aiohttp

from agentscope_runtime.engine.schemas.agent_schemas import (
    AgentRequest,
    ContentType,
    FileContent,
    ImageContent,
    Message,
    Role,
    TextContent,
    VideoContent,
)

from qwenpaw.app.channels.base import (
    BaseChannel,
    OnReplySent,
    OutgoingContentPart,
    ProcessHandler,
)

logger = logging.getLogger(__name__)

# Constants
ZALO_TEXT_LIMIT = 2000
ZALO_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
ZALO_API_VERSION = 647
ZALO_LOGIN_TYPE = 24
DEFAULT_STATE_DIR = Path.home() / ".qwenpaw" / "zalouser"

# Zalo API Endpoints
ZALO_ENDPOINTS = {
    "id_base": "https://id.zalo.me",
    "chat_base": "https://chat.zalo.me",
    "wpa_base": "https://tt-profile-wpa.chat.zalo.me",
    "friend_base": "https://tt-friend-wpa.chat.zalo.me",
    "group_base": "https://tt-group-wpa.chat.zalo.me",
    "convers_base": "https://tt-convers-wpa.chat.zalo.me",
    "files_base": "https://tt-files-wpa.chat.zalo.me",
    "jr_base": "https://jr.chat.zalo.me",
}


class ThreadType(Enum):
    """Zalo thread types."""
    USER = 0
    GROUP = 1


@dataclass
class ZaloCredentials:
    """Zalo credentials storage."""
    imei: str = ""
    user_agent: str = ZALO_USER_AGENT
    cookies: Dict[str, str] = field(default_factory=dict)
    secret_key: str = ""
    user_id: str = ""
    phone_number: str = ""
    zpw_ws: List[str] = field(default_factory=list)
    zpw_enk: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize credentials to dict."""
        return {
            "imei": self.imei,
            "user_agent": self.user_agent,
            "cookies": self.cookies,
            "secret_key": self.secret_key,
            "user_id": self.user_id,
            "phone_number": self.phone_number,
            "zpw_ws": self.zpw_ws,
            "zpw_enk": self.zpw_enk,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ZaloCredentials":
        """Deserialize credentials from dict."""
        return cls(
            imei=data.get("imei", ""),
            user_agent=data.get("user_agent", ZALO_USER_AGENT),
            cookies=data.get("cookies", {}),
            secret_key=data.get("secret_key", ""),
            user_id=data.get("user_id", ""),
            phone_number=data.get("phone_number", ""),
            zpw_ws=data.get("zpw_ws", []),
            zpw_enk=data.get("zpw_enk", ""),
        )
    
    def save(self, path: Path) -> None:
        """Save credentials to file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, path: Path) -> Optional["ZaloCredentials"]:
        """Load credentials from file."""
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls.from_dict(data)
        except Exception as e:
            logger.warning(f"Failed to load credentials: {e}")
            return None
    
    def is_valid(self) -> bool:
        """Check if credentials are valid for login."""
        return bool(self.cookies and self.secret_key and self.imei)


class ZaloCrypto:
    """Zalo encryption/decryption utilities."""
    
    @staticmethod
    def generate_imei(user_agent: str = ZALO_USER_AGENT) -> str:
        """Generate a device IMEI-like UUID."""
        # Zalo uses a specific format based on user agent
        seed = hashlib.md5(user_agent.encode()).hexdigest()
        return f"{seed[:8]}-{seed[8:12]}-{seed[12:16]}-{seed[16:20]}-{seed[20:32]}"
    
    @staticmethod
    def encode_params(params: Any, key: str) -> str:
        """Encode parameters using AES-CBC encryption.
        
        Zalo uses AES-128-CBC with zero IV and PKCS7 padding.
        """
        try:
            raw_key = base64.b64decode(key)
            data = json.dumps(params).encode("utf-8")
            
            # PKCS7 padding
            block_size = 16
            pad_len = block_size - (len(data) % block_size)
            data = data + bytes([pad_len] * pad_len)
            
            # AES-CBC with zero IV
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            cipher = Cipher(algorithms.AES(raw_key), modes.CBC(b"\x00" * 16))
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(data) + encryptor.finalize()
            
            return base64.b64encode(encrypted).decode("utf-8")
        except Exception as e:
            logger.error(f"Failed to encode params: {e}")
            raise
    
    @staticmethod
    def decode_params(encoded: str, key: str) -> Dict[str, Any]:
        """Decode parameters using AES-CBC decryption."""
        try:
            raw_key = base64.b64decode(key)
            cipher_text = base64.b64decode(encoded)
            
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            cipher = Cipher(algorithms.AES(raw_key), modes.CBC(b"\x00" * 16))
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(cipher_text) + decryptor.finalize()
            
            # Remove PKCS7 padding
            pad_len = decrypted[-1]
            decrypted = decrypted[:-pad_len]
            
            return json.loads(decrypted.decode("utf-8"))
        except Exception as e:
            logger.error(f"Failed to decode params: {e}")
            return {}
    
    @staticmethod
    def decode_ws_packet(data: bytes, key: str) -> Dict[str, Any]:
        """Decode WebSocket packet.
        
        Format:
        - encrypt=0: raw JSON
        - encrypt=1: base64 + gzip
        - encrypt=2: AES-GCM + gzip
        """
        try:
            # Try raw JSON first
            try:
                return json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            
            # Try base64 + gzip
            try:
                decoded = base64.b64decode(data)
                decompressed = gzip.decompress(decoded)
                return json.loads(decompressed.decode("utf-8"))
            except (binascii.Error, gzip.BadGzipFile, json.JSONDecodeError, UnicodeDecodeError):
                pass
            
            # Try AES-GCM + gzip (encrypt=2)
            if len(data) >= 48:
                iv = data[:16]
                additional_data = data[16:32]
                cipher_source = data[32:]
                
                raw_key = base64.b64decode(key)
                
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(raw_key)
                decrypted = aesgcm.decrypt(iv, cipher_source, additional_data)
                
                decompressed = gzip.decompress(decrypted)
                return json.loads(decompressed.decode("utf-8"))
        except Exception as e:
            logger.error(f"Failed to decode WS packet: {e}")
            return {}
        
        return {}


class ZaloQRAuth:
    """Zalo QR Code authentication flow."""
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.qr_code: Optional[str] = None
        self.qr_token: Optional[str] = None
        self.qr_image: Optional[bytes] = None
    
    async def generate_qr(self) -> Tuple[str, str, bytes]:
        """Generate QR code for login.
        
        Returns: (code, token, image_bytes)
        """
        headers = {
            "User-Agent": ZALO_USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://id.zalo.me",
            "Referer": "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.6,en;q=0.5",
        }
        
        # Initial session setup
        await self.session.get(
            "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F",
            headers=headers,
        )
        
        # Generate QR
        form_data = {"continue": "https://zalo.me/pc", "v": "5.5.7"}
        resp = await self.session.post(
            "https://id.zalo.me/account/authen/qr/generate",
            headers=headers,
            data=form_data,
        )
        data = await resp.json()
        
        if data.get("error_code") != 0:
            raise Exception(f"Failed to generate QR: {data.get('error_message')}")
        
        payload = data.get("data", {})
        image_b64 = payload.get("image", "")
        self.qr_code = payload.get("code", "")
        self.qr_token = payload.get("token", "")
        
        # Decode base64 image
        if image_b64.startswith("data:image/png;base64,"):
            image_b64 = image_b64[22:]  # Remove prefix
        self.qr_image = base64.b64decode(image_b64)
        
        return self.qr_code, self.qr_token, self.qr_image
    
    async def wait_for_scan(self, max_attempts: int = 60, interval: float = 3.0) -> bool:
        """Wait for user to scan QR code.
        
        Returns True when scanned.
        """
        headers = {
            "User-Agent": ZALO_USER_AGENT,
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://id.zalo.me",
            "Referer": "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F",
        }
        
        for attempt in range(max_attempts):
            form_data = {
                "code": self.qr_code,
                "continue": "https://chat.zalo.me/",
                "v": "5.5.7",
            }
            resp = await self.session.post(
                "https://id.zalo.me/account/authen/qr/waiting-scan",
                headers=headers,
                data=form_data,
            )
            data = await resp.json()
            
            error_code = data.get("error_code", -1)
            if error_code == 0:
                return True
            elif error_code == 1:
                # Not scanned yet, wait
                await asyncio.sleep(interval)
            else:
                logger.warning(f"QR scan error: {data}")
                return False
        
        return False
    
    async def wait_for_confirm(self, max_attempts: int = 20, interval: float = 5.0) -> Dict[str, str]:
        """Wait for user to confirm login on phone.
        
        Returns cookies dict.
        """
        headers = {
            "User-Agent": ZALO_USER_AGENT,
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://id.zalo.me",
            "Referer": "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F",
        }
        
        for attempt in range(max_attempts):
            form_data = {
                "code": self.qr_code,
                "gToken": "",
                "gAction": "CONFIRM_QR",
                "continue": "https://chat.zalo.me/index.html",
                "v": "5.5.7",
            }
            resp = await self.session.post(
                "https://id.zalo.me/account/authen/qr/waiting-confirm",
                headers=headers,
                data=form_data,
            )
            data = await resp.json()
            
            if data.get("error_code") == 0:
                # Get cookies from session
                cookies = self._extract_cookies()
                return cookies
            
            await asyncio.sleep(interval)
        
        raise Exception("QR confirmation timeout")
    
    async def fetch_user_info(self) -> Dict[str, Any]:
        """Fetch user info after login."""
        headers = {
            "User-Agent": ZALO_USER_AGENT,
            "Accept": "*/*",
            "Referer": "https://chat.zalo.me/",
        }
        
        resp = await self.session.get(
            "https://jr.chat.zalo.me/jr/userinfo",
            headers=headers,
        )
        return await resp.json()
    
    def _extract_cookies(self) -> Dict[str, str]:
        """Extract cookies from session."""
        cookies = {}
        for cookie in self.session.cookie_jar:
            if cookie.value:
                cookies[cookie.key] = cookie.value
        return cookies


class ZaloWebSocket:
    """Zalo WebSocket client for real-time messages."""
    
    def __init__(
        self,
        ws_urls: List[str],
        cookies: Dict[str, str],
        secret_key: str,
        user_id: str,
        imei: str,
        on_message: Callable[[Dict[str, Any], ThreadType], None],
        on_event: Optional[Callable[[Dict[str, Any], str], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
    ):
        self.ws_urls = ws_urls
        self.cookies = cookies
        self.secret_key = secret_key
        self.user_id = user_id
        self.imei = imei
        self.on_message = on_message
        self.on_event = on_event
        self.on_error = on_error
        
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self.ws_key: Optional[str] = None
        self.listening = False
        self._ping_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
    
    async def connect(self) -> bool:
        """Connect to WebSocket."""
        headers = {
            "User-Agent": ZALO_USER_AGENT,
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Origin": "https://chat.zalo.me",
            "Pragma": "no-cache",
        }
        
        cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        headers["Cookie"] = cookie_str
        
        for ws_url in self.ws_urls:
            try:
                # Add query params
                params = {
                    "zpw_ver": ZALO_API_VERSION,
                    "zpw_type": ZALO_LOGIN_TYPE,
                    "t": str(int(time.time() * 1000)),
                }
                full_url = f"{ws_url}?{urlencode(params)}"
                
                session = aiohttp.ClientSession()
                self.ws = await session.ws_connect(
                    full_url,
                    headers=headers,
                    heartbeat=60,
                )
                
                self.listening = True
                logger.info(f"Connected to Zalo WebSocket: {ws_url}")
                return True
            except Exception as e:
                logger.warning(f"Failed to connect to {ws_url}: {e}")
        
        return False
    
    async def listen(self) -> None:
        """Listen for messages."""
        if not self.ws:
            await self.connect()
        
        if not self.ws:
            raise Exception("Failed to connect to WebSocket")
        
        # Start ping task
        self._ping_task = asyncio.create_task(self._ping_loop())
        
        try:
            while self.listening and not self._stop_event.is_set():
                try:
                    msg = await self.ws.receive(timeout=30)
                    
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        await self._handle_binary(msg.data)
                    elif msg.type == aiohttp.WSMsgType.TEXT:
                        await self._handle_text(msg.data)
                    elif msg.type == aiohttp.WSMsgType.CLOSED:
                        logger.warning("WebSocket closed")
                        self.listening = False
                        break
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        logger.error(f"WebSocket error: {self.ws.exception()}")
                        if self.on_error:
                            self.on_error(self.ws.exception())
                        break
                except asyncio.TimeoutError:
                    # Continue listening
                    continue
                except Exception as e:
                    logger.error(f"WebSocket receive error: {e}")
                    if self.on_error:
                        self.on_error(e)
        finally:
            await self.stop()
    
    async def _handle_binary(self, data: bytes) -> None:
        """Handle binary WebSocket message."""
        if len(data) < 5:
            return
        
        # Parse header: [version][cmd(2 bytes)][subCmd]
        version = data[0]
        cmd = struct.unpack("<H", data[1:3])[0]
        sub_cmd = data[3]
        
        payload_data = data[4:]
        
        # Key exchange (cmd=1, subCmd=1)
        if version == 1 and cmd == 1 and sub_cmd == 1:
            try:
                parsed = json.loads(payload_data.decode("utf-8"))
                self.ws_key = parsed.get("key", "")
                logger.debug(f"WebSocket key received: {self.ws_key[:20]}...")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            return
        
        # Another connection opened (cmd=3000)
        if version == 1 and cmd == 3000 and sub_cmd == 0:
            logger.warning("Another connection opened, closing this one")
            await self.stop()
            return
        
        # Decrypt payload if we have key
        if self.ws_key:
            try:
                decoded = ZaloCrypto.decode_ws_packet(payload_data, self.ws_key)
                await self._handle_decoded_packet(version, cmd, sub_cmd, decoded)
            except Exception as e:
                logger.error(f"Failed to decode packet: {e}")
    
    async def _handle_text(self, data: str) -> None:
        """Handle text WebSocket message."""
        try:
            parsed = json.loads(data)
            if "key" in parsed:
                self.ws_key = parsed["key"]
        except json.JSONDecodeError:
            pass
    
    async def _handle_decoded_packet(
        self,
        version: int,
        cmd: int,
        sub_cmd: int,
        data: Dict[str, Any],
    ) -> None:
        """Handle decoded WebSocket packet."""
        inner_data = data.get("data", {})
        
        # Direct messages (cmd=501)
        if version == 1 and cmd == 501 and sub_cmd == 0:
            msgs = inner_data.get("msgs", [])
            for msg in msgs:
                self._process_message(msg, ThreadType.USER)
        
        # Group messages (cmd=521)
        if version == 1 and cmd == 521 and sub_cmd == 0:
            msgs = inner_data.get("groupMsgs", [])
            for msg in msgs:
                self._process_message(msg, ThreadType.GROUP)
        
        # Group events (cmd=601)
        if version == 1 and cmd == 601 and sub_cmd == 0:
            controls = inner_data.get("controls", [])
            for ctrl in controls:
                content = ctrl.get("content", {})
                act_type = content.get("act_type", "")
                act = content.get("act", "")
                
                if act_type == "group" and self.on_event:
                    event_data = json.loads(content.get("data", "{}"))
                    self.on_event(event_data, act)
        
        # Reactions (cmd=612)
        if cmd == 612:
            reacts = inner_data.get("reacts", [])
            for react in reacts:
                self._process_message(react, ThreadType.USER)
            
            group_reacts = inner_data.get("reactGroups", [])
            for react in group_reacts:
                self._process_message(react, ThreadType.GROUP)
    
    def _process_message(self, msg: Dict[str, Any], thread_type: ThreadType) -> None:
        """Process incoming message."""
        if self.on_message:
            self.on_message(msg, thread_type)
    
    async def _ping_loop(self) -> None:
        """Send periodic ping to keep connection alive."""
        while self.listening and not self._stop_event.is_set():
            try:
                await asyncio.sleep(60)
                if self.ws and self.ws_key:
                    ping_payload = self._build_ping()
                    await self.ws.send_bytes(ping_payload)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Ping error: {e}")
    
    def _build_ping(self) -> bytes:
        """Build ping payload."""
        payload = {"eventId": int(time.time() * 1000)}
        data = json.dumps(payload).encode("utf-8")
        
        header = bytes([1]) + struct.pack("<I", 2)[0:2] + bytes([1])
        return header + data
    
    async def stop(self) -> None:
        """Stop WebSocket connection."""
        self.listening = False
        self._stop_event.set()
        
        if self._ping_task:
            self._ping_task.cancel()
            try:
                await self._ping_task
            except asyncio.CancelledError:
                pass
        
        if self.ws:
            await self.ws.close()
            self.ws = None
        
        logger.info("WebSocket stopped")


class ZaloHTTPAPI:
    """Zalo HTTP API for sending messages and other operations."""
    
    def __init__(
        self,
        session: aiohttp.ClientSession,
        credentials: ZaloCredentials,
    ):
        self.session = session
        self.credentials = credentials
        self.imei = credentials.imei
        self.user_id = credentials.user_id
        self.secret_key = credentials.secret_key
    
    def _headers(self, referer: str = "https://chat.zalo.me/") -> Dict[str, str]:
        """Build request headers."""
        return {
            "User-Agent": self.credentials.user_agent,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.6,en;q=0.5",
            "Origin": "https://chat.zalo.me",
            "Referer": referer,
            "sec-ch-ua": '"Not-A.Brand";v="99", "Chromium";v="124"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Linux"',
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        }
    
    def _cookie_str(self) -> str:
        """Build cookie string."""
        return "; ".join(f"{k}={v}" for k, v in self.credentials.cookies.items())
    
    def _encode_params(self, params: Dict[str, Any]) -> str:
        """Encode params using secret key."""
        return ZaloCrypto.encode_params(params, self.secret_key)
    
    async def send_message(
        self,
        thread_id: str,
        message: str,
        thread_type: ThreadType,
    ) -> Dict[str, Any]:
        """Send text message."""
        params = {
            "toid": str(thread_id),
            "message": message,
            "imei": self.imei,
            "clientId": str(int(time.time() * 1000)),
        }
        
        encoded_params = self._encode_params(params)
        
        form_data = {
            "params": encoded_params,
            "zpw_ver": ZALO_API_VERSION,
            "zpw_type": ZALO_LOGIN_TYPE,
            "nretry": 0,
        }
        
        if thread_type == ThreadType.USER:
            url = "https://tt-convers-wpa.chat.zalo.me/api/message/sent"
            form_data["type"] = "2"
        else:
            url = "https://tt-group-cm.chat.zalo.me/api/cm/sent"
            form_data["type"] = "11"
            form_data["params"] = self._encode_params({
                "grid": str(thread_id),
                "message": message,
                "imei": self.imei,
                "clientId": str(int(time.time() * 1000)),
            })
        
        headers = self._headers()
        headers["Cookie"] = self._cookie_str()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        resp = await self.session.post(url, headers=headers, data=form_data)
        data = await resp.json()
        
        if data.get("error_code") == 0:
            return {"success": True, "data": data.get("data")}
        else:
            return {"success": False, "error": data.get("error_message", "Unknown error")}
    
    async def send_typing(
        self,
        thread_id: str,
        thread_type: ThreadType,
    ) -> bool:
        """Send typing indicator."""
        params = {
            "imei": self.imei,
        }
        
        if thread_type == ThreadType.USER:
            params["toid"] = str(thread_id)
            url = "https://tt-convers-wpa.chat.zalo.me/api/message/typing"
        else:
            params["grid"] = str(thread_id)
            url = "https://tt-group-cm.chat.zalo.me/api/cm/typing"
        
        encoded_params = self._encode_params(params)
        
        form_data = {
            "params": encoded_params,
            "zpw_ver": ZALO_API_VERSION,
            "zpw_type": ZALO_LOGIN_TYPE,
        }
        
        headers = self._headers()
        headers["Cookie"] = self._cookie_str()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        resp = await self.session.post(url, headers=headers, data=form_data)
        data = await resp.json()
        
        return data.get("error_code") == 0
    
    async def send_image(
        self,
        thread_id: str,
        image_url: str,
        thread_type: ThreadType,
        width: int = 640,
        height: int = 640,
        caption: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send image message."""
        params = {
            "photoUrl": image_url,
            "imei": self.imei,
            "clientId": str(int(time.time() * 1000)),
            "width": width,
            "height": height,
        }
        
        if thread_type == ThreadType.USER:
            params["toid"] = str(thread_id)
            url = "https://tt-files-wpa.chat.zalo.me/api/message/photo_original/send"
        else:
            params["grid"] = str(thread_id)
            url = "https://tt-files-wpa.chat.zalo.me/api/group/photo_original/send"
        
        if caption:
            params["message"] = caption
        
        encoded_params = self._encode_params(params)
        
        form_data = {
            "params": encoded_params,
            "zpw_ver": ZALO_API_VERSION,
            "zpw_type": ZALO_LOGIN_TYPE,
        }
        
        headers = self._headers()
        headers["Cookie"] = self._cookie_str()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        resp = await self.session.post(url, headers=headers, data=form_data)
        data = await resp.json()
        
        if data.get("error_code") == 0:
            return {"success": True, "data": data.get("data")}
        else:
            return {"success": False, "error": data.get("error_message", "Unknown error")}
    
    async def send_file(
        self,
        thread_id: str,
        file_url: str,
        file_name: str,
        file_size: int,
        thread_type: ThreadType,
        caption: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send file message."""
        params = {
            "fileUrl": file_url,
            "fileName": file_name,
            "fileSize": file_size,
            "imei": self.imei,
            "clientId": str(int(time.time() * 1000)),
        }
        
        if thread_type == ThreadType.USER:
            params["toid"] = str(thread_id)
            url = "https://tt-files-wpa.chat.zalo.me/api/message/file/send"
        else:
            params["grid"] = str(thread_id)
            url = "https://tt-files-wpa.chat.zalo.me/api/group/file/send"
        
        if caption:
            params["message"] = caption
        
        encoded_params = self._encode_params(params)
        
        form_data = {
            "params": encoded_params,
            "zpw_ver": ZALO_API_VERSION,
            "zpw_type": ZALO_LOGIN_TYPE,
        }
        
        headers = self._headers()
        headers["Cookie"] = self._cookie_str()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        resp = await self.session.post(url, headers=headers, data=form_data)
        data = await resp.json()
        
        if data.get("error_code") == 0:
            return {"success": True, "data": data.get("data")}
        else:
            return {"success": False, "error": data.get("error_message", "Unknown error")}
    
    async def fetch_user_info(self, user_ids: List[str]) -> Dict[str, Any]:
        """Fetch user info by IDs."""
        params = {
            "friend_pversion_map": [f"{uid}_0" for uid in user_ids],
            "avatar_size": 120,
            "language": "vi",
            "imei": self.imei,
        }
        
        encoded_params = self._encode_params(params)
        
        form_data = {
            "params": encoded_params,
            "zpw_ver": ZALO_API_VERSION,
            "zpw_type": ZALO_LOGIN_TYPE,
        }
        
        headers = self._headers()
        headers["Cookie"] = self._cookie_str()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        resp = await self.session.post(
            "https://tt-profile-wpa.chat.zalo.me/api/social/friend/getprofiles/v2",
            headers=headers,
            data=form_data,
        )
        return await resp.json()
    
    async def fetch_group_info(self, group_ids: List[str]) -> Dict[str, Any]:
        """Fetch group info by IDs."""
        params = {
            "gridVerMap": {gid: 0 for gid in group_ids},
            "imei": self.imei,
        }
        
        encoded_params = self._encode_params(params)
        
        form_data = {
            "params": encoded_params,
            "zpw_ver": ZALO_API_VERSION,
            "zpw_type": ZALO_LOGIN_TYPE,
        }
        
        headers = self._headers()
        headers["Cookie"] = self._cookie_str()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        resp = await self.session.post(
            "https://tt-group-wpa.chat.zalo.me/api/group/getmg-v2",
            headers=headers,
            data=form_data,
        )
        return await resp.json()


class ZaloUserChannel(BaseChannel):
    """Zalo Personal Account Channel for QwenPaw.
    
    Pure Python implementation - no Node.js bridge required.
    
    Configuration options (in config.json under channels.zalouser):
        - enabled: bool - Enable/disable the channel
        - state_dir: str - Directory for credentials storage
        - bot_prefix: str - Prefix for bot commands
        - show_typing: bool - Show typing indicator while processing
        - filter_tool_messages: bool - Filter tool messages from output
        - filter_thinking: bool - Filter thinking blocks from output
        - dm_policy: str - Direct message policy (open, restricted, blocked)
        - group_policy: str - Group message policy (open, restricted, blocked)
        - allow_from: list - List of allowed user/group IDs
        - deny_message: str - Message to send when denied
        - require_mention: bool - Require bot mention in groups
        - max_send_rate: int - Max messages per second (rate limiting)
        - health_check_interval: int - Health check interval in seconds
        - max_restart_attempts: int - Max restart attempts on failure
    
    Note: show_tool_details is a GLOBAL config option (at root level of config.json),
          not a per-channel setting.
    """
    
    channel = "zalouser"
    uses_manager_queue = True
    
    def __init__(
        self,
        process: ProcessHandler,
        enabled: bool = True,
        state_dir: str = "",
        bot_prefix: str = "",
        show_typing: bool = True,
        on_reply_sent: OnReplySent = None,
        show_tool_details: bool = True,
        filter_tool_messages: bool = False,
        filter_thinking: bool = False,
        dm_policy: str = "open",
        group_policy: str = "open",
        allow_from: Optional[List[str]] = None,
        deny_message: str = "",
        require_mention: bool = False,
        max_send_rate: int = 5,
        health_check_interval: int = 30,
        max_restart_attempts: int = 3,
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
        self.state_dir = Path(state_dir).expanduser() if state_dir else DEFAULT_STATE_DIR
        self.bot_prefix = bot_prefix
        self.show_typing = show_typing
        self.max_send_rate = max_send_rate
        self.health_check_interval = health_check_interval
        self.max_restart_attempts = max_restart_attempts
        
        # Internal state
        self.credentials: Optional[ZaloCredentials] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.ws: Optional[ZaloWebSocket] = None
        self.http_api: Optional[ZaloHTTPAPI] = None
        self._ws_task: Optional[asyncio.Task] = None
        self._health_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self._restart_count = 0
        self._last_send_time = 0.0
        self._send_lock = asyncio.Lock()
    
    @classmethod
    def from_env(cls, process: ProcessHandler, on_reply_sent: OnReplySent = None) -> "ZaloUserChannel":
        """Create channel from environment variables."""
        enabled = os.getenv("ZALOUSER_CHANNEL_ENABLED", "1") == "1"
        state_dir = os.getenv("ZALOUSER_STATE_DIR", "")
        bot_prefix = os.getenv("ZALOUSER_BOT_PREFIX", "")
        show_typing = os.getenv("ZALOUSER_SHOW_TYPING", "1") == "1"
        
        return cls(
            process=process,
            enabled=enabled,
            state_dir=state_dir,
            bot_prefix=bot_prefix,
            show_typing=show_typing,
            on_reply_sent=on_reply_sent,
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
        """Create channel from config object."""
        return cls(
            process=process,
            enabled=getattr(config, "enabled", True),
            state_dir=getattr(config, "state_dir", ""),
            bot_prefix=getattr(config, "bot_prefix", ""),
            show_typing=getattr(config, "show_typing", True),
            on_reply_sent=on_reply_sent,
            show_tool_details=show_tool_details,
            filter_tool_messages=getattr(config, "filter_tool_messages", False),
            filter_thinking=getattr(config, "filter_thinking", False),
            dm_policy=getattr(config, "dm_policy", "open"),
            group_policy=getattr(config, "group_policy", "open"),
            allow_from=getattr(config, "allow_from", None),
            deny_message=getattr(config, "deny_message", ""),
            require_mention=getattr(config, "require_mention", False),
            max_send_rate=getattr(config, "max_send_rate", 5),
            health_check_interval=getattr(config, "health_check_interval", 30),
            max_restart_attempts=getattr(config, "max_restart_attempts", 3),
        )
    
    async def start(self) -> None:
        """Start the Zalo channel."""
        if not self.enabled:
            logger.info("Zalo channel is disabled")
            return
        
        # Load credentials
        cred_path = self.state_dir / "credentials.json"
        self.credentials = ZaloCredentials.load(cred_path)
        
        # Create HTTP session
        self.session = aiohttp.ClientSession()
        
        # Check if we need QR login
        if not self.credentials or not self.credentials.is_valid():
            logger.info("No valid credentials, QR login required")
            await self._qr_login()
        
        if not self.credentials or not self.credentials.is_valid():
            logger.error("Failed to obtain valid credentials")
            return
        
        # Initialize HTTP API
        self.http_api = ZaloHTTPAPI(self.session, self.credentials)
        
        # Start WebSocket listener
        self._stop_event.clear()
        self._ws_task = asyncio.create_task(self._ws_loop())
        self._health_task = asyncio.create_task(self._health_loop())
        
        logger.info(f"Zalo channel started for user {self.credentials.user_id}")
    
    async def stop(self) -> None:
        """Stop the Zalo channel."""
        self._stop_event.set()
        
        if self._ws_task:
            self._ws_task.cancel()
            try:
                await self._ws_task
            except asyncio.CancelledError:
                pass
        
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
        
        if self.ws:
            await self.ws.stop()
        
        if self.session:
            await self.session.close()
        
        logger.info("Zalo channel stopped")
    
    async def _qr_login(self) -> None:
        """Perform QR code login."""
        qr_auth = ZaloQRAuth(self.session)
        
        # Generate QR
        code, token, image_bytes = await qr_auth.generate_qr()
        logger.info(f"QR code generated: {code}")
        
        # Save QR image
        qr_path = self.state_dir / "qr_login.png"
        qr_path.parent.mkdir(parents=True, exist_ok=True)
        with open(qr_path, "wb") as f:
            f.write(image_bytes)
        logger.info(f"QR image saved to: {qr_path}")
        
        # Wait for scan
        logger.info("Waiting for QR scan...")
        scanned = await qr_auth.wait_for_scan()
        
        if not scanned:
            logger.error("QR not scanned")
            return
        
        # Wait for confirm
        logger.info("Waiting for confirmation...")
        cookies = await qr_auth.wait_for_confirm()
        
        # Get user info
        user_info = await qr_auth.fetch_user_info()
        
        # Create credentials
        imei = ZaloCrypto.generate_imei()
        
        self.credentials = ZaloCredentials(
            imei=imei,
            cookies=cookies,
            user_id=str(user_info.get("userId", "")),
            phone_number=str(user_info.get("phoneNumber", "")),
            secret_key=user_info.get("zpw_enk", ""),
            zpw_ws=user_info.get("zpw_ws", []),
            zpw_enk=user_info.get("zpw_enk", ""),
        )
        
        # Save credentials
        cred_path = self.state_dir / "credentials.json"
        self.credentials.save(cred_path)
        logger.info(f"Credentials saved to: {cred_path}")
    
    async def _ws_loop(self) -> None:
        """WebSocket listener loop with auto-reconnect."""
        while not self._stop_event.is_set():
            try:
                if not self.credentials or not self.credentials.zpw_ws:
                    logger.error("No WebSocket URLs available")
                    await asyncio.sleep(5)
                    continue
                
                self.ws = ZaloWebSocket(
                    ws_urls=self.credentials.zpw_ws,
                    cookies=self.credentials.cookies,
                    secret_key=self.credentials.secret_key,
                    user_id=self.credentials.user_id,
                    imei=self.credentials.imei,
                    on_message=self._on_zalo_message,
                    on_event=self._on_zalo_event,
                    on_error=self._on_ws_error,
                )
                
                await self.ws.connect()
                await self.ws.listen()
                
                self._restart_count = 0
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                self._restart_count += 1
                
                if self._restart_count > self.max_restart_attempts:
                    logger.error("Max restart attempts reached")
                    break
                
                await asyncio.sleep(5)
    
    async def _health_loop(self) -> None:
        """Health check loop."""
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self.health_check_interval)
                
                if self.ws and not self.ws.listening:
                    logger.warning("WebSocket not listening, attempting reconnect")
                    # WebSocket loop will handle reconnect
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")
    
    def _on_zalo_message(self, msg: Dict[str, Any], thread_type: ThreadType) -> None:
        """Handle incoming Zalo message."""
        try:
            # Extract message data
            sender_id = str(msg.get("uidFrom", msg.get("userId", "")))
            thread_id = str(msg.get("idTo", msg.get("toid", sender_id)))
            content = msg.get("content", "")
            
            # Skip own messages
            if sender_id == self.credentials.user_id:
                return
            
            # Check policy
            if not self._check_policy(sender_id, thread_id, thread_type):
                return
            
            # Check for mention in groups
            if thread_type == ThreadType.GROUP and self.require_mention:
                mentions = msg.get("mentions", [])
                if not any(m.get("uid") == self.credentials.user_id for m in mentions):
                    return
            
            # Parse attachments
            attachments = msg.get("attachments", [])
            
            # Build AgentRequest
            request = self._build_agent_request(
                sender_id=sender_id,
                thread_id=thread_id,
                thread_type=thread_type,
                content=content,
                attachments=attachments,
                msg=msg,
            )
            
            # Enqueue for processing
            asyncio.create_task(self._process_message(request, thread_id, thread_type))
            
        except Exception as e:
            logger.error(f"Failed to process incoming message: {e}")
    
    def _on_zalo_event(self, event: Dict[str, Any], event_type: str) -> None:
        """Handle Zalo group events."""
        logger.debug(f"Zalo event: {event_type} - {event}")
    
    def _on_ws_error(self, error: Exception) -> None:
        """Handle WebSocket errors."""
        logger.error(f"WebSocket error: {error}")
    
    def _check_policy(
        self,
        sender_id: str,
        thread_id: str,
        thread_type: ThreadType,
    ) -> bool:
        """Check message policy."""
        policy = self.dm_policy if thread_type == ThreadType.USER else self.group_policy
        
        if policy == "blocked":
            return False
        
        if policy == "restricted":
            if self.allow_from:
                if thread_type == ThreadType.USER:
                    if sender_id not in self.allow_from:
                        return False
                else:
                    if thread_id not in self.allow_from:
                        return False
        
        return True
    
    def _build_agent_request(
        self,
        sender_id: str,
        thread_id: str,
        thread_type: ThreadType,
        content: str,
        attachments: List[Dict[str, Any]],
        msg: Dict[str, Any],
    ) -> AgentRequest:
        """Build AgentRequest from Zalo message."""
        content_parts: List[Any] = []
        
        # Add text content
        if content:
            content_parts.append(TextContent(type=ContentType.TEXT, text=content))
        
        # Add attachments
        for att in attachments:
            att_type = att.get("type", "")
            url = att.get("url", att.get("href", ""))
            
            if att_type in ("photo", "image"):
                content_parts.append(ImageContent(
                    type=ContentType.IMAGE,
                    url=url,
                ))
            elif att_type in ("video"):
                content_parts.append(VideoContent(
                    type=ContentType.VIDEO,
                    url=url,
                ))
            elif att_type in ("file"):
                content_parts.append(FileContent(
                    type=ContentType.FILE,
                    url=url,
                    filename=att.get("fileName", att.get("filename", "file")),
                ))
        
        # Ensure at least one content part
        if not content_parts:
            content_parts.append(TextContent(type=ContentType.TEXT, text=" "))
        
        # Build message
        message = Message(
            type=ContentType.TEXT,
            role=Role.USER,
            content=content_parts,
        )
        
        # Build session ID
        session_id = self.resolve_session_id(sender_id, {"thread_id": thread_id, "thread_type": thread_type.value})
        
        # Build AgentRequest
        request = AgentRequest(
            session_id=session_id,
            user_id=sender_id,
            input=[message],
            channel=self.channel,
        )
        
        # Add metadata
        request.channel_meta = {
            "thread_id": thread_id,
            "thread_type": thread_type.value,
            "msg_id": msg.get("msgId", ""),
            "cli_msg_id": msg.get("cliMsgId", ""),
            "sender_name": msg.get("senderName", ""),
            "group_name": msg.get("groupName", "") if thread_type == ThreadType.GROUP else "",
            "timestamp": msg.get("timestampMs", int(time.time() * 1000)),
        }
        
        return request
    
    async def _process_message(
        self,
        request: AgentRequest,
        thread_id: str,
        thread_type: ThreadType,
    ) -> None:
        """Process message and send reply."""
        try:
            # Show typing indicator
            if self.show_typing and self.http_api:
                await self.http_api.send_typing(thread_id, thread_type)
            
            # Process message
            await self.consume_one(request)
            
        except Exception as e:
            logger.error(f"Failed to process message: {e}")
    
    def resolve_session_id(
        self,
        sender_id: str,
        channel_meta: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Resolve session ID for message."""
        if channel_meta:
            thread_type = channel_meta.get("thread_type", 0)
            thread_id = channel_meta.get("thread_id", sender_id)
            
            if thread_type == ThreadType.GROUP.value:
                return f"zalouser:group:{thread_id}:{sender_id}"
            else:
                return f"zalouser:user:{thread_id}"
        
        return f"zalouser:user:{sender_id}"
    
    def build_agent_request_from_native(self, native_payload: Any) -> AgentRequest:
        """Build AgentRequest from native Zalo payload."""
        msg = native_payload if isinstance(native_payload, dict) else {}
        
        sender_id = str(msg.get("uidFrom", msg.get("userId", "")))
        thread_id = str(msg.get("idTo", msg.get("toid", sender_id)))
        content = msg.get("content", "")
        attachments = msg.get("attachments", [])
        
        is_group = msg.get("isGroup", False)
        thread_type = ThreadType.GROUP if is_group else ThreadType.USER
        
        return self._build_agent_request(
            sender_id=sender_id,
            thread_id=thread_id,
            thread_type=thread_type,
            content=content,
            attachments=attachments,
            msg=msg,
        )
    
    def to_handle_from_request(self, request: AgentRequest) -> str:
        """Get handle (thread_id) from request."""
        if request.channel_meta:
            return request.channel_meta.get("thread_id", request.user_id)
        return request.user_id
    
    async def send(
        self,
        to_handle: str,
        text: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Send text message."""
        if not self.http_api:
            logger.error("HTTP API not initialized")
            return
        
        thread_type = ThreadType.USER
        if meta:
            thread_type = ThreadType(meta.get("thread_type", 0))
        
        # Apply rate limiting
        async with self._send_lock:
            now = time.time()
            elapsed = now - self._last_send_time
            min_interval = 1.0 / self.max_send_rate
            
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            
            self._last_send_time = time.time()
        
        # Chunk long messages
        chunks = self._chunk_text(text, ZALO_TEXT_LIMIT)
        
        for chunk in chunks:
            result = await self.http_api.send_message(to_handle, chunk, thread_type)
            if not result.get("success"):
                logger.error(f"Failed to send message: {result.get('error')}")
    
    async def send_content_parts(
        self,
        to_handle: str,
        parts: List[OutgoingContentPart],
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Send content parts."""
        if not self.http_api:
            return
        
        thread_type = ThreadType.USER
        if meta:
            thread_type = ThreadType(meta.get("thread_type", 0))
        
        for part in parts:
            if hasattr(part, "type"):
                part_type = part.type
            else:
                part_type = getattr(part, "content_type", ContentType.TEXT)
            
            if part_type == ContentType.TEXT or part_type == "text":
                text = getattr(part, "text", str(part))
                await self.send(to_handle, text, meta)
            
            elif part_type == ContentType.IMAGE or part_type == "image":
                url = getattr(part, "url", "")
                caption = getattr(part, "text", "")
                if url:
                    await self.http_api.send_image(
                        to_handle, url, thread_type,
                        caption=caption if caption else None,
                    )
            
            elif part_type == ContentType.FILE or part_type == "file":
                url = getattr(part, "url", "")
                filename = getattr(part, "filename", "file")
                if url:
                    # Get file size if possible
                    file_size = 0
                    try:
                        async with self.session.head(url) as resp:
                            file_size = int(resp.headers.get("Content-Length", 0))
                    except (aiohttp.ClientError, ValueError):
                        pass
                    
                    await self.http_api.send_file(
                        to_handle, url, filename, file_size, thread_type,
                    )
    
    async def send_media(
        self,
        to_handle: str,
        part: OutgoingContentPart,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Send media content."""
        await self.send_content_parts(to_handle, [part], meta)
    
    def _chunk_text(self, text: str, limit: int) -> List[str]:
        """Chunk text into message-sized pieces."""
        if len(text) <= limit:
            return [text]
        
        chunks = []
        while text:
            chunk = text[:limit]
            text = text[limit:]
            chunks.append(chunk)
        
        return chunks
    
    def health_check(self) -> Dict[str, Any]:
        """Check channel health."""
        if not self.enabled:
            return {
                "channel": self.channel,
                "status": "disabled",
                "detail": "Zalo channel is disabled.",
            }
        
        if not self.credentials or not self.credentials.is_valid():
            return {
                "channel": self.channel,
                "status": "needs_auth",
                "detail": "No valid credentials. QR login required.",
            }
        
        if self.ws and self.ws.listening:
            return {
                "channel": self.channel,
                "status": "healthy",
                "detail": f"Connected as {self.credentials.user_id}",
                "user_id": self.credentials.user_id,
            }
        
        return {
            "channel": self.channel,
            "status": "connecting",
            "detail": "WebSocket connecting...",
        }
    
    @classmethod
    def doctor_connectivity_notes(
        cls,
        agent_id: str,
        config: Any,
        timeout: int = 30,
    ) -> Optional[str]:
        """Doctor connectivity notes."""
        return (
            "Zalo Personal Account Channel:\n"
            "- Requires QR login on first run\n"
            "- Credentials saved to ~/.qwenpaw/zalouser/credentials.json\n"
            "- Uses WebSocket for real-time messages\n"
            "- Uses HTTP API for sending messages\n"
        )