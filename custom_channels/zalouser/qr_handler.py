"""Zalo QR Code Authentication Handler for custom channel.

Stores session cookies from QR generation to reuse during polling.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Request

from qwenpaw.app.channels.qrcode_auth_handler import (
    QRCodeAuthHandler,
    QRCodeResult,
    PollResult,
)

logger = logging.getLogger(__name__)

_ZALO_ID_ORIGIN = "https://id.zalo.me"
_ZALO_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Per-code cache: QR image, cookies, headers
_zalo_qr_cache: dict[str, dict] = {}


def get_cached_qr_image(code: str) -> Optional[str]:
    """Get cached Zalo QR image."""
    entry = _zalo_qr_cache.get(code)
    return entry.get("image") if entry else None


class ZaloUserQRCodeAuthHandler(QRCodeAuthHandler):
    """QR code auth handler for Zalo personal account login."""

    async def fetch_qrcode(self, request: Request) -> QRCodeResult:
        headers = {
            "User-Agent": _ZALO_USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://id.zalo.me",
            "Referer": "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.6,en;q=0.5",
        }

        client = httpx.AsyncClient(timeout=15, follow_redirects=True, http2=True)
        try:
            await client.get(
                f"{_ZALO_ID_ORIGIN}/account?continue=https%3A%2F%2Fchat.zalo.me%2F",
                headers=headers,
            )
            resp = await client.post(
                f"{_ZALO_ID_ORIGIN}/account/authen/qr/generate",
                headers=headers,
                data={"continue": "https://zalo.me/pc", "v": "5.5.7"},
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get("error_code") != 0:
                raise HTTPException(
                    status_code=502,
                    detail=f"Zalo QR generate failed: {data.get('error_message')}",
                )

            payload = data.get("data", {})
            code = payload.get("code", "")
            image_b64 = payload.get("image", "")

            if not code:
                raise HTTPException(status_code=502, detail="Zalo returned empty QR code")

            if image_b64.startswith("data:image/png;base64,"):
                image_b64 = image_b64[22:]

            # Cache QR image + session cookies for polling
            _zalo_qr_cache[code] = {
                "image": image_b64,
                "cookies": dict(client.cookies),
                "headers": headers,
            }

            return QRCodeResult(
                scan_url=f"https://qr.zalo.me/code={code}",
                poll_token=code,
            )
        finally:
            await client.aclose()

    async def poll_status(self, token: str, request: Request) -> PollResult:
        cache_entry = _zalo_qr_cache.get(token)
        if not cache_entry:
            return PollResult(status="expired", credentials={})

        cached_cookies = cache_entry.get("cookies", {})
        headers = cache_entry.get("headers", {}).copy()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        client = httpx.AsyncClient(timeout=15, follow_redirects=True, http2=True, cookies=cached_cookies)
        try:
            # Step 1: Check if scanned
            scan_resp = await client.post(
                f"{_ZALO_ID_ORIGIN}/account/authen/qr/waiting-scan",
                headers=headers,
                data={"code": token, "continue": "https://chat.zalo.me/", "v": "5.5.7"},
            )
            scan_data = scan_resp.json()
            scan_error = scan_data.get("error_code", -1)

            if scan_error == 1:
                return PollResult(status="waiting", credentials={})
            elif scan_error != 0:
                _zalo_qr_cache.pop(token, None)
                return PollResult(status="expired", credentials={})

            # Step 2: Check if confirmed
            confirm_resp = await client.post(
                f"{_ZALO_ID_ORIGIN}/account/authen/qr/waiting-confirm",
                headers=headers,
                data={"code": token, "gToken": "", "gAction": "CONFIRM_QR", "continue": "https://chat.zalo.me/index.html", "v": "5.5.7"},
            )
            confirm_data = confirm_resp.json()
            confirm_error = confirm_data.get("error_code", -1)

            if confirm_error == 0:
                cookies = {name: value for name, value in client.cookies.items() if value}
                userinfo_resp = await client.get(
                    "https://jr.chat.zalo.me/jr/userinfo",
                    headers={"User-Agent": _ZALO_USER_AGENT, "Accept": "*/*", "Referer": "https://chat.zalo.me/"},
                )
                userinfo_data = userinfo_resp.json()
                _zalo_qr_cache.pop(token, None)
                return PollResult(
                    status="success",
                    credentials={
                        "cookies": cookies,
                        "user_id": userinfo_data.get("userId", ""),
                        "phone_number": userinfo_data.get("phoneNumber", ""),
                        "zpw_enk": userinfo_data.get("zpw_enk", ""),
                        "zpw_ws": userinfo_data.get("zpw_ws", []),
                    },
                )
            elif confirm_error == 1:
                return PollResult(status="scanned", credentials={})
            else:
                _zalo_qr_cache.pop(token, None)
                return PollResult(status="expired", credentials={})
        except Exception as exc:
            logger.warning(f"Zalo poll error: {exc}")
            return PollResult(status="waiting", credentials={})
        finally:
            await client.aclose()


def create_qr_router() -> APIRouter:
    """Create custom QR image endpoint."""
    router = APIRouter()

    @router.get("/config/channels/zalouser/qrcode-image")
    async def get_zalo_qr_direct():
        handler = ZaloUserQRCodeAuthHandler()
        request = Request(scope={"type": "http", "method": "GET", "path": "", "headers": [], "query_string": b""})
        result = await handler.fetch_qrcode(request)
        qr_img = get_cached_qr_image(result.poll_token) or ""
        return {"qrcode_img": qr_img, "poll_token": result.poll_token}

    return router