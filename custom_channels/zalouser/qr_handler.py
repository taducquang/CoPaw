"""Zalo QR Code Authentication Handler for custom channel.

This handler is registered dynamically via register_app_routes in __init__.py.
"""

from __future__ import annotations

import httpx
from fastapi import HTTPException, Request

# Import base classes from core
from qwenpaw.app.channels.qrcode_auth_handler import (
    QRCodeAuthHandler,
    QRCodeResult,
    PollResult,
)

_ZALO_ID_ORIGIN = "https://id.zalo.me"
_ZALO_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


class ZaloUserQRCodeAuthHandler(QRCodeAuthHandler):
    """QR code auth handler for Zalo personal account login.

    Flow:
    1. POST /account/authen/qr/generate → QR code + token
    2. Poll /account/authen/qr/waiting-scan until scanned
    3. Poll /account/authen/qr/waiting-confirm until confirmed
    4. GET /jr/userinfo → user_id, cookies, secret_key
    """

    async def fetch_qrcode(self, request: Request) -> QRCodeResult:
        headers = {
            "User-Agent": _ZALO_USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://id.zalo.me",
            "Referer": "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.6,en;q=0.5",
        }

        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                # Initial session setup
                await client.get(
                    f"{_ZALO_ID_ORIGIN}/account?continue=https%3A%2F%2Fchat.zalo.me%2F",
                    headers=headers,
                )

                # Generate QR code
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
                raise HTTPException(
                    status_code=502,
                    detail="Zalo returned empty QR code",
                )

            # Extract base64 image
            if image_b64.startswith("data:image/png;base64,"):
                image_b64 = image_b64[22:]

            # Return base64 image as scan_url (frontend displays directly)
            return QRCodeResult(scan_url=image_b64, poll_token=code)

        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Zalo QR code fetch failed: {exc}",
            ) from exc

    async def poll_status(self, token: str, request: Request) -> PollResult:
        headers = {
            "User-Agent": _ZALO_USER_AGENT,
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://id.zalo.me",
            "Referer": "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F",
        }

        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                # First check if scanned
                scan_resp = await client.post(
                    f"{_ZALO_ID_ORIGIN}/account/authen/qr/waiting-scan",
                    headers=headers,
                    data={
                        "code": token,
                        "continue": "https://chat.zalo.me/",
                        "v": "5.5.7",
                    },
                )
                scan_data = scan_resp.json()

                scan_error = scan_data.get("error_code", -1)
                if scan_error == 1:
                    # Not scanned yet
                    return PollResult(status="waiting", credentials={})
                elif scan_error != 0:
                    return PollResult(status="expired", credentials={})

                # Scanned, now check confirmation
                confirm_resp = await client.post(
                    f"{_ZALO_ID_ORIGIN}/account/authen/qr/waiting-confirm",
                    headers=headers,
                    data={
                        "code": token,
                        "gToken": "",
                        "gAction": "CONFIRM_QR",
                        "continue": "https://chat.zalo.me/index.html",
                        "v": "5.5.7",
                    },
                )
                confirm_data = confirm_resp.json()

                confirm_error = confirm_data.get("error_code", -1)
                if confirm_error != 0:
                    # Not confirmed yet, but scanned
                    return PollResult(status="scanned", credentials={})

                # Confirmed! Get user info
                cookies = {}
                for cookie in client.cookies.jar:
                    if cookie.value:
                        cookies[cookie.name] = cookie.value

                userinfo_resp = await client.get(
                    "https://jr.chat.zalo.me/jr/userinfo",
                    headers={
                        "User-Agent": _ZALO_USER_AGENT,
                        "Accept": "*/*",
                        "Referer": "https://chat.zalo.me/",
                    },
                )
                userinfo_data = userinfo_resp.json()

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

        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Zalo status check failed: {exc}",
            ) from exc