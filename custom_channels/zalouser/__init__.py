# -*- coding: utf-8 -*-
"""Zalo Personal Channel for QwenPaw.

Pure Python implementation using aiohttp for WebSocket/HTTP communication.
"""
from .channel import ZaloUserChannel

__all__ = ["ZaloUserChannel"]


def register_app_routes(app) -> None:
    """Register custom routes and handlers for Zalo channel.

    This hook is called by register_custom_channel_routes in registry.py.
    We use it to register our QR code auth handler with the core registry.
    """
    # Import the core registry and add our handler
    # This works because handlers are looked up at request time, not at route registration time
    try:
        from qwenpaw.app.channels.qrcode_auth_handler import QRCODE_AUTH_HANDLERS
        from .qr_handler import ZaloUserQRCodeAuthHandler

        # Register our handler if not already registered
        if "zalouser" not in QRCODE_AUTH_HANDLERS:
            QRCODE_AUTH_HANDLERS["zalouser"] = ZaloUserQRCodeAuthHandler()
    except ImportError as e:
        # Log warning but don't fail - core module might not be available in some contexts
        import logging
        logging.getLogger(__name__).warning(
            f"Failed to register Zalo QR handler: {e}"
        )