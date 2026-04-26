# Zalo Personal Channel for QwenPaw

Connects QwenPaw to a personal Zalo account using pure Python (no Node.js required).

**WARNING:** This is an unofficial integration using reverse-engineered API.
Using Zalo automation may result in account suspension or ban. Use at your own risk.

## Requirements

- Python 3.10+
- aiohttp (already included in QwenPaw dependencies)
- cryptography (for AES encryption/decryption)

**No Node.js required** - pure Python implementation.

## Setup

### Step 1: Install Dependencies

```bash
pip install cryptography
```

### Step 2: Enable the Channel

Add to your QwenPaw config (`~/.qwenpaw/config.json`):

```json
{
  "channels": {
    "zalouser": {
      "enabled": true,
      "state_dir": "~/.qwenpaw/zalouser",
      "show_typing": true,
      "dm_policy": "open",
      "group_policy": "open"
    }
  }
}
```

Or use environment variables:

```bash
ZALOUSER_CHANNEL_ENABLED=1
```

### Step 3: Start QwenPaw

```bash
qwenpaw app
```

### Step 4: QR Code Login (First Time)

On first start without saved credentials, the channel generates a QR code.

**How to get QR code image:**

1. **Find the QR code image** saved at:
   - Windows: `%USERPROFILE%\.qwenpaw\zalouser\qr_login.png`
   - macOS/Linux: `~/.qwenpaw/zalouser/qr_login.png`

2. **Open the image** with any image viewer

3. **Open Zalo on your phone**

4. **Scan the QR code**:
   - Tap **Settings -> Zalo Web** (or QR scan feature)
   - Scan the QR image
   - Confirm login on your phone

5. **Done** - credentials auto-saved to `~/.qwenpaw/zalouser/credentials.json`

After successful login, the channel automatically starts receiving messages.

## Configuration

Per-channel config options (in `channels.zalouser`):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable the channel |
| `state_dir` | string | `~/.qwenpaw/zalouser` | Credential storage path |
| `bot_prefix` | string | `""` | Prefix for bot replies |
| `show_typing` | bool | `true` | Show typing indicators |
| `filter_tool_messages` | bool | `false` | Hide tool execution messages |
| `filter_thinking` | bool | `false` | Hide model thinking/reasoning |
| `dm_policy` | string | `"open"` | DM access: `"open"`, `"restricted"`, `"blocked"` |
| `group_policy` | string | `"open"` | Group access: `"open"`, `"restricted"`, `"blocked"` |
| `allow_from` | list | `[]` | Allowed sender IDs (for restricted policy) |
| `deny_message` | string | `""` | Message for blocked users |
| `require_mention` | bool | `false` | Require @mention in groups |
| `max_send_rate` | int | `5` | Max messages/second (rate limiting) |
| `health_check_interval` | int | `30` | Health check interval in seconds |
| `max_restart_attempts` | int | `3` | Max crash recovery attempts |

> **Note**: `show_tool_details` is a **global** config option (not per-channel). Set it at the root level of `config.json` to control tool detail visibility across all channels.

## Environment Variables

| Variable | Maps To |
|----------|---------|
| `ZALOUSER_CHANNEL_ENABLED` | `enabled` |
| `ZALOUSER_STATE_DIR` | `state_dir` |
| `ZALOUSER_BOT_PREFIX` | `bot_prefix` |
| `ZALOUSER_SHOW_TYPING` | `show_typing` |

## Architecture

Pure Python - no Node.js bridge:

```
QwenPaw (Python)
    |
    v
ZaloUserChannel (BaseChannel subclass)
    | aiohttp WebSocket/HTTP
    v
Zalo Servers (chat.zalo.me, id.zalo.me)
```

### Components

| Component | Purpose |
|-----------|---------|
| `ZaloCredentials` | Cookie/IMEI storage, load/save |
| `ZaloCrypto` | AES-CBC encode/decode, WebSocket packet decryption |
| `ZaloQRAuth` | QR code generation and login flow |
| `ZaloWebSocket` | Real-time message listener (binary protocol) |
| `ZaloHTTPAPI` | Send messages, images, files via HTTP |
| `ZaloUserChannel` | BaseChannel subclass integrating all components |

## Features

- **Text messages** - DM & group with 2000-char chunking
- **Media support** - Images, files, videos
- **Typing indicators** - Show typing while processing
- **Access control** - DM/group policies, allowlist
- **@mention detection** - Optional requirement in groups
- **Auto-reconnect** - WebSocket reconnects on disconnect
- **Crash recovery** - Configurable restart attempts

## Protocol Details

### WebSocket Message Types

| cmd | subCmd | Description |
|-----|--------|-------------|
| 1 | 1 | Key exchange (sets ws_key) |
| 501 | 0 | Direct messages |
| 521 | 0 | Group messages |
| 601 | 0 | Group events (join, leave, etc.) |
| 612 | 0 | Reactions |
| 3000 | 0 | Another connection opened |

### Encryption

- **HTTP API**: AES-128-CBC with zero IV, PKCS7 padding, base64 key
- **WebSocket (encrypt=2)**: AES-GCM + gzip compression

## Security

- Credentials stored at `{state_dir}/credentials.json`
- **Do not commit to version control**
- Session cookies expire - re-login may be required periodically

## Troubleshooting

### "No WebSocket URLs available"

Credentials may be expired. Delete `credentials.json` and re-login with QR code.

### "Failed to decode packet"

WebSocket encryption key not received. Wait for key exchange message.

### "Failed to send message"

Rate limiting or invalid thread_id. Check `max_send_rate` config.