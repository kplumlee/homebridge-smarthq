# Fork Notes

This is a fork of [homebridge-plugins/homebridge-smarthq](https://github.com/homebridge-plugins/homebridge-smarthq) with reliability improvements.

## Changes from upstream

### OAuth Authentication (`getAccessToken.ts`)
- Increased auth timeout from default to 15s (fixes DNS timeout failures in Docker)
- Added application authorization flow (handled by Python SDK but missing from upstream)
- Extracts actual GE error messages (e.g. "Invalid Credentials") instead of generic failures
- Validates login form exists before submitting
- Redirect depth limit prevents infinite loops

### Websocket Connection (`platform.ts`)
- Auto-reconnects on disconnect with exponential backoff (up to 10 attempts, 1s to 60s delay)
- Keepalive interval is properly cleaned up on disconnect (fixes memory leak)
- Token refresh timers stored and cleaned up on shutdown
- Safe JSON.parse in message handler (malformed messages no longer crash the handler)
- Validates message structure before accessing nested properties
- Checks `ws.OPEN` before sending keepalive pings
- Shutdown handler cleans up all resources (websocket, timers, intervals)

### Device Improvements
- All `readErd`/`writeErd` API calls have 10s timeout (prevents hanging requests)
- Refrigerator temperature values clamped to HomeKit's valid range (-270 to 100C)

## License

Same as upstream. Original work by [donavanbecker](https://github.com/donavanbecker).
