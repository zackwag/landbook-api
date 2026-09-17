# Changelog

## [0.2.0] - 2026-09-17

- `LandbookMQTTClient.connect()` now tears down the half-started paho loop before raising `ConnectionError` on a connect timeout, instead of leaking a background thread that keeps retrying with a stale token.
- `send_write()` no longer raises `ConnectionError` when the broker connection is momentarily down (e.g. during the periodic token-rotation reconnect); the write is queued and replayed in order once the connection is re-established, and dropped if it's still queued after `WRITE_RETRY_WINDOW` (5s).
- Added `reconnect()`: tears down and re-establishes the connection from scratch, for a caller that has independently determined the link is silently dead (the broker can drop the WebSocket without paho ever calling `on_disconnect`).

## [0.1.0] - 2026-07-18

- Initial release, extracted from the [landbook-ha](https://github.com/zackwag/landbook-ha) Home Assistant integration (`api.py` and `mqtt_client.py`, previously bundled with the integration code).
