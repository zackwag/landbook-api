# Changelog

## [0.7.2](https://github.com/zackwag/landbook-api/compare/v0.7.1...v0.7.2) (2026-09-22)


### Bug Fixes

* detect data-plane stall when heartbeats stay alive but property pushes stop ([#30](https://github.com/zackwag/landbook-api/issues/30)) ([3eec3f6](https://github.com/zackwag/landbook-api/commit/3eec3f60591af5c80b524fc7148f7537e23d0074))

## [0.7.1](https://github.com/zackwag/landbook-api/compare/v0.7.0...v0.7.1) (2026-09-22)


### Bug Fixes

* split heartbeat start (28729) from periodic ping (28727) ([#28](https://github.com/zackwag/landbook-api/issues/28)) ([45b1321](https://github.com/zackwag/landbook-api/commit/45b1321e20744bf3fef20f9ba2b7307676f04d8d))

## [0.7.0](https://github.com/zackwag/landbook-api/compare/v0.6.0...v0.7.0) (2026-09-22)


### Features

* detect heartbeat pong timeout and fire on_disconnect ([#26](https://github.com/zackwag/landbook-api/issues/26)) ([4d12b61](https://github.com/zackwag/landbook-api/commit/4d12b61ecdbe3c1dc44f14be15e81a39db85fe4d))

## [0.6.0](https://github.com/zackwag/landbook-api/compare/v0.5.0...v0.6.0) (2026-09-19)


### Features

* add on_disconnect callback and is_connected to LandbookLocalClient ([#24](https://github.com/zackwag/landbook-api/issues/24)) ([ef0d7f8](https://github.com/zackwag/landbook-api/commit/ef0d7f828d2ec72e3825d2d8a5c548674607b3b2))

## [0.5.0](https://github.com/zackwag/landbook-api/compare/v0.4.2...v0.5.0) (2026-09-19)


### Features

* add local-LAN device control as an alternative to cloud MQTT ([#21](https://github.com/zackwag/landbook-api/issues/21)) ([e02b465](https://github.com/zackwag/landbook-api/commit/e02b46557ee787401e99b677240247e0f854e823))

## [0.4.2](https://github.com/zackwag/landbook-api/compare/v0.4.1...v0.4.2) (2026-09-18)


### Bug Fixes

* suppress duplicate reconnect from watchdog-triggered reconnect() ([#19](https://github.com/zackwag/landbook-api/issues/19)) ([65d9ce3](https://github.com/zackwag/landbook-api/commit/65d9ce3312d69e03524c8c28181a0d7266766d44))

## [0.4.1](https://github.com/zackwag/landbook-api/compare/v0.4.0...v0.4.1) (2026-09-17)


### Bug Fixes

* seed msgId counter from wall-clock time, not a fixed value ([#17](https://github.com/zackwag/landbook-api/issues/17)) ([2c5e40c](https://github.com/zackwag/landbook-api/commit/2c5e40ce1e8eb8429ecbe1ae763a0baf2d04ef19))

## [0.4.0](https://github.com/zackwag/landbook-api/compare/v0.3.1...v0.4.0) (2026-09-17)


### Features

* **ci:** add ruff lint + format check ([#15](https://github.com/zackwag/landbook-api/issues/15)) ([168ab6d](https://github.com/zackwag/landbook-api/commit/168ab6d93722030c10d7cd50aff52566fd7a3ccd))

## [0.3.1](https://github.com/zackwag/landbook-api/compare/v0.3.0...v0.3.1) (2026-09-17)


### Bug Fixes

* **ci:** use RELEASE_PLEASE_TOKEN so releases trigger downstream workflows ([#13](https://github.com/zackwag/landbook-api/issues/13)) ([727818b](https://github.com/zackwag/landbook-api/commit/727818b6c5406007a921a38e8b049f8387620a62))

## [0.3.0](https://github.com/zackwag/landbook-api/compare/v0.2.0...v0.3.0) (2026-09-17)


### Features

* **ci:** adopt release-please ([#11](https://github.com/zackwag/landbook-api/issues/11)) ([b86ffa3](https://github.com/zackwag/landbook-api/commit/b86ffa3acda07e1a603ba0a528ffbeb67679fb89))

## [0.2.0] - 2026-09-17

- `LandbookMQTTClient.connect()` now tears down the half-started paho loop before raising `ConnectionError` on a connect timeout, instead of leaking a background thread that keeps retrying with a stale token.
- `send_write()` no longer raises `ConnectionError` when the broker connection is momentarily down (e.g. during the periodic token-rotation reconnect); the write is queued and replayed in order once the connection is re-established, and dropped if it's still queued after `WRITE_RETRY_WINDOW` (5s).
- Added `reconnect()`: tears down and re-establishes the connection from scratch, for a caller that has independently determined the link is silently dead (the broker can drop the WebSocket without paho ever calling `on_disconnect`).

## [0.1.0] - 2026-07-18

- Initial release, extracted from the [landbook-ha](https://github.com/zackwag/landbook-ha) Home Assistant integration (`api.py` and `mqtt_client.py`, previously bundled with the integration code).
