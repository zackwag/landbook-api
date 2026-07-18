# landbook-api

Unofficial Python client for the Landbook smart home cloud API (Netprisma/Landecia), reverse-engineered from the Landbook iOS app. Covers:

- **REST**: email/password login, token refresh, device discovery, TSL (Thing Specification Language) model fetch, device attribute reads.
- **MQTT**: a persistent WebSocket/TLS pub-sub connection for real-time device control and state (`LandbookMQTTClient`).

This library powers the [landbook-ha](https://github.com/zackwag/landbook-ha) Home Assistant integration, but has no dependency on Home Assistant and can be used standalone.

## Installation

```bash
pip install landbook-api
```

## Usage

```python
from landbook_api import login, get_device_list, get_tsl, LandbookMQTTClient

bearer_token, uid, refresh_token = login("you@example.com", "your-password", region="us")

devices = get_device_list(bearer_token, region="us")
pk = devices[0]["productKey"]
dk = devices[0]["deviceKey"]

properties = get_tsl(bearer_token, pk, region="us")

client = LandbookMQTTClient(uid, bearer_token)
client.connect()

def on_message(topic_suffix: str, payload: dict) -> None:
    print(topic_suffix, payload)

device_id = f"qd{pk}{dk}"
client.subscribe_device(device_id, on_message)
client.send_read(device_id, pk, dk, [p["code"] for p in properties])
```

Async equivalents (`async_login`, `async_get_device_list`, `async_get_tsl`, `async_refresh_token`, `async_get_device_attributes`) are also exported — each wraps the sync call in a thread executor.

## Supported Regions

| Region | API |
|--------|-----|
| United States | `iot-api.quectelus.com` |
| Europe | `iot-api.quecteleu.com` |
| China | `iot-gateway.quectel.com` |

Pass `region="us"`, `"eu"`, or `"cn"` to any call (defaults to `"us"`). EU and CN are untested — reports welcome via issues.

## Session Tokens

`login()` returns a `(bearer_token, uid, refresh_token)` tuple. The access token (`bearer_token`) is valid for 2 hours; the refresh token is valid for 30 days and must be used to obtain a new pair via `refresh_token()` before the access token expires. Both values should be persisted by the caller — this library does not manage token storage.

## Development

```bash
pip install -e ".[test]"
pytest
```

## Disclaimer

This is an unofficial, reverse-engineered client with no affiliation to Landbook, Netprisma, or Landecia. It may break if the upstream API changes.
