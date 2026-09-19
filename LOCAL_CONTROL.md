# Local-LAN control

An alternative to the cloud MQTT channel (`LandbookMQTTClient`, see the main [README](README.md)): instead of round-tripping through the cloud, `discover_devices()` and `LandbookLocalClient` (in `landbook_api/local_client.py`) talk to a device directly over the local network, using a binary TCP protocol reverse-engineered from the Landbook app's Quectel IoT SDK.

This exists because the app's own "Auto" control mode **prefers local control over cloud MQTT** whenever it can reach a device's LAN IP — cloud MQTT is only a fallback for when it can't. That has a real consequence: if the cloud channel is degraded (see [landbook-ha#27](https://github.com/zackwag/landbook-ha/issues/27)), the app may never notice, because it's simply not exercising that path while your phone is on the same network as the device. `landbook-ha` runs inside Home Assistant, which is typically on that same network — so local control is usually the better default there too.

## Protocol flow

```mermaid
sequenceDiagram
    participant App as landbook_api
    participant LAN as LAN (UDP 6606)
    participant Dev as Device (TCP)

    App->>LAN: broadcast discovery probe (cmd 28720)
    LAN-->>App: reply: productKey, deviceKey, ip, port (cmd 28721)

    App->>Dev: TCP connect to ip:port
    App->>Dev: request random challenge (cmd 28722)
    Dev-->>App: random challenge (cmd 28723)
    App->>Dev: login = SHA256(hex(authKey) + ";" + random) (cmd 28724)
    Dev-->>App: login result (cmd 28725)

    Note over App,Dev: AES/CBC session armed:<br/>key = raw-decoded authKey, iv = random challenge string

    App->>Dev: heartbeat (cmd 28729, encrypted)
    App->>Dev: write(property) (cmd 19, encrypted)
    Dev-->>App: write ack (cmd 28726, encrypted)
    Dev-->>App: status push (cmd 20, encrypted)
    Dev-->>App: status push (cmd 20, encrypted)
    Note right of Dev: keeps pushing one property<br/>at a time on its own schedule,<br/>independent of any request
```

Everything after the AES handshake — the heartbeat, writes, and every status push — is encrypted, so this diagram is as far as passive wire inspection gets you; the actual TTLV field contents only make sense once decrypted.

The byte-level details (frame layout, checksum, byte-stuffing, TTLV field encoding) are documented in `landbook_api/local_protocol.py`'s module docstring — that's the source of truth, not this file.

## Usage

```python
from landbook_api import login, get_device_list, get_tsl
from landbook_api.local_client import discover_devices, LandbookLocalClient
from landbook_api.local_protocol import field_for_property

bearer_token, uid, refresh_token = login("you@example.com", "your-password", region="us")
devices = get_device_list(bearer_token, region="us")
device = devices[0]
pk, dk, auth_key = device["productKey"], device["deviceKey"], device["authKey"]

found = discover_devices(timeout=5.0)
match = next(d for d in found if d.product_key == pk and d.device_key == dk)

client = LandbookLocalClient(pk, dk, auth_key, match.ip, match.port)
client.on_update = lambda fields: print("update:", fields)
client.on_disconnect = lambda: print("connection lost unexpectedly")
client.connect()  # raises ConnectionError on timeout or a rejected login

# TSL properties carry both a string `code` (used by the cloud MQTT/JSON
# protocol) and a numeric `id` (used here) for the same property.
properties = get_tsl(bearer_token, pk, region="us")
switch = next(p for p in properties if p["code"] == "switch")

client.write([field_for_property(switch["id"], switch["dataType"], True)])

values = client.read_and_wait([p["id"] for p in properties], timeout=10.0)
print(values)  # {property_id: value, ...} — partial if not everything arrived in time

client.disconnect()
```

`on_disconnect` fires only when the connection drops unexpectedly (a broken socket, or the device closing its end) — a caller-initiated `disconnect()` never triggers it. `client.is_connected` is the polling-style equivalent, for a periodic check rather than an event callback.

## Things learned from real hardware that aren't obvious from the protocol alone

Validated end-to-end against a real GE OmniBreeze fan (productKey `p11vkW`) — see [landbook-api#21](https://github.com/zackwag/landbook-api/pull/21) for the full writeup.

- **`read()` alone doesn't produce a direct reply.** The device just continuously pushes one property at a time on its own schedule, regardless of whether `read()` was ever called. Use `read_and_wait(ids, timeout)` instead — it sends the read request and blocks on a passively-maintained `properties` cache until the requested ids show up (or `timeout` elapses, returning whatever arrived rather than raising).
- **`dataType` on a real TSL property is a human-readable name** (`"BOOL"`, `"ENUM"`, `"INT"`, ...), not the short numeric-string code (`"1"`, `"5"`, `"2"`) the app's internal TTLV dispatch uses. `field_for_property()` accepts either form, case-insensitively — but if you're building `TTLVField`s by hand instead, don't assume the numeric form.
- **The write ack (`cmd=28726`) isn't property state.** Its payload doesn't mirror the value that was written — a bool write's ack came back with an unrelated numeric field reusing the same property id. It's deliberately excluded from the `properties` cache and surfaced separately via `on_write_ack`, so it can't silently corrupt cached state for that id.
- **A property's real constraints matter for writes.** `wind_speed`'s TSL `specs` gave a `min`/`max` of 1-5; `working_mode`'s `specs` gave four valid ENUM values (0-3). Writing outside a property's real range/enum is untested territory — resolve valid values from `get_tsl()`'s `specs` field rather than guessing.
- **A device still accepts and echoes writes while powered off**, it just doesn't visibly act on most of them (e.g. changing fan speed while the fan is off beeps and the new value reads back correctly, but nothing spins) — expected appliance behavior, not a protocol issue.
