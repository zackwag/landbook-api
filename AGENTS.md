# Agent instructions for landbook-api

## Honor the API/HA split

This repo is a standalone client for the Landbook cloud API — REST auth and
device discovery (`landbook_api/api.py`) and the MQTT pub/sub connection
(`landbook_api/mqtt_client.py`, `LandbookMQTTClient`). It has **no
dependency on Home Assistant** and must never acquire one: no
`homeassistant` imports, no config-entry/entity/options concepts, nothing
that assumes a specific caller.

Everything about *talking to the Landbook cloud* belongs here: auth,
request/response parsing, MQTT wire format, connection lifecycle,
reconnection behavior, retry and timeout semantics. Everything about *how
Home Assistant uses this client* — config flow, options, entities, HA
timers/scheduling — belongs in
[landbook-ha](https://github.com/zackwag/landbook-ha) instead.

If you're asked to fix something and the fix would make sense for any
caller of `LandbookMQTTClient`/`api.py` — not specifically because it's
Home Assistant — implement it here, as a first-class method on the
client/API surface, not as something a consumer has to subclass or work
around.

### Worked example (why this rule exists)

landbook-ha previously worked around two client limitations by subclassing
`LandbookMQTTClient` inside the integration: queuing writes across a brief
disconnect, and forcing a reconnect by directly manipulating the parent
class's private locks and connection state (`_wire_lock`, `_client`,
`_connected`, `_reconnect_timer`). Neither concern had anything to do with
Home Assistant, so both moved here (see the `0.2.0` entry in
`CHANGELOG.md` and PR #9): `send_write` now defers and replays writes
itself, and a public `reconnect()` method exists for a caller that has
independently determined the connection is dead. landbook-ha now calls
these directly instead of reimplementing them.

## Testing

- `tests/test_mqtt.py` and `tests/test_api.py` mock at the transport
  boundary (`paho.mqtt.client.Client`, `urllib.request.urlopen`), not this
  library's own internals — new tests should do the same so they exercise
  real code paths.
- Add or extend tests for any behavior change here, even if the immediate
  motivation was a landbook-ha issue — landbook-ha's test suite mocks this
  client entirely, so this is the only place that behavior gets exercised.
- Run `pytest` before considering a change complete.

## Releases

A merged PR isn't consumable by landbook-ha until it's released: bump
`pyproject.toml`'s `version`, add a `CHANGELOG.md` entry, then push a
`vX.Y.Z` tag to trigger the publish workflow. See CONTRIBUTING.md for the
full sequence, and flag in your PR description if landbook-ha needs a
corresponding `requirements` bump once the release goes out.
