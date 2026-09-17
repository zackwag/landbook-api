# Contributing to landbook-api

## What lives here vs. in landbook-ha

This repo is a standalone Python client for the Landbook cloud (REST auth
and device discovery, plus `LandbookMQTTClient` for the MQTT pub/sub
connection). It has **no dependency on Home Assistant** and must not gain
one — no `homeassistant` imports, no config-entry or entity concepts.

Anything about *talking to the Landbook cloud* belongs here: auth flow,
request/response shapes, MQTT wire format, connection and reconnection
behavior, retry/timeout semantics. Anything about *how Home Assistant uses
this client* — config flow, options, entities, HA timers/scheduling — belongs
in [landbook-ha](https://github.com/zackwag/landbook-ha) instead. See that
repo's `CONTRIBUTING.md` and `AGENTS.md` for the other half of this split.

A concrete rule of thumb: if a fix would make sense for any caller of this
library, not just the HA integration, it belongs here.

## Local development

```bash
pip install -e ".[test]"
pytest
```

## Tests

`tests/test_api.py` and `tests/test_mqtt.py` are organized as `TestXxx`
classes grouped by method/behavior, mocking at the boundary
(`urllib.request.urlopen` for REST, `paho.mqtt.client.Client` for MQTT)
rather than mocking this library's own methods. Follow that pattern for new
tests, and add coverage in this repo for anything that's genuine client
behavior — connection resilience, retry/deferral logic, protocol
correctness — rather than leaving it to be exercised indirectly through
landbook-ha's (fully-mocked) integration tests.

Run the full suite before opening a PR:

```bash
pytest
```

CI (`.github/workflows/test.yml`) runs this on every PR and push to `main`
across Python 3.10–3.13.

## Versioning and releases

Bump `version` in `pyproject.toml` and add a matching `## [X.Y.Z] -
YYYY-MM-DD` entry to `CHANGELOG.md` in the same PR as the behavior change —
the release workflow extracts that section verbatim as both the PyPI
description context and the GitHub Release body.

A merged PR does not reach PyPI (or landbook-ha, which pins a
`landbook-api>=X.Y.Z` version) by itself. Pushing a `vX.Y.Z` git tag on
`main` triggers `.github/workflows/release.yml`, which runs tests, builds,
publishes to PyPI, and creates the GitHub Release. If landbook-ha is
waiting on your change, it isn't consumable there until this tag is pushed
*and* landbook-ha's `requirements` pin is bumped to match.
