# Contributing to landbook-api

## What lives here vs. in landbook-ha

This repo is a standalone Python client for Landbook devices: REST auth and
device discovery, `LandbookMQTTClient` for the cloud MQTT pub/sub
connection, and `LandbookLocalClient` for direct local-LAN control. It has **no dependency on Home Assistant** and must not gain
one — no `homeassistant` imports, no config-entry or entity concepts.

Anything about *talking to the Landbook cloud or devices* belongs here: auth
flow, request/response shapes, MQTT and local wire formats, connection and reconnection
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

Tests are organized as `TestXxx` classes grouped by behavior, mocking at the
transport boundary rather than this library's own methods or attributes:
`urllib.request.urlopen` for REST, `paho.mqtt.client.Client` for MQTT (the
`Broker` fake in `tests/test_mqtt.py`), and the socket for local control
(`FakeDevice` for TCP, which answers the login handshake like real hardware,
and `TestDiscovery.FakeUDP` for discovery, both in
`tests/test_local_client.py`). Follow that pattern for new
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

Releases are cut by [release-please](https://github.com/googleapis/release-please). Don't hand-edit `version` in `pyproject.toml`, `__version__` in `landbook_api/__init__.py`, or `CHANGELOG.md`.

PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/) (enforced in CI) because the squash-merge commit drives the release: `feat:` bumps the minor version, `!` marks a breaking change, and `fix:`, `perf:`, `refactor:`, `revert:` and `chore:` all cut a patch release (see `release-please-config.json`). Only `docs:`, `ci:`, `test:` and `build:` merge without releasing. Merging to `main` opens or updates a `chore(main): release X.Y.Z` PR; merging that PR tags `vX.Y.Z`, which triggers `.github/workflows/release.yml` to run the tests, build, and publish to PyPI.

A release reaches landbook-ha users only when landbook-ha bumps the `landbook-api` pin in its `manifest.json`, because Home Assistant skips installing a requirement that the installed version already satisfies. If landbook-ha needs your change, bump that pin once the release is out.
