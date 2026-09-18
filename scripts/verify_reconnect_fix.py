#!/usr/bin/env python3
"""Standalone repro/verification for the ghost-session reconnect bug
(landbook-ha#27).

No network, broker, or Landbook account needed — paho's mqtt.Client is
mocked out, and a fake on_disconnect firing during LandbookMQTTClient
.reconnect()'s teardown simulates what paho actually does: invoke the old
client's on_disconnect callback (sometimes inline from disconnect(),
sometimes shortly after from the network thread) when a connection is torn
down.

Bug: reconnect() used to set `_shutting_down = False` *before* tearing down
the old client. That old client's on_disconnect then saw an "unexpected"
disconnect and scheduled its own reconnect 5s later — on top of the
reconnect reconnect() already performs synchronously. Two live MQTT
sessions for one account followed, each with its own msgId range, and the
Landbook cloud rejects every command as a collision (SENDACK status:'fail').

Run:
    python scripts/verify_reconnect_fix.py

Exits 0 and prints PASS if only one new session is ever established;
exits 1 and prints FAIL (reproducing the original bug) otherwise.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from landbook_api.mqtt_client import LandbookMQTTClient


def main() -> int:
    client = LandbookMQTTClient(uid="u1", bearer_token="Bearer tok")

    old_mqtt = MagicMock(name="old_paho_client")
    client._client = old_mqtt
    client._connected = True

    # Simulate paho invoking on_disconnect for the client being torn down —
    # this is what a real broker/paho does when disconnect() is called.
    def fake_old_client_disconnect():
        client._on_disconnect(None, None, None, 1, None)

    old_mqtt.disconnect.side_effect = fake_old_client_disconnect

    connect_calls = []
    scheduled_reconnects = []

    with (
        patch.object(LandbookMQTTClient, "connect", side_effect=lambda: connect_calls.append(1)),
        patch.object(
            LandbookMQTTClient,
            "_schedule_reconnect",
            side_effect=lambda delay=5: scheduled_reconnects.append(delay),
        ),
    ):
        # This is exactly what landbook-ha's watchdog calls every ~5-6 min
        # when it decides the link is silently dead.
        client.reconnect()

    print(f"connect() calls from reconnect(): {len(connect_calls)}")
    print(
        f"duplicate reconnects scheduled by the old client's on_disconnect: {len(scheduled_reconnects)}"
    )
    print(f"_shutting_down restored to False after reconnect(): {client._shutting_down is False}")

    ok = (
        len(connect_calls) == 1
        and len(scheduled_reconnects) == 0
        and client._shutting_down is False
    )

    if ok:
        print(
            "\nPASS — reconnect() established exactly one new session, no ghost reconnect scheduled."
        )
        return 0

    print(
        "\nFAIL — reconnect()'s teardown caused a duplicate reconnect to be scheduled "
        "(the landbook-ha#27 ghost-session bug). Two live MQTT sessions for the same "
        "account would result, with colliding msgIds and every command rejected as "
        "SENDACK status:'fail'."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
