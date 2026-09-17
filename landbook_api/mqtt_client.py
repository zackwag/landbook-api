"""Landbook MQTT client — WebSocket/TLS connection, pub/sub."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import paho.mqtt.client as mqtt

from .const import DEFAULT_REGION, MQTT_KEEPALIVE, MQTT_PORT, MQTT_WS_PATH, REGIONS

_LOGGER = logging.getLogger(__name__)

# How long a write that failed because the connection was momentarily down
# stays queued for replay on reconnect. Longer than the ~1-3s blip caused by
# a token-rotation reconnect, short enough that a tap during a genuine outage
# isn't silently applied minutes later.
WRITE_RETRY_WINDOW = 5.0  # seconds


class LandbookMQTTClient:
    """Manages a single persistent MQTT connection for one account."""

    def __init__(
        self,
        uid: str,
        bearer_token: str,
        mqtt_host: str | None = None,
        token_refresher: Callable[[], str] | None = None,
    ) -> None:
        self._uid = uid
        self._bearer_token = bearer_token
        self._mqtt_host = mqtt_host or REGIONS[DEFAULT_REGION]["mqtt_host"]
        self._token_refresher = token_refresher
        self._client: mqtt.Client | None = None
        self._connected = False
        self._shutting_down = False
        self._reauth_pending = False
        # Seeded from wall-clock time (mod 2**16) rather than a fixed low
        # value: a fresh client instance is created on every integration
        # reload/restart, and a fixed seed meant every such session replayed
        # the same ~1001-1018 msgId range. If the server dedups/rejects
        # recently-seen msgIds (independent of the underlying connection),
        # that guarantees collisions across sessions. Time-seeding makes
        # collisions between two sessions' id ranges unlikely without
        # requiring any persisted state.
        self._msg_counter = int(time.time() * 1000) & 0xFFFF
        self._reconnect_timer: threading.Timer | None = None
        # (deadline, device_id, pk, dk, props) for writes that hit a
        # disconnected client; replayed in order by _flush_deferred_writes
        # once the connection comes back.
        self._deferred_writes: list[tuple[float, str, str, str, dict]] = []

        # Serialize all wire operations. The same client instance is shared
        # across every device of one account (multiple concurrent publishers)
        # and is invoked both from the caller's thread and from paho's network
        # loop thread (_on_connect -> _on_reconnect). Concurrent publish()
        # calls race on paho's internal _sendbuffer and raise BufferError
        # ("Existing exports of data: object cannot be re-sized"), so every
        # socket op takes a per-instance lock. RLock because _subscribe_topics
        # is called both externally (via subscribe_device, already locked) and
        # internally from _on_connect on the network thread.
        self._wire_lock = threading.RLock()

        # device_id -> list of callbacks
        self._listeners: dict[str, list[Callable[[str, Any], None]]] = {}
        # called after (re)connect to refresh state
        self._on_reconnect: Callable[[], None] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Establish the WebSocket/TLS MQTT connection (blocking until connected or timeout)."""
        client_id = f"qu_{self._uid}_{int(time.time() * 1000)}"
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            transport="websockets",
            protocol=mqtt.MQTTv311,
        )
        client.ws_set_options(path=MQTT_WS_PATH)
        client.tls_set()
        client.username_pw_set("", self._bearer_token)
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.on_disconnect = self._on_disconnect

        client.connect(self._mqtt_host, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
        client.loop_start()
        self._client = client

        for _ in range(40):
            if self._connected:
                break
            time.sleep(0.25)

        if not self._connected:
            client.loop_stop()
            client.disconnect()
            self._client = None
            raise ConnectionError("MQTT connection timed out")

    def update_token(self, bearer_token: str) -> None:
        """Update the stored token (e.g. after a refresh)."""
        self._bearer_token = bearer_token

    def halt_reconnects(self) -> None:
        """Stop all reconnect attempts (e.g. while reauth is pending)."""
        self._reauth_pending = True
        if self._reconnect_timer:
            self._reconnect_timer.cancel()
            self._reconnect_timer = None

    def disconnect(self) -> None:
        with self._wire_lock:
            self._shutting_down = True
            if self._reconnect_timer:
                self._reconnect_timer.cancel()
                self._reconnect_timer = None
            if self._client:
                self._client.loop_stop()
                self._client.disconnect()
                self._client = None
            self._connected = False

    def reconnect(self) -> None:
        """Tear down and re-establish the connection from scratch.

        For a caller (e.g. a watchdog) that has independently determined the
        connection is silently dead — the broker can drop a WebSocket link
        mid-stream without paho ever calling on_disconnect, so keepalive
        alone doesn't catch it.
        """
        with self._wire_lock:
            self._shutting_down = False
            if self._reconnect_timer:
                self._reconnect_timer.cancel()
                self._reconnect_timer = None
            if self._client:
                self._client.loop_stop()
                self._client.disconnect()
                self._client = None
            self._connected = False
        self.connect()

    def subscribe_device(
        self,
        device_id: str,
        callback: Callable[[str, Any], None],
    ) -> None:
        """Subscribe to all topics for a device and register a callback.

        callback(topic_suffix, payload_dict)
        """
        with self._wire_lock:
            if device_id not in self._listeners:
                self._listeners[device_id] = []
                if self._client and self._connected:
                    self._subscribe_topics(device_id)

            self._listeners[device_id].append(callback)

    def send_read(self, device_id: str, pk: str, dk: str, codes: list[str]) -> None:
        """Request current values for the given property codes (READ-ATTR)."""
        with self._wire_lock:
            if not self._client or not self._connected:
                return
            self._msg_counter = (self._msg_counter + 1) & 0xFFFF
            payload = json.dumps(
                {
                    "msgId": self._msg_counter,
                    "productKey": pk,
                    "deviceKey": dk,
                    "type": "READ-ATTR",
                    "kv": json.dumps(codes),
                    "cacheTime": 0,
                    "isCache": False,
                    "isCover": False,
                }
            )
            self._client.publish(f"q/1/d/{device_id}/sys_", payload, qos=1)
            _LOGGER.debug("send_read device=%s codes=%s", device_id, codes)

    def send_write(self, device_id: str, pk: str, dk: str, props: dict) -> None:
        """Publish a WRITE-ATTR command.

        If the connection is momentarily down (e.g. the ~1-3s blip during a
        token-rotation reconnect), the write is queued instead of raising and
        is replayed in order once the connection comes back — see
        _flush_deferred_writes. A write still queued after WRITE_RETRY_WINDOW
        is dropped rather than applied late.
        """
        with self._wire_lock:
            if not self._client or not self._connected:
                self._deferred_writes.append(
                    (time.monotonic() + WRITE_RETRY_WINDOW, device_id, pk, dk, props)
                )
                _LOGGER.info(
                    "Landbook: write to %s deferred (MQTT down), will resend on reconnect", dk
                )
                return
            self._publish_write(device_id, pk, dk, props)

    def _publish_write(self, device_id: str, pk: str, dk: str, props: dict) -> None:
        assert self._client
        self._msg_counter = (self._msg_counter + 1) & 0xFFFF
        payload = json.dumps(
            {
                "msgId": self._msg_counter,
                "productKey": pk,
                "deviceKey": dk,
                "type": "WRITE-ATTR",
                "kv": json.dumps([props]),
                "cacheTime": 0,
                "isCache": False,
                "isCover": False,
            }
        )
        self._client.publish(f"q/1/d/{device_id}/sys_", payload, qos=1)
        _LOGGER.debug("send_write device=%s props=%s", device_id, props)

    def _flush_deferred_writes(self) -> None:
        now = time.monotonic()
        with self._wire_lock:
            idx = 0
            while idx < len(self._deferred_writes):
                deadline, device_id, pk, dk, props = self._deferred_writes[idx]
                if now > deadline:
                    _LOGGER.info(
                        "Landbook: dropping deferred write to %s (expired while disconnected)",
                        dk,
                    )
                    idx += 1
                    continue
                if not self._client or not self._connected:
                    break
                self._publish_write(device_id, pk, dk, props)
                idx += 1
            if idx:
                del self._deferred_writes[:idx]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _subscribe_topics(self, device_id: str) -> None:
        with self._wire_lock:
            assert self._client
            # Subscribe to all known downstream topics for this device
            for suffix in ("ack_", "bus_", "onl_", "ota_", "inf_", "loc_"):
                self._client.subscribe(f"q/2/d/{device_id}/{suffix}", qos=1)

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        if str(reason_code) in ("Success", "0") or reason_code == 0:
            self._connected = True
            for device_id in self._listeners:
                self._subscribe_topics(device_id)
            _LOGGER.info("Landbook MQTT connected")
            self._flush_deferred_writes()
            if self._on_reconnect:
                self._on_reconnect()
        else:
            _LOGGER.error("Landbook MQTT connect failed: %s", reason_code)

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        self._connected = False
        if self._shutting_down:
            _LOGGER.debug("Landbook MQTT disconnected cleanly (unload)")
            return
        if self._reauth_pending:
            _LOGGER.debug("Landbook MQTT disconnected while reauth pending — not reconnecting")
            return
        _LOGGER.warning("Landbook MQTT disconnected: %s — scheduling reconnect", reason_code)
        self._schedule_reconnect(delay=5)

    def _schedule_reconnect(self, delay: float = 5) -> None:
        if self._reconnect_timer:
            self._reconnect_timer.cancel()
        self._reconnect_timer = threading.Timer(delay, self._reconnect)
        self._reconnect_timer.daemon = True
        self._reconnect_timer.start()

    def _reconnect(self) -> None:
        if self._reauth_pending:
            return
        _LOGGER.info("Landbook MQTT attempting reconnect")
        try:
            if self._token_refresher:
                self._bearer_token = self._token_refresher()
                _LOGGER.debug("Token refreshed before reconnect")
        except Exception as exc:  # noqa: BLE001 - best-effort refresh, fall back to old token rather than abort the reconnect
            _LOGGER.warning("Token refresh failed, reconnecting with old token: %s", exc)
        if self._reauth_pending:
            return
        try:
            if self._client:
                self._client.loop_stop()
            self.connect()
        except Exception as exc:  # noqa: BLE001 - retry loop, must survive any connect failure
            _LOGGER.warning("Reconnect failed: %s — will retry in 30s", exc)
            self._schedule_reconnect(delay=30)

    def _on_message(self, client, userdata, msg: mqtt.MQTTMessage) -> None:
        parts = msg.topic.split("/")
        # topic format: q/2/d/{device_id}/{suffix}
        if len(parts) < 5:
            return
        device_id = parts[3]
        suffix = parts[4]

        try:
            payload = json.loads(msg.payload.decode())
        except Exception:  # noqa: BLE001 - MQTT callback must not crash on a malformed/unexpected payload
            _LOGGER.debug("Non-JSON MQTT payload on %s", msg.topic)
            return

        _LOGGER.debug("MQTT [%s] %s: %s", device_id, suffix, payload)

        for cb in self._listeners.get(device_id, []):
            try:
                cb(suffix, payload)
            except Exception:
                _LOGGER.exception("Error in MQTT listener for %s", device_id)
