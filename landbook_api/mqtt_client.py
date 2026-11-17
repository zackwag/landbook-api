"""Landbook MQTT client — WebSocket/TLS connection, pub/sub."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from typing import Any, NamedTuple

import paho.mqtt.client as mqtt

from .const import DEFAULT_REGION, MQTT_KEEPALIVE, MQTT_PORT, MQTT_WS_PATH, REGIONS

_LOGGER = logging.getLogger(__name__)

# How long a write that failed because the connection was momentarily down
# stays queued for replay on reconnect. Longer than the ~1-3s blip caused by
# a token-rotation reconnect, short enough that a tap during a genuine outage
# isn't silently applied minutes later.
WRITE_RETRY_WINDOW = 5.0  # seconds

CONNECT_TIMEOUT = 10.0  # seconds to wait for the broker's CONNACK
RECONNECT_DELAY = 5.0  # after an unexpected disconnect
RECONNECT_RETRY_DELAY = 30.0  # after a reconnect attempt itself fails

# Every device topic the broker publishes to: q/2/d/{device_id}/{suffix}
_DEVICE_TOPIC_SUFFIXES = ("ack_", "bus_", "onl_", "ota_", "inf_", "loc_")


class _DeferredWrite(NamedTuple):
    deadline: float
    device_id: str
    pk: str
    dk: str
    props: dict


class LandbookMQTTClient:
    """Manages a single persistent MQTT connection for one account.

    After connect(), an unexpected drop is retried automatically (refreshing
    the token first via `token_refresher`, if given) until disconnect() or
    halt_reconnects() is called.
    """

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

        # The live paho client. Callbacks from any other client instance are
        # from one this object already tore down, and are ignored.
        self._client: mqtt.Client | None = None
        self._connected = False
        self._connack = threading.Event()
        self._auto_reconnect = False
        self._reconnect_timer: threading.Timer | None = None

        # Seeded from wall-clock time rather than a fixed value: if the server
        # dedups/rejects recently-seen msgIds independent of the connection,
        # a fixed seed would make every new client instance (e.g. after a
        # process restart) collide with the previous one's id range.
        self._msg_counter = int(time.time() * 1000) & 0xFFFF
        self._deferred_writes: list[_DeferredWrite] = []

        # One client instance is shared by every device on the account and is
        # called from the caller's threads and paho's network thread.
        # Concurrent publish() calls race on paho's internal _sendbuffer and
        # raise BufferError ("Existing exports of data: object cannot be
        # re-sized"), so every socket op takes this lock.
        self._wire_lock = threading.RLock()
        # Serializes connect/disconnect/timer reconnects, so only one
        # connection attempt (and one CONNACK wait) is ever in flight.
        self._lifecycle_lock = threading.Lock()

        self._listeners: dict[str, list[Callable[[str, Any], None]]] = {}

        # Called with no arguments after every successful (re)connect, once
        # topics are resubscribed and deferred writes replayed — the place to
        # re-read device state that may have changed while disconnected.
        self.on_connect: Callable[[], None] | None = None

    # landbook-ha <= 2.2.6 assigns these private names directly; remove once
    # it uses on_connect and connect()/halt_reconnects() instead.
    @property
    def _on_reconnect(self) -> Callable[[], None] | None:
        return self.on_connect

    @_on_reconnect.setter
    def _on_reconnect(self, callback: Callable[[], None] | None) -> None:
        self.on_connect = callback

    @property
    def _reauth_pending(self) -> bool:
        return not self._auto_reconnect

    @_reauth_pending.setter
    def _reauth_pending(self, pending: bool) -> None:
        if pending:
            self.halt_reconnects()
        else:
            self._auto_reconnect = True

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Establish the connection, blocking until the broker accepts it.

        Any existing connection is torn down first. Raises ConnectionError if
        the broker refuses it or doesn't answer within CONNECT_TIMEOUT, or the
        underlying OSError if the broker can't be reached.
        """
        with self._lifecycle_lock:
            self._auto_reconnect = True
            self._open()

    def reconnect(self) -> None:
        """Tear down and re-establish the connection from scratch.

        For a caller (e.g. a watchdog) that has independently determined the
        connection is silently dead — the broker can drop a WebSocket link
        mid-stream without paho ever calling on_disconnect, so keepalive
        alone doesn't catch it. Same as connect().
        """
        self.connect()

    def disconnect(self) -> None:
        with self._lifecycle_lock:
            self._auto_reconnect = False
            self._teardown()

    def halt_reconnects(self) -> None:
        """Stop all automatic reconnect attempts (e.g. while reauth is pending)
        until the next explicit connect() or reconnect()."""
        self._auto_reconnect = False
        self._cancel_reconnect_timer()

    def update_token(self, bearer_token: str) -> None:
        """Set the token used by the next connection attempt."""
        self._bearer_token = bearer_token

    def _open(self) -> None:
        self._teardown()
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"qu_{self._uid}_{int(time.time() * 1000)}",
            transport="websockets",
            protocol=mqtt.MQTTv311,
            # Reconnects go through _reconnect_from_timer (fresh client, fresh
            # token) only; paho's own retry would reuse the old token.
            reconnect_on_failure=False,
        )
        client.ws_set_options(path=MQTT_WS_PATH)
        client.tls_set()
        client.username_pw_set("", self._bearer_token)
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.on_disconnect = self._on_disconnect

        with self._wire_lock:
            self._client = client
            self._connack.clear()
        try:
            client.connect(self._mqtt_host, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
            client.loop_start()
            if not self._connack.wait(CONNECT_TIMEOUT):
                raise ConnectionError("MQTT connection timed out")
            if not self._connected:
                raise ConnectionError("MQTT connection refused")
        except BaseException:
            self._teardown()
            raise

    def _teardown(self) -> None:
        """Detach and stop the current client.

        Detaching first makes the old client's own on_disconnect (which paho
        may fire synchronously from disconnect() or later from its network
        thread) a stale callback, so it can't schedule a second reconnect on
        top of whatever the caller does next — two live sessions for one
        account get every command rejected (landbook-ha#27). Stopping happens
        outside the lock because loop_stop() joins the network thread, which
        may be waiting on that lock in _on_connect.
        """
        with self._wire_lock:
            client, self._client = self._client, None
            self._connected = False
        self._cancel_reconnect_timer()
        if client is not None:
            client.loop_stop()
            client.disconnect()

    def _schedule_reconnect(self, delay: float) -> None:
        self._cancel_reconnect_timer()
        timer = threading.Timer(delay, self._reconnect_from_timer)
        timer.daemon = True
        self._reconnect_timer = timer
        timer.start()

    def _cancel_reconnect_timer(self) -> None:
        timer, self._reconnect_timer = self._reconnect_timer, None
        if timer is not None:
            timer.cancel()

    def _reconnect_from_timer(self) -> None:
        if not self._auto_reconnect:
            return
        _LOGGER.info("Landbook MQTT attempting reconnect")
        if self._token_refresher:
            try:
                self._bearer_token = self._token_refresher()
            except Exception as exc:  # noqa: BLE001 - best-effort refresh, fall back to old token rather than abort the reconnect
                _LOGGER.warning("Token refresh failed, reconnecting with old token: %s", exc)
        with self._lifecycle_lock:
            # The refresher may itself have halted reconnects (e.g. reauth
            # needed), or disconnect()/connect() may have run meanwhile.
            if not self._auto_reconnect or self._connected:
                return
            try:
                self._open()
            except Exception as exc:  # noqa: BLE001 - retry loop, must survive any connect failure
                _LOGGER.warning(
                    "Reconnect failed: %s — will retry in %.0fs", exc, RECONNECT_RETRY_DELAY
                )
                self._schedule_reconnect(RECONNECT_RETRY_DELAY)

    # ------------------------------------------------------------------
    # Pub/sub
    # ------------------------------------------------------------------

    def subscribe_device(self, device_id: str, callback: Callable[[str, Any], None]) -> None:
        """Subscribe to all topics for a device and register a callback.

        callback(topic_suffix, payload_dict)
        """
        with self._wire_lock:
            if device_id not in self._listeners:
                self._listeners[device_id] = []
                if self._connected:
                    self._subscribe_topics(device_id)
            self._listeners[device_id].append(callback)

    def unsubscribe_device(self, device_id: str, callback: Callable[[str, Any], None]) -> None:
        """Remove a previously registered callback for a device.

        If this was the last callback for the device, the MQTT topic
        subscriptions for that device are left in place (harmless — messages
        with no listener are dropped) rather than unsubscribing, which avoids
        a race with an in-flight message on the broker.
        """
        with self._wire_lock:
            callbacks = self._listeners.get(device_id, [])
            if callback in callbacks:
                callbacks.remove(callback)

    def send_read(self, device_id: str, pk: str, dk: str, codes: list[str]) -> None:
        """Request current values for the given property codes (READ-ATTR).

        Dropped while disconnected: on_connect is the place to re-read state
        once the connection is back.
        """
        with self._wire_lock:
            if not self._connected:
                return
            self._publish(device_id, pk, dk, "READ-ATTR", codes)

    def send_write(self, device_id: str, pk: str, dk: str, props: dict) -> None:
        """Publish a WRITE-ATTR command.

        If the connection is momentarily down (e.g. the ~1-3s blip during a
        token-rotation reconnect), the write is queued instead of raising and
        is replayed in order once the connection comes back. A write still
        queued after WRITE_RETRY_WINDOW is dropped rather than applied late.
        """
        with self._wire_lock:
            if not self._connected:
                now = time.monotonic()
                self._deferred_writes = [w for w in self._deferred_writes if w.deadline >= now]
                self._deferred_writes.append(
                    _DeferredWrite(now + WRITE_RETRY_WINDOW, device_id, pk, dk, props)
                )
                _LOGGER.info(
                    "Landbook: write to %s deferred (MQTT down), will resend on reconnect", dk
                )
                return
            self._publish(device_id, pk, dk, "WRITE-ATTR", [props])

    def _publish(self, device_id: str, pk: str, dk: str, msg_type: str, kv: list) -> None:
        assert self._client is not None
        self._msg_counter = (self._msg_counter + 1) & 0xFFFF
        payload = {
            "msgId": self._msg_counter,
            "productKey": pk,
            "deviceKey": dk,
            "type": msg_type,
            "kv": json.dumps(kv),
            "cacheTime": 0,
            "isCache": False,
            "isCover": False,
        }
        self._client.publish(f"q/1/d/{device_id}/sys_", json.dumps(payload), qos=1)
        _LOGGER.debug("%s device=%s kv=%s", msg_type, device_id, kv)

    def _subscribe_topics(self, device_id: str) -> None:
        assert self._client is not None
        for suffix in _DEVICE_TOPIC_SUFFIXES:
            self._client.subscribe(f"q/2/d/{device_id}/{suffix}", qos=1)

    def _flush_deferred_writes(self) -> None:
        now = time.monotonic()
        pending, self._deferred_writes = self._deferred_writes, []
        for write in pending:
            if now > write.deadline:
                _LOGGER.info(
                    "Landbook: dropping deferred write to %s (expired while disconnected)",
                    write.dk,
                )
                continue
            self._publish(write.device_id, write.pk, write.dk, "WRITE-ATTR", [write.props])

    # ------------------------------------------------------------------
    # paho callbacks (network thread)
    # ------------------------------------------------------------------

    def _on_connect(self, client, userdata, flags, reason_code, properties) -> None:
        with self._wire_lock:
            if client is not self._client:
                return
            if reason_code.is_failure:
                _LOGGER.error("Landbook MQTT connect failed: %s", reason_code)
                self._connack.set()
                return
            self._connected = True
            for device_id in self._listeners:
                self._subscribe_topics(device_id)
            self._flush_deferred_writes()
        self._connack.set()
        _LOGGER.info("Landbook MQTT connected")
        if self.on_connect:
            self.on_connect()

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties) -> None:
        # Under the lock so _teardown's detach-then-cancel can't interleave
        # with a reconnect being scheduled here.
        with self._wire_lock:
            if client is not self._client:
                return
            self._connected = False
            if not self._auto_reconnect:
                _LOGGER.debug("Landbook MQTT disconnected with reconnects halted")
                return
            _LOGGER.warning("Landbook MQTT disconnected: %s — scheduling reconnect", reason_code)
            self._schedule_reconnect(RECONNECT_DELAY)

    def _on_message(self, client, userdata, msg: mqtt.MQTTMessage) -> None:
        parts = msg.topic.split("/")
        if len(parts) < 5:
            return
        device_id, suffix = parts[3], parts[4]

        try:
            payload = json.loads(msg.payload.decode())
        except Exception:  # noqa: BLE001 - MQTT callback must not crash on a malformed/unexpected payload
            _LOGGER.debug("Non-JSON MQTT payload on %s", msg.topic)
            return

        _LOGGER.debug("MQTT [%s] %s: %s", device_id, suffix, payload)

        with self._wire_lock:
            callbacks = list(self._listeners.get(device_id, []))
        for cb in callbacks:
            try:
                cb(suffix, payload)
            except Exception:
                _LOGGER.exception("Error in MQTT listener for %s", device_id)
