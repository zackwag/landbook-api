"""Landbook local-LAN device control — UDP discovery + TCP client.

An alternative control path to LandbookMQTTClient (mqtt_client.py): instead
of the cloud MQTT channel, this talks to a device directly over the local
network using the binary protocol in local_protocol.py. Reverse-engineered
from the Landbook app, which prefers *this* path over cloud MQTT whenever it
can reach the device's LAN IP — cloud MQTT is only a fallback for the app
when the phone and device aren't on the same network. That preference order
is why "the app still works" isn't proof cloud MQTT commands are healthy: a
phone at home controlling a device at home may never touch the cloud path.

Flow:

1. `discover_devices()` broadcasts a UDP probe on port 6606 and collects
   replies carrying each responding device's current LAN ip/port (a device's
   LAN address isn't something the cloud REST API knows — it can only be
   learned this way).
2. `LandbookLocalClient.connect()` opens a TCP socket to that ip/port and
   performs a challenge-response login using the device's `authKey`
   (Base64-encoded, expected to be present on the entries `get_device_list`
   returns from the real API — see api.py). All the byte-level shapes
   involved here live in local_protocol.py.
3. Once logged in, all further frames' payloads are AES/CBC/PKCS5Padding
   encrypted with key=raw-decoded-authKey, iv=the login's random challenge
   string — so `read()`/`write()` and the periodic heartbeat this client
   sends are all opaque on the wire from that point on.

Confirmed end-to-end against a real device (a GE OmniBreeze fan, productKey
p11vkW): discovery, the SHA-256 challenge-response login, AES key/IV
derivation, and `write()` — a bool write to property id=1 visibly turned
the fan on in the Landbook app. `read()` is still unconfirmed as doing
anything, though: on that same device, the properties it asked for never
came back as a direct reply. Instead, the device continuously and
independently pushes one property at a time on `CMD_STATUS_PUSH_OBSERVED`
(cmd=20) regardless of whether a read was ever sent — cycling through its
properties on its own schedule. So the working model for now is: build a
state cache by listening to `on_update` over time rather than expecting a
synchronous reply to `read()`. Whether cmd 17 does anything at all (maybe
it nudges the push cycle, maybe it's a no-op for this product) is still
open.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from .local_protocol import (
    TYPE_BYTES,
    TYPE_NUMBER,
    DecodedFrame,
    FrameDecoder,
    ProtocolError,
    TTLVField,
    decode_fields,
    encode_fields,
    encode_frame,
    encode_id_list,
)

_LOGGER = logging.getLogger(__name__)

DISCOVERY_PORT = 6606
DISCOVERY_CMD = 28720
DISCOVERY_REPLY_CMD = 28721
DISCOVERY_PROBE_INTERVAL = 3.0  # seconds, matches the app's broadcast cadence

CMD_REQUEST_RANDOM = 28722
CMD_RANDOM_REPLY = 28723
CMD_LOGIN = 28724
CMD_LOGIN_RESULT = 28725
CMD_READ = 17
CMD_WRITE = 19
CMD_READ_WRITE_RESP = 18
CMD_STATUS_PUSH = 50
# Observed on a real device (GE OmniBreeze fan, p11vkW) as a continuous,
# unsolicited push independent of any read/write request — the app's
# decompiled dispatch never named this cmd, so CMD_STATUS_PUSH=50 above may
# be wrong, unused by this product, or just one of several status cmds.
CMD_STATUS_PUSH_OBSERVED = 20
# Observed as the immediate reply to a write() on the same real device — the
# app names this "CMD_TLS_WRITE_RES" in its logging. Its payload doesn't
# obviously mirror the written value (a bool write got back a numeric field
# reading 0), so its exact meaning (success/fail code? something else?) is
# still unconfirmed — it's surfaced via on_write_ack, not the property cache.
CMD_WRITE_ACK = 28726
CMD_HEARTBEAT_PING = 28727
CMD_HEARTBEAT_START = 28729
CMD_HEARTBEAT_REPLY = 28728

LOGIN_TIMEOUT = 10.0
# The app sends CMD_HEARTBEAT_START requesting a 30s interval (field 1) with
# field 2 = 1, then pings every 10s. We ping at 15s — close enough for the 30s
# pong timeout while leaving margin for timer jitter.
_HEARTBEAT_START_FIELDS = [TTLVField(1, TYPE_NUMBER, 30), TTLVField(2, TYPE_NUMBER, 1)]
HEARTBEAT_INTERVAL = 15.0
# If no heartbeat reply arrives within this window, treat the connection as
# dead and fire on_disconnect. Matches the Landbook app's 30s pong timeout
# (decompiled from l94.java / mq0.java in APK v3.7.5).
HEARTBEAT_PONG_TIMEOUT = 30.0
# If no property data frame arrives within this window while connected,
# treat the session as wedged and fire on_disconnect. Covers the "silent but
# attached" failure mode where heartbeat replies keep flowing but the device
# stops its spontaneous property-push cycle.
DATA_STALL_TIMEOUT = 90.0
# A quiet device can still be healthy: on a p11vkW, a status read after 92s
# of property silence got fresh properties back in 0.13s on the same
# connection. So a stall first sends one read, and tears down only if no
# property frame answers within one heartbeat interval.
DATA_PROBE_TIMEOUT = 15.0

_PACKET_ID_START = 1000
_PACKET_ID_WRAP = 65535

# TTLV field ids inside the control messages above.
_DISCOVERY_FIELD_PK = 3
_DISCOVERY_FIELD_DK = 4
_DISCOVERY_FIELD_IP = 5
_DISCOVERY_FIELD_PORT = 6
_DISCOVERY_FIELD_VERSION = 7
_RANDOM_FIELD_CHALLENGE = 1
_LOGIN_FIELD_SIGN = 2
_LOGIN_RESULT_FIELD = 3
_LOGIN_RESULT_ACCEPTED = (0, 2)


@dataclass
class DiscoveredDevice:
    product_key: str
    device_key: str
    ip: str
    port: int
    version: int


def discover_devices(timeout: float = 5.0) -> list[DiscoveredDevice]:
    """Broadcast on the local network and collect device replies.

    Binds UDP port 6606 for both sending and receiving, like the app does —
    only one process per host can hold that port, so this collides with
    anything else on the same machine doing Landbook discovery (e.g. a phone
    emulator running the app).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", DISCOVERY_PORT))
    sock.settimeout(0.5)

    probe = encode_frame(DISCOVERY_CMD, b"", packet_id=_PACKET_ID_START)
    decoder = FrameDecoder()
    devices: dict[tuple[str, str], DiscoveredDevice] = {}

    deadline = time.monotonic() + timeout
    next_send = 0.0
    broadcast_failed = False
    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_send:
                try:
                    sock.sendto(probe, ("255.255.255.255", DISCOVERY_PORT))
                except OSError as exc:
                    # No broadcast-capable interface (offline, VPN-only
                    # routing, a sandbox, ...): keep listening in case a reply
                    # arrives anyway, and retry on the next interval.
                    if not broadcast_failed:
                        _LOGGER.warning("Landbook local: discovery broadcast failed: %s", exc)
                        broadcast_failed = True
                next_send = now + DISCOVERY_PROBE_INTERVAL
            try:
                data, _addr = sock.recvfrom(2048)
            except TimeoutError:
                continue
            for frame in decoder.feed(data):
                device = _parse_discovery_reply(frame)
                if device is not None:
                    devices[(device.product_key, device.device_key)] = device
    finally:
        sock.close()
    return list(devices.values())


def _parse_discovery_reply(frame: DecodedFrame) -> DiscoveredDevice | None:
    if frame.cmd != DISCOVERY_REPLY_CMD:
        return None
    try:
        values = {f.id: f.value for f in decode_fields(frame.payload)}
    except ProtocolError:
        _LOGGER.debug("Landbook local: malformed discovery reply, ignoring")
        return None

    pk = values.get(_DISCOVERY_FIELD_PK, b"").decode("utf-8")
    dk = values.get(_DISCOVERY_FIELD_DK, b"").decode("utf-8")
    ip = values.get(_DISCOVERY_FIELD_IP, b"").decode("utf-8")
    port = int(values.get(_DISCOVERY_FIELD_PORT, 0))
    if not (pk and dk and ip and port):
        return None
    version = int(values.get(_DISCOVERY_FIELD_VERSION, 0))
    return DiscoveredDevice(product_key=pk, device_key=dk, ip=ip, port=port, version=version)


class LandbookLocalClient:
    """A single local-LAN TCP connection to one device.

    One background thread per connection reads and dispatches incoming
    frames; callers may invoke read()/write() from any thread. One instance
    per device, matching how LandbookMQTTClient is one instance per account.
    """

    def __init__(
        self,
        product_key: str,
        device_key: str,
        auth_key_b64: str,
        ip: str,
        port: int,
    ) -> None:
        self._pk = product_key
        self._dk = device_key
        self._auth_key = base64.b64decode(auth_key_b64)
        self._ip = ip
        self._port = port

        # The live socket. A receive loop whose socket is no longer this one
        # was superseded by disconnect()/connect() and exits quietly.
        self._sock: socket.socket | None = None
        self._send_lock = threading.Lock()
        self._packet_id = _PACKET_ID_START

        self._login_done = threading.Event()
        self._random_challenge: str | None = None
        # Set once logged in: from then on every payload is AES/CBC encrypted
        # with key=auth key, iv=this. None means not logged in.
        self._session_iv: bytes | None = None

        self._heartbeat_timer: threading.Timer | None = None
        self._last_pong = 0.0
        self.last_property_update = 0.0

        # Guards and signals changes to properties, _write_acks and the
        # connection itself, for read_and_wait()/write_and_wait().
        self._state_changed = threading.Condition()
        # Last known value per property (TSL numeric id, not string code),
        # fed by status pushes and read/write responses as the device sends
        # them on its own schedule.
        self.properties: dict[int, Any] = {}
        # Bumped per id on every report, so write_and_confirm() can tell a
        # fresh report from a cached value that already matched.
        self._property_revision: dict[int, int] = {}
        # When the pending data-stall probe was sent; None when none is.
        self._data_probe_started: float | None = None
        self._write_acks = 0
        # Acks don't identify the write they answer, so confirmed writes go
        # one at a time to attribute each ack to exactly one caller.
        self._confirmed_write_lock = threading.Lock()

        # Called with the decoded TTLV fields from any read/write response
        # or unsolicited status push. Fields carry the property's numeric
        # TSL id (not its string code) — see local_protocol.field_for_property.
        self.on_update: Callable[[list[TTLVField]], None] | None = None
        # Called with the decoded fields from a CMD_WRITE_ACK reply.
        self.on_write_ack: Callable[[list[TTLVField]], None] | None = None
        # Called with no arguments when the connection is lost unexpectedly —
        # a broken socket, the device closing its end, or a heartbeat/data
        # timeout — never for a caller-initiated disconnect().
        self.on_disconnect: Callable[[], None] | None = None

        self._frame_handlers: dict[int, Callable[[list[TTLVField]], None]] = {
            CMD_RANDOM_REPLY: self._on_random_reply,
            CMD_LOGIN_RESULT: self._on_login_result,
            CMD_READ_WRITE_RESP: self._on_data,
            CMD_STATUS_PUSH: self._on_data,
            CMD_STATUS_PUSH_OBSERVED: self._on_data,
            CMD_WRITE_ACK: self._on_write_ack,
        }

    @property
    def is_connected(self) -> bool:
        """Whether the connection is up and logged in. The polling-style
        complement to on_disconnect."""
        return self._session_iv is not None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self, timeout: float = LOGIN_TIMEOUT) -> None:
        """Open the TCP connection and complete the login handshake
        (blocking until logged in, login is rejected, or `timeout` elapses).

        Any existing connection is closed first, and `properties` is
        cleared: values from a previous session may be stale. Raises
        ConnectionError if login fails or times out.
        """
        self.disconnect()
        with self._state_changed:
            self.properties.clear()
            self._property_revision.clear()
            self._data_probe_started = None
        sock = socket.create_connection((self._ip, self._port), timeout=5.0)
        sock.settimeout(0.5)
        self._login_done.clear()
        with self._state_changed:
            self._sock = sock
        threading.Thread(target=self._recv_loop, args=(sock,), daemon=True).start()

        try:
            self._send(CMD_REQUEST_RANDOM, b"")
            if not self._login_done.wait(timeout):
                raise ConnectionError("Landbook local login timed out")
            if not self.is_connected:
                raise ConnectionError("Landbook local login rejected")
        except BaseException:
            self.disconnect()
            raise

    def disconnect(self) -> None:
        with self._state_changed:
            timer, self._heartbeat_timer = self._heartbeat_timer, None
            if timer is not None:
                timer.cancel()
            sock, self._sock = self._sock, None
            self._session_iv = None
            self._random_challenge = None
            if sock is not None:
                _close_quietly(sock)
            self._state_changed.notify_all()

    def read(self, ids: list[int]) -> None:
        """Request the current values of the given property ids (TSL
        numeric `id`, not `code`) — fire-and-forget, matching the app's
        protocol.

        On real hardware tested so far, this alone hasn't produced an
        observable direct reply: the device pushes its properties
        continuously and on its own schedule via `on_update`/`properties`
        regardless of whether this was called. If you actually need
        current values rather than just triggering the request, use
        `read_and_wait()` instead.
        """
        self._send(CMD_READ, encode_id_list(ids))

    def read_and_wait(self, ids: list[int], timeout: float = 10.0) -> dict[int, Any]:
        """Send a read request, then wait up to `timeout` seconds for the
        given property ids to show up in `self.properties`.

        Returns whatever is known for the requested ids once all of them
        are present, or a partial (possibly empty) result if `timeout`
        elapses or the connection drops first — this never raises on
        timeout, since "some properties arrived, some haven't yet" is the
        expected steady state for a device that reports asynchronously
        rather than replying synchronously.
        """
        self.read(ids)
        with self._state_changed:
            self._wait_for(lambda: all(i in self.properties for i in ids), timeout)
            return {i: self.properties[i] for i in ids if i in self.properties}

    def write(self, fields: list[TTLVField]) -> None:
        """Write property values — build fields with
        local_protocol.field_for_property().

        Confirmed working against real hardware: a bool write visibly
        turned a fan on. The device replies with CMD_WRITE_ACK.
        """
        self._send(CMD_WRITE, encode_fields(fields))

    def write_and_wait(self, fields: list[TTLVField], timeout: float = 2.0) -> bool:
        """Write property values and wait for the device's CMD_WRITE_ACK.

        Returns True if an ack arrived within *timeout* seconds, False
        otherwise (including if the connection drops first). A missing ack
        means the device either didn't receive the command or is in a
        half-open state where the socket accepts bytes but the firmware
        doesn't process them — callers should fall back to an alternative
        control path (e.g. cloud MQTT). Concurrent calls are serialized.
        """
        with self._confirmed_write_lock:
            with self._state_changed:
                acks_before = self._write_acks
            self.write(fields)
            return self._wait_for(lambda: self._write_acks > acks_before, timeout)

    def write_and_confirm(self, fields: list[TTLVField], timeout: float = 10.0) -> bool:
        """Write property values, request them back, and wait up to
        *timeout* seconds for the device to report every one of them anew
        with the written value.

        Stricter than write_and_wait(): an ack, a heartbeat reply, or a
        cached value that already matched doesn't count. False means
        unconfirmed, not necessarily unapplied, so only retry idempotent
        assignments on another path.

        Holds the same lock as write_and_wait() for the whole wait, so
        concurrent confirmed writes (e.g. fan speed and light together) run
        one after another, each blocking the next for up to *timeout*.
        Sharing the lock keeps this write's ack from being counted by a
        concurrent write_and_wait().
        """
        if not fields:
            return False
        # Round-trip through the wire format so the comparison sees what the
        # device will report: a bool lives in the TTLV type (its value may
        # be None), and numbers carry the wire's precision.
        expected = {f.id: f.value for f in decode_fields(encode_fields(fields))}
        with self._confirmed_write_lock:
            with self._state_changed:
                revisions = {i: self._property_revision.get(i, 0) for i in expected}
            self.write(fields)
            self.read(list(expected))
            return self._wait_for(
                lambda: all(
                    self._property_revision.get(i, 0) > revisions[i]
                    and self.properties.get(i) == value
                    for i, value in expected.items()
                ),
                timeout,
            )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _wait_for(self, predicate: Callable[[], bool], timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._state_changed:
            while not predicate():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._sock is None:
                    return False
                self._state_changed.wait(remaining)
            return True

    def _send(self, cmd: int, payload: bytes) -> None:
        with self._send_lock:
            sock = self._sock
            if sock is None:
                raise ConnectionError("Landbook local client is not connected")
            if self._session_iv is not None:
                payload = self._cipher().encrypt(pad(payload, AES.block_size))
            self._packet_id += 1
            if self._packet_id >= _PACKET_ID_WRAP:
                self._packet_id = _PACKET_ID_START
            sock.sendall(encode_frame(cmd, payload, self._packet_id))

    def _cipher(self):
        return AES.new(self._auth_key, AES.MODE_CBC, self._session_iv)

    def _decode_payload(self, payload: bytes) -> list[TTLVField]:
        if self._session_iv is not None:
            payload = unpad(self._cipher().decrypt(payload), AES.block_size)
        return decode_fields(payload)

    def _recv_loop(self, sock: socket.socket) -> None:
        decoder = FrameDecoder()
        try:
            while self._sock is sock:
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    continue
                if not chunk:
                    break
                for frame in decoder.feed(chunk):
                    self._handle_frame(frame)
        except OSError:
            pass
        with self._state_changed:
            unexpected = self._sock is sock
            if unexpected:
                self.disconnect()
        if unexpected and self.on_disconnect:
            self.on_disconnect()

    def _handle_frame(self, frame: DecodedFrame) -> None:
        _LOGGER.debug(
            "Landbook local: recv cmd=%s packet_id=%s payload_len=%d",
            frame.cmd,
            frame.packet_id,
            len(frame.payload),
        )
        if frame.cmd == CMD_HEARTBEAT_REPLY:
            self._last_pong = time.monotonic()
            return

        # Cmds without a handler (wifi-list management, etc.) are part of the
        # wider protocol but not needed for property read/write. They're
        # still decoded and logged at debug level, while it's still unclear
        # which cmd numbers this product uses for what.
        handler = self._frame_handlers.get(frame.cmd)
        try:
            fields = self._decode_payload(frame.payload)
        except (ValueError, ProtocolError) as exc:
            _LOGGER.log(
                logging.WARNING if handler else logging.DEBUG,
                "Landbook local: undecodable cmd=%s (%s), raw payload: %s",
                frame.cmd,
                exc,
                frame.payload.hex(),
            )
            return
        if handler is None:
            _LOGGER.debug("Landbook local: unhandled cmd=%s: %s", frame.cmd, fields)
            return
        try:
            handler(fields)
        except OSError:
            raise
        except Exception:
            _LOGGER.exception("Landbook local: error handling cmd=%s", frame.cmd)

    def _on_random_reply(self, fields: list[TTLVField]) -> None:
        challenge = _field_value(fields, _RANDOM_FIELD_CHALLENGE)
        if challenge is None:
            _LOGGER.warning("Landbook local: random-challenge reply missing its challenge field")
            return
        self._random_challenge = challenge.decode("utf-8")
        sign = hashlib.sha256(f"{self._auth_key.hex()};{self._random_challenge}".encode())
        login = TTLVField(_LOGIN_FIELD_SIGN, TYPE_BYTES, sign.hexdigest().encode())
        self._send(CMD_LOGIN, encode_fields([login]))

    def _on_login_result(self, fields: list[TTLVField]) -> None:
        result = _field_value(fields, _LOGIN_RESULT_FIELD)
        if result not in _LOGIN_RESULT_ACCEPTED or self._random_challenge is None:
            _LOGGER.warning("Landbook local: login rejected, result=%s", result)
            self._login_done.set()
            return
        self._session_iv = self._random_challenge.encode("utf-8")
        self._last_pong = self.last_property_update = time.monotonic()
        self._send(CMD_HEARTBEAT_START, encode_fields(_HEARTBEAT_START_FIELDS))
        with self._state_changed:
            if self._sock is not None:
                self._schedule_heartbeat(self._sock)
        self._login_done.set()

    def _on_data(self, fields: list[TTLVField]) -> None:
        # An empty frame carries no properties, so it's no evidence the
        # data plane is alive.
        if not fields:
            return
        with self._state_changed:
            self.last_property_update = time.monotonic()
            self._data_probe_started = None
            for f in fields:
                self.properties[f.id] = f.value
                self._property_revision[f.id] = self._property_revision.get(f.id, 0) + 1
            self._state_changed.notify_all()
        if self.on_update:
            self.on_update(fields)

    def _on_write_ack(self, fields: list[TTLVField]) -> None:
        _LOGGER.debug("Landbook local: write ack: %s", fields)
        with self._state_changed:
            self._write_acks += 1
            self._state_changed.notify_all()
        if self.on_write_ack:
            self.on_write_ack(fields)

    def _schedule_heartbeat(self, sock: socket.socket) -> None:
        timer = threading.Timer(HEARTBEAT_INTERVAL, self._send_heartbeat, args=(sock,))
        timer.daemon = True
        self._heartbeat_timer = timer
        timer.start()

    def _send_heartbeat(self, sock: socket.socket) -> None:
        """Each heartbeat chain belongs to one socket and ends with it, so a
        tick racing disconnect()/connect() can't touch the next session."""
        if self._sock is not sock:
            return
        now = time.monotonic()
        if now - self._last_pong > HEARTBEAT_PONG_TIMEOUT:
            _LOGGER.warning(
                "Landbook local: heartbeat pong timeout (no reply in %.0fs), tearing down",
                now - self._last_pong,
            )
            _close_quietly(sock)
            return
        if now - self.last_property_update > DATA_STALL_TIMEOUT:
            with self._state_changed:
                ids = list(self.properties)
                probe_started = self._data_probe_started
                if probe_started is None and ids:
                    self._data_probe_started = now
            # With no known ids there's nothing to probe for.
            if not ids or (probe_started is not None and now - probe_started >= DATA_PROBE_TIMEOUT):
                _LOGGER.warning(
                    "Landbook local: data stall (no property push in %.0fs), tearing down",
                    now - self.last_property_update,
                )
                _close_quietly(sock)
                return
            if probe_started is None:
                # Pongs only prove the heartbeat handler is alive, so ask for
                # real properties. Not read_and_wait(): cached values would
                # satisfy it immediately.
                _LOGGER.debug("Landbook local: property silence, requesting fresh status")
                try:
                    self.read(ids)
                except OSError:
                    _close_quietly(sock)
                    return
        try:
            self._send(CMD_HEARTBEAT_PING, b"")
        except OSError:
            return
        with self._state_changed:
            if self._sock is sock:
                self._schedule_heartbeat(sock)


def _close_quietly(sock: socket.socket) -> None:
    """Closing (without detaching) makes the receive loop see the failure,
    tear the connection down and fire on_disconnect."""
    try:
        sock.close()
    except OSError:
        pass


def _field_value(fields: list[TTLVField], field_id: int) -> Any:
    return next((f.value for f in fields if f.id == field_id), None)
