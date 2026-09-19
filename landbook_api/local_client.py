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
# still unconfirmed — decoded and surfaced via on_update like any other
# data for now.
CMD_WRITE_ACK = 28726
CMD_HEARTBEAT = 28729

LOGIN_TIMEOUT = 10.0
# The app's heartbeat payload requests a 30s interval (TTLV id=1 -> 30); we
# send at half that for margin. Unconfirmed against real hardware — if the
# device drops the connection despite heartbeats, this is the first place
# to look.
HEARTBEAT_INTERVAL = 15.0

_PACKET_ID_START = 1000
_PACKET_ID_WRAP = 65535


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
    if the Landbook app is running on the same machine (it won't be, in
    practice, since this targets Home Assistant, but e.g. a phone emulator
    on the same host would collide), only one of you can hold that port.
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
                    # No active broadcast-capable interface (offline, VPN-only
                    # routing, a sandboxed environment, ...) — keep listening
                    # in case a reply arrives anyway, and retry sending on the
                    # next interval rather than aborting discovery outright.
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
        fields = decode_fields(frame.payload)
    except ProtocolError:
        _LOGGER.debug("Landbook local: malformed discovery reply, ignoring")
        return None

    pk = dk = ip = None
    port = version = 0
    for f in fields:
        if f.id == 3:
            pk = f.value.decode("utf-8")
        elif f.id == 4:
            dk = f.value.decode("utf-8")
        elif f.id == 5:
            ip = f.value.decode("utf-8")
        elif f.id == 6:
            port = int(f.value)
        elif f.id == 7:
            version = int(f.value)

    if not (pk and dk and ip and port):
        return None
    return DiscoveredDevice(product_key=pk, device_key=dk, ip=ip, port=port, version=version)


class LandbookLocalClient:
    """A single local-LAN TCP connection to one device.

    One background thread reads and dispatches incoming frames; callers may
    invoke read()/write() from any thread. Not designed for multiple
    concurrent LandbookLocalClient instances to share a socket — one
    instance per device, matching how LandbookMQTTClient is one instance
    per account.
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

        self._sock: socket.socket | None = None
        self._decoder = FrameDecoder()
        self._recv_thread: threading.Thread | None = None
        self._shutting_down = False

        self._packet_id = _PACKET_ID_START
        self._wire_lock = threading.RLock()

        self._logged_in = threading.Event()
        self._login_failed = False
        self._random_challenge: str | None = None
        self._cipher_key: bytes | None = None
        self._cipher_iv: bytes | None = None

        self._heartbeat_timer: threading.Timer | None = None

        # Last known value per property (TSL numeric id, not string code),
        # fed by every status push / read-write response — NOT by
        # CMD_WRITE_ACK, whose payload doesn't appear to mirror property
        # state (see _on_write_ack). Populated passively over time by
        # whatever the device pushes on its own schedule; read_and_wait()
        # waits on `_property_updated` for ids not yet present.
        self.properties: dict[int, Any] = {}
        self._property_updated = threading.Condition()

        # Called with the decoded TTLV fields from any read/write response
        # or unsolicited status push. Fields carry the property's numeric
        # TSL id (not its string code) — see local_protocol.field_for_property.
        self.on_update: Callable[[list[TTLVField]], None] | None = None

        # Called with the decoded fields from a CMD_WRITE_ACK reply. Kept
        # separate from on_update since this payload's meaning is still
        # unconfirmed (see module docstring) and doesn't belong in the
        # property cache.
        self.on_write_ack: Callable[[list[TTLVField]], None] | None = None

    def connect(self, timeout: float = LOGIN_TIMEOUT) -> None:
        """Open the TCP connection and complete the login handshake
        (blocking until logged in, login is rejected, or `timeout` elapses).
        """
        sock = socket.create_connection((self._ip, self._port), timeout=5.0)
        sock.settimeout(0.5)
        self._sock = sock
        self._shutting_down = False
        self._login_failed = False
        self._logged_in.clear()

        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

        self._send(CMD_REQUEST_RANDOM, b"")

        if not self._logged_in.wait(timeout):
            self.disconnect()
            raise ConnectionError("Landbook local login timed out")
        if self._login_failed:
            self.disconnect()
            raise ConnectionError("Landbook local login rejected")

    def disconnect(self) -> None:
        self._shutting_down = True
        if self._heartbeat_timer:
            self._heartbeat_timer.cancel()
            self._heartbeat_timer = None
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._logged_in.clear()
        with self._property_updated:
            self._property_updated.notify_all()

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
        """Send a read request, then wait for the given property ids to
        show up in `self.properties` (populated passively from whatever
        the device pushes on its own — see `read()`'s docstring), up to
        `timeout` seconds.

        Returns whatever is known for the requested ids once all of them
        are present, or a partial (possibly empty) result if `timeout`
        elapses first — this never raises on timeout, since "some
        properties arrived, some haven't yet" is the expected steady state
        for a device that reports asynchronously rather than replying
        synchronously.
        """
        self.read(ids)
        deadline = time.monotonic() + timeout
        with self._property_updated:
            while not all(i in self.properties for i in ids):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._property_updated.wait(timeout=remaining)
            return {i: self.properties[i] for i in ids if i in self.properties}

    def write(self, fields: list[TTLVField]) -> None:
        """Write property values — build fields with
        local_protocol.field_for_property().

        Confirmed working against real hardware: a bool write visibly
        turned a fan on. The device replies with CMD_WRITE_ACK; its
        payload's exact meaning is still unconfirmed (see module docstring).
        """
        self._send(CMD_WRITE, encode_fields(fields))

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _next_packet_id(self) -> int:
        with self._wire_lock:
            self._packet_id += 1
            if self._packet_id >= _PACKET_ID_WRAP:
                self._packet_id = _PACKET_ID_START
            return self._packet_id

    def _send(self, cmd: int, payload: bytes) -> None:
        assert self._sock is not None
        if self._cipher_key is not None:
            payload = self._encrypt(payload)
        frame = encode_frame(cmd, payload, self._next_packet_id())
        with self._wire_lock:
            self._sock.sendall(frame)

    def _encrypt(self, payload: bytes) -> bytes:
        assert self._cipher_key is not None and self._cipher_iv is not None
        cipher = AES.new(self._cipher_key, AES.MODE_CBC, self._cipher_iv)
        return cipher.encrypt(pad(payload, AES.block_size))

    def _decrypt(self, payload: bytes) -> bytes:
        assert self._cipher_key is not None and self._cipher_iv is not None
        cipher = AES.new(self._cipher_key, AES.MODE_CBC, self._cipher_iv)
        return unpad(cipher.decrypt(payload), AES.block_size)

    def _recv_loop(self) -> None:
        while not self._shutting_down and self._sock is not None:
            try:
                chunk = self._sock.recv(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if not chunk:
                break
            try:
                frames = self._decoder.feed(chunk)
            except ProtocolError as exc:
                _LOGGER.warning("Landbook local: dropping malformed frame: %s", exc)
                continue
            for frame in frames:
                _LOGGER.debug(
                    "Landbook local: recv cmd=%s packet_id=%s payload_len=%d",
                    frame.cmd,
                    frame.packet_id,
                    len(frame.payload),
                )
                self._handle_frame(frame)

    def _handle_frame(self, frame: DecodedFrame) -> None:
        if frame.cmd == CMD_RANDOM_REPLY:
            self._on_random_reply(frame.payload)
        elif frame.cmd == CMD_LOGIN_RESULT:
            self._on_login_result(frame.payload)
        elif frame.cmd in (CMD_READ_WRITE_RESP, CMD_STATUS_PUSH, CMD_STATUS_PUSH_OBSERVED):
            self._on_data(frame.payload)
        elif frame.cmd == CMD_WRITE_ACK:
            self._on_write_ack(frame.payload)
        else:
            # Other cmds (wifi-list management, etc.) are part of the wider
            # protocol but not needed for property read/write. Opportunistically
            # try to decrypt/decode anyway and log the result — exploratory,
            # while we're still confirming which cmd numbers this product
            # actually uses for what.
            self._try_decode_unknown(frame.cmd, frame.payload)

    def _try_decode_unknown(self, cmd: int, payload: bytes) -> None:
        if self._cipher_key is None:
            _LOGGER.debug("Landbook local: unhandled cmd=%s (pre-auth), ignoring", cmd)
            return
        try:
            decrypted = self._decrypt(payload)
            fields = decode_fields(decrypted)
        except (ValueError, ProtocolError) as exc:
            _LOGGER.debug(
                "Landbook local: unhandled cmd=%s, decode failed (%s), raw payload: %s",
                cmd,
                exc,
                payload.hex(),
            )
            return
        _LOGGER.debug("Landbook local: unhandled cmd=%s decoded successfully: %s", cmd, fields)

    def _on_random_reply(self, payload: bytes) -> None:
        try:
            fields = decode_fields(payload)
        except ProtocolError:
            _LOGGER.warning("Landbook local: malformed random-challenge reply")
            return
        random_field = next((f for f in fields if f.id == 1), None)
        if random_field is None:
            _LOGGER.warning("Landbook local: random-challenge reply missing id=1 field")
            return
        random_str = random_field.value.decode("utf-8")
        self._random_challenge = random_str
        sign = hashlib.sha256(f"{self._auth_key.hex()};{random_str}".encode()).hexdigest()
        login_payload = encode_fields([TTLVField(2, 3, sign.encode())])
        self._send(CMD_LOGIN, login_payload)

    def _on_login_result(self, payload: bytes) -> None:
        try:
            fields = decode_fields(payload)
        except ProtocolError:
            self._login_failed = True
            self._logged_in.set()
            return
        result_field = next((f for f in fields if f.id == 3), None)
        result = int(result_field.value) if result_field is not None else 1
        if result not in (0, 2):
            _LOGGER.warning("Landbook local: login rejected, result=%s", result)
            self._login_failed = True
            self._logged_in.set()
            return
        assert self._random_challenge is not None
        self._cipher_key = self._auth_key
        self._cipher_iv = self._random_challenge.encode("utf-8")
        self._logged_in.set()
        self._send_heartbeat()

    def _decrypt_and_decode(self, payload: bytes, what: str) -> list[TTLVField] | None:
        raw = payload
        if self._cipher_key is not None:
            try:
                payload = self._decrypt(payload)
            except ValueError as exc:
                _LOGGER.warning(
                    "Landbook local: failed to decrypt %s (%s), raw payload: %s",
                    what,
                    exc,
                    raw.hex(),
                )
                return None
        try:
            return decode_fields(payload)
        except ProtocolError as exc:
            _LOGGER.warning(
                "Landbook local: malformed %s (%s), decrypted payload: %s", what, exc, payload.hex()
            )
            return None

    def _on_data(self, payload: bytes) -> None:
        fields = self._decrypt_and_decode(payload, "data frame")
        if fields is None:
            return
        with self._property_updated:
            for f in fields:
                self.properties[f.id] = f.value
            self._property_updated.notify_all()
        if self.on_update:
            self.on_update(fields)

    def _on_write_ack(self, payload: bytes) -> None:
        fields = self._decrypt_and_decode(payload, "write ack")
        if fields is None:
            return
        _LOGGER.debug("Landbook local: write ack: %s", fields)
        if self.on_write_ack:
            self.on_write_ack(fields)

    def _send_heartbeat(self) -> None:
        if self._shutting_down:
            return
        self._send(
            CMD_HEARTBEAT,
            encode_fields([TTLVField(1, TYPE_NUMBER, 30), TTLVField(2, TYPE_NUMBER, 1)]),
        )
        self._heartbeat_timer = threading.Timer(HEARTBEAT_INTERVAL, self._send_heartbeat)
        self._heartbeat_timer.daemon = True
        self._heartbeat_timer.start()
