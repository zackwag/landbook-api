import base64
import queue
import threading
import time

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from landbook_api import local_client as lc
from landbook_api.local_client import LandbookLocalClient, discover_devices
from landbook_api.local_protocol import (
    TYPE_BOOL_TRUE,
    TYPE_BYTES,
    TYPE_NUMBER,
    FrameDecoder,
    TTLVField,
    decode_fields,
    encode_fields,
    encode_frame,
)

AUTH_KEY = b"0123456789abcdef"
AUTH_KEY_B64 = base64.b64encode(AUTH_KEY).decode()
CHALLENGE = "abcdefghijklmnop"
# SHA-256 of "<hex(AUTH_KEY)>;<CHALLENGE>", the login signature the device expects.
EXPECTED_LOGIN_SIGN = "d4c900a5568b2911ee807a3b5fb31d7d23c296629a0cb1b1732760357f02c8f1"


def later(delay, fn, *args):
    def run():
        time.sleep(delay)
        fn(*args)

    threading.Thread(target=run, daemon=True).start()


def wait_until(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return False


class FakeDevice:
    """Stands in for the TCP socket to a device: decodes what the client
    sends, answers the login handshake and writes like real hardware, and
    lets tests push frames back."""

    def __init__(self, auth_key=AUTH_KEY):
        self.auth_key = auth_key
        self.answer_challenge = True
        self.accept_result = 0
        self.ack_writes: bool | int = True  # an int acks only that many writes
        self.ack_delay = 0.0
        self.received: list[tuple[int, list[TTLVField] | bytes]] = []
        self.closed = False
        self._inbox: queue.Queue[bytes] = queue.Queue()
        self._decoder = FrameDecoder()
        self._session_iv: bytes | None = None
        self._packet_id = 1

    # -- socket API used by the client --

    def settimeout(self, _timeout):
        pass

    def sendall(self, data):
        if self.closed:
            raise OSError(9, "Bad file descriptor")
        for frame in self._decoder.feed(data):
            self._on_frame(frame.cmd, frame.payload)

    def recv(self, _n):
        if self.closed:
            raise OSError(9, "Bad file descriptor")
        try:
            return self._inbox.get(timeout=0.02)
        except queue.Empty:
            raise TimeoutError from None

    def close(self):
        self.closed = True

    # -- test controls --

    def push(self, cmd, fields):
        self.push_raw(cmd, encode_fields(fields))

    def push_raw(self, cmd, payload, encrypt=True):
        if encrypt and self._session_iv is not None:
            payload = self._cipher().encrypt(pad(payload, AES.block_size))
        self._packet_id += 1
        self._inbox.put(encode_frame(cmd, payload, self._packet_id))

    def hang_up(self):
        self._inbox.put(b"")

    def sent(self, cmd):
        return [payload for c, payload in self.received if c == cmd]

    # -- device behavior --

    def _cipher(self):
        return AES.new(self.auth_key, AES.MODE_CBC, self._session_iv)

    def _on_frame(self, cmd, payload):
        if self._session_iv is not None:
            payload = unpad(self._cipher().decrypt(payload), AES.block_size)
        if cmd == lc.CMD_READ:
            self.received.append((cmd, payload))
            return
        fields = decode_fields(payload)
        self.received.append((cmd, fields))
        if cmd == lc.CMD_REQUEST_RANDOM and self.answer_challenge:
            self.push(lc.CMD_RANDOM_REPLY, [TTLVField(1, TYPE_BYTES, CHALLENGE.encode())])
        elif cmd == lc.CMD_LOGIN:
            accepted = self.auth_key == AUTH_KEY and fields == [
                TTLVField(2, TYPE_BYTES, EXPECTED_LOGIN_SIGN.encode())
            ]
            result = self.accept_result if accepted else 1
            self.push(lc.CMD_LOGIN_RESULT, [TTLVField(3, TYPE_NUMBER, result)])
            if accepted:
                self._session_iv = CHALLENGE.encode()
        elif cmd == lc.CMD_WRITE and self.ack_writes:
            if self.ack_writes is not True:
                self.ack_writes -= 1
            later(self.ack_delay, self.push, lc.CMD_WRITE_ACK, [TTLVField(1, TYPE_NUMBER, 0)])


class FakeTimer:
    def __init__(self, interval, function, args=()):
        self.interval = interval
        self.function = function
        self.args = args
        self.cancelled = False
        self.daemon = False

    def start(self):
        pass

    def cancel(self):
        self.cancelled = True

    def fire(self):
        self.function(*self.args)


@pytest.fixture
def device(monkeypatch):
    devices = [FakeDevice()]

    def create_connection(_addr, timeout):
        if devices[-1].closed or devices[-1].received:
            devices.append(FakeDevice())
        return devices[-1]

    monkeypatch.setattr(lc.socket, "create_connection", create_connection)
    dev = devices[0]
    dev.all = devices
    return dev


@pytest.fixture
def timers(monkeypatch):
    created: list[FakeTimer] = []

    def new_timer(interval, function, args=()):
        timer = FakeTimer(interval, function, args)
        created.append(timer)
        return timer

    monkeypatch.setattr(lc.threading, "Timer", new_timer)
    return created


@pytest.fixture
def client(device, timers):
    c = LandbookLocalClient("p11vkW", "A8DD9FE36D91", AUTH_KEY_B64, "192.168.1.50", 6607)
    yield c
    c.disconnect()


@pytest.fixture
def connected(client):
    client.connect(timeout=2.0)
    return client


class TestDiscovery:
    class FakeUDP:
        def __init__(self, replies, send_error=None):
            self.replies = list(replies)
            self.send_error = send_error
            self.sent = []
            self.closed = False

        def setsockopt(self, *_a):
            pass

        def bind(self, _addr):
            pass

        def settimeout(self, _t):
            pass

        def sendto(self, data, addr):
            if self.send_error:
                raise self.send_error
            self.sent.append((data, addr))

        def recvfrom(self, _n):
            if self.replies:
                return self.replies.pop(0), ("192.168.1.50", 6606)
            time.sleep(0.01)
            raise TimeoutError

        def close(self):
            self.closed = True

    @staticmethod
    def reply(pk="p11vkW", dk="A8DD9FE36D91", ip="192.168.1.50", port=6607, cmd=28721):
        fields = [
            TTLVField(3, TYPE_BYTES, pk.encode()),
            TTLVField(4, TYPE_BYTES, dk.encode()),
            TTLVField(5, TYPE_BYTES, ip.encode()),
            TTLVField(6, TYPE_NUMBER, port),
            TTLVField(7, TYPE_NUMBER, 1),
        ]
        return encode_frame(cmd, encode_fields(fields), packet_id=1)

    def run(self, monkeypatch, udp):
        monkeypatch.setattr(lc.socket, "socket", lambda *_a: udp)
        return discover_devices(timeout=0.1)

    def test_collects_and_dedups_replies(self, monkeypatch):
        udp = self.FakeUDP([self.reply(), self.reply(), self.reply(dk="OTHER")])
        devices = self.run(monkeypatch, udp)
        assert {(d.product_key, d.device_key, d.ip, d.port, d.version) for d in devices} == {
            ("p11vkW", "A8DD9FE36D91", "192.168.1.50", 6607, 1),
            ("p11vkW", "OTHER", "192.168.1.50", 6607, 1),
        }
        assert udp.sent[0][1] == ("255.255.255.255", 6606)
        assert udp.closed

    def test_ignores_wrong_cmd_incomplete_and_malformed_replies(self, monkeypatch):
        incomplete = encode_frame(
            28721, encode_fields([TTLVField(3, TYPE_BYTES, b"pk")]), packet_id=1
        )
        malformed = encode_frame(28721, b"\xff\xff\xff", packet_id=1)
        udp = self.FakeUDP([self.reply(cmd=1), incomplete, malformed, b"\xaa\xaa\x00\x00\x00"])
        assert self.run(monkeypatch, udp) == []

    def test_keeps_listening_when_broadcast_fails(self, monkeypatch):
        udp = self.FakeUDP([self.reply()], send_error=OSError("no broadcast interface"))
        assert len(self.run(monkeypatch, udp)) == 1


class TestLogin:
    def test_handshake_then_encrypted_heartbeat_start(self, device, connected):
        assert connected.is_connected
        assert device.sent(lc.CMD_REQUEST_RANDOM) == [[]]
        assert device.sent(lc.CMD_HEARTBEAT_START) == [
            [TTLVField(1, TYPE_NUMBER, 30), TTLVField(2, TYPE_NUMBER, 1)]
        ]

    def test_result_2_also_counts_as_accepted(self, device, client):
        device.accept_result = 2
        client.connect(timeout=2.0)
        assert client.is_connected

    def test_wrong_auth_key_is_rejected(self, device, client):
        device.auth_key = b"fedcba9876543210"
        with pytest.raises(ConnectionError, match="rejected"):
            client.connect(timeout=2.0)
        assert not client.is_connected
        assert device.closed

    def test_no_answer_times_out(self, device, client):
        device.answer_challenge = False
        with pytest.raises(ConnectionError, match="timed out"):
            client.connect(timeout=0.1)
        assert not client.is_connected
        assert device.closed

    def test_reconnecting_from_on_disconnect(self, device, connected):
        reconnected = threading.Event()

        def on_disconnect():
            connected.connect(timeout=2.0)
            reconnected.set()

        connected.on_disconnect = on_disconnect
        device.hang_up()
        assert reconnected.wait(3.0)
        assert connected.is_connected
        assert device.all[-1] is not device

    def test_reconnecting_the_same_instance_logs_in_fresh(self, device, connected):
        on_disconnect = []
        connected.on_disconnect = lambda: on_disconnect.append(True)
        connected.connect(timeout=2.0)
        assert connected.is_connected
        assert device.closed
        assert device.all[-1] is not device
        assert on_disconnect == []


class TestReadWrite:
    def test_write_sends_encrypted_fields(self, device, connected):
        connected.write([TTLVField(1, TYPE_BOOL_TRUE, None)])
        assert device.sent(lc.CMD_WRITE) == [[TTLVField(1, TYPE_BOOL_TRUE, True)]]

    def test_write_and_wait_true_on_ack(self, connected):
        assert connected.write_and_wait([TTLVField(1, TYPE_BOOL_TRUE, None)], timeout=2.0)

    def test_write_and_wait_false_without_ack(self, device, connected):
        device.ack_writes = False
        assert not connected.write_and_wait([TTLVField(1, TYPE_BOOL_TRUE, None)], timeout=0.1)

    def test_write_and_wait_returns_early_when_connection_drops(self, device, connected):
        device.ack_writes = False
        later(0.05, device.hang_up)
        start = time.monotonic()
        assert not connected.write_and_wait([TTLVField(1, TYPE_BOOL_TRUE, None)], timeout=5.0)
        assert time.monotonic() - start < 2.0

    def test_concurrent_write_and_wait_each_see_an_ack(self, connected):
        results = []
        threads = [
            threading.Thread(
                target=lambda: results.append(
                    connected.write_and_wait([TTLVField(1, TYPE_BOOL_TRUE, None)], timeout=2.0)
                )
            )
            for _ in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results == [True] * 4

    def test_concurrent_write_and_wait_attributes_one_ack_to_one_caller(self, device, connected):
        device.ack_writes = 1
        device.ack_delay = 0.1  # both callers are waiting by the time the one ack lands
        start = threading.Barrier(2)
        results = []

        def write():
            start.wait()
            results.append(
                connected.write_and_wait([TTLVField(1, TYPE_BOOL_TRUE, None)], timeout=0.5)
            )

        threads = [threading.Thread(target=write) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(results) == [False, True]

    def test_write_after_disconnect_raises_connection_error(self, connected):
        connected.disconnect()
        with pytest.raises(ConnectionError):
            connected.write([TTLVField(1, TYPE_BOOL_TRUE, None)])

    def test_read_sends_untyped_id_list(self, device, connected):
        connected.read([1, 300])
        assert device.sent(lc.CMD_READ) == [b"\x00\x01\x01\x2c"]


class TestPropertyCache:
    def test_status_push_updates_properties_and_fires_on_update(self, device, connected):
        updates = []
        connected.on_update = updates.append
        device.push(lc.CMD_STATUS_PUSH_OBSERVED, [TTLVField(1, TYPE_BOOL_TRUE, None)])
        assert wait_until(lambda: updates)
        assert connected.properties == {1: True}
        assert updates == [[TTLVField(1, TYPE_BOOL_TRUE, True)]]

    def test_write_ack_does_not_touch_property_cache(self, device, connected):
        acks = []
        connected.on_write_ack = acks.append
        device.push(lc.CMD_STATUS_PUSH_OBSERVED, [TTLVField(1, TYPE_BOOL_TRUE, None)])
        # An ack reusing id=1 with an unrelated value must not clobber id=1.
        device.push(lc.CMD_WRITE_ACK, [TTLVField(1, TYPE_NUMBER, 0)])
        assert wait_until(lambda: acks)
        assert connected.properties == {1: True}
        assert acks == [[TTLVField(1, TYPE_NUMBER, 0)]]

    @pytest.mark.parametrize(
        ("payload", "encrypt"),
        [
            (b"\x00\x0b", True),  # truncated TTLV: bytes field with no length prefix
            (b"not a valid ciphertext block!!!", False),
        ],
    )
    def test_bad_frame_is_dropped_and_connection_survives(
        self, device, connected, payload, encrypt
    ):
        updates = []
        connected.on_update = updates.append
        device.push_raw(lc.CMD_STATUS_PUSH_OBSERVED, payload, encrypt=encrypt)
        device.push(lc.CMD_STATUS_PUSH_OBSERVED, [TTLVField(2, TYPE_NUMBER, 5)])
        assert wait_until(lambda: updates)
        assert connected.properties == {2: 5}
        assert connected.is_connected

    def test_callback_exception_does_not_kill_the_connection(self, device, connected):
        def boom(_fields):
            raise ValueError("boom")

        connected.on_update = boom
        device.push(lc.CMD_STATUS_PUSH_OBSERVED, [TTLVField(1, TYPE_NUMBER, 1)])
        device.push(lc.CMD_STATUS_PUSH_OBSERVED, [TTLVField(2, TYPE_NUMBER, 2)])
        assert wait_until(lambda: 2 in connected.properties)
        assert connected.is_connected

    def test_unknown_cmd_is_ignored(self, device, connected):
        device.push(9999, [TTLVField(1, TYPE_NUMBER, 1)])
        device.push(lc.CMD_STATUS_PUSH_OBSERVED, [TTLVField(2, TYPE_NUMBER, 2)])
        assert wait_until(lambda: 2 in connected.properties)
        assert connected.properties == {2: 2}


class TestReadAndWait:
    def test_returns_cached_values(self, device, connected):
        device.push(lc.CMD_STATUS_PUSH_OBSERVED, [TTLVField(1, TYPE_NUMBER, 1)])
        assert wait_until(lambda: 1 in connected.properties)
        assert connected.read_and_wait([1], timeout=0.1) == {1: 1}

    def test_waits_for_a_push(self, device, connected):
        later(0.05, device.push, lc.CMD_STATUS_PUSH_OBSERVED, [TTLVField(9, TYPE_NUMBER, 42)])
        assert connected.read_and_wait([9], timeout=2.0) == {9: 42}

    def test_partial_result_on_timeout(self, device, connected):
        device.push(lc.CMD_STATUS_PUSH_OBSERVED, [TTLVField(1, TYPE_NUMBER, 1)])
        assert wait_until(lambda: 1 in connected.properties)
        assert connected.read_and_wait([1, 2], timeout=0.1) == {1: 1}


class TestDisconnect:
    def test_remote_hang_up_fires_on_disconnect(self, device, connected):
        fired = threading.Event()
        connected.on_disconnect = fired.set
        device.hang_up()
        assert fired.wait(2.0)
        assert not connected.is_connected

    def test_socket_error_fires_on_disconnect(self, device, connected):
        fired = threading.Event()
        connected.on_disconnect = fired.set
        device.close()
        assert fired.wait(2.0)
        assert not connected.is_connected

    def test_missing_on_disconnect_callback_is_fine(self, device, connected):
        device.hang_up()
        assert wait_until(lambda: not connected.is_connected)

    def test_caller_disconnect_does_not_fire_on_disconnect(self, device, connected, timers):
        fired = []
        connected.on_disconnect = lambda: fired.append(True)
        connected.disconnect()
        time.sleep(0.1)
        assert fired == []
        assert not connected.is_connected
        assert device.closed
        assert all(t.cancelled for t in timers)


class TestHeartbeat:
    def test_sends_ping_and_reschedules(self, device, connected, timers):
        [timer] = timers
        assert timer.interval == lc.HEARTBEAT_INTERVAL
        timer.fire()
        assert device.sent(lc.CMD_HEARTBEAT_PING) == [[]]
        assert len(timers) == 2

    @pytest.mark.parametrize("stale", ["HEARTBEAT_PONG_TIMEOUT", "DATA_STALL_TIMEOUT"])
    def test_stale_pong_or_data_tears_down(self, device, connected, timers, monkeypatch, stale):
        monkeypatch.setattr(lc, stale, -1.0)
        fired = threading.Event()
        connected.on_disconnect = fired.set
        timers[0].fire()
        assert fired.wait(2.0)
        assert not connected.is_connected
        assert device.sent(lc.CMD_HEARTBEAT_PING) == []

    def test_pong_and_data_keep_the_connection_alive(self, device, connected, timers, monkeypatch):
        monkeypatch.setattr(lc, "HEARTBEAT_PONG_TIMEOUT", 0.5)
        monkeypatch.setattr(lc, "DATA_STALL_TIMEOUT", 0.5)
        time.sleep(0.6)
        device.push_raw(lc.CMD_HEARTBEAT_REPLY, b"")
        device.push(lc.CMD_STATUS_PUSH_OBSERVED, [TTLVField(1, TYPE_NUMBER, 1)])
        assert wait_until(lambda: 1 in connected.properties)
        timers[0].fire()
        assert connected.is_connected
        assert device.sent(lc.CMD_HEARTBEAT_PING) == [[]]
