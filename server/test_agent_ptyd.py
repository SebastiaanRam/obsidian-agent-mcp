#!/usr/bin/env python3
"""Protocol-level tests for agent-ptyd.py, stdlib unittest only.

Deliberately does not spawn real ptys or open real sockets — a FakeSocket
records what would be written, and Daemon's selectors.DefaultSelector is
never given a registered fd for the fakes, so its register/modify/unregister
calls (wrapped in try/except in the daemon) are harmless no-ops. That keeps
these tests fast and focused on the part most likely to be subtly wrong: the
hand-rolled WebSocket framing and the session-protocol logic around it, not
a browser round-trip.
"""

import contextlib
import importlib.util
import io
import json
import os
import struct
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location("agent_ptyd", os.path.join(_HERE, "agent-ptyd.py"))
agent_ptyd = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(agent_ptyd)


# ── helpers ──────────────────────────────────────────────────────────────────

def mask_frame(opcode, payload, fin=True, mask=b"\x01\x02\x03\x04"):
    """Build a masked client->server frame by hand (independent of
    build_ws_frame, which only builds unmasked server frames)."""
    length = len(payload)
    b0 = (0x80 if fin else 0x00) | opcode
    if length < 126:
        header = struct.pack("!BB", b0, 0x80 | length)
    elif length < 65536:
        header = struct.pack("!BBH", b0, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", b0, 0x80 | 127, length)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return header + mask + masked


class FakeSocket(object):
    def __init__(self):
        self.sent = []
        self.closed = False

    def send(self, data):
        self.sent.append(bytes(data))
        return len(data)

    def close(self):
        self.closed = True

    def fileno(self):
        return -1  # never actually registered with a real selector in tests


def make_daemon(token="s3cret", tmp_root=None):
    config = dict(agent_ptyd.DEFAULT_CONFIG)
    config["token"] = token
    config["root"] = tmp_root or tempfile.mkdtemp()
    config["backends"] = {"shell": ["/bin/sh"]}
    return agent_ptyd.Daemon(config, "/dev/null")


def make_conn(daemon, mode="ws"):
    conn = agent_ptyd.ClientConnection(FakeSocket(), ("127.0.0.1", 5555), daemon)
    conn.mode = mode
    if mode == "ws":
        conn.ws_started_at = 0.0
    daemon.connections[id(conn)] = conn
    return conn


def sent_text_messages(conn):
    """Decode every TEXT frame queued in conn's send_queue as JSON, in order."""
    out = []
    for chunk in conn._send_queue:
        opcode = chunk[0] & 0x0F
        if opcode != agent_ptyd.OP_TEXT:
            continue
        b1 = chunk[1]
        length = b1 & 0x7F
        offset = 2
        if length == 126:
            length = struct.unpack_from("!H", chunk, offset)[0]
            offset += 2
        elif length == 127:
            length = struct.unpack_from("!Q", chunk, offset)[0]
            offset += 8
        out.append(json.loads(chunk[offset:offset + length].decode("utf-8")))
    return out


def sent_binary_payloads(conn):
    """Decode every BINARY frame queued in conn's send_queue, in order."""
    out = []
    for chunk in conn._send_queue:
        opcode = chunk[0] & 0x0F
        if opcode != agent_ptyd.OP_BINARY:
            continue
        b1 = chunk[1]
        length = b1 & 0x7F
        offset = 2
        if length == 126:
            length = struct.unpack_from("!H", chunk, offset)[0]
            offset += 2
        elif length == 127:
            length = struct.unpack_from("!Q", chunk, offset)[0]
            offset += 8
        out.append(chunk[offset:offset + length])
    return out


def make_fake_session(daemon, session_id="s1", backend="shell", cwd="/tmp", cwd_rel="."):
    # Bypasses PtySession.__init__ (and therefore pty.fork()) entirely --
    # these tests exercise the protocol/buffer logic, not real process spawn.
    s = object.__new__(agent_ptyd.PtySession)
    s.id = session_id
    s.backend = backend
    s.cwd = cwd
    s.cwd_rel = cwd_rel
    s.created = 0.0
    s.client = None
    s.attach_generation = 0
    s.state = "running"
    s.exit_code = None
    s.exit_signal = None
    s.closing_since = None
    s._terminate_started = None
    s._buf = bytearray()
    s.base_offset = 0
    s.total_offset = 0
    s._pending_input = bytearray()
    s.pid = -1
    s.master_fd = None
    daemon.sessions[session_id] = s
    return s


def do_hello(conn, daemon, token="right"):
    conn._handle_control_message(json.dumps({"t": "hello", "proto": agent_ptyd.PROTOCOL_VERSION, "token": token}).encode())


# ── WS frame parsing ─────────────────────────────────────────────────────────

class ParseFrameTests(unittest.TestCase):
    def test_masked_text_frame_roundtrip(self):
        raw = mask_frame(agent_ptyd.OP_TEXT, b'{"t":"ping"}')
        frame = agent_ptyd.parse_ws_frame(raw)
        self.assertIsNotNone(frame)
        self.assertEqual(frame.opcode, agent_ptyd.OP_TEXT)
        self.assertTrue(frame.fin)
        self.assertEqual(frame.payload, b'{"t":"ping"}')
        self.assertEqual(frame.frame_len, len(raw))

    def test_extended_16bit_length(self):
        payload = b"x" * 300
        raw = mask_frame(agent_ptyd.OP_BINARY, payload)
        frame = agent_ptyd.parse_ws_frame(raw)
        self.assertEqual(frame.payload, payload)

    def test_extended_64bit_length_header_present(self):
        payload = b"y" * 70000
        raw = mask_frame(agent_ptyd.OP_BINARY, payload)
        frame = agent_ptyd.parse_ws_frame(raw)
        self.assertEqual(len(frame.payload), 70000)

    def test_incomplete_header_returns_none(self):
        self.assertIsNone(agent_ptyd.parse_ws_frame(b""))
        self.assertIsNone(agent_ptyd.parse_ws_frame(b"\x81"))

    def test_incomplete_extended_length_returns_none(self):
        # Declares a 16-bit length field but supplies zero of the two bytes.
        self.assertIsNone(agent_ptyd.parse_ws_frame(bytes([0x81, 0x80 | 126])))

    def test_incomplete_payload_returns_none(self):
        raw = mask_frame(agent_ptyd.OP_TEXT, b"hello world")
        self.assertIsNone(agent_ptyd.parse_ws_frame(raw[:-3]))

    def test_malformed_declared_length_waits_not_errors(self):
        # A 64-bit length field claiming far more than we'll ever send is
        # legal per the wire format; it's not malformed until it also
        # exceeds MAX_FRAME_PAYLOAD (covered by test_oversized_frame_rejected).
        header = struct.pack("!BBQ", 0x80 | agent_ptyd.OP_BINARY, 0x80 | 127, 1000)
        self.assertIsNone(agent_ptyd.parse_ws_frame(header + b"\x00\x00\x00\x00"))

    def test_unmasked_client_frame_rejected(self):
        raw = struct.pack("!BB", 0x80 | agent_ptyd.OP_TEXT, 5) + b"hello"
        with self.assertRaises(agent_ptyd.WSProtocolError):
            agent_ptyd.parse_ws_frame(raw)

    def test_reserved_bits_rejected(self):
        raw = bytearray(mask_frame(agent_ptyd.OP_TEXT, b"hi"))
        raw[0] |= 0x40  # set RSV1
        with self.assertRaises(agent_ptyd.WSProtocolError):
            agent_ptyd.parse_ws_frame(bytes(raw))

    def test_oversized_frame_rejected(self):
        header = struct.pack("!BBQ", 0x80 | agent_ptyd.OP_BINARY, 0x80 | 127, agent_ptyd.MAX_FRAME_PAYLOAD + 1)
        with self.assertRaises(agent_ptyd.WSProtocolError):
            agent_ptyd.parse_ws_frame(header + b"\x00\x00\x00\x00")

    def test_fragmented_control_frame_rejected(self):
        raw = struct.pack("!BB", 0x00 | agent_ptyd.OP_PING, 0x80 | 2) + b"\x00\x00\x00\x00" + b"hi"
        with self.assertRaises(agent_ptyd.WSProtocolError):
            agent_ptyd.parse_ws_frame(raw)

    def test_oversized_control_frame_rejected(self):
        raw = mask_frame(agent_ptyd.OP_PING, b"x" * 126)
        with self.assertRaises(agent_ptyd.WSProtocolError):
            agent_ptyd.parse_ws_frame(raw)


class HandshakeTests(unittest.TestCase):
    def test_accept_key_rfc6455_vector(self):
        # The example key/accept pair from RFC 6455 S1.3.
        self.assertEqual(
            agent_ptyd.compute_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        )

    def test_upgrade_produces_101_with_accept_key(self):
        daemon = make_daemon()
        conn = make_conn(daemon, mode="http")
        headers = {
            "upgrade": "websocket", "connection": "Upgrade",
            "sec-websocket-version": "13", "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
        }
        conn._handle_ws_upgrade(headers)
        self.assertEqual(conn.mode, "ws")
        raw = b"".join(conn._send_queue)
        self.assertIn(b"101 Switching Protocols", raw)
        self.assertIn(b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", raw)

    def test_upgrade_rejects_wrong_version(self):
        daemon = make_daemon()
        conn = make_conn(daemon, mode="http")
        headers = {
            "upgrade": "websocket", "connection": "Upgrade",
            "sec-websocket-version": "8", "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
        }
        conn._handle_ws_upgrade(headers)
        self.assertEqual(conn.mode, "http")
        raw = b"".join(conn._send_queue)
        self.assertIn(b"400", raw)


# ── control protocol (hello / attach / resync / steal-over) ─────────────────

class ControlProtocolTests(unittest.TestCase):
    def test_hello_wrong_token_closes_connection(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        do_hello(conn, daemon, token="wrong")
        self.assertTrue(conn.closed)
        self.assertFalse(conn.authenticated)

    def test_hello_correct_token_authenticates(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        do_hello(conn, daemon, token="right")
        self.assertFalse(conn.closed)
        self.assertTrue(conn.authenticated)
        msgs = sent_text_messages(conn)
        self.assertEqual(msgs[-1], {"t": "hello_ok", "proto": agent_ptyd.PROTOCOL_VERSION})

    def test_hello_wrong_protocol_version_closes(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        conn._handle_control_message(json.dumps({"t": "hello", "proto": 99, "token": "right"}).encode())
        self.assertTrue(conn.closed)

    def test_binary_before_attach_is_protocol_error(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_binary_message(b"echo hi\n")
        self.assertTrue(conn.closed)

    def test_attach_unknown_backend(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "backend": "nope", "cwd": ".", "cols": 80, "rows": 24}
        ).encode())
        self.assertFalse(conn.closed)
        self.assertEqual(sent_text_messages(conn)[-1]["code"], "unknown_backend")

    def test_attach_invalid_size(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "backend": "shell", "cwd": ".", "cols": 0, "rows": 24}
        ).encode())
        self.assertEqual(sent_text_messages(conn)[-1]["code"], "invalid_size")

    def test_attach_cwd_escape_rejected(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "backend": "shell", "cwd": "../../etc", "cols": 80, "rows": 24}
        ).encode())
        self.assertEqual(sent_text_messages(conn)[-1]["code"], "invalid_cwd")

    def test_attach_to_existing_session_backend_mismatch(self):
        daemon = make_daemon(token="right")
        session = make_fake_session(daemon, backend="shell", cwd=daemon.config["root"], cwd_rel=".")
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "session_id": session.id, "backend": "shell", "cwd": "somewhere-else", "cols": 80, "rows": 24}
        ).encode())
        self.assertEqual(sent_text_messages(conn)[-1]["code"], "invalid_cwd")

    def test_reattach_mismatched_backend_rejected(self):
        daemon = make_daemon(token="right")
        daemon.backends["other"] = {"argv": ["/bin/sh"], "label": "Other"}
        session = make_fake_session(daemon, backend="shell", cwd=daemon.config["root"], cwd_rel=".")
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "session_id": session.id, "backend": "other", "cwd": ".", "cols": 80, "rows": 24}
        ).encode())
        self.assertEqual(sent_text_messages(conn)[-1]["code"], "attach_mismatch")
        self.assertIsNone(conn.session)

    def test_resync_required_buffer_expired(self):
        daemon = make_daemon(token="right")
        session = make_fake_session(daemon, cwd=daemon.config["root"])
        # Simulate the ring buffer having trimmed old data: base_offset > 0.
        session._buf = bytearray(b"tail-data")
        session.base_offset = 1000
        session.total_offset = 1000 + len(session._buf)
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "session_id": session.id, "backend": "shell", "cwd": ".", "cols": 80, "rows": 24, "last_seq": 5}
        ).encode())
        msgs = sent_text_messages(conn)
        kinds = [m["t"] for m in msgs]
        self.assertIn("attach_ok", kinds)
        resync = [m for m in msgs if m["t"] == "resync_required"][0]
        self.assertEqual(resync["reason"], "buffer_expired")

    def test_resync_required_invalid_seq(self):
        daemon = make_daemon(token="right")
        session = make_fake_session(daemon, cwd=daemon.config["root"])
        session.total_offset = 10
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "session_id": session.id, "backend": "shell", "cwd": ".", "cols": 80, "rows": 24, "last_seq": 999}
        ).encode())
        resync = [m for m in sent_text_messages(conn) if m["t"] == "resync_required"][0]
        self.assertEqual(resync["reason"], "invalid_seq")

    def test_attach_replays_buffered_output(self):
        daemon = make_daemon(token="right")
        session = make_fake_session(daemon, cwd=daemon.config["root"])
        session._buf = bytearray(b"hello world")
        session.total_offset = len(session._buf)
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "session_id": session.id, "backend": "shell", "cwd": ".", "cols": 80, "rows": 24, "last_seq": 0}
        ).encode())
        binary_payloads = []
        for chunk in conn._send_queue:
            if (chunk[0] & 0x0F) == agent_ptyd.OP_BINARY:
                length = chunk[1] & 0x7F
                binary_payloads.append(chunk[2:2 + length])
        self.assertEqual(b"".join(binary_payloads), b"hello world")

    def test_steal_over_generation_guard(self):
        """Two clients attach to the same session in sequence; the first
        client's (delayed) close handler must not clear the second client's
        attachment. This is the concurrency guard the daemon relies on to
        implement single-attachment-at-a-time semantics safely."""
        daemon = make_daemon(token="right")
        session = make_fake_session(daemon, cwd=daemon.config["root"])

        conn1 = make_conn(daemon)
        do_hello(conn1, daemon)
        conn1._handle_control_message(json.dumps(
            {"t": "attach", "session_id": session.id, "backend": "shell", "cwd": ".", "cols": 80, "rows": 24}
        ).encode())
        self.assertIs(session.client, conn1)
        self.assertTrue(conn1.closed is False)

        conn2 = make_conn(daemon)
        do_hello(conn2, daemon)
        conn2._handle_control_message(json.dumps(
            {"t": "attach", "session_id": session.id, "backend": "shell", "cwd": ".", "cols": 80, "rows": 24}
        ).encode())

        # conn2 is now attached, and conn1 has been forcibly closed as part
        # of the steal-over.
        self.assertIs(session.client, conn2)
        self.assertTrue(conn1.closed)

        # A close handler firing late for conn1 (as if the OS only reported
        # its socket close after conn2 had already taken over) must not
        # clear conn2's attachment.
        daemon.on_connection_closed(conn1)
        self.assertIs(session.client, conn2)

    def test_resize_before_attach_rejected(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps({"t": "resize", "cols": 80, "rows": 24}).encode())
        self.assertEqual(sent_text_messages(conn)[-1]["code"], "not_attached")

    def test_unauthenticated_control_message_other_than_hello_closes(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        conn._handle_control_message(json.dumps({"t": "resize", "cols": 80, "rows": 24}).encode())
        self.assertTrue(conn.closed)


class FragmentationTests(unittest.TestCase):
    def test_fragmented_message_reassembled(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        payload = json.dumps({"t": "hello", "proto": agent_ptyd.PROTOCOL_VERSION, "token": "right"}).encode("utf-8")
        first, second = payload[:5], payload[5:]
        conn._recv_buf.extend(mask_frame(agent_ptyd.OP_TEXT, first, fin=False))
        conn._recv_buf.extend(mask_frame(agent_ptyd.OP_CONTINUATION, second, fin=True))
        conn._consume_frames()
        self.assertTrue(conn.authenticated)
        self.assertEqual(sent_text_messages(conn)[-1]["t"], "hello_ok")

    def test_control_frame_between_fragments_is_handled_immediately(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        payload = json.dumps({"t": "hello", "proto": agent_ptyd.PROTOCOL_VERSION, "token": "right"}).encode("utf-8")
        first, second = payload[:5], payload[5:]
        conn._recv_buf.extend(mask_frame(agent_ptyd.OP_TEXT, first, fin=False))
        conn._recv_buf.extend(mask_frame(agent_ptyd.OP_PING, b"ping-mid-fragment"))
        conn._recv_buf.extend(mask_frame(agent_ptyd.OP_CONTINUATION, second, fin=True))
        conn._consume_frames()
        self.assertTrue(conn.authenticated)
        # A PONG (raw WS frame, not a JSON control message) should have been
        # queued for the PING, in addition to hello_ok.
        pong_opcodes = [c[0] & 0x0F for c in conn._send_queue if (c[0] & 0x0F) == agent_ptyd.OP_PONG]
        self.assertEqual(len(pong_opcodes), 1)

    def test_message_exceeding_max_bytes_closes_connection(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        big = b"x" * (agent_ptyd.MAX_MESSAGE_BYTES // 2 + 100)
        conn._recv_buf.extend(mask_frame(agent_ptyd.OP_BINARY, big, fin=False))
        conn._recv_buf.extend(mask_frame(agent_ptyd.OP_CONTINUATION, big, fin=True))
        conn._consume_frames()
        self.assertTrue(conn.closed)

    def test_continuation_without_start_closes(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon)
        conn._recv_buf.extend(mask_frame(agent_ptyd.OP_CONTINUATION, b"orphan", fin=True))
        conn._consume_frames()
        self.assertTrue(conn.closed)


class CwdResolutionTests(unittest.TestCase):
    def test_relative_cwd_within_root(self):
        root = tempfile.mkdtemp()
        os.makedirs(os.path.join(root, "proj"))
        canon, rel = agent_ptyd.resolve_session_cwd(root, "proj")
        self.assertEqual(canon, os.path.realpath(os.path.join(root, "proj")))
        self.assertEqual(rel, "proj")

    def test_default_cwd_is_root(self):
        root = tempfile.mkdtemp()
        canon, rel = agent_ptyd.resolve_session_cwd(root, "")
        self.assertEqual(canon, os.path.realpath(root))
        self.assertEqual(rel, ".")

    def test_escape_via_dotdot_rejected(self):
        root = tempfile.mkdtemp()
        with self.assertRaises(ValueError):
            agent_ptyd.resolve_session_cwd(root, "../../etc")

    def test_absolute_path_rejected(self):
        root = tempfile.mkdtemp()
        with self.assertRaises(ValueError):
            agent_ptyd.resolve_session_cwd(root, "/etc")

    def test_nonexistent_dir_rejected(self):
        root = tempfile.mkdtemp()
        with self.assertRaises(ValueError):
            agent_ptyd.resolve_session_cwd(root, "does-not-exist")


class SessionsHttpTests(unittest.TestCase):
    def test_sessions_requires_bearer_token(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon, mode="http")
        conn._handle_sessions({})
        raw = b"".join(conn._send_queue)
        self.assertIn(b"401", raw)

    def test_sessions_with_valid_bearer_token(self):
        daemon = make_daemon(token="right")
        make_fake_session(daemon, cwd=daemon.config["root"])
        conn = make_conn(daemon, mode="http")
        conn._handle_sessions({"authorization": "Bearer right"})
        raw = b"".join(conn._send_queue)
        self.assertIn(b"200", raw)
        self.assertIn(b'"backend": "shell"'.replace(b" ", b""), raw.replace(b" ", b""))


# ── auth-failure rate limiting ───────────────────────────────────────────────

class RateLimitTests(unittest.TestCase):
    def test_rate_limit_key_defaults_to_global(self):
        daemon = make_daemon()
        conn = make_conn(daemon)
        self.assertEqual(daemon.rate_limit_key(conn), "*")

    def test_rate_limit_key_uses_forwarded_header_when_configured(self):
        daemon = make_daemon()
        daemon.config["auth_rate_limit_header"] = "x-forwarded-for"
        conn = make_conn(daemon)
        conn.http_headers = {"x-forwarded-for": "1.2.3.4, 127.0.0.1"}
        self.assertEqual(daemon.rate_limit_key(conn), "1.2.3.4")

    def test_rate_limit_key_falls_back_to_global_without_header_value(self):
        daemon = make_daemon()
        daemon.config["auth_rate_limit_header"] = "x-forwarded-for"
        conn = make_conn(daemon)
        conn.http_headers = {}
        self.assertEqual(daemon.rate_limit_key(conn), "*")

    def test_global_bucket_tolerates_a_few_failures(self):
        # A handful of typos/retries from the one real client (spread across
        # however many connections a flaky app makes) must not lock it out.
        daemon = make_daemon(token="right")
        for _ in range(agent_ptyd.AUTH_FAIL_MAX - 1):
            conn = make_conn(daemon)
            do_hello(conn, daemon, token="wrong")
        conn = make_conn(daemon)
        do_hello(conn, daemon, token="right")
        self.assertTrue(conn.authenticated)

    def test_global_bucket_trips_after_max_failures(self):
        daemon = make_daemon(token="right")
        for _ in range(agent_ptyd.AUTH_FAIL_MAX):
            conn = make_conn(daemon)
            do_hello(conn, daemon, token="wrong")
        conn = make_conn(daemon)
        do_hello(conn, daemon, token="right")
        self.assertFalse(conn.authenticated)

    def test_forwarded_header_isolates_buckets_between_clients(self):
        # With per-client keying opted in, one abusive client tripping the
        # limiter must not affect a different client's bucket.
        daemon = make_daemon(token="right")
        daemon.config["auth_rate_limit_header"] = "x-forwarded-for"

        for _ in range(agent_ptyd.AUTH_FAIL_MAX):
            conn = make_conn(daemon)
            conn.http_headers = {"x-forwarded-for": "1.2.3.4"}
            do_hello(conn, daemon, token="wrong")

        blocked = make_conn(daemon)
        blocked.http_headers = {"x-forwarded-for": "1.2.3.4"}
        do_hello(blocked, daemon, token="right")
        self.assertFalse(blocked.authenticated)

        other = make_conn(daemon)
        other.http_headers = {"x-forwarded-for": "9.9.9.9"}
        do_hello(other, daemon, token="right")
        self.assertTrue(other.authenticated)


# ── Origin allow-listing ─────────────────────────────────────────────────────

class OriginTests(unittest.TestCase):
    def test_default_permissive_allows_any_origin(self):
        daemon = make_daemon()
        conn = make_conn(daemon, mode="http")
        self.assertTrue(conn._origin_ok({"origin": "app://obsidian.md"}))
        self.assertTrue(conn._origin_ok({"origin": "https://totally-unexpected.example"}))
        self.assertTrue(conn._origin_ok({}))

    def test_default_permissive_logs_received_origin(self):
        daemon = make_daemon()
        conn = make_conn(daemon, mode="http")
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            conn._origin_ok({"origin": "app://obsidian.md"})
        self.assertIn("app://obsidian.md", buf.getvalue())

    def test_no_origin_header_is_not_logged(self):
        daemon = make_daemon()
        conn = make_conn(daemon, mode="http")
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            conn._origin_ok({})
        self.assertEqual(buf.getvalue(), "")

    def test_explicit_allowlist_enforced(self):
        daemon = make_daemon()
        daemon.config["allowed_origins"] = ["app://obsidian.md"]
        conn = make_conn(daemon, mode="http")
        self.assertTrue(conn._origin_ok({"origin": "app://obsidian.md"}))
        self.assertFalse(conn._origin_ok({"origin": "https://evil.example"}))

    def test_explicit_empty_allowlist_still_permits_absent_origin(self):
        daemon = make_daemon()
        daemon.config["allowed_origins"] = []
        conn = make_conn(daemon, mode="http")
        self.assertTrue(conn._origin_ok({}))
        self.assertFalse(conn._origin_ok({"origin": "app://obsidian.md"}))

    def test_warn_if_permissive_origin_warns_by_default(self):
        config = dict(agent_ptyd.DEFAULT_CONFIG)
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            agent_ptyd.warn_if_permissive_origin(config)
        self.assertIn("WARNING", buf.getvalue())

    def test_warn_if_permissive_origin_silent_once_configured(self):
        config = dict(agent_ptyd.DEFAULT_CONFIG)
        config["allowed_origins"] = ["app://obsidian.md"]
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            agent_ptyd.warn_if_permissive_origin(config)
        self.assertEqual(buf.getvalue(), "")


# ── fresh-attach truncated-history replay ────────────────────────────────────

class TruncatedHistoryTests(unittest.TestCase):
    def test_fresh_attach_full_history_not_truncated(self):
        # base_offset stays 0 -- nothing has been trimmed, so this *is* the
        # complete, faithful history: no clear, no truncation flag.
        daemon = make_daemon(token="right")
        session = make_fake_session(daemon, cwd=daemon.config["root"])
        session._buf = bytearray(b"hello world")
        session.total_offset = len(session._buf)
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "backend": "shell", "cwd": ".", "session_id": session.id, "cols": 80, "rows": 24}
        ).encode())
        attach_ok = [m for m in sent_text_messages(conn) if m["t"] == "attach_ok"][0]
        self.assertFalse(attach_ok["truncated_history"])
        # base_offset is 0, so the replay starts at the true beginning.
        self.assertEqual(attach_ok["seq"], 0)
        payloads = sent_binary_payloads(conn)
        self.assertNotIn(agent_ptyd.CLEAR_SCREEN_SEQUENCE, payloads)
        self.assertEqual(b"".join(payloads), b"hello world")

    def test_fresh_attach_trimmed_buffer_is_cleared_and_flagged(self):
        daemon = make_daemon(token="right")
        session = make_fake_session(daemon, cwd=daemon.config["root"])
        # Simulate the ring buffer having trimmed old data at an arbitrary
        # raw-byte boundary (as it would mid-UTF-8 or mid-escape in practice).
        session._buf = bytearray(b"\x9f-mid-sequence-tail")
        session.base_offset = 5000
        session.total_offset = session.base_offset + len(session._buf)
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "backend": "shell", "cwd": ".", "session_id": session.id, "cols": 80, "rows": 24}
        ).encode())
        msgs = sent_text_messages(conn)
        attach_ok = [m for m in msgs if m["t"] == "attach_ok"][0]
        self.assertTrue(attach_ok["truncated_history"])
        # The client never learns base_offset any other way -- this is what
        # it must seed its own sequence counter from to stay exact on a
        # later reconnect (see the comment on this field in _handle_attach).
        self.assertEqual(attach_ok["seq"], 5000)
        self.assertNotIn("resync_required", [m["t"] for m in msgs])
        payloads = sent_binary_payloads(conn)
        self.assertEqual(payloads[0], agent_ptyd.CLEAR_SCREEN_SEQUENCE)
        self.assertEqual(b"".join(payloads[1:]), bytes(session._buf))

    def test_resume_attach_ok_seq_matches_requested_last_seq(self):
        daemon = make_daemon(token="right")
        session = make_fake_session(daemon, cwd=daemon.config["root"])
        session._buf = bytearray(b"continuation")
        session.base_offset = 200
        session.total_offset = session.base_offset + len(session._buf)
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "backend": "shell", "cwd": ".", "session_id": session.id, "cols": 80, "rows": 24, "last_seq": 200}
        ).encode())
        attach_ok = [m for m in sent_text_messages(conn) if m["t"] == "attach_ok"][0]
        self.assertFalse(attach_ok["truncated_history"])
        self.assertEqual(attach_ok["seq"], 200)
        self.assertEqual(b"".join(sent_binary_payloads(conn)), b"continuation")

    def test_explicit_last_seq_zero_is_strict_resume_not_fresh(self):
        # last_seq: 0 explicitly (unlike an omitted last_seq) means "I've
        # truly applied zero bytes" -- if the buffer has since trimmed past
        # byte 0 this must resync, never silently substitute a truncated
        # replay for what was asked as an exact resume.
        daemon = make_daemon(token="right")
        session = make_fake_session(daemon, cwd=daemon.config["root"])
        session._buf = bytearray(b"tail-only")
        session.base_offset = 100
        session.total_offset = session.base_offset + len(session._buf)
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "backend": "shell", "cwd": ".", "session_id": session.id, "cols": 80, "rows": 24, "last_seq": 0}
        ).encode())
        msgs = sent_text_messages(conn)
        resync = [m for m in msgs if m["t"] == "resync_required"]
        self.assertEqual(len(resync), 1)
        self.assertEqual(resync[0]["reason"], "buffer_expired")
        attach_ok = [m for m in msgs if m["t"] == "attach_ok"][0]
        self.assertFalse(attach_ok["truncated_history"])
        self.assertEqual(sent_binary_payloads(conn), [])

    def test_fresh_attach_on_brand_new_session_not_truncated(self):
        daemon = make_daemon(token="right")
        fake = make_fake_session(daemon, session_id="new1", cwd=daemon.config["root"])
        daemon.create_session = lambda backend, canon, rel, cols, rows: fake
        conn = make_conn(daemon)
        do_hello(conn, daemon)
        conn._handle_control_message(json.dumps(
            {"t": "attach", "backend": "shell", "cwd": ".", "cols": 80, "rows": 24}
        ).encode())
        attach_ok = [m for m in sent_text_messages(conn) if m["t"] == "attach_ok"][0]
        self.assertFalse(attach_ok["truncated_history"])
        self.assertEqual(sent_binary_payloads(conn), [])


# ── backend normalization ────────────────────────────────────────────────────

class NormalizeBackendsTests(unittest.TestCase):
    def test_legacy_argv_list_gets_a_derived_label(self):
        out = agent_ptyd.normalize_backends({"claude_code": ["/usr/bin/claude"]})
        self.assertEqual(out, {"claude_code": {"argv": ["/usr/bin/claude"], "label": "Claude Code"}})

    def test_explicit_label_is_kept(self):
        out = agent_ptyd.normalize_backends({"shell": {"argv": ["/bin/sh"], "label": "Plain Shell"}})
        self.assertEqual(out["shell"]["label"], "Plain Shell")

    def test_object_form_without_label_still_derives_one(self):
        out = agent_ptyd.normalize_backends({"shell": {"argv": ["/bin/sh"]}})
        self.assertEqual(out["shell"]["label"], "Shell")

    def test_rejects_empty_argv(self):
        with self.assertRaises(ValueError):
            agent_ptyd.normalize_backends({"shell": []})

    def test_rejects_non_string_argv_entries(self):
        with self.assertRaises(ValueError):
            agent_ptyd.normalize_backends({"shell": ["/bin/sh", 123]})

    def test_rejects_empty_backends(self):
        with self.assertRaises(ValueError):
            agent_ptyd.normalize_backends({})


# ── GET /info ────────────────────────────────────────────────────────────────

class InfoHttpTests(unittest.TestCase):
    def test_info_requires_bearer_token(self):
        daemon = make_daemon(token="right")
        conn = make_conn(daemon, mode="http")
        conn._handle_info({})
        raw = b"".join(conn._send_queue)
        self.assertIn(b"401", raw)

    def test_info_with_valid_bearer_token(self):
        daemon = make_daemon(token="right")
        daemon.config["backends"] = {"shell": {"argv": ["/bin/sh"], "label": "Shell"}, "claude": {"argv": ["/usr/bin/claude"], "label": "Claude Code"}}
        daemon.backends = agent_ptyd.normalize_backends(daemon.config["backends"])
        conn = make_conn(daemon, mode="http")
        conn._handle_info({"authorization": "Bearer right"})
        raw = b"".join(conn._send_queue)
        self.assertIn(b"200", raw)
        body = raw.split(b"\r\n\r\n", 1)[1]
        payload = json.loads(body)
        self.assertEqual(payload["protocol_version"], agent_ptyd.PROTOCOL_VERSION)
        self.assertEqual(
            payload["backends"],
            [{"id": "claude", "label": "Claude Code"}, {"id": "shell", "label": "Shell"}],
        )
        self.assertEqual(payload["max_sessions"], daemon.config["max_sessions"])
        self.assertEqual(payload["session_create_rate_per_min"], daemon.config["session_create_rate_per_min"])

    def test_info_never_leaks_argv(self):
        daemon = make_daemon(token="right")
        daemon.config["backends"] = {"shell": ["/very/secret/internal/path/sh"]}
        daemon.backends = agent_ptyd.normalize_backends(daemon.config["backends"])
        conn = make_conn(daemon, mode="http")
        conn._handle_info({"authorization": "Bearer right"})
        raw = b"".join(conn._send_queue)
        self.assertNotIn(b"/very/secret/internal/path/sh", raw)

    def test_info_respects_origin_allowlist(self):
        daemon = make_daemon(token="right")
        daemon.config["allowed_origins"] = ["app://obsidian.md"]
        conn = make_conn(daemon, mode="http")
        conn._handle_info({"authorization": "Bearer right", "origin": "https://evil.example"})
        raw = b"".join(conn._send_queue)
        self.assertIn(b"403", raw)


if __name__ == "__main__":
    unittest.main()
