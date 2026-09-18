#!/usr/bin/env python3
"""Remote PTY daemon for the Obsidian Agent MCP plugin (server/agent-ptyd.py).

Runs on a machine where coding agents (claude, codex, ...) are installed and
lets a remote client (the plugin's mobile/remote terminal backend) attach to
long-lived terminal sessions over a WebSocket. A session is one pty + one cwd
+ one backend, owned by this daemon; it outlives any single client
connection, so you can disconnect a phone, walk away, and reattach later to
the same running agent. Standard library only, Python 3.9+, POSIX (Linux/
macOS) only — like src/terminal/bridge.py, it needs pty.fork().

SECURITY — READ THIS BEFORE EXPOSING THIS PROCESS TO A NETWORK
  `root` in the config bounds only the *initial* working directory offered to
  a new session. It is NOT a sandbox: a shell or agent started under it can
  `cd` anywhere, read/write anything, and spawn anything the OS user running
  this daemon can. Anyone holding the auth token can execute arbitrary
  commands as that user. There is no per-session isolation (no containers,
  no chroot, no seccomp). Run this as a dedicated, unprivileged OS user with
  only the access you're willing to hand to holders of the token, keep it
  bound to loopback and reach it through your own tunnel/VPN/SSH port
  forward, and treat the token file (0600, printed once) like a password.

PROTOCOL
  Transport is a single hand-rolled WebSocket endpoint at /attach, plus a
  plain authenticated HTTP GET /sessions for listing and GET /info for the
  daemon's capabilities (protocol version, backend ids/labels, session
  limits — never backend argv). The WebSocket framing
  deliberately implements a narrow RFC 6455 subset — no compression, no
  extensions, every client frame must be masked, control frames can't be
  fragmented — mirroring the framing decisions in ../src/main.ts
  (parseFrame/makeFrame); keep the two in sync if either changes. Binary
  frames carry raw pty bytes; text frames carry JSON control messages:

    client -> server
      hello    {t, proto, token}
      attach   {t, session_id?, backend, cwd, cols, rows, last_seq?}
      resize   {t, cols, rows}
      terminate{t}
      ping     {t, ts}
      pong     {t, ts}
    server -> client
      hello_ok        {t, proto}
      attach_ok       {t, session_id, backend, cwd, cols, rows, created, resumed, truncated_history, seq}
      exit            {t, session_id, code, signal}
      resync_required {t, reason}   # "buffer_expired" | "invalid_seq"
      error           {t, code, message}
      ping / pong     {t, ts}

  Session output is one ordered byte stream per session; "sequence number"
  is just the cumulative byte offset into that stream, which makes resume
  trivial (a slice) and doesn't require tagging every frame. The daemon
  retains the last ~256KB of each session's output. Attaching with an
  explicit `last_seq` is a byte-aligned resume: if it's older than what's
  retained (or newer than we've ever sent) that gets resync_required instead
  of a silent partial replay. Attaching with no `last_seq` at all is treated
  as a fresh client with no prior position — it gets whatever scrollback is
  still retained, but if the buffer has trimmed anything that replay starts
  at an arbitrary raw-byte boundary (mid-UTF-8, mid-escape), so it's
  preceded by a terminal-clear sequence and flagged `truncated_history` in
  attach_ok rather than presented as a faithful, complete screen. attach_ok's
  `seq` is the absolute offset that replay starts at (not total_offset) —
  a client seeds its own counter from it, then increments per byte received
  (skipping the clear sequence), so a later exact reconnect stays accurate
  even though the client never learns base_offset any other way. WebSocket-
  level PING/PONG frames exist for browsers (which auto-reply to a server
  PING) but nothing lets browser JS *send* one, and a non-browser client may
  not implement WS ping/pong at all — so liveness is also checked with the
  JSON ping/pong pair above, in both directions.
"""

import argparse
import base64
import collections
import errno
import fcntl
import hashlib
import hmac
import json
import os
import posixpath
import pty
import secrets
import selectors
import signal
import socket
import struct
import sys
import termios
import time
import traceback
import uuid

# ── Tunable limits ───────────────────────────────────────────────────────────
# Every one of these exists so a misbehaving or hostile client can only ever
# cost this process a bounded amount of memory/fds/CPU, never an unbounded
# amount — see the backpressure and session-limit code below for how each is
# enforced.

PROTOCOL_VERSION = 1

MAX_FRAME_PAYLOAD = 1 * 1024 * 1024          # hard cap on one WS frame
MAX_MESSAGE_BYTES = 2 * 1024 * 1024          # cap on a defragmented WS message
OUTPUT_BUFFER_CAP = 256 * 1024               # per-session replay buffer
OUTPUT_CHUNK_BYTES = 64 * 1024               # coalesced-output frame size
MAX_CLIENT_QUEUE_BYTES = 4 * 1024 * 1024     # per-connection outbound cap
MAX_SESSION_INPUT_QUEUE = 256 * 1024         # per-session pty-input cap
MAX_HTTP_HEADER_BYTES = 8 * 1024

DEFAULT_MAX_SESSIONS = 64
DEFAULT_SESSION_CREATE_RATE_PER_MIN = 30

TERMINATE_GRACE_SECONDS = 3.0                # SIGTERM -> SIGKILL escalation
CLOSING_REAP_TIMEOUT = 10.0                  # fd EOF'd but pid never reaped
AUTH_TIMEOUT_SECONDS = 5.0                   # deadline to send `hello`
HEARTBEAT_INTERVAL_SECONDS = 15.0
HEARTBEAT_TIMEOUT_SECONDS = 45.0
TICK_INTERVAL_SECONDS = 0.5

AUTH_FAIL_WINDOW_SECONDS = 60.0
AUTH_FAIL_MAX = 20
AUTH_BLOCK_SECONDS = 30.0
# See Daemon.rate_limit_key / check_token for why these are sized generously
# and, by default, shared across all clients rather than split per-IP.

DEFAULT_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".config", "agent-ptyd", "config.json")


# ── Config ───────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "root": os.path.join(os.path.expanduser("~"), "agent-ptyd-sessions"),
    "backends": {"shell": [os.environ.get("SHELL", "/bin/bash"), "-l"]},
    "token": None,
    "host": "127.0.0.1",
    "port": 8765,
    # None = permissive: accept (and log) any Origin, since the real value a
    # legitimate client sends isn't known up front — see _origin_ok. Set to a
    # list to enforce an allow-list; [] enforces "no Origin header at all".
    "allowed_origins": None,
    # None = one global auth-failure bucket (the safe default for a daemon
    # reached only through a reverse proxy, where every connection appears to
    # come from the same loopback address). Set to a header name (e.g.
    # "x-forwarded-for") to bucket by that header's value instead — see
    # Daemon.rate_limit_key for the trust tradeoff that requires.
    "auth_rate_limit_header": None,
    "max_sessions": DEFAULT_MAX_SESSIONS,
    "session_create_rate_per_min": DEFAULT_SESSION_CREATE_RATE_PER_MIN,
}


def load_config(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("%s must contain a JSON object" % path)
        config = dict(DEFAULT_CONFIG)
        config.update(data)
    else:
        config = dict(DEFAULT_CONFIG)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    changed = not os.path.exists(path)
    if not config.get("token"):
        config["token"] = secrets.token_hex(32)
        changed = True
        sys.stderr.write(
            "agent-ptyd: generated a new auth token (shown once):\n\n"
            "    %s\n\n"
            "It has been saved to %s (mode 0600) — clients need it to\n"
            "connect. Back it up; it will not be printed again.\n\n" % (config["token"], path)
        )

    os.makedirs(config["root"], exist_ok=True)

    if changed:
        with open(path, "w") as f:
            json.dump(config, f, indent=2)
        os.chmod(path, 0o600)
    return config


def normalize_backends(raw):
    """Accepts either the legacy `{id: [argv...]}` config shape or the
    richer `{id: {"argv": [...], "label": "..."}}` one, and returns the
    latter uniformly — this is what Daemon.backends holds, and what /info
    reports (id + label only; argv never leaves the process, see
    ClientConnection._handle_info). `label` defaults to a title-cased id
    when not given, so the legacy shape keeps working unlabeled."""
    if not isinstance(raw, dict) or not raw:
        raise ValueError("config.backends must be a non-empty object of id -> argv (or {argv, label})")
    out = {}
    for backend_id, spec in raw.items():
        if isinstance(spec, list):
            argv, label = spec, None
        elif isinstance(spec, dict):
            argv, label = spec.get("argv"), spec.get("label")
        else:
            raise ValueError("config.backends[%r] must be an argv list or an {argv, label} object" % backend_id)
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise ValueError("config.backends[%r] must have a non-empty argv list of strings" % backend_id)
        if not label:
            label = backend_id.replace("_", " ").replace("-", " ").title()
        out[backend_id] = {"argv": argv, "label": label}
    return out


def validate_backends(backends):
    normalized = normalize_backends(backends)
    for backend_id, meta in normalized.items():
        if not os.path.isabs(meta["argv"][0]):
            sys.stderr.write(
                "agent-ptyd: WARNING: backend %r command %r is not an absolute\n"
                "path — this daemon's PATH (especially under systemd) may not\n"
                "match your login shell's PATH.\n" % (backend_id, meta["argv"][0])
            )


def warn_if_public_bind(config):
    if config["host"] not in ("127.0.0.1", "::1", "localhost"):
        sys.stderr.write(
            "agent-ptyd: WARNING: binding to %s, not loopback. Anyone who can\n"
            "reach this address AND the auth token can run arbitrary commands\n"
            "as this process's user (see the module docstring's SECURITY\n"
            "section). Prefer a loopback bind plus your own tunnel/VPN/SSH\n"
            "port forward unless you specifically intend to expose this on\n"
            "the network.\n" % config["host"]
        )


def warn_if_permissive_origin(config):
    if config.get("allowed_origins") is None:
        sys.stderr.write(
            "agent-ptyd: WARNING: allowed_origins is not configured, so every\n"
            "WebSocket Origin will be accepted (each one is logged as it\n"
            "arrives). This is deliberately permissive: the Obsidian desktop\n"
            "webview sends Origin: app://obsidian.md, but the mobile webview\n"
            "may send something else or omit Origin entirely, and rejecting\n"
            "the only legitimate client by guessing wrong is worse than not\n"
            "enforcing yet. Once you've seen the real value(s) in this log,\n"
            "set allowed_origins to that list to tighten this.\n"
        )


# ── WebSocket framing ────────────────────────────────────────────────────────
#
# Hand-rolled RFC 6455 framing, deliberately narrow: RSV1-3 must be 0 (we
# negotiate no extensions, so a set reserved bit can only mean a client is
# assuming one we didn't agree to), every client->server frame must be
# masked (RFC 6455 S5.1 — a server MUST close the connection on an unmasked
# client frame, not lenient-accept it), and control frames can never be
# fragmented or exceed 125 bytes. Server->client frames are always a single
# complete (FIN=1), unmasked frame — we never emit fragmented messages, so
# outgoing framing doesn't need the reassembly machinery incoming framing
# does. This mirrors the framing in ../src/main.ts (parseFrame/makeFrame);
# keep the two in sync if either changes.

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA
_CONTROL_OPCODES = (OP_CLOSE, OP_PING, OP_PONG)


class WSProtocolError(Exception):
    """The peer violated the narrow subset above; the connection must close
    (RFC 6455 close code 1002)."""


class WSFrame(object):
    __slots__ = ("opcode", "fin", "payload", "frame_len")

    def __init__(self, opcode, fin, payload, frame_len):
        self.opcode = opcode
        self.fin = fin
        self.payload = payload
        self.frame_len = frame_len


def parse_ws_frame(buf):
    """Parse one frame from the front of `buf` (bytes-like, not consumed).

    Returns a WSFrame, or None if `buf` doesn't yet hold a complete frame —
    the caller should wait for more data and retry. Raises WSProtocolError
    for anything the subset above rejects outright. Length checks happen as
    soon as the length field itself is parsed, before waiting for that much
    payload to arrive, so an oversized-length frame can't be used to make us
    buffer unbounded data first.
    """
    if len(buf) < 2:
        return None
    b0, b1 = buf[0], buf[1]
    fin = bool(b0 & 0x80)
    rsv = b0 & 0x70
    opcode = b0 & 0x0F
    if rsv != 0:
        raise WSProtocolError("reserved bits set (no extensions supported)")
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    offset = 2
    if length == 126:
        if len(buf) < offset + 2:
            return None
        length = struct.unpack_from("!H", buf, offset)[0]
        offset += 2
    elif length == 127:
        if len(buf) < offset + 8:
            return None
        length = struct.unpack_from("!Q", buf, offset)[0]
        offset += 8
    if length > MAX_FRAME_PAYLOAD:
        raise WSProtocolError("frame payload too large (%d bytes)" % length)
    if not masked:
        raise WSProtocolError("client frame must be masked")
    if opcode in _CONTROL_OPCODES and (not fin or length > 125):
        raise WSProtocolError("control frame must be final and <=125 bytes")
    if len(buf) < offset + 4:
        return None
    mask = buf[offset:offset + 4]
    offset += 4
    if len(buf) < offset + length:
        return None
    masked_payload = buf[offset:offset + length]
    payload = bytearray(length)
    for i in range(length):
        payload[i] = masked_payload[i] ^ mask[i & 3]
    return WSFrame(opcode, fin, bytes(payload), offset + length)


def build_ws_frame(opcode, payload):
    """Build one complete (FIN=1), unmasked server->client frame. Callers
    that need to send more than MAX_FRAME_PAYLOAD chunk it themselves into
    several standalone messages (see ClientConnection._send_pty_chunks) —
    we never fragment a single WS *message* across frames on the way out."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", 0x80 | opcode, length)
    elif length < 65536:
        header = struct.pack("!BBH", 0x80 | opcode, 126, length)
    else:
        header = struct.pack("!BBQ", 0x80 | opcode, 127, length)
    return header + payload


def compute_accept_key(key):
    digest = hashlib.sha1((key + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


# ── Session cwd resolution ───────────────────────────────────────────────────

def resolve_session_cwd(root, requested):
    """Canonicalise a client-supplied, forward-slash relative cwd against
    `root`, rejecting anything that resolves outside it (including via
    symlinks, hence the realpath comparison rather than trusting normpath
    alone). Returns (absolute_path, normalized_relative_path). This bounds
    only where a session *starts* — see the module docstring's SECURITY
    section; it is not a sandbox."""
    root_real = os.path.realpath(root)
    requested = (requested or ".").strip().replace("\\", "/")
    if requested.startswith("/") or (len(requested) > 1 and requested[1] == ":"):
        raise ValueError("cwd must be a relative path")
    normalized = posixpath.normpath(requested)
    if normalized == ".." or normalized.startswith("../"):
        raise ValueError("cwd escapes root")
    candidate = root_real if normalized == "." else os.path.realpath(os.path.join(root_real, normalized))
    if candidate != root_real and not candidate.startswith(root_real + os.sep):
        raise ValueError("cwd escapes root")
    if not os.path.isdir(candidate):
        raise ValueError("cwd does not exist")
    return candidate, normalized


def _valid_dim(v):
    # bool is a subclass of int in Python; exclude it explicitly so a stray
    # `true` in JSON doesn't silently pass as cols=1/rows=1.
    return isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 1000


# Sent before a truncated-history replay (see ClientConnection._handle_attach)
# so a mangled leading byte lands on a blank screen instead of corrupting
# whatever the client was already rendering. Home cursor, clear screen, clear
# scrollback — standard xterm sequences understood by any real terminal.
CLEAR_SCREEN_SEQUENCE = b"\x1b[H\x1b[2J\x1b[3J"


# ── pty sessions ─────────────────────────────────────────────────────────────

def set_winsize(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def _spawn_pty(argv, cwd, cols, rows):
    # Mirrors src/terminal/bridge.py's spawn: pty.fork() gives the child a
    # real kernel pty as its controlling TTY (raw mode, ANSI, resize) and
    # calls setsid() for us, so the child becomes its own process group
    # leader — that's what lets _signal_group below reach the whole tree.
    pid, master_fd = pty.fork()
    if pid == 0:
        try:
            os.chdir(cwd)
        except OSError:
            pass
        try:
            os.execvp(argv[0], argv)
        except OSError:
            pass
        os._exit(127)
    set_winsize(master_fd, rows, cols)
    return pid, master_fd


def _signal_group(pid, sig):
    # pgid == pid because pty.fork()'s child called setsid(); signalling the
    # group (not just the direct child) reaches whatever it execs, matching
    # bridge.py's terminate().
    try:
        os.killpg(pid, sig)
    except OSError:
        pass


class SessionLimitError(Exception):
    pass


class PtySession(object):
    """One pty + one cwd + one backend, owned by the Daemon and outliving any
    single attached client. `client` is the currently attached
    ClientConnection or None; `attach_generation` guards against a stale
    close handler from a just-displaced client clobbering a newer one (see
    ClientConnection.on_connection_closed)."""

    def __init__(self, session_id, backend, canon_cwd, cwd_rel, argv, cols, rows):
        self.id = session_id
        self.backend = backend
        self.cwd = canon_cwd
        self.cwd_rel = cwd_rel
        self.created = time.time()

        self.client = None
        self.attach_generation = 0

        self.state = "running"          # running -> terminating -> killing
                                         #         -> closing     -> exited
        self.exit_code = None
        self.exit_signal = None
        self.closing_since = None
        self._terminate_started = None

        self._buf = bytearray()
        self.base_offset = 0            # stream offset of self._buf[0]
        self.total_offset = 0           # base_offset + len(self._buf)
        self._pending_input = bytearray()

        self.pid, self.master_fd = _spawn_pty(argv, canon_cwd, cols, rows)
        os.set_blocking(self.master_fd, False)

    # -- output buffer / replay -------------------------------------------------

    def append_output(self, data):
        self._buf.extend(data)
        self.total_offset += len(data)
        overflow = len(self._buf) - OUTPUT_BUFFER_CAP
        if overflow > 0:
            del self._buf[:overflow]
            self.base_offset += overflow

    def replay_from(self, last_seq):
        """(True, bytes) to replay from last_seq, or (False, None) if the
        client is asking for something we can no longer (or never could)
        serve — the caller sends resync_required instead."""
        if last_seq < 0 or last_seq > self.total_offset or last_seq < self.base_offset:
            return False, None
        return True, bytes(self._buf[last_seq - self.base_offset:])

    def resume_available(self):
        # Whether a *fresh* attach (last_seq=0) could replay the session's
        # entire history so far — i.e. nothing has been trimmed yet.
        return self.base_offset == 0

    # -- pty input (client keystrokes -> shell) ---------------------------------

    def write_input(self, data):
        """Queues `data` for the pty, writing as much as the kernel will
        take immediately. Returns True if bytes remain queued (caller should
        register EVENT_WRITE on master_fd), False if fully flushed."""
        if self.master_fd is None:
            return False
        if self._pending_input:
            self._pending_input.extend(data)
        else:
            try:
                n = os.write(self.master_fd, data)
            except (BlockingIOError, InterruptedError):
                n = 0
            except OSError:
                return False
            if n < len(data):
                self._pending_input.extend(data[n:])
        if len(self._pending_input) > MAX_SESSION_INPUT_QUEUE:
            # The pty isn't draining as fast as the client is typing/pasting.
            # Bounded, not fatal: drop the oldest overflow and keep going —
            # unlike output backpressure, losing some stdin bytes here is far
            # less surprising than disconnecting an interactive session.
            del self._pending_input[:len(self._pending_input) - MAX_SESSION_INPUT_QUEUE]
        return bool(self._pending_input)

    def flush_input(self):
        if not self._pending_input or self.master_fd is None:
            return False
        try:
            n = os.write(self.master_fd, self._pending_input)
        except (BlockingIOError, InterruptedError):
            return True
        except OSError:
            self._pending_input.clear()
            return False
        del self._pending_input[:n]
        return bool(self._pending_input)

    # -- lifecycle ---------------------------------------------------------------

    def resize(self, cols, rows):
        if self.master_fd is None:
            return
        try:
            set_winsize(self.master_fd, rows, cols)
            os.kill(self.pid, signal.SIGWINCH)
        except OSError:
            pass

    def terminate(self):
        if self.state != "running":
            return
        self.state = "terminating"
        self._terminate_started = time.monotonic()
        _signal_group(self.pid, signal.SIGTERM)

    def escalate_if_due(self):
        if self.state == "terminating" and time.monotonic() - self._terminate_started > TERMINATE_GRACE_SECONDS:
            self.state = "killing"
            _signal_group(self.pid, signal.SIGKILL)


# ── Client connections ───────────────────────────────────────────────────────

class ClientConnection(object):
    """One TCP connection: starts as plain HTTP (for the handshake, or for a
    one-shot GET /sessions), optionally upgrades to WebSocket framing, and
    once authenticated may attach to a PtySession."""

    def __init__(self, sock, addr, daemon):
        self.sock = sock
        self.addr = addr
        self.daemon = daemon

        self.mode = "http"              # "http" | "ws"
        self._recv_buf = bytearray()
        self.http_headers = {}          # set once the /attach request line is parsed

        self._send_queue = collections.deque()   # already wire-ready bytes
        self._send_offset = 0
        self._send_queue_bytes = 0
        self._pending_pty = bytearray()           # coalescing buffer, output

        self._msg_opcode = None
        self._msg_buf = None

        self.authenticated = False
        self.connected_at = time.monotonic()
        self.ws_started_at = None
        self.last_activity = time.monotonic()
        self._awaiting_pong = False
        self._ping_sent_at = None

        self.session = None
        self.session_generation = -1

        self.closed = False
        self.want_close_after_flush = False

    # -- socket I/O ---------------------------------------------------------------

    def on_readable(self):
        try:
            data = self.sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self.daemon.drop_connection(self, "recv_error")
            return
        if not data:
            self.daemon.drop_connection(self, "peer_closed")
            return
        self.last_activity = time.monotonic()
        self._recv_buf.extend(data)
        if self.mode == "http":
            self._do_http()
        elif self.mode == "ws":
            self._consume_frames()

    def on_writable(self):
        while self._send_queue:
            chunk = self._send_queue[0]
            try:
                n = self.sock.send(memoryview(chunk)[self._send_offset:])
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                self.daemon.drop_connection(self, "send_error")
                return
            self._send_offset += n
            self._send_queue_bytes -= n
            if self._send_offset >= len(chunk):
                self._send_queue.popleft()
                self._send_offset = 0
        self.daemon.no_longer_want_write(self)
        if self.want_close_after_flush:
            self.close()

    def close(self, code=1000, reason=""):
        if self.closed:
            return
        self.closed = True
        if self.mode == "ws":
            try:
                payload = struct.pack("!H", code) + reason.encode("utf-8")[:123]
                self.sock.send(build_ws_frame(OP_CLOSE, payload))
            except OSError:
                pass
        # Unregister/deregister while the socket is still open — once closed,
        # sock.fileno() returns -1 and the selector can no longer find it.
        self.daemon.on_connection_closed(self)
        try:
            self.sock.close()
        except OSError:
            pass

    # -- HTTP (handshake + /sessions) ---------------------------------------------

    def _do_http(self):
        idx = self._recv_buf.find(b"\r\n\r\n")
        if idx == -1:
            if len(self._recv_buf) > MAX_HTTP_HEADER_BYTES:
                self._send_http_error(400, "header too large")
                self.want_close_after_flush = True
            return
        head = bytes(self._recv_buf[:idx])
        del self._recv_buf[:idx + 4]
        try:
            request_line, _, header_block = head.partition(b"\r\n")
            method, path, _version = request_line.decode("latin-1").split(" ")
            headers = {}
            for line in header_block.split(b"\r\n"):
                if not line:
                    continue
                k, _, v = line.decode("latin-1").partition(":")
                headers[k.strip().lower()] = v.strip()
        except Exception:
            self._send_http_error(400, "malformed request")
            self.want_close_after_flush = True
            return

        if method == "GET" and path == "/attach":
            self._handle_ws_upgrade(headers)
        elif method == "GET" and path == "/sessions":
            self._handle_sessions(headers)
        elif method == "GET" and path == "/info":
            self._handle_info(headers)
        else:
            self._send_http_error(404, "not found")
            self.want_close_after_flush = True

    def _origin_ok(self, headers):
        origin = headers.get("origin")
        allowed = self.daemon.config.get("allowed_origins")
        if origin:
            # Always logged, regardless of enforcement mode: this is how an
            # operator discovers the real value(s) to put in allowed_origins
            # (the Obsidian desktop webview's app://obsidian.md, and whatever
            # the mobile webview turns out to send) before tightening it.
            sys.stderr.write("agent-ptyd: Origin %r from %s\n" % (origin, self.addr[0]))
        if allowed is None:
            return True  # not configured yet — see warn_if_permissive_origin
        if not origin:
            # Non-browser clients (curl, a mobile app) may send no Origin at
            # all; only reject when one is present and not allow-listed.
            return True
        return origin in allowed

    def _handle_ws_upgrade(self, headers):
        self.http_headers = headers  # available later for Daemon.rate_limit_key
        if not self._origin_ok(headers):
            self._send_http_error(403, "origin not allowed")
            self.want_close_after_flush = True
            return
        if headers.get("upgrade", "").lower() != "websocket":
            self._send_http_error(400, "expected websocket upgrade")
            self.want_close_after_flush = True
            return
        conn_tokens = [t.strip().lower() for t in headers.get("connection", "").split(",")]
        if "upgrade" not in conn_tokens:
            self._send_http_error(400, "expected Connection: Upgrade")
            self.want_close_after_flush = True
            return
        if headers.get("sec-websocket-version") != "13":
            self._send_http_error(400, "unsupported websocket version")
            self.want_close_after_flush = True
            return
        key = headers.get("sec-websocket-key")
        if not key:
            self._send_http_error(400, "missing Sec-WebSocket-Key")
            self.want_close_after_flush = True
            return
        # Deliberately no Sec-WebSocket-Protocol / -Extensions in the
        # response: we decline whatever the client offered, keeping the
        # negotiated subset exactly the narrow one this file implements.
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n" % compute_accept_key(key)
        ).encode("ascii")
        self._raw_enqueue(response)
        self.mode = "ws"
        self.ws_started_at = time.monotonic()

    def _handle_sessions(self, headers):
        if not self.daemon.check_bearer(headers.get("authorization")):
            self._send_http_response(401, json.dumps({"error": "unauthorized"}).encode("utf-8"))
            self.want_close_after_flush = True
            return
        if not self._origin_ok(headers):
            self._send_http_response(403, json.dumps({"error": "origin_not_allowed"}).encode("utf-8"))
            self.want_close_after_flush = True
            return
        body = json.dumps({"sessions": self.daemon.sessions_snapshot()}).encode("utf-8")
        self._send_http_response(200, body)
        self.want_close_after_flush = True

    def _handle_info(self, headers):
        # Lets a client populate its backend picker (and know the session
        # limits it should respect) up front, instead of guessing and only
        # finding out a backend id was wrong at attach time.
        if not self.daemon.check_bearer(headers.get("authorization")):
            self._send_http_response(401, json.dumps({"error": "unauthorized"}).encode("utf-8"))
            self.want_close_after_flush = True
            return
        if not self._origin_ok(headers):
            self._send_http_response(403, json.dumps({"error": "origin_not_allowed"}).encode("utf-8"))
            self.want_close_after_flush = True
            return
        body = json.dumps(self.daemon.info_snapshot()).encode("utf-8")
        self._send_http_response(200, body)
        self.want_close_after_flush = True

    def _send_http_error(self, status, message):
        self._send_http_response(status, json.dumps({"error": message}).encode("utf-8"))

    def _send_http_response(self, status, body):
        reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found"}.get(status, "Error")
        header = (
            "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
            % (status, reason, len(body))
        ).encode("ascii")
        self._raw_enqueue(header + body)

    def _raw_enqueue(self, data):
        if self.closed:
            return
        self._send_queue.append(data)
        self._send_queue_bytes += len(data)
        self.daemon.want_write(self)

    # -- WebSocket frame/message assembly -----------------------------------------

    def _consume_frames(self):
        while not self.closed:
            try:
                frame = parse_ws_frame(self._recv_buf)
            except WSProtocolError as e:
                self.close(1002, str(e)[:100])
                return
            if frame is None:
                return
            del self._recv_buf[:frame.frame_len]
            self._handle_frame(frame)

    def _handle_frame(self, frame):
        if frame.opcode == OP_CLOSE:
            code = struct.unpack_from("!H", frame.payload, 0)[0] if len(frame.payload) >= 2 else 1005
            self.close(code, "")
            return
        if frame.opcode == OP_PING:
            self._enqueue_frame(OP_PONG, frame.payload)
            return
        if frame.opcode == OP_PONG:
            return
        if frame.opcode in (OP_TEXT, OP_BINARY):
            if self._msg_opcode is not None:
                self.close(1002, "expected continuation frame")
                return
            self._msg_opcode = frame.opcode
            self._msg_buf = bytearray()
            if not self._append_msg_payload(frame.payload):
                return
            if frame.fin:
                self._complete_message()
            return
        if frame.opcode == OP_CONTINUATION:
            if self._msg_opcode is None:
                self.close(1002, "continuation without a starting frame")
                return
            if not self._append_msg_payload(frame.payload):
                return
            if frame.fin:
                self._complete_message()
            return
        self.close(1002, "unsupported opcode %d" % frame.opcode)

    def _append_msg_payload(self, payload):
        if len(self._msg_buf) + len(payload) > MAX_MESSAGE_BYTES:
            self.close(1009, "message too large")
            return False
        self._msg_buf.extend(payload)
        return True

    def _complete_message(self):
        opcode, data = self._msg_opcode, bytes(self._msg_buf)
        self._msg_opcode = None
        self._msg_buf = None
        if opcode == OP_TEXT:
            self._handle_control_message(data)
        else:
            self._handle_binary_message(data)

    def _handle_control_message(self, data):
        try:
            msg = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send_error("bad_json", "control message is not valid JSON")
            return
        if not isinstance(msg, dict) or not isinstance(msg.get("t"), str):
            self._send_error("bad_message", "control message needs a string 't' field")
            return
        handler = self._HANDLERS.get(msg["t"])
        if handler is None:
            self._send_error("unknown_message_type", msg["t"])
            return
        handler(self, msg)

    def _handle_binary_message(self, data):
        if not self.authenticated or self.session is None:
            self.close(1002, "binary frame before attach")
            return
        if self.session.state != "running" or self.session.master_fd is None:
            return  # session already ended; drop stray input silently
        needs_write = self.session.write_input(data)
        self.daemon.set_session_write_interest(self.session, needs_write)

    # -- control message handlers --------------------------------------------------

    def _handle_hello(self, msg):
        if self.authenticated:
            self._send_error("already_authenticated", "hello already completed")
            return
        if msg.get("proto") != PROTOCOL_VERSION:
            self.close(1002, "unsupported_protocol")
            return
        token = msg.get("token")
        if not isinstance(token, str) or not self.daemon.check_token(token, self):
            self.close(1008, "auth_failed")
            return
        self.authenticated = True
        self.daemon.note_auth_success(self)
        self._send_json({"t": "hello_ok", "proto": PROTOCOL_VERSION})

    def _handle_attach(self, msg):
        if not self.authenticated:
            self.close(1008, "not_authenticated")
            return
        if self.session is not None:
            self._send_error("already_attached", "this connection is already attached to a session")
            return

        backend = msg.get("backend")
        cols, rows = msg.get("cols"), msg.get("rows")
        session_id = msg.get("session_id")
        # Distinguish "omitted last_seq" (a fresh client with no prior
        # position) from "last_seq: 0" (a genuine resume attempt that
        # happens to be from true byte zero) — they get different replay
        # treatment below.
        has_last_seq = "last_seq" in msg
        last_seq = msg.get("last_seq", 0)

        if not isinstance(backend, str) or backend not in self.daemon.backends:
            self._send_error("unknown_backend", "backend not configured")
            return
        if not _valid_dim(cols) or not _valid_dim(rows):
            self._send_error("invalid_size", "cols/rows must be integers in [1,1000]")
            return
        if has_last_seq and (not isinstance(last_seq, int) or isinstance(last_seq, bool) or last_seq < 0):
            self._send_error("invalid_last_seq", "last_seq must be a non-negative integer")
            return
        try:
            canon_cwd, cwd_rel = resolve_session_cwd(self.daemon.config["root"], msg.get("cwd", ""))
        except ValueError as e:
            self._send_error("invalid_cwd", str(e))
            return

        if session_id:
            session = self.daemon.sessions.get(session_id)
            if session is None:
                self._send_error("unknown_session", "no such session")
                return
            if session.backend != backend or session.cwd != canon_cwd:
                self._send_error("attach_mismatch", "backend/cwd differ from the session's own")
                return
            resumed = True
        else:
            try:
                session = self.daemon.create_session(backend, canon_cwd, cwd_rel, cols, rows)
            except SessionLimitError as e:
                self._send_error("session_limit", str(e))
                return
            resumed = False

        # Steal-over: install the new attachment BEFORE closing the old
        # client, so its close handler — which may run asynchronously right
        # after we call close() below — sees attach_generation has already
        # moved on and knows not to clear session.client out from under us.
        old_client = session.client
        session.attach_generation += 1
        session.client = self
        self.session = session
        self.session_generation = session.attach_generation
        if old_client is not None and old_client is not self and not old_client.closed:
            old_client.close(4000, "replaced_by_new_attachment")

        session.resize(cols, rows)

        if has_last_seq:
            # A genuine resume: the client remembers exactly how many bytes
            # it already applied, so the replay is byte-aligned by
            # construction — exact continuation, or resync if we can no
            # longer serve it. Unchanged from before.
            replay_from_seq = last_seq
            ok, data = session.replay_from(replay_from_seq)
            if not ok:
                reason = "invalid_seq" if last_seq > session.total_offset else "buffer_expired"
            truncated = False
        else:
            # A fresh client with no prior position: hand it whatever
            # scrollback we still have, starting at the oldest byte the ring
            # buffer retains. If anything has been trimmed (base_offset > 0)
            # that start point is an arbitrary raw-byte boundary — it can
            # land inside a UTF-8 sequence or an ANSI escape. Realigning it
            # would need a UTF-8/ANSI-aware scan of the buffer; instead we
            # clear the client's terminal first (so a mangled leading byte
            # or two lands on a blank screen, not on top of real content)
            # and flag the replay as truncated so the client treats it as
            # partial scrollback rather than a faithful, complete screen.
            replay_from_seq = session.base_offset
            ok, data = session.replay_from(replay_from_seq)
            reason = None
            truncated = session.base_offset > 0

        self._send_json({
            "t": "attach_ok", "session_id": session.id, "backend": session.backend,
            "cwd": session.cwd_rel, "cols": cols, "rows": rows,
            "created": session.created, "resumed": resumed, "truncated_history": truncated,
            # The absolute offset the replay that follows (if any) starts
            # from — NOT session.total_offset. A client that just counts
            # every byte it receives has no way to know where a *fresh*
            # attach's replay began (it never learned base_offset), so on a
            # later exact-offset reconnect it would send an undercounted
            # last_seq. That's not just inexact: because base_offset only
            # ever grows, the undercount can eventually land back inside
            # [base_offset, total_offset) by coincidence, and replay_from
            # would then silently serve an earlier slice than intended —
            # duplicated output, not just a wasted resync. Seeding the
            # client's counter from this field (then incrementing per byte
            # received, excluding CLEAR_SCREEN_SEQUENCE) keeps it exact.
            "seq": replay_from_seq,
        })

        if not ok:
            self._send_json({"t": "resync_required", "reason": reason})
        else:
            if truncated:
                self._enqueue_frame(OP_BINARY, CLEAR_SCREEN_SEQUENCE)
            if data:
                self._send_pty_chunks(data)

        if session.state == "exited":
            self._send_json({"t": "exit", "session_id": session.id, "code": session.exit_code, "signal": session.exit_signal})

    def _handle_resize(self, msg):
        if not self.authenticated:
            self.close(1008, "not_authenticated")
            return
        if self.session is None:
            self._send_error("not_attached", "attach first")
            return
        cols, rows = msg.get("cols"), msg.get("rows")
        if not _valid_dim(cols) or not _valid_dim(rows):
            self._send_error("invalid_size", "cols/rows must be integers in [1,1000]")
            return
        self.session.resize(cols, rows)

    def _handle_terminate(self, msg):
        if not self.authenticated:
            self.close(1008, "not_authenticated")
            return
        if self.session is None:
            self._send_error("not_attached", "attach first")
            return
        self.daemon.terminate_session(self.session)

    def _handle_ping(self, msg):
        if not self.authenticated:
            self.close(1008, "not_authenticated")
            return
        self._send_json({"t": "pong", "ts": msg.get("ts")})

    def _handle_pong(self, msg):
        if not self.authenticated:
            return
        self._awaiting_pong = False

    _HANDLERS = {
        "hello": _handle_hello,
        "attach": _handle_attach,
        "resize": _handle_resize,
        "terminate": _handle_terminate,
        "ping": _handle_ping,
        "pong": _handle_pong,
    }

    # -- outbound framing / backpressure --------------------------------------------

    def _send_json(self, obj):
        self._enqueue_frame(OP_TEXT, json.dumps(obj, separators=(",", ":")).encode("utf-8"))

    def _send_error(self, code, message):
        self._send_json({"t": "error", "code": code, "message": message})

    def _send_pty_chunks(self, data):
        for i in range(0, len(data), OUTPUT_CHUNK_BYTES):
            self._enqueue_frame(OP_BINARY, data[i:i + OUTPUT_CHUNK_BYTES])

    def _enqueue_frame(self, opcode, payload):
        if self.closed:
            return
        frame = build_ws_frame(opcode, payload)
        self._send_queue.append(frame)
        self._send_queue_bytes += len(frame)
        if self._send_queue_bytes > MAX_CLIENT_QUEUE_BYTES:
            self.daemon.drop_connection(self, "output_queue_overflow")
            return
        self.daemon.want_write(self)

    def queue_pty_output(self, data):
        # Coalescing buffer: pty reads land here and get framed as one (or a
        # few, if large) WS message per select() tick by flush_pty_output,
        # rather than one frame per os.read() call.
        self._pending_pty.extend(data)
        if len(self._pending_pty) > MAX_CLIENT_QUEUE_BYTES:
            self.daemon.drop_connection(self, "output_queue_overflow")

    def flush_pty_output(self):
        if not self._pending_pty or self.closed:
            return
        data = bytes(self._pending_pty)
        self._pending_pty.clear()
        self._send_pty_chunks(data)


# ── Daemon ───────────────────────────────────────────────────────────────────

class Daemon(object):
    def __init__(self, config, config_path):
        self.config = config
        self.config_path = config_path
        self.token = config["token"]
        # Normalized once here (not just at startup via validate_backends) so
        # a Daemon built directly from a raw config dict — as tests do — sees
        # the same {id: {"argv", "label"}} shape as a real one.
        self.backends = normalize_backends(config["backends"])

        self.sessions = {}
        self.connections = {}   # id(conn) -> conn
        self.sel = selectors.DefaultSelector()
        self.listen_sock = None

        self._create_timestamps = collections.deque()
        self._auth_failures = {}       # rate-limit key -> [monotonic timestamps]
        self._auth_blocked_until = {}  # rate-limit key -> monotonic deadline

        self._shutdown = False

    # -- auth -------------------------------------------------------------------
    #
    # The auth-failure limiter below is deliberately NOT primarily a defense
    # against brute-forcing the token: the token is 32 random bytes (256 bits
    # of entropy, from secrets.token_hex), so guessing it is not a realistic
    # attack at any rate limit we'd tolerate. Its real job is bounding the
    # CPU/log noise of a retry storm (a buggy client, a stale token left in
    # an app after rotation) — which is why AUTH_FAIL_MAX/AUTH_BLOCK_SECONDS
    # are sized generously and the block is short: a lockout that also hits
    # the legitimate user is a worse outcome than under-throttling an
    # attacker who cannot feasibly guess the token anyway.
    #
    # What it keys on matters more than the numbers. This daemon is meant to
    # be reached only through a reverse proxy (e.g. `tailscale serve`) on
    # loopback, so every real connection to our listening socket arrives
    # from 127.0.0.1 — a *per-IP* bucket would collapse every client (the
    # legitimate user AND anyone else who reaches the proxy) into one key,
    # which is not isolation, just a confusing single global bucket wearing
    # an IP-shaped label. Two supported modes:
    #
    #  - Default (auth_rate_limit_header unset): one explicit GLOBAL bucket
    #    (key "*"). Simple, safe, and honest about what it protects: noise,
    #    not identity.
    #  - Opt-in (auth_rate_limit_header set to e.g. "x-forwarded-for"):
    #    bucket by that header's value, restoring per-client isolation. Only
    #    enable this if the daemon is provably unreachable except through a
    #    proxy that sets the header itself — otherwise any direct client can
    #    forge it to frame, or evade, another client's bucket. It does NOT
    #    protect against a proxy that forwards a forged header from upstream.

    def rate_limit_key(self, conn):
        header_name = self.config.get("auth_rate_limit_header")
        if header_name:
            value = (conn.http_headers or {}).get(header_name.lower())
            if value:
                # X-Forwarded-For may be a comma-separated proxy chain; the
                # first entry is the client closest to the origin as seen by
                # the nearest proxy hop.
                return value.split(",")[0].strip()
        return "*"

    def check_bearer(self, header_value):
        if not header_value or not header_value.startswith("Bearer "):
            return False
        supplied = header_value[len("Bearer "):].strip()
        return hmac.compare_digest(supplied, self.token)

    def check_token(self, token, conn):
        key = self.rate_limit_key(conn)
        if self._is_key_blocked(key):
            return False
        ok = hmac.compare_digest(token, self.token)
        if not ok:
            self._note_auth_failure(key)
        return ok

    def note_auth_success(self, conn):
        key = self.rate_limit_key(conn)
        self._auth_failures.pop(key, None)
        self._auth_blocked_until.pop(key, None)

    def _note_auth_failure(self, key):
        now = time.monotonic()
        fails = self._auth_failures.setdefault(key, [])
        fails.append(now)
        cutoff = now - AUTH_FAIL_WINDOW_SECONDS
        while fails and fails[0] < cutoff:
            fails.pop(0)
        if len(fails) >= AUTH_FAIL_MAX:
            self._auth_blocked_until[key] = now + AUTH_BLOCK_SECONDS

    def _is_key_blocked(self, key):
        until = self._auth_blocked_until.get(key)
        return until is not None and time.monotonic() < until

    def _prune_auth_state(self, now_m):
        for key in list(self._auth_blocked_until):
            if self._auth_blocked_until[key] < now_m:
                del self._auth_blocked_until[key]

    # -- sessions ---------------------------------------------------------------

    def create_session(self, backend, canon_cwd, cwd_rel, cols, rows):
        now = time.monotonic()
        cutoff = now - 60.0
        while self._create_timestamps and self._create_timestamps[0] < cutoff:
            self._create_timestamps.popleft()
        if len(self.sessions) >= self.config["max_sessions"]:
            raise SessionLimitError("max_sessions (%d) reached" % self.config["max_sessions"])
        if len(self._create_timestamps) >= self.config["session_create_rate_per_min"]:
            raise SessionLimitError("session creation rate limit exceeded")

        argv = self.backends[backend]["argv"]
        session_id = uuid.uuid4().hex
        session = PtySession(session_id, backend, canon_cwd, cwd_rel, argv, cols, rows)
        self.sessions[session_id] = session
        self._create_timestamps.append(now)
        self.sel.register(session.master_fd, selectors.EVENT_READ, ("session_pty", session))
        return session

    def terminate_session(self, session):
        session.terminate()

    def sessions_snapshot(self):
        out = []
        for s in self.sessions.values():
            out.append({
                "id": s.id, "backend": s.backend, "cwd": s.cwd_rel,
                "state": "running" if s.state != "exited" else "exited",
                "created": s.created,
                "attached": s.client is not None and not s.client.closed,
                "last_seq": s.total_offset,
                "resume_available": s.resume_available(),
            })
        return out

    def info_snapshot(self):
        # Backend argv is deliberately excluded: it may contain filesystem
        # paths the client has no business knowing, and it isn't needed to
        # populate a backend picker — only the id (what to send back in
        # `attach`) and a display label are.
        return {
            "protocol_version": PROTOCOL_VERSION,
            "backends": [
                {"id": backend_id, "label": meta["label"]}
                for backend_id, meta in sorted(self.backends.items())
            ],
            "max_sessions": self.config["max_sessions"],
            "session_create_rate_per_min": self.config["session_create_rate_per_min"],
        }

    def set_session_write_interest(self, session, want):
        if session.master_fd is None:
            return
        mask = selectors.EVENT_READ | selectors.EVENT_WRITE if want else selectors.EVENT_READ
        try:
            self.sel.modify(session.master_fd, mask, ("session_pty", session))
        except (KeyError, ValueError):
            pass

    def handle_pty_readable(self, session):
        if session.master_fd is None:
            return
        try:
            data = os.read(session.master_fd, 65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""  # EIO and friends: the slave side is gone
        if data:
            session.append_output(data)
            if session.client is not None and not session.client.closed:
                session.client.queue_pty_output(data)
            return
        # EOF: every copy of the pty slave fd has been closed. The owning
        # process may not be reaped yet (waitpid can lag a tick behind the
        # fd closing), so don't report exit here — mark "closing" and let
        # the _reap_sessions sweep confirm it. That same sweep (not this
        # read path) is what catches a process that already exited while a
        # background grandchild kept the slave open, which would otherwise
        # keep this fd from ever reaching EOF on its own — the session must
        # not read as "still live" just because that grandchild exists.
        if session.state != "exited":
            session.state = "closing"
            session.closing_since = time.monotonic()
        self._close_master(session)

    def _close_master(self, session):
        if session.master_fd is None:
            return
        try:
            self.sel.unregister(session.master_fd)
        except (KeyError, ValueError):
            pass
        try:
            os.close(session.master_fd)
        except OSError:
            pass
        session.master_fd = None

    def _reap_sessions(self, now_m):
        for session in list(self.sessions.values()):
            if session.state == "exited":
                continue
            if session.state == "closing" and session.closing_since and now_m - session.closing_since > CLOSING_REAP_TIMEOUT:
                self._finalize(session, None, None)
                continue
            try:
                wpid, status = os.waitpid(session.pid, os.WNOHANG)
            except ChildProcessError:
                self._finalize(session, None, None)
                continue
            if wpid == 0:
                continue
            if os.WIFEXITED(status):
                code, sig = os.WEXITSTATUS(status), None
            elif os.WIFSIGNALED(status):
                code, sig = None, os.WTERMSIG(status)
            else:
                code, sig = None, None
            self._finalize(session, code, sig)

    def _finalize(self, session, code, sig):
        self._close_master(session)
        session.state = "exited"
        session.exit_code = code
        session.exit_signal = sig
        client = session.client
        if client is not None and not client.closed:
            client._send_json({"t": "exit", "session_id": session.id, "code": code, "signal": sig})

    # -- connections --------------------------------------------------------------

    def want_write(self, conn):
        try:
            self.sel.modify(conn.sock, selectors.EVENT_READ | selectors.EVENT_WRITE, ("conn", conn))
        except (KeyError, ValueError):
            pass

    def no_longer_want_write(self, conn):
        try:
            self.sel.modify(conn.sock, selectors.EVENT_READ, ("conn", conn))
        except (KeyError, ValueError):
            pass

    def drop_connection(self, conn, reason):
        conn.close(1011, reason)

    def on_connection_closed(self, conn):
        try:
            self.sel.unregister(conn.sock)
        except (KeyError, ValueError):
            pass
        self.connections.pop(id(conn), None)
        session = conn.session
        if session is not None and session.client is conn and session.attach_generation == conn.session_generation:
            session.client = None

    # -- event loop -----------------------------------------------------------------

    def _accept(self):
        while True:
            try:
                sock, addr = self.listen_sock.accept()
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            sock.setblocking(False)
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            conn = ClientConnection(sock, addr, self)
            self.connections[id(conn)] = conn
            self.sel.register(sock, selectors.EVENT_READ, ("conn", conn))

    def _dispatch_conn(self, conn, mask):
        if conn.closed:
            return
        if mask & selectors.EVENT_READ:
            conn.on_readable()
        if conn.closed:
            return
        if mask & selectors.EVENT_WRITE:
            conn.on_writable()

    def _dispatch_pty(self, session, mask):
        if mask & selectors.EVENT_READ:
            self.handle_pty_readable(session)
        if session.master_fd is None:
            return
        if mask & selectors.EVENT_WRITE:
            still_pending = session.flush_input()
            self.set_session_write_interest(session, still_pending)

    def _check_heartbeats(self, now_m):
        for conn in list(self.connections.values()):
            if conn.mode != "ws" or not conn.authenticated or conn.closed:
                continue
            if conn._awaiting_pong:
                if now_m - conn._ping_sent_at > HEARTBEAT_TIMEOUT_SECONDS:
                    self.drop_connection(conn, "heartbeat_timeout")
                continue
            if now_m - conn.last_activity > HEARTBEAT_INTERVAL_SECONDS:
                conn._send_json({"t": "ping", "ts": time.time()})
                conn._awaiting_pong = True
                conn._ping_sent_at = now_m

    def _check_deadlines(self, now_m):
        for conn in list(self.connections.values()):
            if conn.closed:
                continue
            if conn.mode == "http" and now_m - conn.connected_at > AUTH_TIMEOUT_SECONDS:
                self.drop_connection(conn, "handshake_timeout")
            elif conn.mode == "ws" and not conn.authenticated and now_m - conn.ws_started_at > AUTH_TIMEOUT_SECONDS:
                self.drop_connection(conn, "auth_timeout")

    def _flush_pending_output(self):
        # Runs once per tick, after all ready fds this iteration have been
        # processed, so every session's pty reads from this tick land in one
        # coalesced WS message instead of one per os.read().
        for conn in self.connections.values():
            if not conn.closed:
                conn.flush_pty_output()

    def tick(self):
        now_m = time.monotonic()
        self._flush_pending_output()
        self._reap_sessions(now_m)
        for session in self.sessions.values():
            session.escalate_if_due()
        self._check_heartbeats(now_m)
        self._check_deadlines(now_m)
        self._prune_auth_state(now_m)

    def run(self):
        self.sel.register(self.listen_sock, selectors.EVENT_READ, ("listen", None))
        while not self._shutdown:
            try:
                events = self.sel.select(timeout=TICK_INTERVAL_SECONDS)
            except InterruptedError:
                events = []
            for key, mask in events:
                kind, obj = key.data
                try:
                    if kind == "listen":
                        self._accept()
                    elif kind == "conn":
                        self._dispatch_conn(obj, mask)
                    elif kind == "session_pty":
                        self._dispatch_pty(obj, mask)
                except Exception:
                    # One bad fd must never take the whole daemon down.
                    traceback.print_exc()
            self.tick()
        self._shutdown_sequence()

    def _shutdown_sequence(self):
        sys.stderr.write("agent-ptyd: shutting down, terminating %d session(s)...\n" % len(self.sessions))
        for session in self.sessions.values():
            if session.state == "running":
                session.terminate()
        deadline = time.monotonic() + TERMINATE_GRACE_SECONDS + 1.0
        while time.monotonic() < deadline and any(s.state != "exited" for s in self.sessions.values()):
            self._reap_sessions(time.monotonic())
            for s in self.sessions.values():
                s.escalate_if_due()
            time.sleep(0.1)
        for s in self.sessions.values():
            if s.state != "exited":
                _signal_group(s.pid, signal.SIGKILL)
        time.sleep(0.2)
        self._reap_sessions(time.monotonic())
        for conn in list(self.connections.values()):
            conn.close(1001, "server shutting down")
        try:
            self.listen_sock.close()
        except OSError:
            pass


# ── Bootstrap ────────────────────────────────────────────────────────────────

def make_listen_socket(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(128)
    sock.setblocking(False)
    return sock


def _install_signal_handlers(daemon):
    def _handle(_signum, _frame):
        daemon._shutdown = True
    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)


def main():
    ap = argparse.ArgumentParser(description="Remote PTY daemon for the Obsidian Agent MCP plugin")
    ap.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="path to the daemon's JSON config (created on first run)")
    args = ap.parse_args()

    try:
        config = load_config(args.config)
        validate_backends(config["backends"])
    except (ValueError, OSError) as e:
        sys.stderr.write("agent-ptyd: config error: %s\n" % e)
        sys.exit(1)
    warn_if_public_bind(config)
    warn_if_permissive_origin(config)

    daemon = Daemon(config, args.config)
    try:
        daemon.listen_sock = make_listen_socket(config["host"], config["port"])
    except OSError as e:
        sys.stderr.write("agent-ptyd: could not bind %s:%d: %s\n" % (config["host"], config["port"], e))
        sys.exit(1)

    _install_signal_handlers(daemon)
    sys.stderr.write(
        "agent-ptyd: listening on %s:%d, root=%s, backends=%s\n"
        % (config["host"], config["port"], config["root"], ", ".join(sorted(config["backends"])))
    )
    daemon.run()


if __name__ == "__main__":
    main()
