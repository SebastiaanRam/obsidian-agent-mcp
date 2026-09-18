import { requestUrl } from "obsidian";
import type { IPty } from "./pty";

/*
 * Client for server/agent-ptyd.py's remote pty protocol (see that file's
 * module docstring for the full wire protocol this mirrors). No Node APIs
 * here — this must also run inside Obsidian's mobile webview, which has no
 * Node integration, so everything below is browser-standard (WebSocket,
 * TextEncoder/TextDecoder, fetch-via-requestUrl).
 */

// Must match server/agent-ptyd.py's PROTOCOL_VERSION.
const PROTOCOL_VERSION = 1;

const BASE_RECONNECT_DELAY_MS = 500;
const MAX_RECONNECT_DELAY_MS = 15_000;
const MAX_RECONNECT_ATTEMPTS = 10;
const HEARTBEAT_INTERVAL_MS = 20_000;
// Caps how much locally-typed input we'll hold while not yet attached (e.g.
// stuck retrying, or mid-reconnect) — bounded like every queue on the daemon
// side, for the same reason: something has to give before "unbounded".
const MAX_PENDING_WRITE_CHARS = 65_536;

export interface RemotePtyOptions {
  /** Daemon base URL, e.g. "ws://127.0.0.1:8765". http(s):// and a bare
   * host:port are also accepted (see toAttachUrl) since that's what users
   * are likely to have copied from checking GET /info with curl. */
  url: string;
  token: string;
  /** Which of the daemon's own configured backends (from GET /info) to
   * attach as — not a local AgentBackend id. */
  backend: string;
  /** Relative path under the daemon's own `root`. Never a local filesystem
   * path: the vault's location on this machine and the project's location
   * on the daemon's host are unrelated (see settings.ts's RemoteSettings). */
  cwd: string;
  cols: number;
  rows: number;
  /** A previously learned session id, to reattach instead of creating a new
   * session (e.g. after closing and reopening this terminal pane). */
  sessionId?: string;
  /** Called once whenever we learn a session id we didn't already have —
   * on first attach, on reattach-after-mismatch, or after resync — so the
   * caller can persist it for next time. */
  onSessionId: (id: string) => void;
}

function clampDim(n: number): number {
  return Math.max(1, Math.min(1000, Math.floor(n) || 1));
}

// Accepts ws(s)://, http(s)://, or a bare host:port and returns the ws(s)
// URL for the daemon's /attach endpoint.
function toAttachUrl(base: string): string {
  let url = base.trim().replace(/\/+$/, "");
  if (/^https:\/\//i.test(url)) url = "wss://" + url.slice("https://".length);
  else if (/^http:\/\//i.test(url)) url = "ws://" + url.slice("http://".length);
  else if (!/^wss?:\/\//i.test(url)) url = "ws://" + url;
  return url + "/attach";
}

function toHttpBase(base: string): string {
  let url = base.trim().replace(/\/+$/, "");
  if (/^wss:\/\//i.test(url)) url = "https://" + url.slice("wss://".length);
  else if (/^ws:\/\//i.test(url)) url = "http://" + url.slice("ws://".length);
  else if (!/^https?:\/\//i.test(url)) url = "http://" + url;
  return url;
}

type ConnectionState = "connecting" | "attaching" | "live";

// Client half of server/agent-ptyd.py. Implements IPty (see pty.ts) so
// view.ts can use it interchangeably with the local Python-bridge pty, but
// its kill() has a DIFFERENT meaning than that name suggests — see the loud
// comment on kill() below before touching this class.
export class RemotePty implements IPty {
  private dataCbs = new Set<(d: string) => void>();
  private exitCbs = new Set<(e: { exitCode: number; signal?: number | string }) => void>();

  private ws: WebSocket | null = null;
  private state: ConnectionState = "connecting";
  // Set on kill() (deliberate detach) or a real "exit" from the server —
  // both mean "never reconnect again", but only one of them should ever
  // also fire onExit (see handleExit / kill's comment).
  private stopped = false;
  private exited = false;

  // True once this instance has completed at least one attach_ok. Governs
  // whether the *next* attach sends last_seq at all — see sendAttach.
  private everAttached = false;
  private sessionId: string | null;
  // Absolute byte offset into the session's stream that we've consumed up
  // to. Seeded from attach_ok.seq (never assumed to start at 0 — see
  // handleAttachOk for why), then incremented per live byte received.
  private lastSeq = 0;
  // True for exactly the one binary message expected right after an
  // attach_ok with truncated_history: true — see handleBinary.
  private expectClearSequence = false;

  private cols: number;
  private rows: number;

  private pendingWrites: string[] = [];
  private pendingWriteChars = 0;

  private reconnectAttempts = 0;
  private reconnectTimer: number | null = null;
  // Set right before we close the socket ourselves to force an immediate,
  // un-backed-off reconnect (see handleResyncRequired) — distinguishes that
  // from a real transport failure in handleClose.
  private forcingImmediateReconnect = false;

  private heartbeatTimer: number | null = null;
  private awaitingPong = false;

  // Bound once so it can be added and removed with the same reference.
  private readonly visibilityHandler = () => this.handleVisibilityChange();

  private readonly decoder = new TextDecoder("utf-8");
  private readonly encoder = new TextEncoder();

  constructor(private readonly opts: RemotePtyOptions) {
    this.cols = clampDim(opts.cols);
    this.rows = clampDim(opts.rows);
    this.sessionId = opts.sessionId ?? null;
    // A phone that's locked or backgrounded is not a flaky network — it's a
    // process that stops running JS entirely for an unbounded time. Bounded
    // backoff (below) is the right response to a bad connection, but it must
    // not be the ONLY way back: without this, a lock screen held past the
    // ~105s retry budget leaves a dead pane showing "gave up" even though
    // the daemon was reachable the whole time. See handleVisibilityChange.
    document.addEventListener("visibilitychange", this.visibilityHandler);
    // startPty()-style callers (view.ts) get an IPty back synchronously and
    // wire onData/onExit immediately after — deferring the first connect to
    // a microtask guarantees those listeners are attached before we emit
    // anything or open the socket, so "connecting…" is never lost.
    void Promise.resolve().then(() => this.connect());
  }

  // ── IPty ─────────────────────────────────────────────────────────────────

  onData(cb: (data: string) => void) {
    this.dataCbs.add(cb);
    return { dispose: () => { this.dataCbs.delete(cb); } };
  }

  onExit(cb: (evt: { exitCode: number; signal?: number | string }) => void) {
    this.exitCbs.add(cb);
    return { dispose: () => { this.exitCbs.delete(cb); } };
  }

  resize(cols: number, rows: number): void {
    this.cols = clampDim(cols);
    this.rows = clampDim(rows);
    if (this.state === "live") this.sendJson({ t: "resize", cols: this.cols, rows: this.rows });
  }

  write(data: string): void {
    if (this.stopped) return;
    if (this.state !== "live") {
      this.queueWrite(data);
      return;
    }
    this.sendBinary(this.encoder.encode(data));
  }

  // ────────────────────────────────────────────────────────────────────────
  // CRITICAL: kill() MUST DETACH, NOT TERMINATE.
  //
  // This is IPty.kill(), and view.ts calls `this.pty?.kill()` from
  // stopSession() — which runs on EVERY pane close AND EVERY backend switch,
  // not just when the user actually wants the agent gone. For a remote
  // session, "gone" would mean the daemon kills the shell/agent process on
  // its side. That must NOT happen here: it would kill the user's long-lived
  // agent every time they close this pane or switch the terminal's agent
  // dropdown, which defeats the entire reason this backend exists (an agent
  // that survives the local device going away).
  //
  // kill() therefore only closes OUR end of the WebSocket and stops trying
  // to reconnect. The daemon's session keeps running; a future RemotePty
  // (new pane, or reopening this one) can reattach to it via sessionId and
  // pick up exactly where this left off.
  //
  // Ending the remote process for real is terminate() below: a separate,
  // explicit method, never called from here, from onClose, from a backend
  // switch, or from any other teardown path. If you're adding a call to it,
  // it should be reachable only from something the user directly asked for.
  // ────────────────────────────────────────────────────────────────────────
  kill(): void {
    this.stopped = true;
    this.clearReconnectTimer();
    this.clearHeartbeat();
    document.removeEventListener("visibilitychange", this.visibilityHandler);
    this.ws?.close();
    this.ws = null;
  }

  // Explicit, user-initiated termination of the REMOTE process. Deliberately
  // not part of IPty and not wired into any disposal path — see kill()'s
  // comment above.
  terminate(): void {
    if (this.state === "live") this.sendJson({ t: "terminate" });
  }

  // ── connection lifecycle ─────────────────────────────────────────────────

  private connect(): void {
    if (this.stopped) return;
    this.state = "connecting";
    this.emit(`\x1b[90m[remote] connecting to ${this.opts.url}…\x1b[0m\r\n`);

    let ws: WebSocket;
    try {
      ws = new WebSocket(toAttachUrl(this.opts.url));
    } catch (err) {
      this.emit(`\x1b[31m[remote] invalid daemon URL: ${String(err)}\x1b[0m\r\n`);
      this.scheduleReconnect();
      return;
    }
    ws.binaryType = "arraybuffer";
    // A connection that fails before ever opening doesn't reliably fire
    // both "error" and "close" — some WebSocket implementations (confirmed:
    // Node's built-in client) fire only "error" in that case, and nothing
    // guarantees every mobile webview engine fires "close" afterward either.
    // Relying on "close" alone stalls the whole reconnect loop forever the
    // first time a connection is refused rather than dropped after opening.
    // A per-attempt flag makes whichever fires first win and ignores the
    // other, so reconnect logic runs exactly once per failed attempt either
    // way.
    let settled = false;
    const onDisconnect = () => {
      if (settled) return;
      settled = true;
      this.handleClose();
    };
    ws.onopen = () => this.sendJson({ t: "hello", proto: PROTOCOL_VERSION, token: this.opts.token });
    ws.onmessage = (ev: MessageEvent<string | ArrayBuffer>) => this.handleMessage(ev);
    ws.onclose = onDisconnect;
    ws.onerror = onDisconnect;
    this.ws = ws;
  }

  private handleClose(): void {
    this.ws = null;
    this.clearHeartbeat();
    if (this.stopped) return;

    if (this.forcingImmediateReconnect) {
      this.forcingImmediateReconnect = false;
      this.state = "connecting";
      this.connect();
      return;
    }

    const wasLive = this.state === "live";
    this.state = "connecting";
    if (wasLive) {
      // A mobile-style drop (sleep, network change, backgrounding) is a
      // normal state, not an error — say so plainly and keep trying.
      this.emit("\x1b[33m[remote] connection lost, reconnecting…\x1b[0m\r\n");
    }
    this.scheduleReconnect();
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    this.reconnectAttempts++;
    if (this.reconnectAttempts > MAX_RECONNECT_ATTEMPTS) {
      // Deliberately NOT this.stopped = true: that's reserved for kill()
      // (detach) and a real "exit" (see their comments) and would permanently
      // stop handleVisibilityChange from ever reviving this instance. Giving
      // up here just means no more TIMED attempts — write() still queues,
      // and either reopening the pane (a fresh instance) or the app coming
      // to the foreground (handleVisibilityChange, same instance) can still
      // bring it back without losing queued input.
      this.emit(
        `\x1b[31m[remote] gave up after ${MAX_RECONNECT_ATTEMPTS} attempts — ` +
        "reopen this terminal, or bring the app to the foreground, to retry.\x1b[0m\r\n",
      );
      return;
    }
    const backoff = Math.min(BASE_RECONNECT_DELAY_MS * 2 ** (this.reconnectAttempts - 1), MAX_RECONNECT_DELAY_MS);
    const jittered = backoff + backoff * 0.3 * Math.random();
    this.reconnectTimer = window.setTimeout(() => this.connect(), Math.round(jittered));
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  // Bounded backoff (scheduleReconnect) answers "the network is flaky, retry
  // patiently." Foregrounding answers a different question — "the device
  // just wasn't running JS at all, so however long we waited is meaningless"
  // — and needs a different trigger: the moment the app is usable again, not
  // a fixed schedule computed before we knew it would be backgrounded. This
  // fires for every visibility change (not just after giving up): even a
  // still-in-budget wait is worth pre-empting once the user is actually
  // looking at the screen again, since the alternative is just staring at a
  // "reconnecting…" pane for whatever's left of a delay picked for a
  // scenario (unattended retrying) that no longer applies.
  private handleVisibilityChange(): void {
    if (document.visibilityState !== "visible") return;
    if (this.stopped) return; // kill()'d, or the remote process actually exited — nothing to revive
    if (this.ws) return; // already connecting/attaching/live — nothing to nudge
    this.clearReconnectTimer();
    this.reconnectAttempts = 0;
    this.connect();
  }

  // ── protocol: hello / attach ─────────────────────────────────────────────

  private sendAttach(): void {
    this.state = "attaching";
    const msg: Record<string, unknown> = {
      t: "attach", backend: this.opts.backend, cwd: this.opts.cwd,
      cols: this.cols, rows: this.rows,
    };
    if (this.sessionId) msg.session_id = this.sessionId;
    // Only a genuine reconnect within THIS instance's lifetime has a byte
    // count worth trusting. A brand new instance — first connection ever,
    // or reopening a pane with a persisted sessionId but no in-memory
    // tracking — always omits last_seq and lets the server's fresh-attach
    // path hand back whatever scrollback it still has.
    if (this.everAttached) msg.last_seq = this.lastSeq;
    this.sendJson(msg);
  }

  private handleAttachOk(msg: Record<string, unknown>): void {
    const sid = typeof msg.session_id === "string" ? msg.session_id : null;
    if (sid && sid !== this.sessionId) {
      this.sessionId = sid;
      this.opts.onSessionId(sid);
    }

    // The server tells us the absolute offset its replay starts at — NOT
    // just 0. A client that only counts bytes it has personally received
    // has no way to know where a *fresh* attach's replay began on a session
    // whose buffer has already been trimmed; seeding from this field (see
    // agent-ptyd.py's attach_ok "seq" comment) is what keeps a later
    // exact-offset reconnect accurate instead of silently replaying a
    // stale, wrongly-shifted slice.
    this.lastSeq = typeof msg.seq === "number" ? msg.seq : 0;
    this.expectClearSequence = msg.truncated_history === true;

    const wasReconnect = this.everAttached;
    this.everAttached = true;
    this.reconnectAttempts = 0;
    this.state = "live";
    this.flushPendingWrites();
    this.startHeartbeat();

    if (wasReconnect) this.emit("\x1b[90m[remote] reconnected\x1b[0m\r\n");
    if (msg.truncated_history) {
      this.emit("\x1b[90m[remote] resumed with partial scrollback (older output was trimmed)\x1b[0m\r\n");
    }
  }

  private handleResyncRequired(msg: Record<string, unknown>): void {
    this.emit(`\x1b[33m[remote] can't resume exactly (${String(msg.reason)}) — reattaching fresh\x1b[0m\r\n`);
    // The server allows only one attach per connection, so we can't just
    // resend `attach` here. Reconnect from scratch, this time omitting
    // last_seq so the server's fresh-attach path (which itself clears the
    // client's screen and flags truncated_history) handles it — and do it
    // immediately, not backed off: the server responded correctly, this
    // isn't a connectivity failure.
    this.everAttached = false;
    this.lastSeq = 0;
    this.forcingImmediateReconnect = true;
    this.ws?.close();
  }

  private handleExit(msg: Record<string, unknown>): void {
    if (this.exited) return; // fire onExit exactly once
    this.exited = true;
    this.stopped = true; // the process is gone — nothing left to reconnect to
    this.clearReconnectTimer();
    this.clearHeartbeat();
    document.removeEventListener("visibilitychange", this.visibilityHandler);
    const code = typeof msg.code === "number" ? msg.code : -1;
    const signal = typeof msg.signal === "string" ? msg.signal : undefined;
    for (const cb of this.exitCbs) cb({ exitCode: code, signal });
    this.ws?.close();
    this.ws = null;
  }

  private handleError(msg: Record<string, unknown>): void {
    const code = typeof msg.code === "string" ? msg.code : "error";
    const message = typeof msg.message === "string" ? msg.message : "";

    if (this.state === "live") {
      // Recoverable: something after attach (e.g. a resize) was rejected,
      // but the session itself is unaffected. Just surface it.
      this.emit(`\x1b[33m[remote] ${code}: ${message}\x1b[0m\r\n`);
      return;
    }

    if (code === "unknown_session" || code === "attach_mismatch") {
      // The persisted session id no longer applies (deleted daemon-side, or
      // its backend/cwd were reconfigured). These errors return before the
      // server marks this connection attached, so we're free to just
      // resend `attach` — forget the stale id and start a new session
      // instead of getting stuck retrying the same bad one forever.
      this.emit(`\x1b[33m[remote] ${message} — starting a new session\x1b[0m\r\n`);
      this.sessionId = null;
      this.sendAttach();
      return;
    }

    // Anything else here (unknown backend, cwd outside the daemon's root,
    // session limit reached, ...) means the connection/config itself is
    // wrong. Retrying won't help until the user fixes settings, so stop
    // instead of reconnect-looping forever against the same rejection.
    this.emit(`\x1b[31m[remote] ${code}: ${message}\x1b[0m\r\n`);
    this.stopped = true;
    this.ws?.close();
  }

  // ── protocol: message dispatch ───────────────────────────────────────────

  private handleMessage(ev: MessageEvent<string | ArrayBuffer>): void {
    if (typeof ev.data === "string") this.handleControl(ev.data);
    else this.handleBinary(ev.data);
  }

  private handleControl(raw: string): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return;
    }
    switch (msg.t) {
      case "hello_ok": this.sendAttach(); break;
      case "attach_ok": this.handleAttachOk(msg); break;
      case "resync_required": this.handleResyncRequired(msg); break;
      case "exit": this.handleExit(msg); break;
      case "error": this.handleError(msg); break;
      // Application-level heartbeat: browsers can't send (or originate)
      // WebSocket-level ping frames, so liveness is checked with these
      // JSON messages in both directions — reply to the server's, and see
      // startHeartbeat for us sending our own.
      case "ping": this.sendJson({ t: "pong", ts: msg.ts }); break;
      case "pong": this.awaitingPong = false; break;
      default: break;
    }
  }

  private handleBinary(buf: ArrayBuffer): void {
    const bytes = new Uint8Array(buf);
    if (this.expectClearSequence) {
      // Sent by the server as its own complete message (see
      // CLEAR_SCREEN_SEQUENCE in agent-ptyd.py) purely so a truncated
      // replay clears the screen before it lands, rather than appending
      // possibly-mid-escape bytes onto whatever was already there. It was
      // never counted in the server's own byte-offset stream, so it must
      // not advance lastSeq either — still forwarded to onData like any
      // other bytes so the terminal actually clears.
      this.expectClearSequence = false;
      this.emit(this.decoder.decode(bytes, { stream: true }));
      return;
    }
    this.lastSeq += bytes.length;
    const text = this.decoder.decode(bytes, { stream: true });
    if (text) this.emit(text);
  }

  // ── heartbeat ────────────────────────────────────────────────────────────

  private startHeartbeat(): void {
    this.clearHeartbeat();
    this.heartbeatTimer = window.setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
      if (this.awaitingPong) {
        // No pong since the last tick: the socket is silently dead (a
        // common way for a mobile network change or sleep to manifest)
        // even though onclose hasn't fired — force it closed so reconnect
        // logic takes over instead of waiting on a transport timeout that
        // may never come.
        this.ws.close();
        return;
      }
      this.sendJson({ t: "ping", ts: Date.now() });
      this.awaitingPong = true;
    }, HEARTBEAT_INTERVAL_MS);
  }

  private clearHeartbeat(): void {
    if (this.heartbeatTimer !== null) {
      window.clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    this.awaitingPong = false;
  }

  // ── outgoing data ────────────────────────────────────────────────────────

  private sendJson(obj: Record<string, unknown>): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(obj));
  }

  private sendBinary(bytes: Uint8Array): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(bytes);
  }

  private queueWrite(data: string): void {
    this.pendingWrites.push(data);
    this.pendingWriteChars += data.length;
    while (this.pendingWriteChars > MAX_PENDING_WRITE_CHARS && this.pendingWrites.length > 1) {
      const dropped = this.pendingWrites.shift();
      if (dropped) this.pendingWriteChars -= dropped.length;
    }
  }

  private flushPendingWrites(): void {
    if (!this.pendingWrites.length) return;
    const combined = this.pendingWrites.join("");
    this.pendingWrites = [];
    this.pendingWriteChars = 0;
    this.sendBinary(this.encoder.encode(combined));
  }

  private emit(s: string): void {
    if (s) for (const cb of this.dataCbs) cb(s);
  }
}

// ── GET /info (for the settings-tab backend picker) ─────────────────────────

export interface RemoteBackendInfo {
  id: string;
  label: string;
}

export interface RemoteInfo {
  protocolVersion: number;
  backends: RemoteBackendInfo[];
  maxSessions: number;
  sessionCreateRatePerMin: number;
}

// Uses Obsidian's requestUrl rather than fetch(): the daemon sends no CORS
// headers (it isn't meant to be a browser-facing API), and requestUrl goes
// through Electron's net module / native mobile networking instead of the
// page's fetch, so it isn't subject to CORS at all.
export async function fetchRemoteInfo(url: string, token: string): Promise<RemoteInfo> {
  const res = await requestUrl({
    url: `${toHttpBase(url)}/info`,
    headers: { Authorization: `Bearer ${token}` },
    throw: false,
  });
  if (res.status !== 200) {
    throw new Error(`daemon returned ${res.status}: ${res.text || "no body"}`);
  }
  const body = res.json as {
    protocol_version: number;
    backends: RemoteBackendInfo[];
    max_sessions: number;
    session_create_rate_per_min: number;
  };
  return {
    protocolVersion: body.protocol_version,
    backends: body.backends,
    maxSessions: body.max_sessions,
    sessionCreateRatePerMin: body.session_create_rate_per_min,
  };
}
