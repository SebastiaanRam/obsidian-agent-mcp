import { execFile, process } from "../nodeApi";
import { defaultShell } from "./pty";
import { fetchRemoteInfo } from "./remote";
import type { AgentBackend } from "../settings";

// Whether a backend's CLI has been found on the user's system. Probing is lazy
// and cached for the session, so nothing runs at plugin load and the check never
// sits on a render or keystroke path.
export type Availability = "unknown" | "checking" | "available" | "missing";

// The shell used to probe. It must match how the terminal actually launches
// agents (see agentShell in pty.ts): a GUI-launched Obsidian inherits a stripped
// PATH, so only an interactive login shell resolves tools added in .zprofile /
// .zshrc. Probing with Node's inherited PATH would report false negatives.
export interface ProbeShell {
  shell?: string;
  shellArgs?: string[];
}

// Only simple, single-token binary names are probed. Anything with shell
// metacharacters (a custom startup command that is a pipeline, etc.) can't be
// safely interpolated, so we assume it's available rather than block launch.
const SAFE_CLI = /^[\w.\-/]+$/;

// Desktop only: spawns a shell via Node's child_process, which does not exist
// in Obsidian's mobile webview at all. Never call this on mobile — see
// probeMobile below for mobile's equivalent, and BackendAvailability's
// ensureMobile/recheckMobile for the methods that route to it instead.
function probeCli(cliName: string, shell: ProbeShell): Promise<boolean> {
  // The terminal is macOS/Linux only; `command -v` is POSIX. Never gate on other
  // platforms (nothing launches there anyway).
  if (process.platform === "win32") return Promise.resolve(true);
  if (!SAFE_CLI.test(cliName)) return Promise.resolve(true);

  const file = shell.shell?.trim() || defaultShell().file;
  const loginArgs = shell.shellArgs && shell.shellArgs.length ? shell.shellArgs : ["-i", "-l"];
  const args = [...loginArgs, "-c", `command -v ${cliName}`];

  return new Promise(resolve => {
    execFile(file, args, { timeout: 4000 }, (err, stdout) => {
      resolve(!err && stdout.trim().length > 0);
    });
  });
}

// Mobile has no local process of any kind — nothing to spawn, nothing on a
// PATH to probe. "remote" is the only backend that can ever be real there
// (see view.ts), and its availability is whatever the configured daemon
// reports over GET /info, not a filesystem check. Every other backend is
// simply never available on mobile, and this never touches a Node API to
// find that out.
function probeMobile(backend: AgentBackend, remote: { url: string; token: string } | null): Promise<boolean> {
  if (backend !== "remote" || !remote) return Promise.resolve(false);
  return fetchRemoteInfo(remote.url, remote.token).then(info => info.backends.length > 0).catch(() => false);
}

// Session-scoped cache of backend availability, with in-flight de-duplication so
// concurrent callers (settings tab + terminal open) share a single probe.
export class BackendAvailability {
  private cache = new Map<AgentBackend, Availability>();
  private inflight = new Map<AgentBackend, Promise<Availability>>();

  // Cached state without triggering a probe. Safe to call on every render.
  get(backend: AgentBackend): Availability {
    return this.cache.get(backend) ?? "unknown";
  }

  // Probe once if the result isn't already known; return the cached result
  // otherwise. Concurrent calls for the same backend await the same probe.
  ensure(backend: AgentBackend, cliName: string, shell: ProbeShell): Promise<Availability> {
    return this.run(backend, () => probeCli(cliName, shell));
  }

  // Force a fresh probe, discarding any cached result. Used after the user
  // installs a CLI and asks to recheck.
  recheck(backend: AgentBackend, cliName: string, shell: ProbeShell): Promise<Availability> {
    this.cache.delete(backend);
    this.inflight.delete(backend);
    return this.ensure(backend, cliName, shell);
  }

  // Mobile counterparts of ensure/recheck (see probeMobile above) — kept as
  // separate methods rather than a branch inside ensure()/recheck() so
  // desktop's probing path is untouched byte-for-byte, per the "no Node
  // imports on any mobile path" requirement this was split out for.
  ensureMobile(backend: AgentBackend, remote: { url: string; token: string } | null): Promise<Availability> {
    return this.run(backend, () => probeMobile(backend, remote));
  }

  recheckMobile(backend: AgentBackend, remote: { url: string; token: string } | null): Promise<Availability> {
    this.cache.delete(backend);
    this.inflight.delete(backend);
    return this.ensureMobile(backend, remote);
  }

  private run(backend: AgentBackend, probe: () => Promise<boolean>): Promise<Availability> {
    const cached = this.cache.get(backend);
    if (cached === "available" || cached === "missing") return Promise.resolve(cached);

    const existing = this.inflight.get(backend);
    if (existing) return existing;

    this.cache.set(backend, "checking");
    const p = probe()
      .then(ok => this.settle(backend, ok))
      .catch(() => this.settle(backend, false));
    this.inflight.set(backend, p);
    return p;
  }

  private settle(backend: AgentBackend, ok: boolean): Availability {
    const state: Availability = ok ? "available" : "missing";
    this.cache.set(backend, state);
    this.inflight.delete(backend);
    return state;
  }
}
