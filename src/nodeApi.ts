/*
 * Typed facade over the Node.js builtins this plugin uses.
 *
 * Obsidian's hosted plugin review type-checks the source in an environment
 * where the node:* type declarations never resolve (regardless of where
 * @types/node is declared), so every value imported from a Node builtin is
 * `any` there, and each use trips the review's type-checked no-unsafe-*
 * rules — hundreds of false positives across the plugin's fs/net/terminal
 * code. Asserting each builtin to a structural type here keeps every other
 * line of the plugin fully typed in both environments. The interfaces
 * describe only the API surface the plugin actually uses; `npm run
 * typecheck` (with real @types/node installed) still validates these shapes
 * and all call sites against the real types.
 *
 * Node builtins are also resolved lazily, on first use, rather than at
 * module load: Obsidian mobile has no `require` for them at all (there is no
 * Node runtime), and a static top-level `import * as nodeFs from "node:fs"`
 * — which esbuild turns into a top-level `require("node:fs")` in the bundle
 * — throws the instant the plugin loads, taking the whole plugin down with
 * it. Every export below is a thin wrapper that only touches `window.require`
 * when actually called, so requiring this module (as main.ts does at its own
 * top level) is safe on every platform; only *calling* a desktop-only export
 * from a still-unguarded mobile code path fails, and it fails with a clear
 * error rather than a silent crash at load. Going through `window.require`
 * rather than a bare `require(id)` also keeps esbuild from statically
 * analysing and re-inlining the dependency, which would reintroduce the
 * top-level require it's meant to avoid.
 *
 * The assertions are type-level only: the bundled output for every call site
 * elsewhere in the plugin is unchanged.
 */

// Resolves one Node builtin by id via window.require, memoizing the result so
// repeated calls don't re-require. Absent on mobile (no Node runtime), in
// which case we throw a clear, module-naming error instead of letting the
// call site fail on `undefined.someMethod`.
function lazyModule<T>(id: string): () => T {
  let mod: T | undefined;
  return () => {
    if (mod === undefined) {
      const req = (window as unknown as { require?: (id: string) => unknown }).require;
      if (!req) {
        throw new Error(`[agent-mcp] "${id}" is unavailable: Node.js APIs don't exist on this platform (e.g. Obsidian mobile)`);
      }
      mod = req(id) as T;
    }
    return mod;
  };
}

// ── Buffer ───────────────────────────────────────────────────────────────────

export interface Buffer {
  readonly length: number;
  [index: number]: number;
  subarray(start?: number, end?: number): Buffer;
  readUInt16BE(offset: number): number;
  readBigUInt64BE(offset: number): bigint;
  writeUInt16BE(value: number, offset: number): number;
  writeBigUInt64BE(value: bigint, offset: number): number;
  toString(encoding?: string): string;
}

interface BufferConstructor {
  alloc(size: number): Buffer;
  concat(list: readonly Buffer[]): Buffer;
  from(data: string | Buffer): Buffer;
}

const bufferModule = lazyModule<{ Buffer: BufferConstructor }>("node:buffer");

export const Buffer: BufferConstructor = {
  alloc: size => bufferModule().Buffer.alloc(size),
  concat: list => bufferModule().Buffer.concat(list),
  from: data => bufferModule().Buffer.from(data),
};

// ── process ──────────────────────────────────────────────────────────────────

export type EnvVars = Record<string, string | undefined>;

interface ProcessLike {
  readonly pid: number;
  readonly platform: string;
  readonly env: EnvVars;
  kill(pid: number, signal: number | string): boolean;
}

// The renderer window exposes Node's `process` directly (Obsidian desktop runs
// plugins with Node integration) rather than through `require`, so this isn't
// part of the lazy-require scheme above: reading a possibly-absent property off
// `window` can't throw. On mobile this is simply `undefined` — callers that may
// run on mobile must check `Platform.isMobile` before touching it, same as any
// other desktop-only export here.
export const process = (
  window as unknown as { process?: unknown }
).process as ProcessLike;

// ── fs ───────────────────────────────────────────────────────────────────────

interface FsModule {
  writeFileSync: (path: string, data: string) => void;
  renameSync: (oldPath: string, newPath: string) => void;
  unlinkSync: (path: string) => void;
  readdirSync: (path: string) => string[];
  readFileSync: (path: string, encoding: string) => string;
  mkdirSync: (path: string, options?: { recursive?: boolean }) => void;
  existsSync: (path: string) => boolean;
}

const fs = lazyModule<FsModule>("node:fs");

export function writeFileSync(path: string, data: string): void { fs().writeFileSync(path, data); }
export function renameSync(oldPath: string, newPath: string): void { fs().renameSync(oldPath, newPath); }
export function unlinkSync(path: string): void { fs().unlinkSync(path); }
export function readdirSync(path: string): string[] { return fs().readdirSync(path); }
export function readFileSync(path: string, encoding: string): string { return fs().readFileSync(path, encoding); }
export function mkdirSync(path: string, options?: { recursive?: boolean }): void { fs().mkdirSync(path, options); }
export function existsSync(path: string): boolean { return fs().existsSync(path); }

// ── path / os ────────────────────────────────────────────────────────────────

interface PathModule {
  join: (...paths: string[]) => string;
}

interface OsModule {
  homedir: () => string;
}

const pathModule = lazyModule<PathModule>("node:path");
const osModule = lazyModule<OsModule>("node:os");

export function join(...paths: string[]): string { return pathModule().join(...paths); }
export function homedir(): string { return osModule().homedir(); }

// ── crypto ───────────────────────────────────────────────────────────────────

interface Hash {
  update(data: string): Hash;
  digest(encoding: string): string;
}

interface CryptoModule {
  randomUUID: () => string;
  createHash: (algorithm: string) => Hash;
}

const cryptoModule = lazyModule<CryptoModule>("node:crypto");

export function randomUUID(): string { return cryptoModule().randomUUID(); }
export function createHash(algorithm: string): Hash { return cryptoModule().createHash(algorithm); }

// ── http / net ───────────────────────────────────────────────────────────────

export interface Socket {
  readonly writable: boolean;
  write(data: string | Buffer): boolean;
  destroy(): void;
  unshift(data: Buffer): void;
  on(event: "data", cb: (data: Buffer) => void): this;
  on(event: "close" | "error", cb: () => void): this;
}

export interface IncomingMessage {
  readonly headers: Record<string, string | string[] | undefined>;
  readonly url?: string;
  readonly method?: string;
  on(event: "data", cb: (chunk: Buffer) => void): this;
  on(event: "end" | "close", cb: () => void): this;
}

export interface ServerResponse {
  readonly writableEnded: boolean;
  writeHead(status: number, headers?: Record<string, string>): this;
  write(data: string): boolean;
  end(body?: string): void;
}

export interface Server {
  close(): void;
  listen(port: number, host: string, cb?: () => void): void;
  address(): unknown;
  on(event: "upgrade", cb: (req: IncomingMessage, socket: Socket, head: Buffer) => void): this;
  on(event: "error", cb: (err: Error & { code?: string }) => void): this;
}

interface HttpModule {
  createServer: (handler: (req: IncomingMessage, res: ServerResponse) => void) => Server;
}

const httpModule = lazyModule<HttpModule>("node:http");

export function createServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Server {
  return httpModule().createServer(handler);
}

// ── child_process ────────────────────────────────────────────────────────────

export interface Writable {
  write(data: string): boolean;
}

interface Readable {
  on(event: "data", cb: (data: Buffer) => void): this;
}

export interface ChildProcess {
  readonly stdio: ReadonlyArray<Writable | Readable | null | undefined>;
  readonly stdin: Writable | null;
  readonly stdout: Readable | null;
  readonly stderr: Readable | null;
  on(event: "error", cb: (err: Error) => void): this;
  on(event: "exit", cb: (code: number | null, signal: string | null) => void): this;
  kill(signal?: string): boolean;
}

interface ChildProcessModule {
  spawn: (
    command: string,
    args: readonly string[],
    options: { cwd?: string; env?: EnvVars; stdio?: readonly string[] },
  ) => ChildProcess;
  execFile: (
    command: string,
    args: readonly string[],
    options: { timeout?: number },
    callback: (err: Error | null, stdout: string) => void,
  ) => void;
}

const childProcessModule = lazyModule<ChildProcessModule>("node:child_process");

export function spawn(
  command: string,
  args: readonly string[],
  options: { cwd?: string; env?: EnvVars; stdio?: readonly string[] },
): ChildProcess {
  return childProcessModule().spawn(command, args, options);
}

export function execFile(
  command: string,
  args: readonly string[],
  options: { timeout?: number },
  callback: (err: Error | null, stdout: string) => void,
): void {
  childProcessModule().execFile(command, args, options, callback);
}

// ── string_decoder ───────────────────────────────────────────────────────────

interface StringDecoderInstance {
  write(buffer: Buffer): string;
}

interface StringDecoderModule {
  StringDecoder: new (encoding: string) => StringDecoderInstance;
}

const stringDecoderModule = lazyModule<StringDecoderModule>("node:string_decoder");

// A thin class rather than a re-exported constructor, so `new StringDecoder(...)`
// only resolves node:string_decoder when actually constructed, not at import
// time. The class doubles as the instance type (as the old destructured export
// did via `export type StringDecoder = StringDecoderInstance`), so callers that
// write `new StringDecoder("utf8")` see no difference.
export class StringDecoder implements StringDecoderInstance {
  private readonly inner: StringDecoderInstance;

  constructor(encoding: string) {
    this.inner = new (stringDecoderModule().StringDecoder)(encoding);
  }

  write(buffer: Buffer): string {
    return this.inner.write(buffer);
  }
}
