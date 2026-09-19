import { ItemView, WorkspaceLeaf, setIcon, Platform, Notice } from "obsidian";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import { CanvasAddon } from "@xterm/addon-canvas";

import { agentShell, defaultShell, spawnShell, type IPty } from "./pty";
import { RemotePty } from "./remote";
import { AGENT_BACKENDS, type AgentBackend } from "../settings";
import type { Availability } from "./availability";

export const AGENT_TERMINAL_VIEW_TYPE = "agent-terminal";

const RESIZE_DEBOUNCE_MS = 60;

// Below this many px of visualViewport shrinkage, treat it as noise (browser
// chrome show/hide, a rounding wobble) rather than the soft keyboard opening.
const KEYBOARD_MIN_INSET_PX = 80;

export interface TerminalConfig {
  // Desktop-only: read only by startPty() to spawn a local pty, which never
  // happens on mobile (see the Platform.isMobile check in startSession()).
  // getTerminalConfig() (main.ts) leaves both unset there rather than resolve
  // them through nodeApi, which has nothing to resolve on mobile.
  pluginDir?: string;
  pythonPath?: string;
  cwd?: string;
  shell?: string;
  shellArgs?: string[];
  fontFamily?: string;
  fontSize?: number;
  /** Extra environment variables for the agent process (e.g. CLAUDE_CODE_SSE_PORT). */
  env?: Record<string, string>;
  /** Agent the terminal starts with. */
  backend: AgentBackend;
  /** Agents to list in the switcher (enabled, and not known to be missing). */
  backends: Array<{ id: AgentBackend; label: string }>;
  /** Cached availability of an agent's CLI; safe to call synchronously. */
  getAvailability: (backend: AgentBackend) => Availability;
  /** Probe availability if unknown; resolves to the settled state. */
  ensureAvailability: (backend: AgentBackend) => Promise<Availability>;
  /** Force a fresh probe (after the user installs a CLI); resolves to the state. */
  recheckAvailability: (backend: AgentBackend) => Promise<Availability>;
  /** The CLI binary name for an agent, used in the "not installed" message. */
  cliName: (backend: AgentBackend) => string;
  /** Command auto-run to launch the given agent, so a bare shell is never shown. */
  resolveStartupCommand: (backend: AgentBackend) => string;
  /** Called when the user switches agents from the toolbar, to persist the choice. */
  onBackendChange: (backend: AgentBackend) => void;
  /** Opens this plugin's settings tab (toolbar gear button). */
  openSettings: () => void;
  /** Remote daemon connection info; present only when backend "remote" is
   * both enabled and fully configured (see main.ts's remoteConfig()).
   * Undefined means "not configured" — selecting "remote" then shows a
   * prompt to configure it rather than attempting a connection. */
  remote?: {
    url: string;
    token: string;
    cwd: string;
    backend: string;
    sessionId: string | null;
    onSessionId: (id: string) => void;
  };
}

export class AgentTerminalView extends ItemView {
  private term: Terminal | null = null;
  private fit: FitAddon | null = null;
  private pty: IPty | null = null;
  private resizeObserver: ResizeObserver | null = null;
  private resizeTimer: number | null = null;
  private disposers: Array<{ dispose(): void }> = [];

  private cfg: TerminalConfig | null = null;
  private currentBackend: AgentBackend = "claude";
  private host: HTMLElement | null = null;
  private select: HTMLSelectElement | null = null;
  // Mobile composer state (see buildMobileComposer). Untouched on desktop.
  private composerEl: HTMLElement | null = null;
  private composerTextarea: HTMLTextAreaElement | null = null;
  private composerSendBtn: HTMLButtonElement | null = null;
  private rawModeToggle: HTMLButtonElement | null = null;
  private rawMode = false;
  private composerInsetRafScheduled = false;
  // Bumped on every start/switch so an async availability probe from a superseded
  // session can't spawn into the wrong (or a torn-down) terminal.
  private sessionSeq = 0;

  constructor(
    leaf: WorkspaceLeaf,
    private readonly configProvider: () => TerminalConfig,
  ) {
    super(leaf);
    this.navigation = true;
  }

  getViewType(): string {
    return AGENT_TERMINAL_VIEW_TYPE;
  }

  getDisplayText(): string {
    return "Agent terminal";
  }

  getIcon(): string {
    return "bot";
  }

  focusTerminal(): void {
    this.term?.focus();
  }

  async onOpen(): Promise<void> {
    const container = this.contentEl;
    container.empty();
    container.addClass("agent-mcp-terminal-container");

    this.cfg = this.configProvider();
    // On mobile no local process can ever run — not a CLI agent, not even a
    // plain shell — so "remote" is the only backend that's ever real there,
    // regardless of what's persisted as the desktop default. main.ts's
    // enabledBackendList() also filters the switcher itself down to just
    // "remote" on mobile, so this never gets contradicted by a dropdown
    // offering something switching to it wouldn't actually do.
    this.currentBackend = Platform.isMobile ? "remote" : this.cfg.backend;

    this.buildToolbar(container);
    this.host = container.createDiv({ cls: "agent-mcp-terminal-host" });
    if (Platform.isMobile) this.buildMobileComposer(container);

    void this.startSession();
  }

  // Toolbar with the agent switcher. Switching restarts the session with the
  // newly selected agent so the user always stays inside an agent interface.
  private buildToolbar(container: HTMLElement): void {
    const bar = container.createDiv({ cls: "agent-mcp-terminal-toolbar" });
    bar.createSpan({ cls: "agent-mcp-terminal-toolbar-label", text: "Agent" });

    const select = bar.createEl("select", {
      cls: "dropdown agent-mcp-terminal-select",
    });
    this.select = select;
    this.populateBackendOptions();

    this.registerDomEvent(select, "change", () => {
      const next = select.value as AgentBackend;
      if (next === this.currentBackend) return;
      this.switchBackend(next);
    });

    const settingsBtn = bar.createEl("button", {
      cls: "clickable-icon agent-mcp-terminal-settings-btn",
      attr: { "aria-label": "Open plugin settings" },
    });
    setIcon(settingsBtn, "settings");
    this.registerDomEvent(settingsBtn, "click", () => this.cfg?.openSettings());
  }

  // Mobile-only composer, pinned above the soft keyboard. Typing happens in
  // this ordinary <textarea>, never in xterm's hidden input: a real textarea
  // focuses reliably from a tap (xterm's own mousedown-based focus frequently
  // isn't recognised as a direct gesture in a mobile webview — see the
  // touchend workaround in startSession()) and it lets the platform's normal
  // autocorrect/predictive text/auto-caps run without corrupting the pty
  // stream a keystroke at a time, since nothing reaches the pty until the
  // user explicitly hits Send. This also folds in the old top-of-view
  // Esc/Tab/arrow row (buildMobileKeyBar): those controls move down here,
  // next to where the user's thumb and the keyboard already are, alongside a
  // new Ctrl-C — the universal interrupt, and previously not sendable at all.
  private buildMobileComposer(container: HTMLElement): void {
    const composer = container.createDiv({ cls: "agent-mcp-terminal-composer" });
    this.composerEl = composer;

    const controls = composer.createDiv({ cls: "agent-mcp-terminal-composer-controls" });
    const keys: Array<{ label: string; seq: string; title: string }> = [
      { label: "Esc", seq: "\x1b", title: "Escape" },
      // Esc only interrupts an agent CLI's own turn; Ctrl-C is the one way
      // to kill a runaway process under the shell backend, and until now
      // there was no way to send it from mobile at all.
      { label: "^C", seq: "\x03", title: "Interrupt (Ctrl-C)" },
      { label: "Tab", seq: "\t", title: "Tab" },
      { label: "↑", seq: "\x1b[A", title: "Up" },
      { label: "↓", seq: "\x1b[B", title: "Down" },
      { label: "←", seq: "\x1b[D", title: "Left" },
      { label: "→", seq: "\x1b[C", title: "Right" },
    ];
    for (const { label, seq, title } of keys) {
      const btn = controls.createEl("button", {
        cls: "agent-mcp-terminal-composer-key",
        text: label,
        attr: { "aria-label": title },
      });
      // touchstart, not click: a click only fires after the webview has
      // already moved focus to the button, which would dismiss the soft
      // keyboard (or drop xterm's focus in raw mode) before the byte is even
      // sent. preventDefault() stops the button from taking focus at all.
      this.registerDomEvent(btn, "touchstart", (e: TouchEvent) => {
        e.preventDefault();
        this.pty?.write(seq);
        if (this.rawMode) this.term?.focus();
      });
    }

    const rawToggle = controls.createEl("button", {
      cls: "agent-mcp-terminal-composer-raw-toggle",
      text: "Raw",
      attr: { "aria-label": "Toggle raw keystroke mode" },
    });
    this.rawModeToggle = rawToggle;
    this.registerDomEvent(rawToggle, "touchstart", (e: TouchEvent) => {
      e.preventDefault();
      this.setRawMode(!this.rawMode);
    });

    const inputRow = composer.createDiv({ cls: "agent-mcp-terminal-composer-input-row" });
    const textarea = inputRow.createEl("textarea", {
      cls: "agent-mcp-terminal-composer-textarea",
      attr: {
        rows: "1",
        placeholder: "Message",
        // "enter", not "send": Return always inserts a newline here (phones
        // have no practical Shift key for the usual Shift+Enter split), so
        // the return key's own label must not promise that it submits.
        enterkeyhint: "enter",
      },
    });
    this.composerTextarea = textarea;

    this.registerDomEvent(textarea, "input", () => this.autoGrowComposerTextarea());
    this.registerDomEvent(textarea, "keydown", (e: KeyboardEvent) => {
      if (e.key !== "Tab") return;
      // The composer can't drive per-keystroke completion (that needs Raw
      // mode, below), and the browser's default behaviour for Tab in a text
      // field is to move focus to the next element — silently stealing it
      // from the composer. Insert a literal tab character instead, so Tab
      // always does exactly one well-defined thing here.
      e.preventDefault();
      insertAtCursor(textarea, "\t");
      this.autoGrowComposerTextarea();
    });

    const sendBtn = inputRow.createEl("button", {
      cls: "agent-mcp-terminal-composer-send",
      attr: { "aria-label": "Send" },
    });
    setIcon(sendBtn, "send");
    this.composerSendBtn = sendBtn;
    this.registerDomEvent(sendBtn, "touchstart", (e: TouchEvent) => {
      e.preventDefault();
      this.sendComposerText();
    });

    const vv = window.visualViewport;
    if (vv) {
      const onViewportChange = () => this.scheduleKeyboardInsetUpdate();
      vv.addEventListener("resize", onViewportChange);
      vv.addEventListener("scroll", onViewportChange);
      // Tied to the view's own lifetime (unregistered on unload/onClose),
      // not the pty session's: stopSession()/startSession() run on every
      // agent switch, but the composer itself is built once in onOpen and
      // outlives session restarts.
      this.register(() => {
        vv.removeEventListener("resize", onViewportChange);
        vv.removeEventListener("scroll", onViewportChange);
      });
      // Establish a baseline in case the view opens while a keyboard is
      // already up (e.g. re-focusing the app mid-edit elsewhere).
      this.scheduleKeyboardInsetUpdate();
    }
    // No `else`: without visualViewport support the composer simply stays in
    // its resting flex position (still above the fold at rest) rather than
    // erroring — it just won't track a keyboard that hides it on that engine.
  }

  // Raw mode gives xterm's hidden textarea real focus so per-keystroke input
  // works again (tab completion, Ctrl-R, curses apps like vim or htop) —
  // things a composer fundamentally can't drive, since it only ever hands
  // over complete lines. The composer's own textarea is disabled while it's
  // on, both so typing can't land in two places at once and as part of the
  // visual change below — the user must never have to wonder which mode
  // they're in.
  private setRawMode(next: boolean): void {
    this.rawMode = next;
    this.composerEl?.classList.toggle("is-raw-mode", next);
    this.rawModeToggle?.classList.toggle("is-active", next);
    this.rawModeToggle?.setText(next ? "Raw: On" : "Raw");
    if (this.composerTextarea) {
      this.composerTextarea.disabled = next;
      this.composerTextarea.placeholder = next ? "Raw mode — tap the terminal to type" : "Message";
    }
    if (this.composerSendBtn) this.composerSendBtn.disabled = next;
    if (next) {
      this.composerTextarea?.blur();
      this.term?.focus();
    } else {
      this.term?.textarea?.blur();
      this.composerTextarea?.focus();
    }
  }

  private autoGrowComposerTextarea(): void {
    const ta = this.composerTextarea;
    if (!ta) return;
    // Reset before measuring so scrollHeight reflects the current content
    // (not a stale, larger height) — needed for the box to shrink back down
    // when text is deleted, not just grow. max-height in CSS caps this.
    ta.style.removeProperty("height");
    ta.style.height = `${ta.scrollHeight}px`;
  }

  private sendComposerText(): void {
    const ta = this.composerTextarea;
    const pty = this.pty;
    if (!ta || !pty || this.rawMode) return;
    const text = ta.value;
    if (!text) return;
    ta.value = "";
    this.autoGrowComposerTextarea();
    this.sendComposedText(pty, text);
  }

  // Multi-line composer text can't be sent as literal bytes with an embedded
  // "\n": an agent CLI (or a plain shell) reading the pty in line mode takes
  // the FIRST newline as Enter and submits whatever was typed so far, so
  // every following line arrives as its own separate, later prompt instead
  // of being part of the one message the user composed. Bracketed paste
  // (CSI 200~ ... CSI 201~) is how a terminal tells the app on the other end
  // "the newlines in here are content, not Enter" — it isn't a formatting
  // nicety, it's the only mechanism that lets a multi-line message survive
  // as a single message at all.
  //
  // That only works if the app on the other end actually asked for it via
  // CSI ?2004h — xterm tracks whether it did as term.modes.bracketedPasteMode,
  // driven entirely by what the pty side has sent, never assumed here. An
  // app that never enabled it wouldn't strip the CSI 200~/201~ markers
  // either — they'd show up as literal garbage in its input line instead of
  // vanishing. With no reliable way to preserve real newlines against an app
  // we know doesn't support them, lines are joined with spaces instead: a
  // visibly different but still-single, still-correct submission, rather
  // than silently refragmenting into several separate prompts.
  private sendComposedText(pty: IPty, text: string): void {
    if (!text.includes("\n")) {
      pty.write(text + "\r");
      return;
    }
    if (this.term?.modes.bracketedPasteMode) {
      pty.write("\x1b[200~" + text + "\x1b[201~\r");
      return;
    }
    pty.write(text.replace(/\n+/g, " ") + "\r");
    new Notice("This session hasn't enabled multi-line input — sent as one line.");
  }

  private scheduleKeyboardInsetUpdate(): void {
    if (this.composerInsetRafScheduled) return;
    this.composerInsetRafScheduled = true;
    window.requestAnimationFrame(() => {
      this.composerInsetRafScheduled = false;
      this.applyKeyboardInset();
    });
  }

  // Pins the composer above the soft keyboard by giving it enough
  // padding-bottom to reach the keyboard's top edge — not position: fixed.
  // The composer is already the last flex child of the container, so
  // growing its own box by exactly the keyboard's height shrinks the
  // terminal host by the same amount through the very same
  // ResizeObserver → scheduleResize → applyResize path used for every other
  // resize, which keeps the pty's rows/cols and xterm's rendered rows
  // consistent with what's actually visible for free — see applyResize()'s
  // mobile scrollToBottom() call for the other half of that.
  //
  // iOS in particular does not shrink window.innerHeight when the keyboard
  // opens (the whole reason this exists), so window.innerHeight is the one
  // stable reference for "how much of the layout viewport isn't visible
  // right now" — that gap is read from visualViewport, never assumed.
  private applyKeyboardInset(): void {
    const composer = this.composerEl;
    const vv = window.visualViewport;
    if (!composer || !vv) return;

    const scale = vv.scale || 1;
    // vv.height/offsetTop shrink for two unrelated reasons — the keyboard
    // opening, or the user pinching to zoom in — and look identical as raw
    // numbers. Multiplying back by `scale` converts the zoomed visual
    // viewport back to layout-viewport-equivalent pixels (the units
    // window.innerHeight is already in), so a pure pinch-zoom with the
    // keyboard still closed cancels back out to ~0 instead of being misread
    // as a keyboard opening.
    const visibleBottom = (vv.offsetTop + vv.height) * scale;
    const keyboardInset = Math.max(0, Math.round(window.innerHeight - visibleBottom));
    const keyboardOpen = keyboardInset > KEYBOARD_MIN_INSET_PX;

    // Below the threshold, clear the inline style so the CSS rule's own
    // env(safe-area-inset-bottom) takes over again. Once the keyboard is
    // open, the visible viewport already ends AT the keyboard's top edge —
    // past where the home indicator would be — so also keeping that padding
    // would double-count the same strip of screen and leave a dead gap
    // between the composer and the keyboard.
    composer.style.paddingBottom = keyboardOpen ? `${keyboardInset}px` : "";
  }

  // Rebuilds the switcher options from the current enabled/available agent list,
  // always including the running agent so the control reflects the live session.
  private populateBackendOptions(): void {
    const select = this.select;
    if (!select) return;
    select.empty();

    const options = this.cfg ? [...this.cfg.backends] : [];
    if (!options.some(b => b.id === this.currentBackend)) {
      const meta = AGENT_BACKENDS.find(b => b.id === this.currentBackend);
      if (meta) options.unshift({ id: meta.id, label: meta.label });
    }
    for (const { id, label } of options) {
      const opt = select.createEl("option", { value: id, text: label });
      if (id === this.currentBackend) opt.selected = true;
    }
  }

  // Called by the plugin when the enabled-agents setting changes, so an already
  // open terminal updates its switcher instantly without a reload. Pulls a fresh
  // config (its backends list reflects the new toggles) and repopulates.
  refreshBackends(): void {
    if (this.cfg) this.cfg.backends = this.configProvider().backends;
    this.populateBackendOptions();
  }

  private switchBackend(backend: AgentBackend): void {
    this.currentBackend = backend;
    this.cfg?.onBackendChange(backend);
    this.stopSession();
    void this.startSession();
  }

  // Builds the terminal + PTY and auto-runs the agent command. Reused by
  // onOpen and by switchBackend, so it starts from a clean host element.
  private async startSession(): Promise<void> {
    const cfg = this.cfg;
    const host = this.host;
    if (!cfg || !host) return;
    const seq = ++this.sessionSeq;
    const backend = this.currentBackend;
    host.empty();

    // Gate CLI-backed agents on availability BEFORE building a terminal. If the
    // tool isn't installed we show a message panel and launch nothing — never a
    // shell (the user shouldn't land at a prompt for an agent they didn't get).
    const meta = AGENT_BACKENDS.find(b => b.id === backend);
    if (meta?.requiresCli) {
      let state = cfg.getAvailability(backend);
      if (state === "unknown" || state === "checking") {
        this.renderInfoPanel(host, `Checking whether ${meta.label} is installed…`);
        state = await cfg.ensureAvailability(backend);
        if (seq !== this.sessionSeq) return;
        host.empty();
      }
      if (state === "missing") {
        this.renderMissingPanel(host, backend);
        return;
      }
    }

    // Same shape of gate as the CLI check above, but for the remote backend:
    // if it's selected without a full configuration (main.ts only sets
    // cfg.remote once enabled + url + token + backend are all present), show
    // a prompt instead of a dead pane.
    if (backend === "remote" && !cfg.remote) {
      this.renderRemoteNotConfiguredPanel(host);
      return;
    }

    const command = cfg.resolveStartupCommand(backend);

    const term = new Terminal({
      fontFamily: cfg.fontFamily || "Menlo, Consolas, \"Liberation Mono\", monospace",
      fontSize: cfg.fontSize || 13,
      cursorBlink: true,
      convertEol: false,
      allowProposedApi: true,
      theme: readTheme(),
      scrollback: 10_000,
      // Wide CJK glyphs & modern emoji span two cells. Matches iTerm2, Alacritty, etc.
      // The actual width table is swapped to Unicode 11 below via the addon.
    });

    const fit = new FitAddon();
    const links = new WebLinksAddon();
    const unicode11 = new Unicode11Addon();

    term.loadAddon(fit);
    term.loadAddon(links);
    term.loadAddon(unicode11);
    term.unicode.activeVersion = "11";

    term.open(host);

    if (Platform.isMobile) {
      // Raw mode (setRawMode) is the only place xterm's hidden textarea gets
      // focus at all on mobile — everywhere else, typing goes through the
      // composer instead (see buildMobileComposer), specifically so this
      // textarea's own autocorrect/auto-caps never runs against a live pty
      // stream one keystroke at a time. It still needs these attributes for
      // when raw mode IS on: without them it silently auto-capitalises
      // commands and substitutes smart quotes.
      const ta = term.textarea;
      if (ta) {
        ta.setAttribute("autocapitalize", "off");
        ta.setAttribute("autocorrect", "off");
        ta.setAttribute("autocomplete", "off");
        ta.setAttribute("spellcheck", "false");
      }
      // xterm focuses its hidden input textarea from its own "mousedown"
      // handler, which calls preventDefault() before this.focus(). On a
      // touch-based mobile webview that's frequently not enough for the OS
      // to treat it as a direct user gesture, so the soft keyboard never
      // raises even though xterm's own model believes the terminal is
      // focused. A real, unmodified "touchend" on the host reliably counts
      // as one — focus explicitly from it as a defensive addition, but only
      // in raw mode: outside it, tapping the transcript must never focus
      // xterm's hidden textarea (that's the composer's whole point). This
      // could not be visually verified in this environment (no real mobile
      // webview available); confirm on an actual device that tapping the
      // terminal raises the keyboard before relying on this.
      this.registerDomEvent(host, "touchend", () => {
        if (this.rawMode) term.focus();
      });
    }

    // Canvas renderer renders block characters (▀▄█▐▌) and box-drawing chars
    // crisply with no anti-aliasing seams — which the Claude Code splash logo
    // relies on. It must be loaded AFTER .open().
    try {
      term.loadAddon(new CanvasAddon());
    } catch {
      // Fall back to the default DOM renderer if canvas isn't available.
    }

    this.term = term;
    this.fit = fit;

    // Wait for layout to settle so fit() has real dimensions to measure.
    this.scheduleInitialFit(host);

    try {
      this.pty = backend === "remote" && cfg.remote
        ? this.startRemotePty(cfg.remote, term.cols, term.rows)
        : this.startPty(cfg, command, term.cols, term.rows);
    } catch (err) {
      // Only synchronous throws from spawnShell() land here — i.e. writeFileSync
      // failing to write the bridge script (missing plugin dir, permissions).
      // A failed python spawn is never one of them: it arrives later on the
      // child's "error" event and is handled in PythonPty (pty.ts), which
      // prints its own Python-path message. So no Python advice belongs here.
      const e = err as Error;
      term.writeln("\x1b[31mFailed to start shell:\x1b[0m " + (e.message ?? String(err)));
      return;
    }

    this.wirePtyToTerm(this.pty, term);

    this.resizeObserver = new ResizeObserver(() => this.scheduleResize());
    this.resizeObserver.observe(host);

    // On mobile, focus xterm's hidden textarea only if the user was already
    // in raw mode before this (re)start (e.g. switching agents) — never as
    // the default, since typing lives in the composer instead. Desktop is
    // unaffected: it always focuses, exactly as before.
    if (!Platform.isMobile || this.rawMode) term.focus();
  }

  // A transient status line while an agent's CLI is being probed.
  private renderInfoPanel(host: HTMLElement, message: string): void {
    const panel = host.createDiv({ cls: "agent-mcp-terminal-message" });
    panel.createDiv({ cls: "agent-mcp-terminal-message-body", text: message });
  }

  // Shown when "Remote" is selected but main.ts didn't supply cfg.remote —
  // i.e. it isn't fully configured yet (enabled + URL + token + backend all
  // set). Mirrors renderMissingPanel's shape for a CLI agent: no attempt to
  // connect, just where to go fix it.
  private renderRemoteNotConfiguredPanel(host: HTMLElement): void {
    const panel = host.createDiv({ cls: "agent-mcp-terminal-message" });
    panel.createDiv({ cls: "agent-mcp-terminal-message-title", text: "Remote backend not configured" });
    panel.createDiv({
      cls: "agent-mcp-terminal-message-body",
      text: "Set a daemon URL, auth token, and remote backend in the plugin settings.",
    });
    const actions = panel.createDiv({ cls: "agent-mcp-terminal-message-actions" });
    const settings = actions.createEl("button", { text: "Open settings" });
    this.registerDomEvent(settings, "click", () => this.cfg?.openSettings());
  }

  // Shown instead of launching a CLI-backed agent whose tool isn't installed. No
  // shell, no install directories (those change and add maintenance) — just which
  // CLI to install, plus Recheck (after installing) and a jump to settings.
  private renderMissingPanel(host: HTMLElement, backend: AgentBackend): void {
    const meta = AGENT_BACKENDS.find(b => b.id === backend);
    const label = meta?.label ?? backend;
    const cli = this.cfg?.cliName(backend) || backend;

    const panel = host.createDiv({ cls: "agent-mcp-terminal-message" });
    panel.createDiv({ cls: "agent-mcp-terminal-message-title", text: `${label} is not installed` });

    const body = panel.createDiv({ cls: "agent-mcp-terminal-message-body" });
    body.appendText("The ");
    body.createEl("code", { text: cli });
    body.appendText(" command wasn't found on your PATH. Install it, then recheck.");

    const actions = panel.createDiv({ cls: "agent-mcp-terminal-message-actions" });

    if (meta?.installUrl) {
      // A real link so Obsidian opens it in the system browser; styled as a button.
      const install = actions.createEl("a", {
        cls: "agent-mcp-terminal-message-link",
        text: `Install ${label}`,
        href: meta.installUrl,
        attr: { target: "_blank", rel: "noopener" },
      });
      install.addClass("mod-cta");
    }

    const recheck = actions.createEl("button", { text: "Recheck" });
    this.registerDomEvent(recheck, "click", () => {
      recheck.setText("Checking…");
      recheck.disabled = true;
      void this.recheckAndMaybeStart(backend);
    });

    const settings = actions.createEl("button", { text: "Open settings" });
    this.registerDomEvent(settings, "click", () => this.cfg?.openSettings());
  }

  // Re-probe after the user says they installed the CLI, then re-run the session:
  // it builds the terminal if the tool is now found, or re-renders the panel.
  private async recheckAndMaybeStart(backend: AgentBackend): Promise<void> {
    const cfg = this.cfg;
    if (!cfg) return;
    await cfg.recheckAvailability(backend);
    if (this.currentBackend !== backend) return;
    this.populateBackendOptions();
    void this.startSession();
  }

  private scheduleInitialFit(host: HTMLElement): void {
    // Two rAFs: first lets the browser flush layout after element insertion,
    // second lets xterm commit its initial render before we measure.
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
      if (host.clientWidth === 0 || host.clientHeight === 0) return;
      this.applyResize();
    }));
  }

  private scheduleResize(): void {
    if (this.resizeTimer) window.clearTimeout(this.resizeTimer);
    this.resizeTimer = window.setTimeout(() => {
      this.resizeTimer = null;
      this.applyResize();
    }, RESIZE_DEBOUNCE_MS);
  }

  private applyResize(): void {
    if (!this.fit || !this.term || !this.pty) return;
    const dims = this.fit.proposeDimensions();
    if (!dims || !isFinite(dims.cols) || !isFinite(dims.rows) || dims.cols < 2 || dims.rows < 2) {
      // Pane is collapsed, hidden, or mid-animation — skip this tick.
      return;
    }
    try {
      this.fit.fit();
      if (this.term.cols !== dims.cols || this.term.rows !== dims.rows) {
        this.pty.resize(dims.cols, dims.rows);
      } else {
        this.pty.resize(this.term.cols, this.term.rows);
      }
      // The composer growing to clear the keyboard (applyKeyboardInset)
      // shrinks the host, which lands here through the same ResizeObserver
      // as any other resize. Without this, the keyboard opening leaves the
      // newest output hidden behind the composer until the user manually
      // scrolls. Mobile-only: this must not change desktop's resize behaviour.
      if (Platform.isMobile) this.term.scrollToBottom();
    } catch {
      // Transient races between xterm and the PTY on rapid resize — ignore.
    }
  }

  private startPty(cfg: TerminalConfig, command: string, cols: number, rows: number): IPty {
    // Only reachable on desktop: startSession() never takes this path on
    // mobile (backend is forced to "remote" there), so pluginDir/cwd
    // (desktop-only, see TerminalConfig) are always set here even though the
    // type allows undefined for the mobile case.
    if (!cfg.pluginDir || !cfg.cwd) throw new Error("startPty: missing pluginDir/cwd (unreachable on mobile)");

    const cmd = command.trim();
    // Launch straight into the agent (never a bare shell). If no command resolves
    // (plain terminal, or a missing-CLI fallback), use an interactive login shell.
    const { file, args } = cmd
      ? agentShell(cmd, cfg.shell, cfg.shellArgs)
      : (cfg.shell ? { file: cfg.shell, args: cfg.shellArgs ?? [] } : defaultShell());
    return spawnShell({
      pluginDir: cfg.pluginDir,
      pythonPath: cfg.pythonPath,
      shell: file,
      args,
      cwd: cfg.cwd,
      env: cfg.env,
      cols: Math.max(cols, 2),
      rows: Math.max(rows, 2),
    });
  }

  // Builds a RemotePty (see remote.ts) instead of spawning a local shell.
  // Synchronous like startPty(), even though the actual connection happens
  // asynchronously inside RemotePty — it reports its own "connecting…" and
  // any errors through onData once wirePtyToTerm subscribes, right after
  // this returns.
  private startRemotePty(remote: NonNullable<TerminalConfig["remote"]>, cols: number, rows: number): IPty {
    return new RemotePty({
      url: remote.url,
      token: remote.token,
      backend: remote.backend,
      cwd: remote.cwd,
      cols: Math.max(cols, 2),
      rows: Math.max(rows, 2),
      sessionId: remote.sessionId ?? undefined,
      onSessionId: remote.onSessionId,
    });
  }

  private wirePtyToTerm(pty: IPty, term: Terminal): void {
    this.disposers.push(
      pty.onData(data => term.write(data)),
      pty.onExit(({ exitCode }) => {
        term.writeln("");
        term.writeln(`\x1b[90m[process exited with code ${exitCode}]\x1b[0m`);
      }),
      term.onData(data => pty.write(data)),
    );
  }

  // Tears down the current terminal + PTY but leaves the toolbar and host in
  // place, so a new session can be started on the same view (agent switch).
  private stopSession(): void {
    if (this.resizeTimer) {
      window.clearTimeout(this.resizeTimer);
      this.resizeTimer = null;
    }
    for (const d of this.disposers) {
      try { d.dispose(); } catch { /* noop */ }
    }
    this.disposers = [];
    this.resizeObserver?.disconnect();
    this.resizeObserver = null;
    try { this.pty?.kill(); } catch { /* noop */ }
    this.pty = null;
    try { this.term?.dispose(); } catch { /* noop */ }
    this.term = null;
    this.fit = null;
  }

  async onClose(): Promise<void> {
    this.stopSession();
    this.host = null;
    this.cfg = null;
    this.select = null;
    this.composerEl = null;
    this.composerTextarea = null;
    this.composerSendBtn = null;
    this.rawModeToggle = null;
  }
}

// Inserts text at the caret (replacing any selection), for the composer's
// literal-tab handling — plain DOM textareas have no other built-in way to
// insert text at an arbitrary cursor position.
function insertAtCursor(el: HTMLTextAreaElement, text: string): void {
  const start = el.selectionStart ?? el.value.length;
  const end = el.selectionEnd ?? el.value.length;
  el.value = el.value.slice(0, start) + text + el.value.slice(end);
  el.selectionStart = el.selectionEnd = start + text.length;
}

function readTheme() {
  const styles = activeWindow.getComputedStyle(activeDocument.body);
  const v = (name: string, fallback: string) => styles.getPropertyValue(name).trim() || fallback;
  return {
    background: v("--background-primary", "#1e1e1e"),
    foreground: v("--text-normal", "#d4d4d4"),
    cursor: v("--text-normal", "#d4d4d4"),
    selectionBackground: v("--text-selection", "#264f78"),
  };
}
