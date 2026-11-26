import { EventEmitter } from "node:events";
import * as fs from "node:fs";
import { classifyRequest, isIpAddress, isLoopback, knownChildOwner, normalizeHost } from "./classify.js";
import { computeScore } from "./grade.js";
import { SensitiveMatcher, ownNamespaces } from "./watchlist.js";
import type {
  AttributionKind,
  AuditEvent,
  ChildActivity,
  DnsEvent,
  ProcessAttribution,
  EventSource,
  FileEvent,
  FileSummary,
  HostCategory,
  HostSummary,
  NetEvent,
  Protocol,
  ScoreResult,
  WatchEntry,
  WatchKind,
} from "./types.js";

/** Higher = more trustworthy counts for a host. */
const SOURCE_RANK: Record<EventSource, number> = {
  preload: 5,
  proxy: 4,
  strace: 3,
  fs_usage: 3,
  lsof: 1,
  narc: 0,
};

interface SourceStats {
  requests: number;
  bytesOut: number;
  bytesIn: number;
  ports: Set<number>;
  protocols: Set<Protocol>;
  methods: Set<string>;
  paths: Set<string>;
}

interface HostRecord {
  host: string;
  category: HostCategory;
  firstSeen: number;
  perSource: Map<EventSource, SourceStats>;
  pids: Set<number>;
  /** Attributions handed in with events (regrade of a saved report). */
  explicit: ProcessAttribution[];
}

interface FileRecord {
  path: string;
  ops: Map<string, number>;
  sources: Set<EventSource>;
  pids: Set<number>;
  watch: WatchEntry | null;
  /** True once any access saw the path exist (events without the flag count as existing). */
  exists: boolean;
  /** Accounting names of processes that touched it (from layers that know them). */
  procs: Set<string>;
  explicit: ProcessAttribution[];
  /** True when the path is a directory (listing or probing a directory is never a secret read). */
  isDir: boolean;
}

export type Alert = { launcher: boolean; attribution?: ProcessAttribution } & (
  | { level: "high"; kind: "file"; event: FileEvent; watch: WatchEntry; display: string }
  | { level: "high"; kind: "net"; event: NetEvent }
  | { level: "warn"; kind: "net"; event: NetEvent }
  | { level: "info"; kind: "net"; event: NetEvent }
  | { level: "info"; kind: "file"; event: FileEvent; display: string }
);

export interface CollectorOptions {
  matcher: SensitiveMatcher;
  ownNamespaces: Set<string>;
  /** Loopback ports owned by narc itself (proxy, IPC). Connections to them are ignored. */
  ignoreLocalPorts?: Iterable<number>;
  /** Hosts from the user's own OTEL_EXPORTER_OTLP_* env: classified USER_OTLP, never penalised. */
  userOtlpHosts?: Iterable<string>;
  /** Fold external child processes' activity into the grade (default: excluded). */
  includeChildren?: boolean;
}

export class Collector extends EventEmitter {
  readonly matcher: SensitiveMatcher;
  readonly ownNamespaces: Set<string>;
  readonly events: AuditEvent[] = [];
  private files = new Map<string, FileRecord>();
  private hosts = new Map<string, HostRecord>();
  private netById = new Map<string, NetEvent>();
  private ipToHost = new Map<string, string>();
  private ignoreLocalPorts: Set<number>;
  private launcher: { pid: number; name: string } | null = null;
  private resolveProc: ((pid: number) => string | undefined) | null = null;
  private attributor: ((pid: number) => ProcessAttribution) | null = null;
  private nameAttributor: ((name: string) => ProcessAttribution | null) | null = null;
  private observedChildren: (() => Set<string>) | null = null;
  private ownCache = new Map<string, Set<string>>();
  private userOtlp: Set<string>;
  readonly includeChildren: boolean;
  private seq = 0;

  constructor(opts: CollectorOptions) {
    super();
    this.matcher = opts.matcher;
    this.ownNamespaces = opts.ownNamespaces;
    this.ignoreLocalPorts = new Set(opts.ignoreLocalPorts ?? []);
    this.userOtlp = new Set([...(opts.userOtlpHosts ?? [])].map(normalizeHost));
    this.includeChildren = opts.includeChildren ?? false;
  }

  /** Per-pid classification (target vs external child), consulted at summary time. */
  setAttributor(fn: (pid: number) => ProcessAttribution): void {
    this.attributor = fn;
  }

  /** Classification by accounting name, for layers that know no pid (fs_usage). */
  setNameAttributor(fn: (name: string) => ProcessAttribution | null): void {
    this.nameAttributor = fn;
  }

  /** External child CLIs seen in the tree, for attributing short-lived connections whose pid vanished. */
  setObservedChildren(fn: () => Set<string>): void {
    this.observedChildren = fn;
  }

  /** The proxy learns a connection's pid a little after the request was logged. */
  setNetPid(id: string, pid: number): void {
    const ev = this.netById.get(id);
    if (!ev || ev.pid === pid) return;
    ev.pid = pid;
    this.hosts.get(ev.host)?.pids.add(pid);
  }

  attributionOfPid(pid: number | undefined): ProcessAttribution | undefined {
    return pid !== undefined && this.attributor ? this.attributor(pid) : undefined;
  }

  attributionOfName(name: string): ProcessAttribution | null {
    return this.nameAttributor ? this.nameAttributor(name) : null;
  }

  /**
   * Combine every process that touched a record into one verdict: target wins
   * over child. A host nobody could be pinned to is handed to a well-known
   * child CLI that was actually observed in the tree, or left `unattributed`;
   * a file with no process information counts against the target (file
   * events always come with a pid or a process name, so this is theoretical).
   */
  private resolveAttribution(
    pids: Iterable<number>,
    names: Iterable<string>,
    explicit: ProcessAttribution[],
    host?: string,
  ): { attribution: AttributionKind; via: string; processNames: string[] } {
    const atts: ProcessAttribution[] = [...explicit];
    for (const pid of pids) {
      const a = this.attributionOfPid(pid);
      if (a) atts.push(a);
    }
    for (const n of names) {
      const a = this.attributionOfName(n);
      if (a) atts.push(a);
    }
    const processNames = [...new Set(atts.map((a) => a.processName).filter(Boolean))];
    if (!atts.length) {
      // Only a run that could attribute at all (process tracking active) may call a host
      // unattributed; a plain collector or an old report without attribution stays "target".
      if (host !== undefined && (this.attributor || this.observedChildren)) {
        const owner = knownChildOwner(host);
        if (owner && this.observedChildren?.().has(owner)) return { attribution: "child", via: owner, processNames: [owner] };
        return { attribution: "unattributed", via: "", processNames: [] };
      }
      return { attribution: "target", via: "", processNames: [...new Set(names)] };
    }
    if (atts.some((a) => a.attribution === "target")) return { attribution: "target", via: "", processNames };
    if (atts.every((a) => a.attribution === "unattributed")) return { attribution: "unattributed", via: "", processNames };
    return { attribution: "child", via: [...new Set(atts.filter((a) => a.attribution === "child").map((a) => a.via).filter(Boolean))].join("+"), processNames };
  }

  ignorePort(port: number): void {
    this.ignoreLocalPorts.add(port);
  }

  /**
   * Mark the direct child as a package runner (npx, pnpm dlx, bunx, …). Its own
   * reads and requests (registry lookups, ~/.npmrc, ~/.gitconfig) are reported
   * but excluded from the grade so the tool is judged on its own behaviour.
   */
  setLauncher(pid: number, name: string): void {
    this.launcher = { pid, name };
  }

  getLauncher(): { pid: number; name: string } | null {
    return this.launcher;
  }

  /** Lets the collector turn pids from the hook into process names at summary time. */
  setProcessResolver(fn: (pid: number) => string | undefined): void {
    this.resolveProc = fn;
  }

  private ownOf(proc: string): Set<string> {
    let v = this.ownCache.get(proc);
    if (!v) {
      v = ownNamespaces([proc]);
      this.ownCache.set(proc, v);
    }
    return v;
  }

  private isLauncherPid(pid: number | undefined): boolean {
    return this.launcher !== null && pid !== undefined && pid === this.launcher.pid;
  }

  private launcherOnly(pids: Set<number>): boolean {
    if (!this.launcher || pids.size === 0) return false;
    for (const p of pids) if (p !== this.launcher.pid) return false;
    return true;
  }

  nextId(prefix: string): string {
    return `${prefix}-${++this.seq}`;
  }

  // ---- files ---------------------------------------------------------------

  addFile(input: {
    source: EventSource;
    pid?: number;
    path: string;
    op: string;
    ts?: number;
    id?: string;
    exists?: boolean;
    proc?: string | string[];
    attribution?: ProcessAttribution;
  }): FileEvent | null {
    const norm = this.matcher.normalize(input.path);
    const watch = this.matcher.match(norm);
    const dot = watch ? true : this.matcher.isDotfileUnderHome(norm);
    if (!watch && !dot) return null; // not interesting

    const ev: FileEvent = {
      kind: "file",
      id: input.id ?? this.nextId("f"),
      ts: input.ts ?? Date.now(),
      source: input.source,
      pid: input.pid,
      path: norm,
      op: input.op,
      sensitive: watch ? watch.id : null,
      exists: input.exists,
      proc: Array.isArray(input.proc) ? input.proc[0] : input.proc,
      processName: input.attribution?.processName,
      attribution: input.attribution?.attribution,
      via: input.attribution?.via,
    };
    this.events.push(ev);

    let rec = this.files.get(norm);
    const first = !rec;
    if (!rec) {
      let isDir = /^(promises\.)?readdir(Sync)?$/.test(input.op);
      if (!isDir && input.exists !== false) {
        try {
          isDir = fs.statSync(norm).isDirectory();
        } catch {
          /* unknown: treat as a file */
        }
      }
      rec = { path: norm, ops: new Map(), sources: new Set(), pids: new Set(), watch, exists: false, procs: new Set(), explicit: [], isDir };
      this.files.set(norm, rec);
    }
    if (input.attribution) rec.explicit.push(input.attribution);
    rec.ops.set(ev.op, (rec.ops.get(ev.op) ?? 0) + 1);
    rec.sources.add(ev.source);
    if (ev.pid !== undefined) rec.pids.add(ev.pid);
    for (const pr of Array.isArray(input.proc) ? input.proc : input.proc ? [input.proc] : []) rec.procs.add(pr);
    if (input.exists !== false) rec.exists = true;

    // Probes of absent paths are recorded but never alerted on.
    if (first && input.exists === false) return ev;
    if (first) {
      const display = this.matcher.display(norm);
      const launcher = this.isLauncherPid(ev.pid);
      const attribution = input.attribution ?? this.attributionOfPid(ev.pid) ?? (ev.proc ? this.attributionOfName(ev.proc) ?? undefined : undefined);
      if (watch && watch.kind === "secret") {
        const alert: Alert = { level: "high", kind: "file", event: ev, watch, display, launcher, attribution };
        this.emit("alert", alert);
      } else {
        const alert: Alert = { level: "info", kind: "file", event: ev, display, launcher, attribution };
        this.emit("alert", alert);
      }
    }
    return ev;
  }

  // ---- dns -----------------------------------------------------------------

  addDns(input: { source: EventSource; pid?: number; host: string; addresses: string[]; id?: string }): void {
    const host = normalizeHost(input.host);
    if (!host) return;
    for (const a of input.addresses) {
      if (a && !this.ipToHost.has(a)) this.ipToHost.set(a, host);
    }
    const ev: DnsEvent = {
      kind: "dns",
      id: input.id ?? this.nextId("d"),
      ts: Date.now(),
      source: input.source,
      pid: input.pid,
      host,
      addresses: input.addresses,
    };
    this.events.push(ev);
  }

  resolveIp(ip: string): string | undefined {
    return this.ipToHost.get(ip);
  }

  // ---- net -----------------------------------------------------------------

  addNet(input: {
    source: EventSource;
    pid?: number;
    host: string;
    port: number;
    protocol: Protocol;
    method?: string;
    path?: string;
    url?: string;
    bytesOut?: number;
    bytesIn?: number;
    ts?: number;
    id?: string;
    attribution?: ProcessAttribution;
  }): NetEvent | null {
    let host = normalizeHost(input.host);
    if (!host) return null;
    if (isLoopback(host)) return null; // loopback is never an outbound host (and covers narc's own plumbing)
    if (isIpAddress(host)) {
      const mapped = this.ipToHost.get(host);
      if (mapped) host = mapped;
    }
    const category: HostCategory = this.userOtlp.has(host) ? "USER_OTLP" : classifyRequest(host, input.path);
    const ev: NetEvent = {
      kind: "net",
      id: input.id ?? this.nextId("n"),
      ts: input.ts ?? Date.now(),
      source: input.source,
      pid: input.pid,
      host,
      port: input.port,
      protocol: input.protocol,
      method: input.method,
      path: input.path,
      url: input.url,
      bytesOut: input.bytesOut ?? 0,
      bytesIn: input.bytesIn ?? 0,
      category,
      processName: input.attribution?.processName,
      attribution: input.attribution?.attribution,
      via: input.attribution?.via,
    };
    this.events.push(ev);
    this.netById.set(ev.id, ev);

    let rec = this.hosts.get(host);
    const first = !rec;
    let upgraded = false;
    if (!rec) {
      rec = { host, category, firstSeen: ev.ts, perSource: new Map(), pids: new Set(), explicit: [] };
      this.hosts.set(host, rec);
    } else if (rec.category !== "TELEMETRY" && category === "TELEMETRY") {
      // A path-aware layer just showed this generic host is a telemetry endpoint.
      rec.category = "TELEMETRY";
      upgraded = true;
    }
    let stats = rec.perSource.get(ev.source);
    if (!stats) {
      stats = {
        requests: 0,
        bytesOut: 0,
        bytesIn: 0,
        ports: new Set(),
        protocols: new Set(),
        methods: new Set(),
        paths: new Set(),
      };
      rec.perSource.set(ev.source, stats);
    }
    if (ev.pid !== undefined) rec.pids.add(ev.pid);
    if (input.attribution) rec.explicit.push(input.attribution);
    stats.requests += 1;
    stats.bytesOut += ev.bytesOut;
    stats.bytesIn += ev.bytesIn;
    stats.ports.add(ev.port);
    stats.protocols.add(ev.protocol);
    if (ev.method) stats.methods.add(ev.method);
    if (ev.path) stats.paths.add(ev.path);

    if (first || upgraded) {
      const level = category === "TELEMETRY" ? "high" : category === "UNKNOWN" ? "warn" : "info";
      const alert = { level, kind: "net", event: ev, launcher: this.isLauncherPid(ev.pid), attribution: input.attribution ?? this.attributionOfPid(ev.pid) } as Alert;
      this.emit("alert", alert);
    } else if (ev.source === "preload" || ev.source === "proxy") {
      // Subsequent requests to an already-known risky host: emit a quiet update
      // so the live feed can show paths like /v1/ingest as they happen.
      this.emit("request", ev);
    }
    return ev;
  }

  updateNet(id: string, bytesOut?: number, bytesIn?: number): void {
    const ev = this.netById.get(id);
    if (!ev) return;
    const rec = this.hosts.get(ev.host);
    const stats = rec?.perSource.get(ev.source);
    if (bytesOut !== undefined) {
      const delta = bytesOut - ev.bytesOut;
      ev.bytesOut = bytesOut;
      if (stats) stats.bytesOut += delta;
    }
    if (bytesIn !== undefined) {
      const delta = bytesIn - ev.bytesIn;
      ev.bytesIn = bytesIn;
      if (stats) stats.bytesIn += delta;
    }
  }

  // ---- summary -------------------------------------------------------------

  private fileSummary(rec: FileRecord): FileSummary {
    const ops: Record<string, number> = {};
    for (const [k, v] of rec.ops) ops[k] = v;
    const procs = new Set(rec.procs);
    if (this.resolveProc) {
      for (const pid of rec.pids) {
        const n = this.resolveProc(pid);
        if (n) procs.add(n);
      }
    }
    // Own namespace: the audited command owns the entry (by id, owner namespace or the
    // config namespace the path lives in), or every process that touched the file does
    // (codex reading ~/.codex, git reading ~/.gitconfig).
    const ids = new Set<string>();
    if (rec.watch) {
      ids.add(rec.watch.id);
      if (rec.watch.owner) ids.add(rec.watch.owner);
      const ns = this.matcher.ownerOf(rec.path);
      if (ns) ids.add(ns);
    }
    const ownedBy = (set: Set<string>) => [...ids].some((id) => set.has(id));
    let own = rec.watch ? ownedBy(this.ownNamespaces) : false;
    if (!own && rec.watch && procs.size) own = [...procs].every((p) => ownedBy(this.ownOf(p)));
    const kind: WatchKind = rec.watch ? (rec.isDir && rec.watch.kind === "secret" ? "config" : rec.watch.kind) : "config";
    const att = this.resolveAttribution(rec.pids, rec.procs, rec.explicit);
    return {
      path: rec.path,
      ops,
      sources: [...rec.sources],
      pids: [...rec.pids],
      watch: rec.watch,
      ownNamespace: own,
      launcher: this.launcherOnly(rec.pids),
      exists: rec.exists,
      procs: [...new Set([...procs, ...att.processNames])],
      graded: kind === "secret",
      kind,
      attribution: att.attribution,
      via: att.via,
      processName: att.processNames[0] ?? [...procs][0] ?? "",
    };
  }

  sensitiveFiles(): FileSummary[] {
    return [...this.files.values()]
      .filter((r) => r.watch && r.exists)
      .map((r) => this.fileSummary(r))
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  /** Watchlist paths the tool tried to open that do not exist here. Reported, never graded. */
  probedFiles(): FileSummary[] {
    return [...this.files.values()]
      .filter((r) => r.watch && !r.exists)
      .map((r) => this.fileSummary(r))
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  otherDotfiles(): FileSummary[] {
    return [...this.files.values()]
      .filter((r) => !r.watch && r.exists)
      .map((r) => this.fileSummary(r))
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  /**
   * Raw IP records that only socket-level layers saw while a hostname-level
   * layer (proxy / hook) was also reporting named hosts in this run. They are
   * almost always the same connections seen twice, so they are reported
   * separately and not graded.
   */
  private isSuppressedIp(rec: HostRecord, hasNamedHosts: boolean): boolean {
    if (!hasNamedHosts || !isIpAddress(rec.host)) return false;
    for (const src of rec.perSource.keys()) if (src === "proxy" || src === "preload") return false;
    return true;
  }

  private hasNamedHosts(): boolean {
    for (const rec of this.hosts.values()) {
      if (isIpAddress(rec.host)) continue;
      for (const src of rec.perSource.keys()) if (src === "proxy" || src === "preload") return true;
    }
    return false;
  }

  suppressedHosts(): HostSummary[] {
    return this.allHostSummaries().filter((h) => h.suppressed);
  }

  hostSummaries(): HostSummary[] {
    return this.allHostSummaries().filter((h) => !h.suppressed);
  }

  private allHostSummaries(): Array<HostSummary & { suppressed: boolean }> {
    const named = this.hasNamedHosts();
    const out: Array<HostSummary & { suppressed: boolean }> = [];
    for (const rec of this.hosts.values()) {
      let best: EventSource | null = null;
      for (const s of rec.perSource.keys()) {
        if (!best || SOURCE_RANK[s] > SOURCE_RANK[best]) best = s;
      }
      if (!best) continue;
      const primary = rec.perSource.get(best)!;
      const ports = new Set<number>();
      const protocols = new Set<Protocol>();
      const methods = new Set<string>();
      const paths = new Set<string>();
      let bytesOut = primary.bytesOut;
      let bytesIn = primary.bytesIn;
      for (const [src, st] of rec.perSource) {
        for (const p of st.ports) ports.add(p);
        for (const p of st.protocols) protocols.add(p);
        for (const m of st.methods) methods.add(m);
        for (const p of st.paths) paths.add(p);
        // The proxy knows exact tunnel byte volumes; prefer them if the primary has none.
        if (src !== best && bytesOut === 0 && bytesIn === 0) {
          bytesOut = st.bytesOut;
          bytesIn = st.bytesIn;
        }
      }
      out.push({
        host: rec.host,
        category: rec.category,
        requests: primary.requests,
        bytesOut,
        bytesIn,
        ports: [...ports].sort((a, b) => a - b),
        protocols: [...protocols],
        methods: [...methods],
        paths: [...paths].slice(0, 50),
        sources: [...rec.perSource.keys()],
        primarySource: best,
        firstSeen: rec.firstSeen,
        launcher: this.launcherOnly(rec.pids),
        suppressed: this.isSuppressedIp(rec, named),
        ...this.resolveAttribution(rec.pids, [], rec.explicit, rec.host),
        pids: [...rec.pids],
      });
    }
    const order: Record<HostCategory, number> = { TELEMETRY: 0, UNKNOWN: 1, USER_OTLP: 2, LLM_API: 3, AUTH: 4 };
    return out.sort(
      (a, b) => order[a.category] - order[b.category] || b.requests - a.requests || a.host.localeCompare(b.host),
    );
  }

  /** Activity that counts toward the grade: the target's own, plus children only with --include-children. Never unattributed. */
  private graded<T extends { attribution: AttributionKind }>(items: T[]): T[] {
    return items.filter((i) => i.attribution === "target" || (this.includeChildren && i.attribution === "child"));
  }

  /** Hosts whose owning process vanished before it could be resolved and that no observed child explains. */
  unattributedHosts(): string[] {
    return this.hostSummaries()
      .filter((h) => h.attribution === "unattributed")
      .map((h) => h.host);
  }

  score(): ScoreResult {
    const hosts = this.graded(this.hostSummaries());
    return computeScore({
      telemetryHosts: hosts.filter((h) => h.category === "TELEMETRY" && !h.launcher).map((h) => h.host),
      unknownHosts: hosts.filter((h) => h.category === "UNKNOWN" && !h.launcher).map((h) => h.host),
      sensitiveFiles: this.graded(this.sensitiveFiles())
        .filter((f) => !f.ownNamespace && !f.launcher && f.graded)
        .map((f) => this.matcher.display(f.path)),
    });
  }

  /** What external child CLIs did, grouped by the child binary (`via`). */
  childActivity(): Record<string, ChildActivity> {
    const out: Record<string, ChildActivity> = {};
    const get = (via: string): ChildActivity =>
      (out[via] ??= { processName: via, telemetryHosts: [], otherHosts: [], llmHosts: [], authHosts: [], filesAccessed: [], bytesOut: 0 });
    for (const h of this.hostSummaries()) {
      if (h.attribution !== "child") continue;
      const c = get(h.via || h.processNames[0] || "child");
      if (h.category === "TELEMETRY") c.telemetryHosts.push(h.host);
      else if (h.category === "LLM_API") c.llmHosts.push(h.host);
      else if (h.category === "AUTH") c.authHosts.push(h.host);
      else c.otherHosts.push(h.host);
      c.bytesOut += h.bytesOut;
    }
    for (const f of this.sensitiveFiles()) {
      if (f.attribution !== "child") continue;
      get(f.via || f.processName || "child").filesAccessed.push(this.matcher.display(f.path));
    }
    return out;
  }
}
