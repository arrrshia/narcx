import { EventEmitter } from "node:events";
import { classifyRequest, isIpAddress, isLoopback, normalizeHost } from "./classify.js";
import { computeScore } from "./grade.js";
import { SensitiveMatcher, ownNamespaces } from "./watchlist.js";
import type {
  AuditEvent,
  DnsEvent,
  EventSource,
  FileEvent,
  FileSummary,
  HostCategory,
  HostSummary,
  NetEvent,
  Protocol,
  ScoreResult,
  WatchEntry,
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
}

export type Alert = { launcher: boolean } & (
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
  private ownCache = new Map<string, Set<string>>();
  private seq = 0;

  constructor(opts: CollectorOptions) {
    super();
    this.matcher = opts.matcher;
    this.ownNamespaces = opts.ownNamespaces;
    this.ignoreLocalPorts = new Set(opts.ignoreLocalPorts ?? []);
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
    };
    this.events.push(ev);

    let rec = this.files.get(norm);
    const first = !rec;
    if (!rec) {
      rec = { path: norm, ops: new Map(), sources: new Set(), pids: new Set(), watch, exists: false, procs: new Set() };
      this.files.set(norm, rec);
    }
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
      if (watch) {
        const alert: Alert = { level: "high", kind: "file", event: ev, watch, display, launcher };
        this.emit("alert", alert);
      } else {
        const alert: Alert = { level: "info", kind: "file", event: ev, display, launcher };
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
  }): NetEvent | null {
    let host = normalizeHost(input.host);
    if (!host) return null;
    if (isLoopback(host)) return null; // loopback is never an outbound host (and covers narc's own plumbing)
    if (isIpAddress(host)) {
      const mapped = this.ipToHost.get(host);
      if (mapped) host = mapped;
    }
    const category = classifyRequest(host, input.path);
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
    };
    this.events.push(ev);
    this.netById.set(ev.id, ev);

    let rec = this.hosts.get(host);
    const first = !rec;
    let upgraded = false;
    if (!rec) {
      rec = { host, category, firstSeen: ev.ts, perSource: new Map(), pids: new Set() };
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
    stats.requests += 1;
    stats.bytesOut += ev.bytesOut;
    stats.bytesIn += ev.bytesIn;
    stats.ports.add(ev.port);
    stats.protocols.add(ev.protocol);
    if (ev.method) stats.methods.add(ev.method);
    if (ev.path) stats.paths.add(ev.path);

    if (first || upgraded) {
      const level = category === "TELEMETRY" ? "high" : category === "UNKNOWN" ? "warn" : "info";
      const alert = { level, kind: "net", event: ev, launcher: this.isLauncherPid(ev.pid) } as Alert;
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
    // Own namespace: the audited command owns the entry, or every process that touched
    // the file owns it (codex reading ~/.codex, git reading ~/.gitconfig).
    let own = rec.watch ? this.ownNamespaces.has(rec.watch.id) : false;
    if (!own && rec.watch && procs.size) {
      const id = rec.watch.id;
      own = [...procs].every((p) => this.ownOf(p).has(id));
    }
    return {
      path: rec.path,
      ops,
      sources: [...rec.sources],
      pids: [...rec.pids],
      watch: rec.watch,
      ownNamespace: own,
      launcher: this.launcherOnly(rec.pids),
      exists: rec.exists,
      procs: [...procs],
      graded: rec.watch ? rec.watch.graded !== false : false,
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
      });
    }
    const order: Record<HostCategory, number> = { TELEMETRY: 0, UNKNOWN: 1, LLM_API: 2, AUTH: 3 };
    return out.sort(
      (a, b) => order[a.category] - order[b.category] || b.requests - a.requests || a.host.localeCompare(b.host),
    );
  }

  score(): ScoreResult {
    const hosts = this.hostSummaries();
    return computeScore({
      telemetryHosts: hosts.filter((h) => h.category === "TELEMETRY" && !h.launcher).map((h) => h.host),
      unknownHosts: hosts.filter((h) => h.category === "UNKNOWN" && !h.launcher).map((h) => h.host),
      sensitiveFiles: this.sensitiveFiles()
        .filter((f) => !f.ownNamespace && !f.launcher && f.graded)
        .map((f) => this.matcher.display(f.path)),
    });
  }
}
