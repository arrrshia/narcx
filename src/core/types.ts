export type HostCategory = "LLM_API" | "AUTH" | "TELEMETRY" | "USER_OTLP" | "UNKNOWN";

/** Who did it: the audited tool (and its own bundled processes) or an external CLI it spawned. */
export type AttributionKind = "target" | "child";

export interface ProcessAttribution {
  pid?: number;
  /** Short name of the process that acted, e.g. "claude", "codex", "git". */
  processName: string;
  attribution: AttributionKind;
  /** For child activity: the external binary directly under the target that this process belongs to. */
  via: string;
}

export type EventSource =
  | "proxy"
  | "preload"
  | "lsof"
  | "strace"
  | "fs_usage"
  | "narc";

export type Protocol = "http" | "https" | "tcp" | "udp" | "unix";

export interface FileEvent {
  kind: "file";
  id: string;
  ts: number;
  source: EventSource;
  pid?: number;
  path: string;
  op: string;
  /** Watchlist entry id if the path is sensitive, else null. */
  sensitive: string | null;
  /** False when the path did not exist at the time of the call (a probe, not a read). */
  exists?: boolean;
  /** Accounting name of the process that made the call, when a layer knows it. */
  proc?: string;
  processName?: string;
  attribution?: AttributionKind;
  via?: string;
}

export interface NetEvent {
  kind: "net";
  id: string;
  ts: number;
  source: EventSource;
  pid?: number;
  host: string;
  port: number;
  protocol: Protocol;
  method?: string;
  path?: string;
  url?: string;
  bytesOut: number;
  bytesIn: number;
  category: HostCategory;
  processName?: string;
  attribution?: AttributionKind;
  via?: string;
}

export interface DnsEvent {
  kind: "dns";
  id: string;
  ts: number;
  source: EventSource;
  pid?: number;
  host: string;
  addresses: string[];
}

export type AuditEvent = FileEvent | NetEvent | DnsEvent;

/** Wire format sent from the preload hook to the parent over IPC. */
export type WireMessage =
  | { t: "hello"; pid: number; ppid: number; argv: string[]; exec: string }
  | { t: "file"; id: string; pid: number; path: string; op: string; exists?: boolean }
  | {
      t: "net";
      id: string;
      pid: number;
      host: string;
      port: number;
      protocol: Protocol;
      method: string;
      path: string;
      url: string;
      bytesOut: number;
    }
  | { t: "net-update"; id: string; bytesOut?: number; bytesIn?: number }
  | { t: "dns"; id: string; pid: number; host: string; addresses: string[] };

export interface WatchEntry {
  /** Stable id, e.g. "ssh", "aws", "claude". */
  id: string;
  /** Human label, e.g. "SSH keys". */
  label: string;
  /** Glob-ish patterns. "~/" prefix is relative to home. */
  patterns: string[];
  /** False for files every TLS-speaking process opens (keychain trust store): reported, never graded. */
  graded?: boolean;
}

export interface Deduction {
  reason: string;
  points: number;
  detail: string;
}

export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export interface ScoreResult {
  score: number;
  grade: Grade;
  deductions: Deduction[];
}

export interface FileSummary {
  path: string;
  ops: Record<string, number>;
  sources: EventSource[];
  pids: number[];
  watch: WatchEntry | null;
  /** True when the file is sensitive but belongs to the tool's own namespace. */
  ownNamespace: boolean;
  /** True when only the launcher process (npx, pnpm dlx, …) touched it. Not graded. */
  launcher: boolean;
  /** False when every access was a probe of a path that does not exist. Listed under probedFiles, not graded. */
  exists: boolean;
  /** Processes that touched it (accounting names), e.g. ["codex", "git-remote-https"]. */
  procs: string[];
  /** False when the watchlist entry is informational only (e.g. keychain trust store). */
  graded: boolean;
  /** Whether the target itself or an external child process did this. Child activity is not graded. */
  attribution: AttributionKind;
  /** Child binary the activity belongs to (e.g. "claude"); empty for target activity. */
  via: string;
  processName: string;
}

export interface HostSummary {
  host: string;
  category: HostCategory;
  requests: number;
  bytesOut: number;
  bytesIn: number;
  ports: number[];
  protocols: Protocol[];
  methods: string[];
  paths: string[];
  sources: EventSource[];
  /** The source whose counts were used (highest fidelity). */
  primarySource: EventSource;
  firstSeen: number;
  /** True when only the launcher process (npx, pnpm dlx, …) contacted it. Not graded. */
  launcher: boolean;
  attribution: AttributionKind;
  via: string;
  processNames: string[];
  pids: number[];
}

/** How much of the child's file activity narc could actually see. */
export interface FileTracing {
  /** deep = kernel tracing (fs_usage/strace); hook = NODE_OPTIONS preload; none = nothing hooked. */
  mode: "deep" | "hook" | "none";
  /** full = every observed process was traced; partial = some native processes were not; none = nothing traced. */
  coverage: "full" | "partial" | "none";
  /** Names of native executables in the process tree that were not traced. */
  untraced: string[];
}

export interface ChildActivity {
  processName: string;
  telemetryHosts: string[];
  otherHosts: string[];
  llmHosts: string[];
  authHosts: string[];
  /** Sensitive (watchlist) files the child accessed, including its own config. */
  filesAccessed: string[];
  bytesOut: number;
}

export interface AuditReport {
  narcVersion: string;
  /** Display name for the scorecard (e.g. "Claude Code 2.1.323"); defaults to the command's basename. */
  title: string;
  /** Left footer text on the card; defaults to the out-of-the-box-defaults line. Set it for variant runs. */
  footer?: string;
  platform: string;
  command: string[];
  /** Short human-friendly rendering of `command` for the scorecard. */
  commandLabel: string;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  exitCode: number | null;
  signal: string | null;
  layers: Record<string, boolean>;
  /** Package-runner process (npx, pnpm dlx, bunx, …) whose own activity is reported but not graded. */
  launcher: { pid: number; name: string } | null;
  fileTracing: FileTracing;
  score: ScoreResult;
  sensitiveFiles: FileSummary[];
  otherDotfiles: FileSummary[];
  /** Watchlist paths the tool tried to open that do not exist on this machine. Not graded. */
  probedFiles: FileSummary[];
  hosts: HostSummary[];
  /** Raw IPs seen only by lsof/strace while hostname-level layers were active: likely duplicates, not graded. */
  suppressedHosts: HostSummary[];
  /** Processes the tool left running after it exited (daemons); narc terminates them and lists them here. */
  leftoverProcesses: string[];
  /** Install root the target was resolved to (processes under it are "target"). */
  installRoot: string | null;
  /** True when --include-children folded spawned external CLIs into the grade. */
  includeChildren: boolean;
  /** Hostnames taken from the user's own OTEL_EXPORTER_OTLP_* environment; never penalised. */
  userOtlpHosts: string[];
  /** Everything external child CLIs did, grouped by child binary. Excluded from the grade unless includeChildren. */
  childActivity: Record<string, ChildActivity>;
  events: AuditEvent[];
}
