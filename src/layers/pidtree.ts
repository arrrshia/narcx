import { execFile } from "node:child_process";
import * as path from "node:path";

export interface ProcInfo {
  pid: number;
  ppid: number;
  /** Executable path as `ps -o comm` reports it (resolved, may contain spaces). */
  comm: string;
  /** Kernel accounting name (`ps -o ucomm`, 16 chars max): what fs_usage prints. */
  ucomm: string;
  /** Full command line (`ps -o args`), used to name interpreter processes by their script. */
  args: string;
}

const INTERPRETERS = new Set(["node", "nodejs", "bun", "deno", "python", "python3", "python2", "perl", "ruby", "sh", "bash", "zsh", "dash", "fish"]);
/** Interpreter flags that consume the next token. */
const FLAGS_WITH_VALUE = new Set(["-r", "--require", "--import", "--loader", "--experimental-loader", "--max-old-space-size", "-m", "-W"]);
/** Flags after which the "script" is inline code, so no script name exists. */
const INLINE_FLAGS = new Set(["-e", "--eval", "-p", "--print", "-c"]);

/** First script path on an interpreter command line, or null for inline code / REPLs. */
function scriptOf(args: string): string | null {
  const toks = args.split(/\s+/).filter(Boolean);
  for (let i = 1; i < toks.length; i++) {
    const t = toks[i]!;
    if (INLINE_FLAGS.has(t)) return null;
    if (FLAGS_WITH_VALUE.has(t)) {
      i++;
      continue;
    }
    if (t.startsWith("-")) continue;
    return t;
  }
  return null;
}

/**
 * Tracks the descendants of a root pid by polling `ps`. Shared by the lsof
 * poller and the fs_usage tracer so we only pay for one `ps` per tick.
 */
export class PidTree {
  rootPid: number;
  private procs = new Map<number, ProcInfo>();
  private descendants = new Set<number>();
  private everSeen = new Map<number, ProcInfo>();
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(rootPid: number, private readonly intervalMs = 150) {
    this.rootPid = rootPid;
    if (rootPid > 0) this.descendants.add(rootPid);
  }

  /** Set (or change) the root after construction, e.g. once the child has spawned. */
  setRoot(pid: number): void {
    this.rootPid = pid;
    this.descendants = new Set([pid]);
    void this.refresh();
  }

  start(): void {
    if (this.timer) return;
    void this.refresh();
    this.timer = setInterval(() => void this.refresh(), this.intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Current pid set: root + all live descendants. */
  pids(): number[] {
    return this.rootPid > 0 ? [...this.descendants] : [];
  }

  has(pid: number): boolean {
    return this.descendants.has(pid);
  }

  /** Accounting names (and executable basenames) for every live pid in the tree. */
  names(): Set<string> {
    const out = new Set<string>();
    for (const pid of this.descendants) {
      const p = this.procs.get(pid);
      if (!p) continue;
      if (p.ucomm) out.add(p.ucomm);
      out.add(path.basename(p.comm.split(" ")[0] ?? p.comm));
    }
    return out;
  }

  info(pid: number): ProcInfo | undefined {
    return this.procs.get(pid) ?? this.everSeen.get(pid);
  }

  /**
   * Human name for a process: the accounting name, unless it is a bare
   * version string (`2.1.323` -> executable name) or an interpreter, in which
   * case the script it runs names it (`node npm-cli.js` -> `npm`).
   */
  static displayName(p: ProcInfo): string {
    const exe = path.basename(p.comm.split(" ")[0] ?? p.comm);
    const base = !p.ucomm || /^[\d.]+$/.test(p.ucomm) ? exe : p.ucomm;
    if (INTERPRETERS.has(base) || INTERPRETERS.has(exe)) {
      const script = p.args ? scriptOf(p.args) : null;
      if (script) {
        let n = path.basename(script).replace(/\.(c|m)?js$|\.py$|\.rb$|\.pl$|\.sh$/, "");
        if (n === "npm-cli") n = "npm";
        else if (n === "npx-cli") n = "npx";
        if (n) return n;
      }
    }
    return base;
  }

  /** Short display name for a pid seen at any point during the run. */
  nameOf(pid: number): string | undefined {
    const p = this.everSeen.get(pid) ?? this.procs.get(pid);
    return p ? PidTree.displayName(p) : undefined;
  }

  /** Map an accounting name fs_usage printed back to a display name of a process in the tree. */
  displayNameFor(ucomm: string): string {
    for (const p of [...this.procs.values(), ...this.everSeen.values()]) {
      if (p.ucomm === ucomm || (ucomm.length >= 15 && p.ucomm.startsWith(ucomm))) return PidTree.displayName(p);
    }
    return ucomm;
  }

  /** Every process observed in the tree during the run, including ones that have exited. */
  seenProcesses(): ProcInfo[] {
    return [...this.everSeen.values()];
  }

  /**
   * Processes observed in the tree that are still alive after the root exited
   * (daemonised servers, detached helpers). The accounting name must still
   * match so a reused pid is never mistaken for one of ours.
   */
  leftovers(): ProcInfo[] {
    const out: ProcInfo[] = [];
    for (const seen of this.everSeen.values()) {
      if (seen.pid === this.rootPid) continue;
      const now = this.procs.get(seen.pid);
      if (now && now.ucomm === seen.ucomm && now.comm === seen.comm) out.push(now);
    }
    return out;
  }

  refresh(): Promise<void> {
    if (this.running) return Promise.resolve();
    this.running = true;
    return new Promise((resolve) => {
      execFile("ps", ["-axo", "pid=,ppid=,comm="], { maxBuffer: 16 * 1024 * 1024, timeout: 2000 }, (err, stdout) => {
        if (err || !stdout) {
          this.running = false;
          return resolve();
        }
        execFile("ps", ["-axo", "pid=,ucomm="], { maxBuffer: 16 * 1024 * 1024, timeout: 2000 }, (err2, names) => {
          execFile("ps", ["-axo", "pid=,args="], { maxBuffer: 32 * 1024 * 1024, timeout: 2000 }, (err3, argv) => {
            this.running = false;
            this.ingest(stdout, err2 ? "" : names, err3 ? "" : argv);
            resolve();
          });
        });
      });
    });
  }

  /** Parse `ps -axo pid=,ppid=,comm=` (+ optional `ps -axo pid=,ucomm=` and `ps -axo pid=,args=`) output and recompute the tree. */
  ingest(psOutput: string, ucommOutput = "", argsOutput = ""): void {
    const ucomms = new Map<number, string>();
    for (const raw of ucommOutput.split("\n")) {
      const m = /^\s*(\d+)\s+(.*)$/.exec(raw);
      if (m) ucomms.set(Number(m[1]), (m[2] ?? "").trim());
    }
    const argv = new Map<number, string>();
    for (const raw of argsOutput.split("\n")) {
      const m = /^\s*(\d+)\s+(.*)$/.exec(raw);
      if (m) argv.set(Number(m[1]), (m[2] ?? "").trim());
    }
    const procs = new Map<number, ProcInfo>();
    for (const raw of psOutput.split("\n")) {
      const m = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(raw);
      if (!m) continue;
      const pid = Number(m[1]);
      const comm = (m[3] ?? "").trim();
      procs.set(pid, { pid, ppid: Number(m[2]), comm, ucomm: ucomms.get(pid) ?? "", args: argv.get(pid) ?? "" });
    }
    const children = new Map<number, number[]>();
    for (const p of procs.values()) {
      const arr = children.get(p.ppid);
      if (arr) arr.push(p.pid);
      else children.set(p.ppid, [p.pid]);
    }
    const seen = new Set<number>([this.rootPid]);
    const stack = [this.rootPid];
    while (stack.length) {
      const cur = stack.pop()!;
      for (const c of children.get(cur) ?? []) {
        if (!seen.has(c)) {
          seen.add(c);
          stack.push(c);
        }
      }
    }
    this.procs = procs;
    this.descendants = seen;
    for (const pid of seen) {
      const p = procs.get(pid);
      if (!p) continue;
      const prev = this.everSeen.get(pid);
      // Keep the latest image: a wrapper that exec()s into a native binary keeps its pid.
      if (!prev || prev.comm !== p.comm || (!prev.ucomm && p.ucomm) || (!prev.args && p.args)) this.everSeen.set(pid, p);
    }
  }
}
