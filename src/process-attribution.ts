/**
 * Per-process attribution: is a given pid the audited tool itself (including
 * the wrapper scripts and bundled binaries it ships) or an external CLI it
 * spawned, such as `claude`, `codex`, `gemini`, `git` or `gh`?
 *
 * Target = the root pid, plus any descendant whose executable (or, for
 * interpreters, the script it runs) lives inside the target's install root or
 * carries the target's identity in its name or path (`t3-resource-monitor`,
 * `~/.t3/runtime/.../t3`, `.../@openai/codex-darwin-arm64/.../codex`).
 * Child = any other descendant. Child activity is reported but not graded.
 */
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import type { AttributionKind, ProcessAttribution } from "./core/types.js";

export interface ProcRecord {
  pid: number;
  ppid: number;
  /** Executable path as the OS reports it (may be a symlink or unresolved). */
  exe: string;
  /** Full command line. */
  args: string;
}

const INTERPRETERS = new Set(["node", "nodejs", "bun", "deno", "python", "python3", "python2", "perl", "ruby", "sh", "bash", "zsh", "dash", "fish"]);
const FLAGS_WITH_VALUE = new Set(["-r", "--require", "--import", "--loader", "--experimental-loader", "--max-old-space-size", "-m", "-W"]);
const INLINE_FLAGS = new Set(["-e", "--eval", "-p", "--print", "-c"]);

/**
 * First script path on an interpreter command line, or null for inline code /
 * REPLs. Accepts argv (exact) or a flat `ps args` string, in which case a
 * path containing spaces is recovered by joining tokens until one exists.
 */
export function scriptOf(args: string | readonly string[]): string | null {
  const toks = Array.isArray(args) ? [...(args as string[])] : String(args).split(/\s+/).filter(Boolean);
  const flat = !Array.isArray(args);
  for (let i = 1; i < toks.length; i++) {
    const t = toks[i]!;
    if (INLINE_FLAGS.has(t)) return null;
    if (FLAGS_WITH_VALUE.has(t)) {
      i++;
      continue;
    }
    if (t.startsWith("-")) continue;
    if (!flat || fs.existsSync(t)) return t;
    // "ps args" lost the quoting: try "/Users/me/Application Support/x.js" piece by piece.
    let cand = t;
    for (let j = i + 1; j < Math.min(toks.length, i + 8); j++) {
      cand += " " + toks[j];
      if (fs.existsSync(cand)) return cand;
    }
    return t;
  }
  return null;
}

/** `ps` prints `(name)` for processes it cannot fully inspect; strip the parentheses. */
function cleanPsName(s: string): string {
  const m = /^\((.*)\)$/.exec(s.trim());
  return m ? m[1]! : s.trim();
}

export function isInterpreter(exe: string): boolean {
  return INTERPRETERS.has(path.basename(exe));
}

function realpathSafe(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return p;
  }
}

function stripExt(name: string): string {
  return name.replace(/\.(c|m)?js$|\.py$|\.rb$|\.pl$|\.sh$|\.ts$/, "");
}

const GENERIC_DIRS = new Set(["bin", "sbin", "lib", "libexec", "dist", "build", "out", "versions", "version", "releases", "release", "current", "Contents", "MacOS", "Resources", "Frameworks", "Helpers", "node_modules", ".bin", "vendor", "target", "debug"]);
const isVersionLike = (s: string) => /^v?\d+(\.\d+)+([-+][\w.]+)?$/.test(s);

/**
 * `~/.local/share/claude/versions/2.1.323` is named "claude": when the file
 * name is a version string, walk up past generic directories to the first
 * segment that reads like a product name (a leading dot is dropped).
 */
export function nameFromPath(p: string): string {
  const segs = p.split(/[\\/]+/).filter(Boolean);
  for (let i = segs.length - 1; i >= 0; i--) {
    const seg = segs[i]!.replace(/^\./, "");
    if (!seg || isVersionLike(seg) || GENERIC_DIRS.has(segs[i]!) || /^[a-z0-9]{6,}-[a-z0-9-]+$/i.test(seg) && /^(darwin|linux|win|x64|arm|aarch)/i.test(seg) === false && seg.length > 24) continue;
    if (/^(x64|arm64|aarch64|darwin|linux|win32)(-[\w.]+)*$/i.test(seg)) continue;
    return seg;
  }
  return path.basename(p);
}

/** Clean short label for a process: script name for interpreters, else the executable name. */
export function processLabel(rec: Pick<ProcRecord, "exe" | "args">): string {
  const exePath = cleanPsName(rec.exe.split(" ")[0] ?? rec.exe);
  const exe = isVersionLike(path.basename(exePath)) ? nameFromPath(exePath) : path.basename(exePath);
  if (isInterpreter(exe)) {
    const script = rec.args ? scriptOf(rec.args) : null;
    if (script) {
      let n = stripExt(path.basename(script));
      if (n === "npm-cli") n = "npm";
      else if (n === "npx-cli") n = "npx";
      if (n) return n;
    }
  }
  return exe;
}

export interface TargetIdentity {
  /** What the tool is called: `claude`, `codex`, `t3`, `shady-ai-tool`. */
  identity: string;
  /** Resolved install root; processes running from under it are target. */
  root: string | null;
  /** Resolved path of the executable (or entry script) actually run. */
  entry: string;
}

function findOnPath(cmd: string): string | null {
  if (cmd.includes("/")) return path.resolve(cmd);
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    const cand = path.join(dir, cmd);
    try {
      fs.accessSync(cand, fs.constants.X_OK);
      return cand;
    } catch {
      /* next */
    }
  }
  return null;
}

/** Nearest ancestor directory that contains a package.json, within `maxUp` levels. */
function nearestPackageRoot(from: string, maxUp = 8): string | null {
  let dir = from;
  for (let i = 0; i < maxUp; i++) {
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

/**
 * Work out the target's identity and install root from the command line.
 * `node /x/tool/dist/cli.js` -> identity "cli"? No: identity is the command
 * basename when it names the tool, else the script name; root prefers an
 * ancestor directory named after the identity, then the nearest package
 * root, then an .app bundle, then the executable's directory.
 */
export function resolveTarget(command: readonly string[]): TargetIdentity {
  const first = command[0] ?? "";
  const found = findOnPath(first) ?? first;
  let entry = realpathSafe(found);
  let identity = stripExt(path.basename(first));
  if (isInterpreter(path.basename(entry)) || isInterpreter(identity)) {
    const script = scriptOf(command);
    if (script) {
      entry = realpathSafe(path.resolve(script));
      identity = stripExt(path.basename(script));
    }
  }
  // Version-string executables (~/.local/share/claude/versions/2.1.323) keep the typed name.
  if (/^[\d.]+$/.test(identity)) identity = stripExt(path.basename(first));
  const dir = path.dirname(entry);
  let root: string | null = null;
  const segs = dir.split(path.sep);
  for (let i = segs.length - 1; i > 0; i--) {
    const seg = segs[i]!;
    if (seg === identity || seg === "." + identity || seg.endsWith(".app")) {
      root = segs.slice(0, i + 1).join(path.sep);
      break;
    }
  }
  root ??= nearestPackageRoot(dir);
  root ??= dir;
  return { identity, root, entry };
}

export class ProcessAttributor {
  private cache = new Map<number, ProcessAttribution>();
  private records = new Map<number, ProcRecord>();
  readonly target: TargetIdentity;

  constructor(
    readonly rootPid: number,
    command: readonly string[],
    /** Live/ever-seen process lookup (the pid tree); the attributor falls back to `ps -p`. */
    private readonly lookup: (pid: number) => ProcRecord | undefined,
    target?: TargetIdentity,
  ) {
    this.target = target ?? resolveTarget(command);
  }

  /** Register precise info from a hooked process (hello message). */
  register(rec: ProcRecord): void {
    this.records.set(rec.pid, rec);
    this.cache.delete(rec.pid);
  }

  /**
   * Forget cached verdicts. Early verdicts (live alerts) may rest on a `ps -p`
   * fallback for a process the tree had not polled yet; call this before the
   * final summary so every pid is re-classified against the full tree.
   */
  clearCache(): void {
    this.cache.clear();
  }

  record(pid: number): ProcRecord | undefined {
    const rec = this.records.get(pid) ?? this.lookup(pid) ?? psLookup(pid);
    if (!rec) return undefined;
    return { ...rec, exe: cleanPsName(rec.exe) };
  }

  /** Does this executable / script belong to the target? */
  isTargetPath(effective: string): boolean {
    const real = realpathSafe(effective);
    const { root, identity } = this.target;
    if (root && (real === root || real.startsWith(root + path.sep))) return true;
    if (root && (effective === root || effective.startsWith(root + path.sep))) return true;
    const base = stripExt(path.basename(real));
    if (base === identity || base.startsWith(identity + "-") || base.startsWith(identity + "_")) return true;
    const segs = real.split(path.sep);
    if (segs.includes(identity) || segs.includes("." + identity)) return true;
    return false;
  }

  classify(pid: number): ProcessAttribution {
    const hit = this.cache.get(pid);
    if (hit) return hit;
    let out: ProcessAttribution;
    if (pid === this.rootPid) {
      out = { pid, processName: this.target.identity, attribution: "target", via: "" };
    } else {
      const rec = this.record(pid);
      if (!rec) {
        out = { pid, processName: "unknown", attribution: "target", via: "" };
      } else {
        const exe = rec.exe.split(" ")[0] ?? rec.exe;
        const script = isInterpreter(path.basename(exe)) ? scriptOf(rec.args) : null;
        void cleanPsName;
        const effective = script ? path.resolve(script) : exe;
        const name = processLabel(rec);
        if (this.isTargetPath(effective) || (script === null && isInterpreter(path.basename(exe)) && this.parentIsTarget(rec))) {
          out = { pid, processName: name, attribution: "target", via: "" };
        } else {
          // via: the external binary directly below the nearest target ancestor.
          const parent = rec.ppid > 1 && rec.ppid !== pid ? this.classify(rec.ppid) : null;
          const via = parent && parent.attribution === "child" ? parent.via : name;
          out = { pid, processName: name, attribution: "child", via };
        }
      }
    }
    this.cache.set(pid, out);
    return out;
  }

  /** An interpreter running inline code (`node -e`, `sh -c`) belongs to whoever spawned it. */
  private parentIsTarget(rec: ProcRecord): boolean {
    if (rec.ppid <= 1 || rec.ppid === rec.pid) return false;
    return this.classify(rec.ppid).attribution === "target";
  }

  /** Names (`via`) of external child CLIs seen in the tree so far. */
  observedChildren(candidates: ProcRecord[]): Set<string> {
    const out = new Set<string>();
    for (const r of candidates) {
      const a = this.classify(r.pid);
      if (a.attribution === "child" && a.via) out.add(a.via);
    }
    return out;
  }

  /** Classify by process name (for layers that only know the accounting name, like fs_usage). */
  classifyName(name: string, candidates: ProcRecord[]): ProcessAttribution | null {
    const matches = candidates.filter((r) => processLabel(r) === name || path.basename(r.exe) === name);
    if (!matches.length) return null;
    const atts = matches.map((r) => this.classify(r.pid));
    const target = atts.find((a) => a.attribution === "target");
    if (target) return { processName: name, attribution: "target", via: "" };
    const first = atts[0]!;
    return { processName: name, attribution: "child", via: first.via };
  }
}

const PS_CACHE = new Map<number, ProcRecord | undefined>();

/** `ps -p <pid> -o ppid=,comm=,args=` for a pid the tree never saw. Cached by pid. */
export function psLookup(pid: number): ProcRecord | undefined {
  if (PS_CACHE.has(pid)) return PS_CACHE.get(pid);
  let rec: ProcRecord | undefined;
  try {
    const out = spawnSync("ps", ["-p", String(pid), "-o", "ppid=,comm=,args="], { encoding: "utf8", timeout: 2000 }).stdout;
    const m = /^\s*(\d+)\s+(\S+)\s+(.*)$/.exec((out ?? "").trim());
    if (m) rec = { pid, ppid: Number(m[1]), exe: cleanPsName(m[2]!), args: cleanPsName((m[3] ?? "").trim()) };
  } catch {
    rec = undefined;
  }
  PS_CACHE.set(pid, rec);
  return rec;
}

export function describeAttribution(a: ProcessAttribution): string {
  return a.attribution === "target" ? `target (${a.processName})` : `child via ${a.via}${a.via !== a.processName ? ` (${a.processName})` : ""}`;
}

export type { AttributionKind };
