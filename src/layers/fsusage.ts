import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import * as path from "node:path";
import type { Collector } from "../core/collector.js";
import type { PidTree } from "./pidtree.js";

export interface FsUsageHandle {
  stop(): void;
  active: boolean;
}

export interface FsUsageLine {
  call: string;
  pathTail: string | null;
  procName: string;
  tid: number | null;
  /** errno when the call failed (e.g. 2 = ENOENT), else null. */
  errno: number | null;
}

/**
 * Parse one line of `fs_usage -w -f filesys`. Format (wide):
 *   HH:MM:SS.ffffff  call  [F=n] [B=0x..] [[errno]] [(flags)]  <path>  <elapsed> [W]  procname.tid
 * Paths longer than the column are trimmed from the LEFT, so `pathTail`
 * may be a suffix of the real path.
 */
export function parseFsUsageLine(line: string): FsUsageLine | null {
  const m = /^\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+(\S+)\s+(.*?)\s+(\d+\.\d+)\s+(?:W\s+)?(\S+?)(?:\.(\d+))?\s*$/.exec(line);
  if (!m) return null;
  const call = m[1] ?? "";
  let middle = (m[2] ?? "").trim();
  let errno: number | null = null;
  const err = /\[\s*(\d+)\]/.exec(middle);
  if (err) errno = Number(err[1]);
  middle = middle
    .replace(/^F=-?\d+\s*/, "")
    .replace(/^B=0x[0-9a-fA-F]+\s*/, "")
    .replace(/^\[\s*\d+\]\s*/, "")
    .replace(/^\([^)]*\)\s*/, "")
    .replace(/^\[\s*\d+\]\s*/, "")
    .trim();
  const pathTail = middle.length ? middle : null;
  return { call, pathTail, procName: m[4] ?? "", tid: m[5] ? Number(m[5]) : null, errno };
}

const OPEN_CALLS = new Set([
  "open",
  "openat",
  "open_nocancel",
  "openat_nocancel",
  "open_extended",
  "guarded_open_np",
  "open_dprotected_np",
]);

/**
 * Turn a possibly left-trimmed path tail into an absolute path we can match.
 * If it does not start with "/", assume it lives under `home` and rebuild from
 * the first "/" onwards (e.g. "rshia/.aws/credentials" -> "<home>/.aws/credentials").
 */
const ROOTS = /\/(Users|home|private|tmp|var|etc|Library|opt|usr|System|Applications|dev|nix|Volumes)\//;

export function reconstructPath(tail: string, home: string): string | null {
  const t = tail.trim();
  if (t.startsWith("/")) return t;
  if (!t.includes("/")) return null;
  // 1) the home directory appears somewhere after glued or spaced junk: "F=-2/Users/me/x", "0x1a2b /Users/me/x"
  const h = t.indexOf(home + "/");
  if (h >= 0) return t.slice(h);
  // 2) junk token(s) then an absolute path elsewhere: "D=0x12 O=0x0 /private/tmp/x/.env"
  const lastSpace = t.lastIndexOf(" ");
  if (lastSpace >= 0 && t[lastSpace + 1] === "/") return t.slice(lastSpace + 1);
  // 3) only the leading slash was trimmed: "Users/me/.claude.json"
  const withSlash = "/" + t;
  if (withSlash === home || withSlash.startsWith(home + "/")) return withSlash;
  // 4) a known root glued to junk ("F=-2/private/tmp/x"), unless the "junk" is a trimmed fragment of the home dir
  const m = ROOTS.exec(t);
  if (m && m.index > 0 && !home.endsWith(t.slice(0, m.index))) return t.slice(m.index);
  // 5) trimmed somewhere inside the home prefix: "rshia/.aws/credentials"
  return path.join(home, t.slice(t.indexOf("/") + 1));
}

export function sudoCached(): boolean {
  const r = spawnSync("sudo", ["-n", "true"], { stdio: "ignore", timeout: 3000 });
  return r.status === 0;
}

/** Interactively validate sudo (prompts on the tty). Returns true on success. */
export function sudoValidate(prompt: string): boolean {
  const r = spawnSync("sudo", ["-p", prompt, "-v"], { stdio: "inherit" });
  return r.status === 0;
}

/**
 * macOS --deep layer: kernel-level file tracing via fs_usage. Runs system-wide
 * (fs_usage cannot follow forks) and is filtered to the child's process tree
 * by process name, which is the only identity fs_usage prints.
 */
export function startFsUsage(opts: {
  collector: Collector;
  tree: PidTree;
  home: string;
  asRoot: boolean;
}): FsUsageHandle {
  const { collector, tree, home } = opts;
  const args = ["-w", "-f", "filesys"];
  let child: ChildProcess;
  if (opts.asRoot) {
    child = spawn("fs_usage", args, { stdio: ["ignore", "pipe", "ignore"] });
  } else {
    child = spawn("sudo", ["-n", "fs_usage", ...args], { stdio: ["ignore", "pipe", "ignore"] });
  }
  const handle: FsUsageHandle = { active: true, stop: () => undefined };
  child.on("error", () => (handle.active = false));
  child.on("exit", () => (handle.active = false));

  let buf = "";
  child.stdout?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      const parsed = parseFsUsageLine(line);
      if (!parsed || !parsed.pathTail || !OPEN_CALLS.has(parsed.call)) continue;
      if (!nameInTree(parsed.procName, tree)) continue;
      const full = reconstructPath(parsed.pathTail, home);
      if (!full) continue;
      // A failed open (errno set, e.g. ENOENT) is a probe of a path that is not there, not a read.
      collector.addFile({ source: "fs_usage", path: full, op: parsed.call, proc: tree.displayNameFor(parsed.procName), exists: parsed.errno === null });
    }
  });

  handle.stop = () => {
    handle.active = false;
    try {
      child.stdout?.destroy();
    } catch {
      /* ignore */
    }
    if (child.pid) {
      if (opts.asRoot) {
        try {
          process.kill(child.pid, "SIGTERM");
        } catch {
          /* ignore */
        }
      } else {
        spawnSync("sudo", ["-n", "kill", "-TERM", String(child.pid)], { stdio: "ignore", timeout: 2000 });
      }
    }
  };
  return handle;
}

/** fs_usage truncates names (p_comm is 16 bytes), so compare on the prefix. */
export function nameInTree(procName: string, tree: PidTree): boolean {
  if (!procName) return false;
  for (const n of tree.names()) {
    if (n === procName) return true;
    if (procName.length >= 15 && n.startsWith(procName)) return true;
  }
  return false;
}
