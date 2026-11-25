import { execFileSync } from "node:child_process";
import type { Collector } from "../core/collector.js";

/** Returns true if strace is installed and ptrace is permitted. */
export function straceAvailable(): boolean {
  if (process.platform !== "linux") return false;
  try {
    execFileSync("strace", ["-qq", "-e", "trace=none", "-o", "/dev/null", "--", "/bin/true"], {
      stdio: "ignore",
      timeout: 3000,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Wrap a command so it runs under `strace -f`, writing trace lines to fd 3.
 * The caller spawns the result with `stdio: ['inherit','inherit','inherit','pipe']`.
 */
export function straceWrap(command: string[]): string[] {
  return [
    "strace",
    "-f",
    "-qq",
    "-s",
    "512",
    "-e",
    "trace=open,openat,openat2,connect",
    "-e",
    "signal=none",
    "-o",
    "/dev/fd/3",
    "--",
    ...command,
  ];
}

export interface StraceLine {
  pid: number;
  syscall: string;
  args: string;
  result: string | null;
}

const LINE_RE = /^(?:\[pid\s+)?(\d+)\]?\s+(?:<\.\.\.\s+(\w+)\s+resumed>|(\w+)\()(.*?)(?:\)\s*=\s*(.+))?$/;

export function parseStraceLine(line: string): StraceLine | null {
  const m = LINE_RE.exec(line.trim());
  if (!m) return null;
  const syscall = m[2] ?? m[3];
  if (!syscall) return null;
  return { pid: Number(m[1]), syscall, args: m[4] ?? "", result: m[5] ?? null };
}

export interface StraceEvent {
  pid: number;
  kind: "file" | "net";
  path?: string;
  host?: string;
  port?: number;
  protocol?: "tcp" | "udp";
}

/** Extract an audit event from one strace line, or null if uninteresting. */
export function straceEvent(line: string): StraceEvent | null {
  const p = parseStraceLine(line);
  if (!p) return null;
  if (p.result && /^-1\s/.test(p.result)) return null; // failed call
  if (p.syscall === "open" || p.syscall === "openat" || p.syscall === "openat2") {
    const m = /"((?:[^"\\]|\\.)*)"/.exec(p.args);
    if (!m) return null;
    return { pid: p.pid, kind: "file", path: unescapeC(m[1] ?? "") };
  }
  if (p.syscall === "connect") {
    if (/AF_UNIX/.test(p.args)) return null;
    const port = /sin6?_port=htons\((\d+)\)/.exec(p.args);
    const v4 = /inet_addr\("([^"]+)"\)/.exec(p.args);
    const v6 = /inet_pton\(AF_INET6,\s*"([^"]+)"/.exec(p.args);
    const host = v4?.[1] ?? v6?.[1];
    if (!host || !port) return null;
    // strace does not tell us the socket type here; assume TCP unless it is DNS.
    const portNum = Number(port[1]);
    return { pid: p.pid, kind: "net", host, port: portNum, protocol: portNum === 53 ? "udp" : "tcp" };
  }
  return null;
}

function unescapeC(s: string): string {
  return s.replace(/\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|.)/g, (_, e: string) => {
    if (e.startsWith("x")) return String.fromCharCode(parseInt(e.slice(1), 16));
    if (/^[0-7]+$/.test(e)) return String.fromCharCode(parseInt(e, 8));
    const map: Record<string, string> = { n: "\n", t: "\t", r: "\r", '"': '"', "\\": "\\" };
    return map[e] ?? e;
  });
}

/** Feed a readable stream of strace output into the collector. */
export function attachStrace(stream: NodeJS.ReadableStream, collector: Collector): void {
  let buf = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      const ev = straceEvent(line);
      if (!ev) continue;
      if (ev.kind === "file" && ev.path) {
        collector.addFile({ source: "strace", pid: ev.pid, path: ev.path, op: "openat" });
      } else if (ev.kind === "net" && ev.host) {
        collector.addNet({
          source: "strace",
          pid: ev.pid,
          host: ev.host,
          port: ev.port ?? 0,
          protocol: ev.protocol ?? "tcp",
        });
      }
    }
  });
}
