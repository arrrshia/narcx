import { execFile } from "node:child_process";
import type { Collector } from "../core/collector.js";
import type { PidTree } from "./pidtree.js";

export interface LsofHandle {
  stop(): void;
  /** Number of successful lsof polls (for the layers report). */
  polls: number;
}

export interface LsofConnection {
  pid: number;
  command: string;
  protocol: "tcp" | "udp";
  localHost: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
}

/**
 * Parse `lsof -F pcPn` output into remote connections (listening sockets are
 * skipped). Field lines: p<pid> c<command> f<fd> P<proto> n<name>.
 */
export function parseLsof(output: string): LsofConnection[] {
  const out: LsofConnection[] = [];
  let pid = 0;
  let command = "";
  let proto: "tcp" | "udp" | null = null;
  for (const line of output.split("\n")) {
    if (!line) continue;
    const tag = line[0];
    const val = line.slice(1);
    switch (tag) {
      case "p":
        pid = Number(val);
        break;
      case "c":
        command = val;
        break;
      case "P":
        proto = val.toUpperCase() === "UDP" ? "udp" : val.toUpperCase() === "TCP" ? "tcp" : null;
        break;
      case "n": {
        if (!proto) break;
        const arrow = val.indexOf("->");
        if (arrow < 0) break; // listening / unconnected
        const local = splitAddr(val.slice(0, arrow));
        const remoteRaw = val.slice(arrow + 2).replace(/\s*\(.*\)$/, "");
        const remote = splitAddr(remoteRaw);
        if (!remote) break;
        out.push({
          pid,
          command,
          protocol: proto,
          localHost: local?.host ?? "",
          localPort: local?.port ?? 0,
          remoteHost: remote.host,
          remotePort: remote.port,
        });
        break;
      }
      default:
        break;
    }
  }
  return out;
}

function splitAddr(s: string): { host: string; port: number } | null {
  const t = s.trim();
  if (!t) return null;
  const m = /^(?:\[([^\]]+)\]|([^:]+)):(\d+|\*)$/.exec(t);
  if (!m) return null;
  const host = m[1] ?? m[2] ?? "";
  const port = m[3] === "*" ? 0 : Number(m[3]);
  return { host, port };
}

/**
 * Layer 3 (default, no sudo): poll `lsof -i -n -P` for the child's process
 * tree every `intervalMs` and log any remote connection we have not seen.
 * `-n -P` are essential: they stop lsof itself from doing DNS/port lookups.
 */
export function startLsofPoller(opts: {
  collector: Collector;
  tree: PidTree;
  intervalMs?: number;
}): LsofHandle {
  const { collector, tree } = opts;
  const seen = new Set<string>();
  let busy = false;
  let stopped = false;
  const handle: LsofHandle = { polls: 0, stop: () => undefined };

  const tick = () => {
    if (busy || stopped) return;
    const pids = tree.pids();
    if (!pids.length) return;
    busy = true;
    execFile(
      "lsof",
      ["-n", "-P", "-i", "-a", "-p", pids.join(","), "-F", "pcPn"],
      { maxBuffer: 8 * 1024 * 1024, timeout: 3000 },
      (_err, stdout) => {
        busy = false;
        // lsof exits 1 when nothing matched; stdout is still meaningful.
        if (!stdout) return;
        handle.polls++;
        for (const c of parseLsof(stdout)) {
          const key = `${c.pid}|${c.protocol}|${c.localPort}|${c.remoteHost}|${c.remotePort}`;
          if (seen.has(key)) continue;
          seen.add(key);
          collector.addNet({
            source: "lsof",
            pid: c.pid,
            host: c.remoteHost,
            port: c.remotePort,
            protocol: c.protocol,
          });
        }
        if (seen.size > 20000) seen.clear();
      },
    );
  };

  const timer = setInterval(tick, opts.intervalMs ?? 150);
  timer.unref();
  tick();
  handle.stop = () => {
    stopped = true;
    clearInterval(timer);
  };
  return handle;
}
