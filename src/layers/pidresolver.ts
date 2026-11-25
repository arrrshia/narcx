/**
 * Resolve which local process owns a TCP connection to narc's proxy, from the
 * client's ephemeral port. Batched: every pending port is answered by one
 * `lsof -n -P -i TCP -sTCP:ESTABLISHED -F pn` scoped to the audited tree.
 * On Linux /proc/net/tcp + /proc/<pid>/fd is used when lsof is unavailable.
 */
import { execFile } from "node:child_process";
import * as fs from "node:fs";

export interface PortPidResolverOptions {
  /** Pids to scope the lookup to (the audited process tree). */
  pids: () => number[];
  /** The proxy's listening port, to pick the client end of the pair. */
  proxyPort: number;
  /** How many lookups to attempt before giving up on a port (connection may already be gone). */
  attempts?: number;
}

/** Parse `lsof -F pn` output into local-port -> pid for connections to `proxyPort`. */
export function parseLsofPorts(output: string, proxyPort: number): Map<number, number> {
  const out = new Map<number, number>();
  let pid = 0;
  for (const line of output.split("\n")) {
    if (!line) continue;
    const tag = line[0];
    const val = line.slice(1);
    if (tag === "p") pid = Number(val);
    else if (tag === "n") {
      const m = /^(?:\[[^\]]+\]|[^:]+):(\d+)->(?:\[[^\]]+\]|[^:]+):(\d+)/.exec(val);
      if (m && Number(m[2]) === proxyPort && pid) out.set(Number(m[1]), pid);
    }
  }
  return out;
}

/** Linux fallback: map local ports of connections to `proxyPort` -> pid via /proc. */
export function procNetTcpPorts(proxyPort: number, pids: number[]): Map<number, number> {
  const out = new Map<number, number>();
  let table = "";
  try {
    table = fs.readFileSync("/proc/net/tcp", "utf8") + "\n" + (fs.existsSync("/proc/net/tcp6") ? fs.readFileSync("/proc/net/tcp6", "utf8") : "");
  } catch {
    return out;
  }
  const inodeToPort = new Map<string, number>();
  for (const line of table.split("\n").slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 10) continue;
    const local = cols[1]!;
    const remote = cols[2]!;
    const state = cols[3];
    if (state !== "01") continue; // ESTABLISHED
    const lport = parseInt(local.split(":").pop() ?? "0", 16);
    const rport = parseInt(remote.split(":").pop() ?? "0", 16);
    if (rport === proxyPort) inodeToPort.set(cols[9]!, lport);
  }
  if (!inodeToPort.size) return out;
  for (const pid of pids) {
    let fds: string[] = [];
    try {
      fds = fs.readdirSync(`/proc/${pid}/fd`);
    } catch {
      continue;
    }
    for (const fd of fds) {
      try {
        const link = fs.readlinkSync(`/proc/${pid}/fd/${fd}`);
        const m = /^socket:\[(\d+)\]$/.exec(link);
        if (m && inodeToPort.has(m[1]!)) out.set(inodeToPort.get(m[1]!)!, pid);
      } catch {
        /* ignore */
      }
    }
  }
  return out;
}

export class PortPidResolver {
  private pending = new Map<number, { resolve: (pid: number | null) => void; tries: number }>();
  private running = false;
  private queued = false;
  private readonly attempts: number;

  constructor(private readonly opts: PortPidResolverOptions) {
    this.attempts = opts.attempts ?? 3;
  }

  /** Start resolving right away; resolves to null when the connection vanished before lsof could see it. */
  resolve(localPort: number): Promise<number | null> {
    return new Promise((resolve) => {
      this.pending.set(localPort, { resolve, tries: 0 });
      this.kick();
    });
  }

  private kick(): void {
    if (this.running) {
      this.queued = true;
      return;
    }
    this.running = true;
    this.lookup()
      .then((map) => {
        for (const [port, p] of this.pending) {
          const pid = map.get(port);
          if (pid) {
            p.resolve(pid);
            this.pending.delete(port);
          } else if (++p.tries >= this.attempts) {
            p.resolve(null);
            this.pending.delete(port);
          }
        }
      })
      .finally(() => {
        this.running = false;
        if (this.pending.size) {
          this.queued = false;
          setTimeout(() => this.kick(), 40);
        } else if (this.queued) {
          this.queued = false;
          this.kick();
        }
      });
  }

  private lookup(): Promise<Map<number, number>> {
    const pids = this.opts.pids();
    if (!pids.length) return Promise.resolve(new Map());
    return new Promise((resolve) => {
      execFile(
        "lsof",
        ["-n", "-P", "-i", "TCP", "-sTCP:ESTABLISHED", "-a", "-p", pids.join(","), "-F", "pn"],
        { maxBuffer: 8 * 1024 * 1024, timeout: 3000 },
        (_err, stdout) => {
          const map = parseLsofPorts(stdout ?? "", this.opts.proxyPort);
          if (!map.size && process.platform === "linux") {
            for (const [k, v] of procNetTcpPorts(this.opts.proxyPort, pids)) map.set(k, v);
          }
          resolve(map);
        },
      );
    });
  }
}
