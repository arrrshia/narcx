import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import type { Collector } from "../core/collector.js";
import type { WireMessage } from "../core/types.js";

export interface IpcHandle {
  /** Value for NARC_SOCK: a unix socket path or `tcp://127.0.0.1:<port>`. */
  address: string;
  /** Set of child pids that loaded the preload hook. */
  hookedPids: Set<number>;
  close(): Promise<void>;
}

/**
 * Receives NDJSON events from the preload hook (Layer 2). Prefers a Unix
 * domain socket; falls back to loopback TCP when the tmpdir path would exceed
 * the sun_path limit (~104 bytes on macOS).
 */
export async function startIpc(collector: Collector, tmpDir: string): Promise<IpcHandle> {
  const hookedPids = new Set<number>();
  const sockets = new Set<net.Socket>();

  const server = net.createServer((sock) => {
    sockets.add(sock);
    sock.once("close", () => sockets.delete(sock));
    sock.on("error", () => sock.destroy());
    let buf = "";
    sock.setEncoding("utf8");
    sock.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg: WireMessage;
        try {
          msg = JSON.parse(line) as WireMessage;
        } catch {
          continue;
        }
        dispatch(collector, hookedPids, msg);
      }
    });
  });

  let address: string;
  const unixPath = path.join(tmpDir, "ipc.sock");
  const canUnix = os.platform() !== "win32" && Buffer.byteLength(unixPath) < 100;

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    if (canUnix) {
      try {
        fs.rmSync(unixPath, { force: true });
      } catch {
        /* ignore */
      }
      server.listen(unixPath, () => resolve());
    } else {
      server.listen(0, "127.0.0.1", () => resolve());
    }
  });

  if (canUnix) {
    address = unixPath;
  } else {
    const a = server.address();
    const port = typeof a === "object" && a ? a.port : 0;
    collector.ignorePort(port);
    address = `tcp://127.0.0.1:${port}`;
  }

  return {
    address,
    hookedPids,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => {
          if (canUnix) {
            try {
              fs.rmSync(unixPath, { force: true });
            } catch {
              /* ignore */
            }
          }
          resolve();
        });
        setTimeout(resolve, 300).unref();
      }),
  };
}

function dispatch(collector: Collector, hookedPids: Set<number>, msg: WireMessage): void {
  switch (msg.t) {
    case "hello":
      hookedPids.add(msg.pid);
      break;
    case "file":
      hookedPids.add(msg.pid);
      collector.addFile({ source: "preload", pid: msg.pid, path: msg.path, op: msg.op, id: "p" + msg.id, exists: msg.exists });
      break;
    case "net":
      hookedPids.add(msg.pid);
      collector.addNet({
        source: "preload",
        pid: msg.pid,
        host: msg.host,
        port: msg.port,
        protocol: msg.protocol,
        method: msg.method,
        path: msg.path,
        url: msg.url,
        bytesOut: msg.bytesOut,
        id: "p" + msg.id,
      });
      break;
    case "net-update":
      collector.updateNet("p" + msg.id, msg.bytesOut, msg.bytesIn);
      break;
    case "dns":
      collector.addDns({ source: "preload", pid: msg.pid, host: msg.host, addresses: msg.addresses, id: "p" + msg.id });
      break;
  }
}
