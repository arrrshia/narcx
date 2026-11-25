import * as http from "node:http";
import * as net from "node:net";
import type { Collector } from "../core/collector.js";
import { PortPidResolver } from "./pidresolver.js";

export interface ProxyHandle {
  port: number;
  close(): Promise<void>;
}

export interface ProxyOptions {
  collector: Collector;
  /**
   * Optional upstream override (used by --demo so nothing leaves the machine).
   * Return null to connect to the real destination.
   */
  resolveUpstream?: (host: string, port: number) => { host: string; port: number } | null;
  /** Pids of the audited tree, so each connection can be attributed to the process that opened it. */
  pids?: () => number[];
}

const HOP_BY_HOP = new Set([
  "proxy-connection",
  "proxy-authorization",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
]);

function headerBytes(method: string, url: string, raw: string[]): number {
  let n = method.length + 1 + url.length + 11; // "METHOD url HTTP/1.1\r\n"
  for (let i = 0; i < raw.length; i += 2) n += (raw[i]?.length ?? 0) + 2 + (raw[i + 1]?.length ?? 0) + 2;
  return n + 2;
}

/**
 * Layer 1: an ephemeral HTTP forward proxy + HTTPS CONNECT tunnel on 127.0.0.1.
 * Plain HTTP requests are logged with method + path; CONNECT tunnels are logged
 * with host + byte volume only. TLS is never terminated.
 */
export async function startProxy(opts: ProxyOptions): Promise<ProxyHandle> {
  const { collector } = opts;
  const sockets = new Set<net.Socket>();
  const track = (s: net.Socket) => {
    sockets.add(s);
    s.once("close", () => sockets.delete(s));
  };
  // Which local process opened each client socket: looked up the moment the
  // connection arrives, while it is still established, and attached to the
  // event once known.
  let resolver: PortPidResolver | null = null;
  const lookups = new WeakMap<net.Socket, Promise<number | null>>();
  const attribute = (sock: net.Socket | null | undefined, id: string | undefined) => {
    if (!sock || !id) return;
    lookups.get(sock)?.then((pid) => {
      if (pid) collector.setNetPid(id, pid);
    });
  };

  const server = http.createServer((req, res) => {
    let target: URL;
    try {
      target = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    } catch {
      res.writeHead(400).end("narc: bad request");
      return;
    }
    const host = target.hostname;
    const port = Number(target.port) || (target.protocol === "https:" ? 443 : 80);
    const method = req.method ?? "GET";
    const pathq = target.pathname + target.search;

    let bytesOut = headerBytes(method, req.url ?? "/", req.rawHeaders);
    let bytesIn = 0;
    const ev = collector.addNet({
      source: "proxy",
      host,
      port,
      protocol: "http",
      method,
      path: pathq,
      url: target.toString(),
      bytesOut,
    });
    const tick = () => ev && collector.updateNet(ev.id, bytesOut, bytesIn);
    attribute(req.socket, ev?.id);

    const up = opts.resolveUpstream?.(host, port) ?? { host, port };
    const headers: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined || HOP_BY_HOP.has(k)) continue;
      headers[k] = v;
    }
    headers["connection"] = "close";

    const upstream = http.request(
      { host: up.host, port: up.port, method, path: pathq, headers, setHost: false },
      (upRes) => {
        bytesIn += 12 + JSON.stringify(upRes.rawHeaders).length;
        res.writeHead(upRes.statusCode ?? 502, upRes.headers);
        upRes.on("data", (c: Buffer) => {
          bytesIn += c.length;
          tick();
        });
        upRes.pipe(res);
      },
    );
    upstream.on("error", () => {
      if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
      res.end("narc: upstream connection failed");
      tick();
    });
    req.on("data", (c: Buffer) => {
      bytesOut += c.length;
      tick();
    });
    req.on("error", () => upstream.destroy());
    res.on("close", tick);
    req.pipe(upstream);
  });

  server.on("connect", (req, clientSocket: net.Socket, head: Buffer) => {
    track(clientSocket);
    const [rawHost, rawPort] = splitHostPort(req.url ?? "");
    const host = rawHost;
    const port = rawPort || 443;
    let bytesOut = head.length;
    let bytesIn = 0;
    const ev = collector.addNet({
      source: "proxy",
      host,
      port,
      protocol: port === 443 ? "https" : "tcp",
      method: "CONNECT",
      bytesOut,
    });
    const tick = () => ev && collector.updateNet(ev.id, bytesOut, bytesIn);
    attribute(clientSocket, ev?.id);

    const up = opts.resolveUpstream?.(host, port) ?? { host, port };
    const upstream = net.connect(up.port, up.host);
    track(upstream);
    upstream.setNoDelay(true);
    clientSocket.setNoDelay(true);

    upstream.once("connect", () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: narc\r\n\r\n");
      if (head.length) upstream.write(head);
      clientSocket.on("data", (c: Buffer) => {
        bytesOut += c.length;
        tick();
      });
      upstream.on("data", (c: Buffer) => {
        bytesIn += c.length;
        tick();
      });
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    });
    const teardown = () => {
      tick();
      clientSocket.destroy();
      upstream.destroy();
    };
    upstream.on("error", () => {
      if (clientSocket.writable && !clientSocket.destroyed) {
        clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      }
      teardown();
    });
    clientSocket.on("error", teardown);
    clientSocket.on("close", teardown);
    upstream.on("close", teardown);
  });

  server.on("connection", (sock: net.Socket) => {
    track(sock);
    if (resolver && sock.remotePort) lookups.set(sock, resolver.resolve(sock.remotePort));
  });
  server.on("clientError", (_err, socket) => {
    try {
      socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    } catch {
      /* ignore */
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  collector.ignorePort(port);
  if (opts.pids) resolver = new PortPidResolver({ pids: opts.pids, proxyPort: port, attempts: 5 });

  return {
    port,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => resolve());
        setTimeout(resolve, 500).unref();
      }),
  };
}

export function splitHostPort(s: string): [string, number] {
  const m = /^\[?([^\]]+?)\]?(?::(\d+))?$/.exec(s.trim());
  if (!m) return [s, 0];
  return [m[1] ?? s, m[2] ? Number(m[2]) : 0];
}

/** Environment variables that make well-behaved clients use the proxy. */
export function proxyEnv(port: number): Record<string, string> {
  const url = `http://127.0.0.1:${port}`;
  return {
    HTTP_PROXY: url,
    HTTPS_PROXY: url,
    ALL_PROXY: url,
    http_proxy: url,
    https_proxy: url,
    all_proxy: url,
    // Make sure nothing is excluded from the proxy. narc's own ports are
    // filtered on the collector side, so looping back is harmless.
    NO_PROXY: "",
    no_proxy: "",
    // Node >= 24 honours proxy env vars for fetch/http when this is set.
    NODE_USE_ENV_PROXY: "1",
    // global-agent users
    GLOBAL_AGENT_HTTP_PROXY: url,
    GLOBAL_AGENT_HTTPS_PROXY: url,
  };
}
