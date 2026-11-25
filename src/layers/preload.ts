/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Layer 2: zero-sudo preload hook, injected into child Node processes via
 * `NODE_OPTIONS=--require <this file>`. Bundled to CommonJS so it loads into
 * both CJS and ESM programs.
 *
 * IMPORTANT: this file uses bare `require()` on purpose. An `import * as fs`
 * would give esbuild's `__toESM` copy and the monkey-patches would land on the
 * copy instead of the real module object.
 */
import { SensitiveMatcher } from "../core/watchlist.js";
import { isLoopback } from "../core/classify.js";
import type { WireMessage } from "../core/types.js";

declare const require: NodeRequire;

(function narcPreload() {
  const g = globalThis as any;
  if (g.__narc_preload_loaded) return;
  g.__narc_preload_loaded = true;

  const SOCK = process.env.NARC_SOCK;
  if (!SOCK) return;
  const PROXY_PORT = Number(process.env.NARC_PROXY_PORT || 0);
  const HOME = process.env.NARC_HOME || require("node:os").homedir();

  const net = require("node:net") as typeof import("node:net");
  const fs = require("node:fs") as typeof import("node:fs");
  const http = require("node:http") as typeof import("node:http");
  const https = require("node:https") as typeof import("node:https");
  const dns = require("node:dns") as typeof import("node:dns");

  const matcher = new SensitiveMatcher(HOME);
  const pid = process.pid;
  let seq = 0;
  const nextId = () => `${pid}-${++seq}`;

  // ---- transport ------------------------------------------------------------

  let sock: import("node:net").Socket | null = null;
  let connected = false;
  let dead = false;
  const queue: string[] = [];

  function flush() {
    if (!sock || !connected) return;
    while (queue.length) sock.write(queue.shift()!);
    // Once the startup backlog is delivered, stop holding the event loop open.
    sock.unref();
  }

  function send(msg: WireMessage) {
    if (dead) return;
    const line = JSON.stringify(msg) + "\n";
    if (connected && sock) {
      sock.write(line);
    } else {
      queue.push(line);
      if (queue.length > 5000) queue.shift();
    }
  }

  try {
    const tcp = /^tcp:\/\/([^:]+):(\d+)$/.exec(SOCK);
    sock = tcp ? net.connect(Number(tcp[2]), tcp[1]) : net.connect(SOCK);
    sock.on("connect", () => {
      connected = true;
      flush();
    });
    const die = () => {
      dead = true;
      connected = false;
      sock = null;
    };
    sock.on("error", die);
    sock.on("close", die);
  } catch {
    dead = true;
  }

  send({ t: "hello", pid, ppid: process.ppid, argv: process.argv });

  // ---- helpers --------------------------------------------------------------

  function pathToString(p: unknown): string | null {
    if (typeof p === "string") return p;
    if (Buffer.isBuffer(p)) return p.toString();
    if (p instanceof URL) {
      if (p.protocol !== "file:") return null;
      try {
        return require("node:url").fileURLToPath(p);
      } catch {
        return null;
      }
    }
    return null;
  }

  const origAccessSync = fs.accessSync;
  function reportFile(op: string, p: unknown) {
    try {
      const s = pathToString(p);
      if (!s) return;
      if (!matcher.isSensitive(s) && !matcher.isDotfileUnderHome(s)) return;
      const norm = matcher.normalize(s);
      let exists = true;
      try {
        origAccessSync(norm);
      } catch {
        exists = false; // a probe of a path that is not there, not a read
      }
      send({ t: "file", id: nextId(), pid, path: norm, op, exists });
    } catch {
      /* never break the host program */
    }
  }

  function wrap<T extends object>(obj: T, name: keyof T & string, op: string, pathArg = 0) {
    const orig = (obj as any)[name];
    if (typeof orig !== "function") return;
    const patched = function (this: unknown, ...args: unknown[]) {
      reportFile(op, args[pathArg]);
      return orig.apply(this, args);
    };
    Object.defineProperty(patched, "name", { value: orig.name });
    (obj as any)[name] = patched;
  }

  // ---- fs -------------------------------------------------------------------

  wrap(fs, "readFile", "readFile");
  wrap(fs, "readFileSync", "readFileSync");
  wrap(fs, "open", "open");
  wrap(fs, "openSync", "openSync");
  wrap(fs, "createReadStream", "createReadStream");
  wrap(fs, "readdir", "readdir");
  wrap(fs, "readdirSync", "readdirSync");
  if (fs.promises) {
    wrap(fs.promises, "readFile", "promises.readFile");
    wrap(fs.promises, "open", "promises.open");
    wrap(fs.promises, "readdir", "promises.readdir");
  }

  // ---- http / https ---------------------------------------------------------

  const ipcMatch = /^tcp:\/\/[^:]+:(\d+)$/.exec(SOCK);
  const IPC_TCP_PORT = ipcMatch ? Number(ipcMatch[1]) : -1;
  function isNarcPort(host: string, port: number): boolean {
    return isLoopback(host) && (port === PROXY_PORT || port === IPC_TCP_PORT);
  }

  function describe(args: unknown[], proto: "http" | "https") {
    const a0 = args[0];
    const a1 = args[1];
    let o: any = {};
    if (typeof a0 === "string" || a0 instanceof URL) {
      const u = new URL(String(a0));
      o = {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
      };
      if (a1 && typeof a1 === "object") o = { ...o, ...(a1 as object) };
    } else if (a0 && typeof a0 === "object") {
      o = a0;
    }
    const protocol: "http" | "https" = String(o.protocol || proto + ":").startsWith("https") ? "https" : "http";
    let hostname: string = o.hostname || o.host || "localhost";
    hostname = String(hostname).replace(/:\d+$/, "");
    const port = Number(o.port) || (protocol === "https" ? 443 : 80);
    const method = String(o.method || "GET").toUpperCase();
    const path = String(o.path || "/");
    const hostPart = port === (protocol === "https" ? 443 : 80) ? hostname : `${hostname}:${port}`;
    return { protocol, hostname, port, method, path, url: `${protocol}://${hostPart}${path}` };
  }

  function observe(req: import("node:http").ClientRequest, args: unknown[], proto: "http" | "https") {
    const d = describe(args, proto);
    if (isNarcPort(d.hostname, d.port)) return; // goes through the proxy; it will log it
    const id = nextId();
    send({
      t: "net",
      id,
      pid,
      host: d.hostname,
      port: d.port,
      protocol: d.protocol,
      method: d.method,
      path: d.path,
      url: d.url,
      bytesOut: 0,
    });
    let w0 = 0;
    let r0 = 0;
    let sent = false;
    let socketRef: import("node:net").Socket | null = null;
    req.on("socket", (s) => {
      socketRef = s;
      w0 = s.bytesWritten;
      r0 = s.bytesRead;
    });
    const update = () => {
      if (!socketRef) return;
      const out = Math.max(0, socketRef.bytesWritten - w0);
      const inn = Math.max(0, socketRef.bytesRead - r0);
      send({ t: "net-update", id, bytesOut: out, bytesIn: inn });
    };
    req.on("finish", () => {
      sent = true;
      update();
    });
    req.on("response", (res) => {
      res.on("end", update);
      res.on("close", update);
    });
    req.on("close", () => {
      if (!sent) update();
      else update();
    });
  }

  function wrapRequest(mod: any, name: "request" | "get", proto: "http" | "https") {
    const orig = mod[name];
    if (typeof orig !== "function") return;
    mod[name] = function (this: unknown, ...args: unknown[]) {
      const req = orig.apply(this, args);
      try {
        observe(req, args, proto);
      } catch {
        /* ignore */
      }
      return req;
    };
  }
  wrapRequest(http, "request", "http");
  wrapRequest(http, "get", "http");
  wrapRequest(https, "request", "https");
  wrapRequest(https, "get", "https");

  // ---- fetch ----------------------------------------------------------------

  const origFetch = g.fetch;
  if (typeof origFetch === "function") {
    const bodySize = (b: unknown): number => {
      try {
        if (b == null) return 0;
        if (typeof b === "string") return Buffer.byteLength(b);
        if (b instanceof ArrayBuffer) return b.byteLength;
        if (ArrayBuffer.isView(b)) return b.byteLength;
        if (b instanceof URLSearchParams) return Buffer.byteLength(b.toString());
        if (typeof (b as any).size === "number") return (b as any).size; // Blob
      } catch {
        /* ignore */
      }
      return 0;
    };
    const patchedFetch = function (this: unknown, input: any, init?: any) {
      let id: string | null = null;
      try {
        const isReq = typeof Request !== "undefined" && input instanceof Request;
        const u = new URL(isReq ? input.url : String(input));
        const protocol: "http" | "https" = u.protocol === "https:" ? "https" : "http";
        const port = Number(u.port) || (protocol === "https" ? 443 : 80);
        if (!isNarcPort(u.hostname, port)) {
          id = nextId();
          const method = String(init?.method || (isReq ? input.method : "GET")).toUpperCase();
          send({
            t: "net",
            id,
            pid,
            host: u.hostname,
            port,
            protocol,
            method,
            path: u.pathname + u.search,
            url: u.toString(),
            bytesOut: bodySize(init?.body),
          });
        }
      } catch {
        /* relative URL or weird input: let the real fetch deal with it */
      }
      const p: Promise<Response> = origFetch.call(this, input, init);
      if (id) {
        const rid = id;
        p.then(
          (res) => {
            try {
              const cl = Number(res.headers.get("content-length"));
              if (cl > 0) send({ t: "net-update", id: rid, bytesIn: cl });
            } catch {
              /* ignore */
            }
          },
          () => {
            /* request failed; nothing to add */
          },
        );
      }
      return p;
    };
    try {
      Object.defineProperty(g, "fetch", { value: patchedFetch, writable: true, configurable: true });
    } catch {
      g.fetch = patchedFetch;
    }
  }

  // ---- dns (lets the parent map raw IPs seen by lsof back to hostnames) ------

  function reportDns(host: unknown, result: unknown) {
    try {
      if (typeof host !== "string") return;
      const addresses: string[] = [];
      if (typeof result === "string") addresses.push(result);
      else if (Array.isArray(result)) {
        for (const r of result) {
          if (typeof r === "string") addresses.push(r);
          else if (r && typeof r.address === "string") addresses.push(r.address);
        }
      }
      if (addresses.length) send({ t: "dns", id: nextId(), pid, host, addresses });
    } catch {
      /* ignore */
    }
  }
  const origLookup = dns.lookup;
  (dns as any).lookup = function (this: unknown, host: unknown, ...rest: unknown[]) {
    const cbIdx = rest.findIndex((x) => typeof x === "function");
    if (cbIdx >= 0) {
      const cb = rest[cbIdx] as (...a: unknown[]) => void;
      rest[cbIdx] = function (this: unknown, err: unknown, addr: unknown, ...more: unknown[]) {
        if (!err) reportDns(host, addr);
        return cb.call(this, err, addr, ...more);
      };
    }
    return (origLookup as any).call(this, host, ...rest);
  };
  if (dns.promises && typeof dns.promises.lookup === "function") {
    const origP = dns.promises.lookup;
    (dns.promises as any).lookup = function (this: unknown, host: unknown, ...rest: unknown[]) {
      const p = (origP as any).call(this, host, ...rest);
      p.then((r: unknown) => reportDns(host, r), () => undefined);
      return p;
    };
  }
})();
