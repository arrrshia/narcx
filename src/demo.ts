import * as fs from "node:fs";
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import * as path from "node:path";
import { DEMO_CERT, DEMO_KEY } from "./fixtures/demo-cert.js";

export interface DemoEnv {
  home: string;
  cwd: string;
  command: string[];
  env: Record<string, string>;
  /** Sinkhole every upstream the proxy would contact. */
  resolveUpstream: (host: string, port: number) => { host: string; port: number } | null;
  /** Loopback ports the sinks listen on. */
  sinkPorts: number[];
  close(): Promise<void>;
}

const FAKE_FILES: Record<string, string> = {
  ".claude.json": JSON.stringify({ oauthAccount: { emailAddress: "fake@example.invalid" }, primaryApiKey: "sk-ant-FAKE-FAKE-FAKE" }, null, 2),
  ".ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nTHIS-IS-A-FAKE-KEY-FOR-THE-NARC-DEMO\n-----END OPENSSH PRIVATE KEY-----\n",
  ".ssh/config": "Host *\n  IdentityFile ~/.ssh/id_rsa\n",
  ".aws/credentials": "[default]\naws_access_key_id = AKIAFAKEFAKEFAKEFAKE\naws_secret_access_key = FAKE/FAKE/FAKE\n",
  ".config/gh/hosts.yml": "github.com:\n    oauth_token: gho_FAKEFAKEFAKE\n    user: demo\n",
  ".npmrc": "//registry.npmjs.org/:_authToken=npm_FAKEFAKEFAKE\n",
  ".gitconfig": "[user]\n\tname = Demo\n\temail = demo@example.invalid\n",
  "project/.env": "OPENAI_API_KEY=sk-FAKE\nDATABASE_URL=postgres://fake\n",
  "project/README.md": "# demo project\n",
  ".config/shady-ai/settings.json": JSON.stringify({ theme: "dark", telemetry: true }),
};

const FAKE_CHILD = `#!/usr/bin/env node
// narc --demo: fake external "claude" agent spawned by shady-ai-tool.
const fs = require("node:fs"), https = require("node:https"), path = require("node:path");
const home = process.env.HOME || "";
try { fs.readFileSync(path.join(home, ".claude.json")); } catch {}
const lookup = (_h, opts, cb) => (opts && opts.all ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4));
const req = https.request(
  { host: "http-intake.logs.us5.datadoghq.com", port: Number(process.env.NARC_DEMO_HTTPS_SINK || 0), method: "POST", path: "/api/v2/logs", lookup, rejectUnauthorized: false, timeout: 3000 },
  (res) => { res.resume(); res.on("end", () => process.exit(0)); },
);
req.on("error", () => process.exit(0));
req.on("timeout", () => req.destroy());
req.end(JSON.stringify({ ddsource: "claude", message: "session started" }));
`;

/**
 * Builds an isolated fake HOME full of decoy secrets and two loopback sinks
 * (HTTP + HTTPS) so the mock tool can "phone home" without a single byte
 * leaving the machine.
 */
export async function setupDemo(tmpDir: string, distDir: string): Promise<DemoEnv> {
  const home = path.join(tmpDir, "home");
  for (const [rel, content] of Object.entries(FAKE_FILES)) {
    const abs = path.join(home, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, { mode: 0o600 });
  }
  // A fake external agent CLI, installed outside the shady tool's own package, that the
  // tool delegates to. It reads its *own* config and reports to its *own* vendor: that
  // activity is the child's, not the tool's, and must not move the tool's grade.
  const bin = path.join(tmpDir, "bin");
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(bin, "claude"), FAKE_CHILD, { mode: 0o755 });

  const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
    req.on("data", () => undefined);
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json", "content-length": "11" });
      res.end('{"ok":true}');
    });
  };
  const httpSink = http.createServer(handler);
  const httpsSink = https.createServer({ key: DEMO_KEY, cert: DEMO_CERT }, handler);
  const sockets = new Set<net.Socket>();
  for (const s of [httpSink, httpsSink]) {
    s.on("connection", (sock) => {
      sockets.add(sock);
      sock.once("close", () => sockets.delete(sock));
    });
    s.on("clientError", (_e, sock) => sock.destroy());
  }
  await Promise.all([listen(httpSink), listen(httpsSink)]);
  const httpPort = portOf(httpSink);
  const httpsPort = portOf(httpsSink);

  return {
    home,
    cwd: path.join(home, "project"),
    command: [process.execPath, path.join(distDir, "shady-ai-tool.cjs")],
    env: {
      HOME: home,
      NARC_HOME: home,
      NARC_DEMO_HTTP_SINK: String(httpPort),
      NARC_DEMO_HTTPS_SINK: String(httpsPort),
      NARC_DEMO_BIN: bin,
    },
    resolveUpstream: (_host, port) => ({ host: "127.0.0.1", port: port === 443 ? httpsPort : httpPort }),
    sinkPorts: [httpPort, httpsPort],
    close: async () => {
      for (const s of sockets) s.destroy();
      await Promise.all([closeServer(httpSink), closeServer(httpsSink)]);
    },
  };
}

function listen(s: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => resolve());
  });
}
function portOf(s: http.Server): number {
  const a = s.address();
  return typeof a === "object" && a ? a.port : 0;
}
function closeServer(s: http.Server): Promise<void> {
  return new Promise((resolve) => {
    s.close(() => resolve());
    setTimeout(resolve, 300).unref();
  });
}
