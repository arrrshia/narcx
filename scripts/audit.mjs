#!/usr/bin/env node
/**
 * Reproducible narcx audit harness.
 *
 *   node scripts/audit.mjs [--deep] [--only id1,id2] [--all] [--boot 12] [--max 40]
 *                          [--sandbox /tmp/narc-audit-sandbox] [--out ./audit-results]
 *                          [--tools-dir /tmp/narc-audit-tools]
 *                          [--env KEY=VALUE ...] [--title-suffix "· telemetry disabled"]
 *
 * npm-distributed targets are installed once into --tools-dir (outside narcx)
 * and their bin is executed directly, so npx's own registry lookups and
 * ~/.npmrc reads never appear in the audit.
 *
 * For every target it spawns
 *   python3 scripts/pty-run.py node dist/cli.js --card <out>/<id>.png --json <out>/<id>.json [--deep] -- <target...>
 * inside a fresh pty (so TUIs boot like they would in a real terminal), lets it run
 * for `boot` seconds (or until natural exit), then walks a SIGINT ladder:
 * Ctrl-C on the pty, Ctrl-C again, SIGINT to narcx, SIGINT again (narcx then
 * SIGKILLs its child), and finally SIGKILL on the whole group. narcx itself
 * exits after its child does, prints the scorecard and writes JSON + PNG.
 *
 * Environment hygiene: all CLAUDE* variables from the calling shell are
 * removed (this harness is often run from inside Claude Code), a `.narc-bin`
 * directory with no-op `open`/`xdg-open` shims is prepended to PATH so tools
 * cannot pop a browser, and nothing else is changed. No telemetry opt-out
 * flags are set: targets run with their out-of-the-box defaults.
 */
import { execFileSync, spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const NARC = path.join(ROOT, "dist", "cli.js");
const PTY_RUN = path.join(ROOT, "scripts", "pty-run.py");
const HOME = os.homedir();

// ---------------------------------------------------------------------------
// targets
// ---------------------------------------------------------------------------
const TARGETS = [
  {
    id: "t3code",
    name: "T3 Code",
    kind: "local",
    pkg: "t3",
    bin: "t3",
    boot: 12,
    runtimeHint: "native executable (Bun) launched by a Node wrapper",
    prewarm: ["--help"],
    // T3 attaches to an already-running background service; stop one left over from an
    // earlier run so the audit observes a fresh service inside narcx's process tree.
    preRun: () => stopMatching(/\/\.t3\/runtime\//, "T3 Code background service"),
  },
  {
    id: "claude-code",
    name: "Claude Code",
    kind: "bin",
    bin: "claude",
    exec: ["claude", "-p", "reply with just ok"],
    bootCommand: ["claude"],
    boot: 10,
  },
  {
    id: "codex-cli",
    name: "Codex CLI",
    kind: "bin",
    bin: "codex",
    exec: ["codex", "exec", "reply with just ok"],
    bootCommand: ["codex"],
    boot: 10,
  },
  { id: "opencode", name: "OpenCode", kind: "bin", bin: "opencode", bootCommand: ["opencode"], boot: 10, optional: true },
  {
    id: "gemini-cli",
    name: "Gemini CLI",
    kind: "local",
    pkg: "@google/gemini-cli",
    bin: "gemini",
    boot: 10,
    prewarm: ["--version"],
  },
  {
    id: "context7-mcp",
    name: "Context7 MCP server",
    kind: "local",
    pkg: "@upstash/context7-mcp",
    bin: "context7-mcp",
    boot: 10,
    prewarm: ["--help"],
    optional: true,
  },
];

// ---------------------------------------------------------------------------
// args
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
const flag = (name, def) => {
  const i = args.indexOf(name);
  if (i < 0) return def;
  const v = args[i + 1];
  return v === undefined || v.startsWith("--") ? true : v;
};
const DEEP = args.includes("--deep");
const ONLY = flag("--only", null) ? String(flag("--only")).split(",").map((s) => s.trim()) : null;
const BOOT_OVERRIDE = flag("--boot", null) ? Number(flag("--boot")) : null;
const MAX_EXEC = Number(flag("--max", 40)); // cap for "exec"/-p style runs that should finish on their own
const SANDBOX = path.resolve(String(flag("--sandbox", "/tmp/narc-audit-sandbox")));
const OUT = path.resolve(String(flag("--out", path.join(ROOT, "audit-results"))));
const TOOLS = path.resolve(String(flag("--tools-dir", "/tmp/narc-audit-tools"))); // npm --prefix install root
const ALL = args.includes("--all");
// sudo tickets are per-tty, so --deep must run narcx on the terminal where `sudo -v` was typed,
// not inside a fresh pty. Interactive deep runs therefore inherit this process's stdio.
const INTERACTIVE = DEEP && Boolean(process.stdin.isTTY && process.stdout.isTTY);
// Variant runs: --env KEY=VALUE (repeatable) is added to the target's environment,
// --title-suffix is appended to the scorecard headline, e.g. "· telemetry disabled".
const EXTRA_ENV = {};
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--env" && args[i + 1]) {
    const eq = args[i + 1].indexOf("=");
    if (eq > 0) EXTRA_ENV[args[i + 1].slice(0, eq)] = args[i + 1].slice(eq + 1);
    i++;
  }
}
const TITLE_SUFFIX = flag("--title-suffix", null) ? String(flag("--title-suffix")) : "";

fs.mkdirSync(OUT, { recursive: true });
if (!fs.existsSync(NARC)) {
  console.error(`narcx is not built (${NARC}); run npm run build first`);
  process.exit(2);
}
if (!fs.existsSync(SANDBOX)) {
  console.error(`sandbox ${SANDBOX} does not exist`);
  process.exit(2);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (s) => process.stdout.write(`[audit] ${s}\n`);
const tilde = (p) => (typeof p === "string" && p.startsWith(HOME) ? "~" + p.slice(HOME.length) : p);

function which(bin) {
  const r = spawnSync("sh", ["-c", `command -v ${bin}`], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
}

function fileType(p) {
  try {
    return execFileSync("file", ["-b", p], { encoding: "utf8" }).trim();
  } catch {
    return "";
  }
}

/** Classify how a binary runs: native, Node, or a Node wrapper around a native binary. */
function runtimeOf(bin) {
  const p = which(bin);
  if (!p) return { runtime: "not installed", path: null };
  const real = fs.realpathSync(p);
  const ft = fileType(real);
  if (/Mach-O|ELF/.test(ft)) return { runtime: "native binary (Bun/Rust compiled)", path: real, file: ft };
  if (/node script|JavaScript|ASCII text|Unicode text/.test(ft)) {
    // find the package root and look for vendored native executables
    let dir = path.dirname(real);
    for (let i = 0; i < 6; i++) {
      if (fs.existsSync(path.join(dir, "package.json"))) break;
      dir = path.dirname(dir);
    }
    // Look for a native executable that carries the tool's own name, e.g.
    // @openai/codex -> node_modules/@openai/codex-darwin-arm64/.../codex.
    // Helper binaries (ripgrep, node-pty) do not count: the tool is still Node.
    const natives = [];
    const walk = (d, depth) => {
      if (depth > 6 || natives.length > 3) return;
      let ents = [];
      try {
        ents = fs.readdirSync(d, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of ents) {
        const fp = path.join(d, e.name);
        if (e.isDirectory()) {
          if (e.name === "node_modules" && depth > 0) continue;
          walk(fp, depth + 1);
        } else if (e.isFile() && e.name.toLowerCase().includes(bin.toLowerCase()) && !/\.(js|cjs|mjs|md|json|map|ts)$/.test(e.name)) {
          // npm may ship the vendored binary without an exec bit; the wrapper chmods it at runtime.
          if (/Mach-O|ELF/.test(fileType(fp))) natives.push(fp);
        }
      }
    };
    walk(dir, 0);
    if (natives.length) return { runtime: `Node wrapper -> native binary (${path.basename(natives[0])})`, path: real, native: natives[0] };
    return { runtime: "Node", path: real };
  }
  return { runtime: ft || "unknown", path: real };
}

function versionOf(bin) {
  try {
    const out = execFileSync(bin, ["--version"], { encoding: "utf8", timeout: 20000, stdio: ["ignore", "pipe", "pipe"], env: cleanEnv() });
    return out.trim().split("\n")[0].trim();
  } catch (e) {
    const out = (e.stdout || "") + (e.stderr || "");
    return out.trim().split("\n")[0]?.trim() || "unknown";
  }
}

function npmVersion(pkg) {
  try {
    return execFileSync("npm", ["view", pkg, "version"], { encoding: "utf8", timeout: 30000 }).trim();
  } catch {
    return "unknown";
  }
}

/**
 * Install <pkg>@<ver> into the tools prefix (outside narcx, once) and return
 * the path of its bin, so the audited command is the tool itself and not
 * `npx` resolving, downloading and re-validating the package.
 */
function localInstall(pkg, ver, bin, prewarm) {
  const binPath = path.join(TOOLS, "node_modules", ".bin", bin);
  const marker = path.join(TOOLS, `.installed-${bin}-${ver}`);
  if (!fs.existsSync(binPath) || !fs.existsSync(marker)) {
    fs.mkdirSync(TOOLS, { recursive: true });
    log(`installing ${pkg}@${ver} into ${TOOLS} (outside narcx)`);
    execFileSync("npm", ["install", "--prefix", TOOLS, "--no-audit", "--no-fund", "--loglevel", "error", `${pkg}@${ver}`], {
      stdio: ["ignore", "ignore", "inherit"],
      timeout: 600000,
      env: cleanEnv(),
    });
    fs.writeFileSync(marker, new Date().toISOString());
  }
  if (prewarm) {
    // Run once outside narcx so first-run downloads (e.g. T3's native executable) are cached.
    try {
      execFileSync(binPath, prewarm, { stdio: "ignore", timeout: 300000, env: cleanEnv(), cwd: SANDBOX });
    } catch {
      /* a non-zero exit is fine; we only want the cache warm */
    }
  }
  return binPath;
}

let scrubbedKeys = [];
function cleanEnv() {
  const env = {};
  scrubbedKeys = [];
  for (const [k, v] of Object.entries(process.env)) {
    if (/^CLAUDE/i.test(k) || k === "NARC_SOCK" || k === "NARC_PROXY_PORT" || k === "NARC_HOME") {
      scrubbedKeys.push(k);
      continue;
    }
    // A loopback ANTHROPIC_BASE_URL is the desktop app's own relay, not the user's default.
    if (k === "ANTHROPIC_BASE_URL" && /\/\/(localhost|127\.0\.0\.1|\[::1\])/.test(v || "")) {
      scrubbedKeys.push(k + " (loopback relay)");
      continue;
    }
    env[k] = v;
  }
  env.PATH = `${path.join(SANDBOX, ".narc-bin")}:${env.PATH || ""}`;
  env.BROWSER = "none";
  Object.assign(env, EXTRA_ENV);
  return env;
}

/** SIGTERM (then SIGKILL) every process whose command line matches; returns how many. */
function stopMatching(re, label) {
  const list = () =>
    execFileSync("ps", ["-axo", "pid=,command="], { encoding: "utf8" })
      .split("\n")
      .map((l) => /^\s*(\d+)\s+(.*)$/.exec(l))
      .filter((m) => m && re.test(m[2]))
      .map((m) => Number(m[1]));
  const pids = list();
  if (!pids.length) return 0;
  log(`stopping ${pids.length} leftover ${label} process(es): ${pids.join(", ")}`);
  for (const pid of pids) try { process.kill(pid, "SIGTERM"); } catch { /* gone */ }
  const deadline = Date.now() + 2000;
  while (Date.now() < deadline && list().length) spawnSync("sleep", ["0.2"]);
  for (const pid of list()) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
  return pids.length;
}

function sudoCached() {
  return spawnSync("sudo", ["-n", "true"], { stdio: "ignore" }).status === 0;
}

// ---------------------------------------------------------------------------
// one audited run
// ---------------------------------------------------------------------------
async function runOnce({ id, command, boot, maxWait, deep, attempt, title }) {
  const jsonPath = path.join(OUT, `${id}.json`);
  const pngPath = path.join(OUT, `${id}.png`);
  const logPath = path.join(OUT, `${id}${attempt > 1 ? `.attempt${attempt}` : ""}.log`);
  // Park any previous report so a failed run never destroys a good one.
  const parked = [];
  for (const p of [jsonPath, pngPath]) {
    if (fs.existsSync(p)) {
      fs.renameSync(p, p + ".prev");
      parked.push(p);
    }
  }

  const envNote = Object.keys(EXTRA_ENV).length ? Object.entries(EXTRA_ENV).map(([k, v]) => `${k}=${v}`).join(" ") + " · no TLS interception · zero auditor network calls" : null;
  const narcArgs = [NARC, "--card", pngPath, "--json", jsonPath, ...(title ? ["--title", title] : []), ...(envNote ? ["--footer", envNote] : []), ...(deep ? ["--deep"] : []), "--", ...command];
  const usePty = !(deep && INTERACTIVE);
  log(`${id}: ${command.join(" ")}  (boot ${boot}s, max ${maxWait}s${deep ? ", --deep" : ""}${usePty ? "" : ", on this terminal"})`);

  const started = Date.now();
  const child = usePty
    ? spawn("python3", [PTY_RUN, process.execPath, ...narcArgs], { cwd: SANDBOX, env: cleanEnv(), stdio: ["pipe", "pipe", "pipe"], detached: true })
    : spawn(process.execPath, narcArgs, { cwd: SANDBOX, env: cleanEnv(), stdio: "inherit" });
  const chunks = [];
  if (usePty) {
    child.stdout.on("data", (c) => chunks.push(c));
    child.stderr.on("data", (c) => chunks.push(c));
  }

  let exited = false;
  let exitCode = null;
  const done = new Promise((resolve) => {
    child.on("close", (code) => {
      exited = true;
      exitCode = code;
      resolve();
    });
    child.on("error", () => {
      exited = true;
      resolve();
    });
  });

  const narcPid = () => {
    if (!usePty) return child.pid;
    try {
      const out = execFileSync("pgrep", ["-P", String(child.pid)], { encoding: "utf8" });
      return out.trim().split("\n").map(Number).filter(Boolean)[0] ?? null;
    } catch {
      return null;
    }
  };
  const safeKill = (pid, sig) => {
    try {
      process.kill(pid, sig);
      return true;
    } catch {
      return false;
    }
  };

  const ladder = [];
  const waitUntil = async (ms) => {
    const deadline = started + ms;
    while (!exited && Date.now() < deadline) await sleep(100);
    return exited;
  };

  // Phase 0: let it run until natural exit or the boot/max deadline.
  if (!(await waitUntil(boot * 1000))) {
    if (usePty) {
      ladder.push("ctrl-c (pty)");
      child.stdin.write("\x03");
      if (!(await waitUntil(boot * 1000 + 1500))) {
        ladder.push("ctrl-c (pty) x2");
        child.stdin.write("\x03");
      }
    } else {
      ladder.push(`SIGINT -> narcx pid ${child.pid}`);
      safeKill(child.pid, "SIGINT"); // narcx forwards it to the tool
    }
    if (!(await waitUntil(boot * 1000 + 4000))) {
      const np = narcPid();
      ladder.push(`SIGINT -> narcx pid ${np}`);
      if (np) safeKill(np, "SIGINT");
    }
    if (!(await waitUntil(boot * 1000 + 8000))) {
      const np = narcPid();
      ladder.push(`SIGINT x2 -> narcx pid ${np} (child gets SIGKILL)`);
      if (np) safeKill(np, "SIGINT");
    }
    if (!(await waitUntil(Math.max(maxWait, boot + 15) * 1000))) {
      ladder.push(usePty ? "SIGKILL process group" : "SIGKILL narcx");
      safeKill(usePty ? -child.pid : child.pid, "SIGKILL");
      await waitUntil(Math.max(maxWait, boot + 15) * 1000 + 3000);
    }
  }
  if (usePty) {
    try {
      child.stdin.end();
    } catch {
      /* ignore */
    }
  }
  await done;
  const durationMs = Date.now() - started;
  const output = usePty ? Buffer.concat(chunks).toString("utf8") : "";
  fs.writeFileSync(logPath, usePty ? output : "(deep mode ran on the real terminal; live output was not captured — see the JSON report)\n");

  const ok = fs.existsSync(jsonPath) && fs.statSync(jsonPath).size > 0;
  let report = null;
  if (ok) {
    try {
      report = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
    } catch {
      report = null;
    }
  }
  let restored = false;
  for (const p of parked) {
    if (report) fs.rmSync(p + ".prev", { force: true });
    else {
      fs.renameSync(p + ".prev", p); // keep the previous good report
      restored = true;
    }
  }
  return { jsonPath, pngPath, logPath, exitCode, durationMs, ladder, report, output, restored };
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
async function main() {
  const narcVersion = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).version;
  const sudoOk = sudoCached();
  log(`narcx v${narcVersion} · sandbox ${SANDBOX} · out ${path.relative(ROOT, OUT) || "."} · sudo cached: ${sudoOk} · deep: ${DEEP}`);
  cleanEnv();
  log(`scrubbed env vars: ${scrubbedKeys.length ? scrubbedKeys.join(" ") : "(none)"}`);

  const manifestPath = path.join(OUT, "manifest.json");
  const manifest = fs.existsSync(manifestPath)
    ? JSON.parse(fs.readFileSync(manifestPath, "utf8"))
    : { generatedAt: null, narcVersion, sandbox: SANDBOX, platform: `${process.platform}-${process.arch}`, node: process.version, targets: {} };
  manifest.generatedAt = new Date().toISOString();
  manifest.narcVersion = narcVersion;
  manifest.scrubbedEnv = scrubbedKeys;
  manifest.browserShim = true;
  manifest.sudoCached = sudoOk;
  if (Object.keys(EXTRA_ENV).length) manifest.extraEnv = { ...EXTRA_ENV };
  manifest.sandboxIsGitRepo = fs.existsSync(path.join(SANDBOX, ".git"));

  if (DEEP && !INTERACTIVE) log("warning: --deep without a terminal — sudo tickets are per-tty, so narcx will skip fs_usage unless sudo is passwordless");

  for (const t of TARGETS) {
    if (ONLY ? !ONLY.includes(t.id) : t.optional && !ALL) continue;
    const prevEntry = manifest.targets[t.id];
    const entry = { id: t.id, name: t.name, attempts: [] };

    // resolve command + version + runtime
    let command;
    let version = "unknown";
    let runtime = "unknown";
    let exec = null;
    if (t.kind === "local") {
      version = npmVersion(t.pkg);
      if (version === "unknown") {
        log(`${t.id}: could not resolve ${t.pkg} on npm — skipped`);
        entry.skipped = "npm version lookup failed";
        manifest.targets[t.id] = entry;
        continue;
      }
      const binPath = localInstall(t.pkg, version, t.bin, t.prewarm);
      command = [binPath];
      runtime = t.runtimeHint ?? runtimeOf(binPath).runtime;
      entry.installed = true;
      entry.binary = binPath;
      entry.package = `${t.pkg}@${version}`;
    } else {
      const rt = runtimeOf(t.bin);
      if (!rt.path) {
        if (t.npxFallback) {
          version = npmVersion(t.npxFallback);
          command = ["npx", "-y", `${t.npxFallback}@${version}`];
          runtime = "Node (npx)";
          entry.installed = false;
        } else {
          log(`${t.id}: ${t.bin} is not installed — skipped`);
          entry.installed = false;
          entry.skipped = "not installed";
          manifest.targets[t.id] = entry;
          continue;
        }
      } else {
        entry.installed = true;
        entry.binary = tilde(rt.path);
        runtime = rt.runtime;
        version = versionOf(t.bin);
        command = t.bootCommand;
        exec = t.exec ?? null;
      }
    }
    entry.versionRaw = version;
    entry.version = (/(\d+\.\d+\.\d+(?:[-+][\w.]+)?)/.exec(version) || [null, version])[1];
    entry.runtime = runtime;
    const isNative = /native/.test(runtime);
    const deep = DEEP && isNative;
    entry.mode = deep ? "--deep" : "standard";
    entry.needsDeepTrace = isNative && !deep;
    const title = `${t.name} ${entry.version}${TITLE_SUFFIX ? " " + TITLE_SUFFIX : ""}`;
    if (Object.keys(EXTRA_ENV).length) entry.extraEnv = { ...EXTRA_ENV };

    const boot = BOOT_OVERRIDE ?? t.boot;
    if (t.preRun) entry.preRunStopped = t.preRun();

    // Attempt 1: authenticated one-shot (`claude -p`, `codex exec`) if the target has one.
    let result = null;
    if (exec) {
      const r = await runOnce({ id: t.id, command: exec, boot: MAX_EXEC, maxWait: MAX_EXEC, deep, attempt: 1, title });
      entry.attempts.push({ command: exec, exitCode: r.exitCode, durationMs: r.durationMs, ladder: r.ladder, log: path.basename(r.logPath) });
      const text = stripAnsi(r.output).slice(0, 6000);
      const authFailed =
        r.exitCode !== 0 ||
        /not logged in|not authenticated|please (log|sign) in|run .claude. to (log|sign) in|invalid api key|unauthori[sz]ed|\b401\b/i.test(text);
      if (!authFailed && r.report) {
        result = r;
        entry.command = exec;
        entry.note = "authenticated one-shot run completed";
      } else {
        log(`${t.id}: one-shot run did not complete cleanly (exit ${r.exitCode}); falling back to boot + SIGINT`);
        fs.renameSync(r.logPath, path.join(OUT, `${t.id}.exec-attempt.log`));
        entry.attempts[entry.attempts.length - 1].log = `${t.id}.exec-attempt.log`;
      }
    }
    if (!result) {
      const r = await runOnce({ id: t.id, command, boot, maxWait: boot + 15, deep, attempt: 1, title });
      entry.attempts.push({ command, exitCode: r.exitCode, durationMs: r.durationMs, ladder: r.ladder, log: path.basename(r.logPath) });
      result = r;
      entry.command = command;
      entry.note = exec ? "booted interactively, then SIGINT (one-shot run was not usable)" : `booted for ${boot}s, then SIGINT`;
    }

    entry.exitCode = result.exitCode;
    entry.durationMs = result.durationMs;
    entry.ladder = result.ladder;
    entry.json = result.report ? path.basename(result.jsonPath) : null;
    entry.png = fs.existsSync(result.pngPath) ? path.basename(result.pngPath) : null;
    entry.ok = Boolean(result.report && entry.png);
    if (result.report) {
      entry.grade = result.report.score.grade;
      entry.score = result.report.score.score;
      entry.layers = result.report.layers;
      entry.fileTracing = result.report.fileTracing;
      // narcx's own view wins: it saw which processes were actually hooked.
      if (result.report.fileTracing && !deep) entry.needsDeepTrace = result.report.fileTracing.coverage !== "full";
      entry.childExit = result.report.exitCode;
      entry.childSignal = result.report.signal;
      // Capture a runtime version string from the tool's own output if it printed one.
      const m = /\bv?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)\b/.exec(stripAnsi(result.output).split("\n").find((l) => /version|v\d+\.\d+\.\d+/i.test(l)) || "");
      if (m && version === "unknown") entry.version = m[1];
    }
    log(`${t.id}: done — grade ${entry.grade ?? "n/a"} (${entry.ok ? "json+png ok" : "MISSING OUTPUT"}) in ${(result.durationMs / 1000).toFixed(1)}s${result.ladder.length ? " · " + result.ladder.join(" → ") : ""}`);
    if (!entry.ok && prevEntry?.ok && result.restored) {
      log(`${t.id}: run produced no report — keeping the previous ${prevEntry.mode} report`);
      manifest.targets[t.id] = { ...prevEntry, lastFailedAttempt: { mode: entry.mode, exitCode: entry.exitCode, durationMs: entry.durationMs, ladder: entry.ladder, at: new Date().toISOString() } };
    } else {
      manifest.targets[t.id] = entry;
    }
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  }
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  log(`manifest written to ${path.relative(ROOT, manifestPath)}`);
}

function stripAnsi(s) {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\u001b\[[0-9;?]*[A-Za-z]/g, "");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
