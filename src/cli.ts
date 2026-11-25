import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import pc from "picocolors";
import pkg from "../package.json";
import { Collector } from "./core/collector.js";
import { userOtlpHostsFromEnv } from "./core/classify.js";
import { ProcessAttributor, type ProcRecord } from "./process-attribution.js";
import type { HelloRecord } from "./layers/ipc.js";
import type { AuditReport, FileTracing } from "./core/types.js";
import { SensitiveMatcher, ownNamespaces } from "./core/watchlist.js";
import { setupDemo, type DemoEnv } from "./demo.js";
import { startFsUsage, sudoCached, sudoValidate, type FsUsageHandle } from "./layers/fsusage.js";
import { startIpc } from "./layers/ipc.js";
import { startLsofPoller, type LsofHandle } from "./layers/lsof.js";
import { PidTree, type ProcInfo } from "./layers/pidtree.js";
import { proxyEnv, startProxy } from "./layers/proxy.js";
import { attachStrace, straceAvailable, straceWrap } from "./layers/strace.js";
import { writeCardPng } from "./ui/card.js";
import { attachLiveFeed } from "./ui/live.js";
import { renderScorecard } from "./ui/scorecard.js";
import { shellJoin } from "./ui/format.js";

const VERSION: string = (pkg as { version: string }).version;
const DIST_DIR = path.dirname(fileURLToPath(import.meta.url));

interface Options {
  card: string | null;
  json: string | null;
  deep: boolean;
  demo: boolean;
  render: string | null;
  regrade: string | null;
  title: string | null;
  footer: string | null;
  quiet: boolean;
  verbose: boolean;
  includeChildren: boolean;
  lsof: boolean;
  interval: number;
  command: string[];
}

const HELP = `
${pc.bold("narc")} ${pc.dim("v" + VERSION)} — catch any CLI, AI harness or MCP server phoning home or reading your dotfiles.

${pc.bold("USAGE")}
  narc [options] -- <command> [args...]
  narc --demo [--card ./report.png]
  ${pc.dim("(npm package: narcx — run without installing via")} npx narcx -- <command>${pc.dim(")")}

${pc.bold("OPTIONS")}
  --card [path]     Save a 1200x675 Privacy Scorecard PNG (editorial audit sheet) (default ./narc-report.png)
  --json [path]     Export the raw audit log as JSON (default ./narc-report.json)
  --deep            Kernel-level tracing: fs_usage on macOS (asks for sudo), strace -f on Linux
  --demo            Run the built-in mock "shady-ai-tool" to see every layer fire
  --render <json>   Re-render the scorecard (terminal + --card PNG) from a saved --json report
  --regrade <json>  Rebuild a saved report's summaries and grade from its events under the current rules (writes it back)
  --title <text>    Display name for the scorecard, e.g. "Claude Code 2.1.323" (default: command basename)
  --footer <text>   Left footer line on the card, e.g. "T3CODE_TELEMETRY_ENABLED=false · no TLS interception"
  -v, --verbose     Also show LLM API traffic, dotfile reads and repeat requests live
  -q, --quiet       No live alerts, only the exit scorecard
  --include-children  Grade external CLIs the tool spawns (claude, codex, git, …) as if the tool did it
  --no-lsof         Disable the lsof socket poller
  --interval <ms>   lsof poll interval (default 150)
  -h, --help        Show this help
  -V, --version     Print version

${pc.bold("LAYERS")} ${pc.dim("(all work without sudo)")}
  1. HTTP/HTTPS CONNECT proxy on 127.0.0.1, injected via HTTP(S)_PROXY / ALL_PROXY — logs host, method, path, bytes. TLS is never broken.
  2. NODE_OPTIONS preload hook — patches fs.*, http(s).request and fetch inside Node children for exact URLs and file paths.
  3. lsof -i poller on the child's process tree — catches Go/Rust/Python binaries that ignore proxy env vars.

${pc.bold("GRADING")}
  100 points, then: −25 per telemetry host, −30 per sensitive file read outside the tool's own namespace, −10 per unknown host.
  A+ 100 · A 90+ · B 80+ · C 65+ · D 50+ · F below 50

${pc.bold("EXAMPLES")}
  narc -- npx some-ai-cli --help
  narc --card --json -- claude -p "hello"
  narc --deep -- ./my-go-binary serve
`;

function parseArgs(argv: string[]): Options {
  const o: Options = {
    card: null,
    json: null,
    deep: false,
    demo: false,
    render: null,
    regrade: null,
    title: null,
    footer: null,
    quiet: false,
    verbose: false,
    includeChildren: false,
    lsof: true,
    interval: 150,
    command: [],
  };
  let i = 0;
  const optionalPath = (def: string): string => {
    const next = argv[i + 1];
    if (next !== undefined && next !== "--" && !next.startsWith("-")) {
      i++;
      return next;
    }
    return def;
  };
  for (; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") {
      o.command = argv.slice(i + 1);
      break;
    }
    if (a === "--card") o.card = optionalPath("./narc-report.png");
    else if (a.startsWith("--card=")) o.card = a.slice(7);
    else if (a === "--json") o.json = optionalPath("./narc-report.json");
    else if (a.startsWith("--json=")) o.json = a.slice(7);
    else if (a === "--deep") o.deep = true;
    else if (a === "--demo") o.demo = true;
    else if (a === "--render") o.render = argv[++i] ?? fail("--render needs a path to a narc JSON report");
    else if (a.startsWith("--render=")) o.render = a.slice(9);
    else if (a === "--regrade") o.regrade = argv[++i] ?? fail("--regrade needs a path to a narc JSON report");
    else if (a.startsWith("--regrade=")) o.regrade = a.slice(10);
    else if (a === "--title") o.title = argv[++i] ?? fail("--title needs a value");
    else if (a.startsWith("--title=")) o.title = a.slice(8);
    else if (a === "--footer") o.footer = argv[++i] ?? fail("--footer needs a value");
    else if (a.startsWith("--footer=")) o.footer = a.slice(9);
    else if (a === "-q" || a === "--quiet") o.quiet = true;
    else if (a === "-v" || a === "--verbose") o.verbose = true;
    else if (a === "--no-lsof") o.lsof = false;
    else if (a === "--include-children") o.includeChildren = true;
    else if (a === "--interval") o.interval = Math.max(50, Number(argv[++i]) || 150);
    else if (a.startsWith("--interval=")) o.interval = Math.max(50, Number(a.slice(11)) || 150);
    else if (a === "-h" || a === "--help") {
      process.stdout.write(HELP + "\n");
      process.exit(0);
    } else if (a === "-V" || a === "--version") {
      process.stdout.write(VERSION + "\n");
      process.exit(0);
    } else if (a.startsWith("-")) {
      fail(`unknown option ${a}`);
    } else {
      // Lenient: first bare token starts the command.
      o.command = argv.slice(i);
      break;
    }
  }
  return o;
}

function fail(msg: string, code = 2): never {
  process.stderr.write(`${pc.red(pc.bold("narc:"))} ${msg}\n`);
  process.exit(code);
}

const log = (s: string) => process.stderr.write(`${pc.dim("[narc]")} ${s}\n`);

/** When run via `sudo narc …`, resolve who to drop privileges to. */
function sudoDrop(): { uid: number; gid: number; home: string; user: string } | null {
  if (typeof process.getuid !== "function" || process.getuid() !== 0) return null;
  const user = process.env.SUDO_USER;
  if (!user || user === "root") return null;
  try {
    const uid = Number(execFileSync("id", ["-u", user], { encoding: "utf8" }).trim());
    const gid = Number(execFileSync("id", ["-g", user], { encoding: "utf8" }).trim());
    let home = "";
    if (process.platform === "darwin") {
      const out = execFileSync("dscl", [".", "-read", `/Users/${user}`, "NFSHomeDirectory"], { encoding: "utf8" });
      home = out.replace("NFSHomeDirectory:", "").trim();
    } else {
      const out = execFileSync("getent", ["passwd", user], { encoding: "utf8" });
      home = out.split(":")[5] ?? "";
    }
    if (!home) home = path.join(process.platform === "darwin" ? "/Users" : "/home", user);
    return { uid, gid, home, user };
  } catch {
    return null;
  }
}

function loadReport(file: string, opts: Options): { src: string; report: AuditReport } {
  const src = path.resolve(file);
  let report: AuditReport;
  try {
    report = JSON.parse(fs.readFileSync(src, "utf8")) as AuditReport;
  } catch (e) {
    fail(`cannot read report ${src}: ${(e as Error).message}`);
  }
  if (!report.score || !Array.isArray(report.hosts)) fail(`${src} is not a narc JSON report`);
  // Backfill fields older reports may lack.
  report.title = opts.title ?? report.title ?? path.basename(report.command[0] ?? "narc");
  if (opts.footer) report.footer = opts.footer;
  report.suppressedHosts ??= [];
  report.probedFiles ??= [];
  report.leftoverProcesses ??= [];
  report.fileTracing ??= {
    mode: report.layers.fs_usage || report.layers.strace ? "deep" : report.layers.preload ? "hook" : "none",
    coverage: report.layers.fs_usage || report.layers.strace ? "full" : report.layers.preload ? "partial" : "none",
    untraced: [],
  };
  report.childActivity ??= {};
  report.userOtlpHosts ??= [];
  report.includeChildren ??= false;
  report.installRoot ??= null;
  for (const f of [...report.sensitiveFiles, ...report.otherDotfiles, ...report.probedFiles]) {
    f.procs ??= [];
    f.graded ??= true;
    f.attribution ??= "target";
    f.via ??= "";
    f.processName ??= f.procs[0] ?? "";
  }
  for (const h of [...report.hosts, ...report.suppressedHosts]) {
    h.attribution ??= "target";
    h.via ??= "";
    h.processNames ??= [];
    h.pids ??= [];
  }
  return { src, report };
}

function explicitAttribution(e: { processName?: string; attribution?: "target" | "child"; via?: string }) {
  return e.attribution ? { processName: e.processName ?? "", attribution: e.attribution, via: e.via ?? "" } : undefined;
}

/**
 * Re-derive every summary and the grade from the events a report recorded,
 * under the classifier, watchlist and ownership rules of this narc version.
 * Lets old reports be re-scored after a rules change without re-running the tool.
 */
async function regradeFromJson(opts: Options): Promise<void> {
  const { src, report } = loadReport(opts.regrade!, opts);
  const matcher = new SensitiveMatcher(process.env.NARC_HOME || os.homedir());
  const includeChildren = opts.includeChildren || report.includeChildren;
  const userOtlp = new Set([...report.userOtlpHosts, ...userOtlpHostsFromEnv(process.env)]);
  const collector = new Collector({ matcher, ownNamespaces: ownNamespaces(report.command), userOtlpHosts: userOtlp, includeChildren });
  if (report.launcher) collector.setLauncher(report.launcher.pid, report.launcher.name);
  // Process attribution for hook events lives in the old summaries (the pid tree is gone).
  const procsByPath = new Map<string, string[]>();
  for (const f of [...report.sensitiveFiles, ...report.otherDotfiles, ...report.probedFiles]) {
    if (f.procs?.length) procsByPath.set(matcher.normalize(f.path), f.procs);
  }
  const before = report.score;
  for (const e of report.events) {
    if (e.kind === "file") {
      const procs = e.proc ? [e.proc] : procsByPath.get(matcher.normalize(e.path)) ?? [];
      collector.addFile({ source: e.source, pid: e.pid, path: e.path, op: e.op, exists: e.exists, proc: procs, id: e.id, ts: e.ts, attribution: explicitAttribution(e) });
    } else if (e.kind === "net") {
      collector.addNet({
        source: e.source,
        pid: e.pid,
        host: e.host,
        port: e.port,
        protocol: e.protocol,
        method: e.method,
        path: e.path,
        url: e.url,
        bytesOut: e.bytesOut,
        bytesIn: e.bytesIn,
        id: e.id,
        ts: e.ts,
        attribution: explicitAttribution(e),
      });
    } else if (e.kind === "dns") {
      collector.addDns({ source: e.source, pid: e.pid, host: e.host, addresses: e.addresses, id: e.id });
    }
  }
  report.sensitiveFiles = collector.sensitiveFiles();
  report.otherDotfiles = collector.otherDotfiles();
  report.probedFiles = collector.probedFiles();
  report.hosts = collector.hostSummaries();
  report.suppressedHosts = collector.suppressedHosts();
  report.childActivity = collector.childActivity();
  report.includeChildren = includeChildren;
  report.userOtlpHosts = [...userOtlp];
  report.score = collector.score();
  (report as AuditReport & { regradedAt?: string; regradedWith?: string }).regradedAt = new Date().toISOString();
  (report as AuditReport & { regradedWith?: string }).regradedWith = VERSION;
  fs.writeFileSync(src, JSON.stringify(report, null, 2));
  log(`regraded ${relative(src)}: ${before.grade} (${before.score}) → ${report.score.grade} (${report.score.score})`);
  let cardPath: string | null = null;
  if (opts.card) cardPath = await writeCardPng(report, matcher, opts.card);
  if (!opts.quiet) {
    process.stderr.write("\n" + renderScorecard(report, { matcher, cardPath: cardPath && relative(cardPath), jsonPath: relative(src) }) + "\n");
  }
  process.exit(0);
}

/** Re-render a saved report without running anything. */
async function renderFromJson(opts: Options): Promise<void> {
  const { src, report } = loadReport(opts.render!, opts);
  const matcher = new SensitiveMatcher(process.env.NARC_HOME || os.homedir());
  let cardPath: string | null = null;
  if (opts.card) cardPath = await writeCardPng(report, matcher, opts.card);
  if (!opts.quiet) {
    process.stderr.write("\n" + renderScorecard(report, { matcher, cardPath: cardPath && relative(cardPath), jsonPath: relative(src) }) + "\n");
  }
  process.exit(0);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.render) return renderFromJson(opts);
  if (opts.regrade) return regradeFromJson(opts);
  if (!opts.demo && !opts.command.length) {
    process.stdout.write(HELP + "\n");
    process.exit(2);
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "narc-"));
  const cleanups: Array<() => void | Promise<void>> = [];
  const cleanupSync = () => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  };
  process.on("exit", cleanupSync);

  const drop = sudoDrop();
  let demo: DemoEnv | null = null;
  let home = drop?.home ?? os.homedir();
  let command = opts.command;
  let cwd = process.cwd();
  const childEnv: NodeJS.ProcessEnv = { ...process.env };

  if (opts.demo) {
    demo = await setupDemo(tmpDir, DIST_DIR);
    cleanups.push(() => demo!.close());
    home = demo.home;
    command = demo.command;
    cwd = demo.cwd;
    Object.assign(childEnv, demo.env);
    log(`${pc.bold("demo mode")} — decoy HOME at ${pc.cyan(home)}, every "vendor" is a loopback sink. Nothing leaves this machine.`);
  }

  const matcher = new SensitiveMatcher(home);
  const userOtlp = userOtlpHostsFromEnv(process.env);
  const collector = new Collector({ matcher, ownNamespaces: ownNamespaces(command), userOtlpHosts: userOtlp, includeChildren: opts.includeChildren });
  attachLiveFeed(collector, { quiet: opts.quiet, verbose: opts.verbose });
  if (userOtlp.length && !opts.quiet) log(`OTEL_EXPORTER_OTLP_* in your environment: ${userOtlp.join(", ")} will be reported as USER OTLP, not penalised`);

  // Process tree + attribution (target vs spawned external CLI). The attributor
  // needs the child's pid, so hello records arriving before spawn are parked.
  const tree = new PidTree(0, opts.interval);
  let attributor: ProcessAttributor | null = null;
  const helloRecords = new Map<number, HelloRecord>();
  const onHello = (rec: HelloRecord) => {
    helloRecords.set(rec.pid, rec);
    attributor?.register(rec);
  };

  // ---- Layer 1 + 2 plumbing -------------------------------------------------
  const [ipc, proxy] = await Promise.all([
    startIpc(collector, tmpDir, onHello),
    startProxy({ collector, resolveUpstream: demo?.resolveUpstream, pids: () => tree.pids() }),
  ]);
  cleanups.push(() => ipc.close(), () => proxy.close());

  const preloadSrc = path.join(DIST_DIR, "preload.cjs");
  const preloadPath = path.join(tmpDir, "narc-preload.cjs");
  fs.copyFileSync(preloadSrc, preloadPath);
  if (drop) fs.chmodSync(preloadPath, 0o644);

  Object.assign(childEnv, proxyEnv(proxy.port));
  const existingNodeOpts = process.env.NODE_OPTIONS ? process.env.NODE_OPTIONS + " " : "";
  childEnv.NODE_OPTIONS = `${existingNodeOpts}--require "${preloadPath}"`;
  childEnv.NARC_SOCK = ipc.address;
  childEnv.NARC_PROXY_PORT = String(proxy.port);
  if (!childEnv.NARC_HOME) childEnv.NARC_HOME = home;
  if (drop) {
    childEnv.HOME = drop.home;
    childEnv.USER = drop.user;
    childEnv.LOGNAME = drop.user;
    delete childEnv.SUDO_USER;
    delete childEnv.SUDO_UID;
    delete childEnv.SUDO_GID;
    delete childEnv.SUDO_COMMAND;
  }

  // ---- Layer 3: OS-level ---------------------------------------------------
  let spawnCommand = command;
  let useStrace = false;
  let fsUsage: FsUsageHandle | null = null;
  const layers: Record<string, boolean> = { proxy: true, preload: false, lsof: false };

  if (opts.deep) {
    if (process.platform === "linux") {
      if (straceAvailable()) {
        useStrace = true;
        spawnCommand = straceWrap(command);
        log(`deep mode: tracing openat/connect with ${pc.bold("strace -f")}`);
      } else {
        log(pc.yellow("deep mode requested but strace is unavailable (not installed or ptrace blocked); continuing without it"));
      }
    } else if (process.platform === "darwin") {
      const asRoot = typeof process.getuid === "function" && process.getuid() === 0;
      let ok = asRoot || sudoCached();
      if (!ok && process.stdin.isTTY) {
        log(`deep mode: ${pc.bold("fs_usage")} needs root for kernel tracing. Asking sudo once; the traced command itself runs as you.`);
        ok = sudoValidate("[narc] sudo password for fs_usage: ");
      } else if (!ok) {
        log(pc.yellow("deep mode: sudo needs a password but there is no terminal to ask on (sudo tickets are per-tty); continuing without fs_usage"));
      }
      if (ok) {
        fsUsage = startFsUsage({ collector, tree, home, asRoot });
        cleanups.unshift(() => fsUsage?.stop());
        await new Promise((r) => setTimeout(r, 400)); // let ktrace spin up
        layers.fs_usage = true;
      } else {
        log(pc.yellow("sudo not granted; continuing without fs_usage"));
      }
    } else {
      log(pc.yellow(`deep mode is not available on ${process.platform}`));
    }
  }

  // ---- spawn ---------------------------------------------------------------
  const startedAt = Date.now();
  let child: ChildProcess;
  try {
    child = spawn(spawnCommand[0]!, spawnCommand.slice(1), {
      stdio: useStrace ? ["inherit", "inherit", "inherit", "pipe"] : "inherit",
      env: childEnv,
      cwd,
      uid: drop?.uid,
      gid: drop?.gid,
    });
  } catch (e) {
    fail(`failed to start ${command[0]}: ${(e as Error).message}`, 127);
  }
  if (useStrace && child.stdio[3]) attachStrace(child.stdio[3] as NodeJS.ReadableStream, collector);

  const spawnError = new Promise<Error | null>((resolve) => {
    child.once("error", (e) => resolve(e));
    child.once("spawn", () => resolve(null));
  });
  const err = await spawnError;
  if (err) {
    const code = (err as NodeJS.ErrnoException).code;
    await runCleanups(cleanups);
    fail(code === "ENOENT" ? `command not found: ${command[0]}` : `failed to start ${command[0]}: ${err.message}`, 127);
  }

  const launcherName = launcherOf(command);
  if (launcherName) collector.setLauncher(child.pid!, launcherName);
  const rootName = path.basename(command[0] ?? "");
  collector.setProcessResolver((pid) => (pid === child.pid ? rootName : tree.nameOf(pid)));
  const toRec = (pid: number): ProcRecord | undefined => {
    const p = tree.info(pid);
    return p ? { pid, ppid: p.ppid, exe: p.comm, args: p.args } : undefined;
  };
  attributor = new ProcessAttributor(child.pid!, command, toRec);
  for (const r of helloRecords.values()) attributor.register(r);
  const att = attributor;
  collector.setAttributor((pid) => att.classify(pid));
  collector.setNameAttributor((name) =>
    att.classifyName(
      name,
      tree.seenProcesses().map((p) => ({ pid: p.pid, ppid: p.ppid, exe: p.comm, args: p.args })),
    ),
  );
  if (opts.verbose) log(`target: ${att.target.identity} · install root: ${att.target.root ?? "(none)"}`);

  tree.setRoot(child.pid!);
  tree.start();
  cleanups.unshift(() => tree.stop());
  let lsof: LsofHandle | null = null;
  if (opts.lsof && (process.platform === "darwin" || process.platform === "linux")) {
    lsof = startLsofPoller({ collector, tree, intervalMs: opts.interval });
    cleanups.unshift(() => lsof?.stop());
  }

  // ---- signals -------------------------------------------------------------
  let interrupts = 0;
  const forward = (sig: NodeJS.Signals) => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    interrupts++;
    try {
      child.kill(interrupts >= 2 ? "SIGKILL" : sig);
    } catch {
      /* ignore */
    }
  };
  process.on("SIGINT", () => forward("SIGINT"));
  process.on("SIGTERM", () => forward("SIGTERM"));
  process.on("SIGHUP", () => forward("SIGHUP"));

  const { code, signal } = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    child.once("close", (c, s) => resolve({ code: c, signal: s }));
  });
  const endedAt = Date.now();

  // Give in-flight IPC messages and one last lsof tick a moment to land.
  await new Promise((r) => setTimeout(r, Math.min(300, opts.interval + 100)));

  // Anything the tool left running (daemonised servers, detached helpers) is ours to stop.
  await tree.refresh();
  const leftovers = tree.leftovers();
  const leftoverProcesses = leftovers.map((p) => PidTree.displayName(p));
  if (leftovers.length) {
    for (const p of leftovers) {
      try {
        process.kill(p.pid, "SIGTERM");
      } catch {
        /* already gone */
      }
    }
    await new Promise((r) => setTimeout(r, 600));
    await tree.refresh();
    for (const p of tree.leftovers()) {
      try {
        process.kill(p.pid, "SIGKILL");
      } catch {
        /* already gone */
      }
    }
    log(pc.yellow(`stopped ${leftovers.length} process${leftovers.length === 1 ? "" : "es"} the tool left running: ${[...new Set(leftoverProcesses)].join(", ")}`));
  }
  await runCleanups(cleanups);

  layers.preload = ipc.hookedPids.size > 0;
  layers.lsof = Boolean(lsof && lsof.polls > 0);
  if (useStrace) layers.strace = true;
  const fileTracing = computeFileTracing({
    deep: Boolean(layers.fs_usage || layers.strace),
    hooked: ipc.hookedPids,
    seen: tree.seenProcesses(),
    childPid: child.pid!,
    command,
  });

  att.clearCache(); // final verdicts come from the complete process tree, not early ps fallbacks
  for (const e of collector.events) {
    if (e.kind === "file" && !e.proc && e.pid !== undefined) e.proc = e.pid === child.pid ? rootName : tree.nameOf(e.pid);
    if (e.kind === "file" || e.kind === "net") {
      const a = e.pid !== undefined ? att.classify(e.pid) : e.kind === "file" && e.proc ? collector.attributionOfName(e.proc) : null;
      if (a) {
        e.processName = a.processName;
        e.attribution = a.attribution;
        e.via = a.via;
      }
    }
  }

  const report: AuditReport = {
    narcVersion: VERSION,
    title: opts.title ?? (demo ? "shady-ai-tool" : path.basename(command[0] ?? "narc")),
    footer: opts.footer ?? undefined,
    platform: `${process.platform}-${process.arch}`,
    command,
    commandLabel: demo ? "shady-ai-tool  (narc --demo fixture)" : shellJoin(displayCommand(command, matcher.homes)),
    startedAt: new Date(startedAt).toISOString(),
    endedAt: new Date(endedAt).toISOString(),
    durationMs: endedAt - startedAt,
    exitCode: code,
    signal,
    layers,
    launcher: launcherName ? { pid: child.pid!, name: launcherName } : null,
    fileTracing,
    score: collector.score(),
    sensitiveFiles: collector.sensitiveFiles(),
    otherDotfiles: collector.otherDotfiles(),
    probedFiles: collector.probedFiles(),
    hosts: collector.hostSummaries(),
    suppressedHosts: collector.suppressedHosts(),
    leftoverProcesses: [...new Set(leftoverProcesses)],
    installRoot: att.target.root,
    includeChildren: opts.includeChildren,
    userOtlpHosts: userOtlp,
    childActivity: collector.childActivity(),
    events: collector.events,
  };

  let cardPath: string | null = null;
  let jsonPath: string | null = null;
  if (opts.json) {
    jsonPath = path.resolve(opts.json);
    fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
    fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  }
  if (opts.card) {
    try {
      cardPath = await writeCardPng(report, matcher, opts.card);
    } catch (e) {
      log(pc.yellow(`could not render PNG scorecard: ${(e as Error).message}`));
    }
  }

  process.stderr.write("\n" + renderScorecard(report, { matcher, cardPath: cardPath && relative(cardPath), jsonPath: jsonPath && relative(jsonPath) }) + "\n");

  if (signal) {
    const n = os.constants.signals[signal] ?? 1;
    process.exit(128 + n);
  }
  process.exit(code ?? 1);
}

/** Shell builtins and utilities a tool may spawn; untraced but irrelevant to file-read coverage. */
const UTILITIES = new Set([
  "sh", "bash", "zsh", "fish", "dash", "env", "git", "ps", "lsof", "uname", "sw_vers", "which", "whoami", "id",
  "cat", "ls", "sed", "awk", "grep", "tr", "head", "tail", "mkdir", "rm", "cp", "mv", "ln", "chmod", "touch", "sleep",
  "tee", "cut", "sort", "uniq", "wc", "date", "hostname", "xcrun", "xcode-select", "security", "osascript", "defaults",
  "launchctl", "sysctl", "ioreg", "system_profiler", "pbcopy", "pbpaste", "script", "stty", "tput", "open", "xdg-open",
  "python3", "python", "perl", "ruby", "curl", "wget",
]);

const MAGIC = new Set([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0x7f454c46]);

/** True if the executable at `exe` is a Mach-O or ELF binary (as opposed to a script). */
function isNativeExecutable(exe: string): boolean {
  if (!path.isAbsolute(exe)) return false;
  try {
    const fd = fs.openSync(exe, "r");
    const b = Buffer.alloc(4);
    const n = fs.readSync(fd, b, 0, 4, 0);
    fs.closeSync(fd);
    return n === 4 && MAGIC.has(b.readUInt32BE(0));
  } catch {
    return false;
  }
}

/**
 * Work out how much file activity narc could see. Any native executable in
 * the process tree that never loaded the preload hook (Bun/Rust binaries,
 * node started with a scrubbed env) is a blind spot unless --deep was on.
 */
function computeFileTracing(input: {
  deep: boolean;
  hooked: Set<number>;
  seen: ProcInfo[];
  childPid: number;
  command: readonly string[];
}): FileTracing {
  if (input.deep) return { mode: "deep", coverage: "full", untraced: [] };
  const untraced = new Set<string>();
  for (const p of input.seen) {
    if (input.hooked.has(p.pid)) continue;
    const exe = p.comm.split(" ")[0] ?? "";
    const base = PidTree.displayName(p);
    if (UTILITIES.has(base) || UTILITIES.has(path.basename(exe))) continue;
    if (!isNativeExecutable(exe)) continue;
    untraced.add(p.pid === input.childPid ? path.basename(input.command[0] ?? base) : base);
  }
  const mode = input.hooked.size > 0 ? "hook" : "none";
  const coverage = mode === "none" ? "none" : untraced.size ? "partial" : "full";
  return { mode, coverage, untraced: [...untraced] };
}

const RUNNERS = new Set(["npx", "pnpx", "bunx", "uvx", "pipx"]);

/** Package runners whose own activity (registry lookups, ~/.npmrc, ~/.gitconfig) is not the tool's. */
export function launcherOf(cmd: readonly string[]): string | null {
  const base = path.basename(cmd[0] ?? "").toLowerCase();
  const sub = (cmd[1] ?? "").toLowerCase();
  if (RUNNERS.has(base)) return base;
  if (base === "npm" && (sub === "exec" || sub === "x")) return `npm ${sub}`;
  if (base === "pnpm" && sub === "dlx") return "pnpm dlx";
  if (base === "yarn" && sub === "dlx") return "yarn dlx";
  if (base === "bun" && sub === "x") return "bun x";
  return null;
}

const INTERPRETERS = new Set(["node", "nodejs", "python", "python3", "ruby", "deno", "bun", "perl", "php", "sh", "bash", "zsh"]);

/**
 * Display-only rendering of the command: interpreter paths become their
 * basename and anything under the home directory becomes `~/...` so a
 * username never ends up in a shared scorecard.
 */
function displayCommand(cmd: readonly string[], homes: readonly string[]): string[] {
  const out = cmd.map((tok) => {
    for (const h of homes) {
      if (tok === h) return "~";
      if (tok.startsWith(h + path.sep)) return "~" + tok.slice(h.length);
    }
    return tok;
  });
  const first = cmd[0];
  if (first && path.isAbsolute(first) && INTERPRETERS.has(path.basename(first))) out[0] = path.basename(first);
  return out;
}

function relative(p: string): string {
  const r = path.relative(process.cwd(), p);
  return r.startsWith("..") ? p : "./" + r;
}

async function runCleanups(cleanups: Array<() => void | Promise<void>>): Promise<void> {
  const list = cleanups.splice(0, cleanups.length);
  for (const fn of list) {
    try {
      await fn();
    } catch {
      /* ignore */
    }
  }
}

main().catch((e) => {
  fail((e as Error).stack ?? String(e), 1);
});
