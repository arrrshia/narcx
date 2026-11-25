#!/usr/bin/env node
/**
 * Builds launch assets from audit-results/*.json + manifest.json:
 *   - audit-results/RESULTS.md      strict table, sourced only from the narcx JSON reports
 *   - audit-results/twitter-grid.png 1600x900 2x2 collage of the top four scorecards
 *   - audit-results/run-deep.sh     one-command upgrade for native-binary targets (needs sudo)
 *
 *   node scripts/report.mjs [--out ./audit-results] [--top id1,id2,id3,id4]
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { Resvg } = require("@resvg/resvg-js");

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const flag = (name, def) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
};
const OUT = path.resolve(flag("--out", path.join(ROOT, "audit-results")));
const HOME = os.homedir();
const REAL_HOME = (() => {
  try {
    return fs.realpathSync(HOME);
  } catch {
    return HOME;
  }
})();

const manifest = JSON.parse(fs.readFileSync(path.join(OUT, "manifest.json"), "utf8"));
const FONT_DIR = path.join(ROOT, "assets", "fonts");
const FONT_FILES = fs.existsSync(FONT_DIR) ? fs.readdirSync(FONT_DIR).filter((f) => /\.(ttf|otf)$/i.test(f)).map((f) => path.join(FONT_DIR, f)) : [];
const CAT = { TELEMETRY: "telemetry", UNKNOWN: "other", LLM_API: "LLM", AUTH: "auth" };
const ORDER = ["claude-code", "codex-cli", "t3code", "gemini-cli", "opencode", "context7-mcp"];

const tilde = (p) => {
  if (typeof p !== "string") return p;
  for (const h of [HOME, REAL_HOME]) if (p === h || p.startsWith(h + "/")) return "~" + p.slice(h.length);
  return p;
};
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const md = (s) => String(s).replace(/\|/g, "\\|");

// ---------------------------------------------------------------------------
// gather
// ---------------------------------------------------------------------------
const rows = [];
for (const id of ORDER) {
  const t = manifest.targets[id];
  if (!t) continue;
  if (!t.json) {
    rows.push({ id, t, report: null });
    continue;
  }
  const jsonPath = path.join(OUT, `${id}.json`);
  const report = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
  rows.push({ id, t, report });
}

function hostLabel(h) {
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-f:]+:[0-9a-f:]*$/i.test(h.host);
  const via = h.sources.map((s) => (s === "preload" ? "hook" : s)).join("+");
  const detail = [];
  if (h.paths && h.paths.length) detail.push(`${h.methods[0] ?? ""} ${h.paths[0]}`.trim() + (h.paths.length > 1 ? ` +${h.paths.length - 1}` : ""));
  detail.push(`${h.requests} req`);
  if (h.bytesOut) detail.push(`${h.bytesOut} B↑`);
  detail.push(`via ${via}`);
  const launcher = h.launcher ? " — npx itself, not graded" : "";
  return `\`${h.host}\`${isIp ? " (ip)" : ""} (${detail.join(", ")})${launcher}`;
}

function filesCell(report) {
  if (report.fileTracing && report.fileTracing.coverage === "none") return "_not traced (native binary; run `--deep`)_";
  const graded = (f) => f.graded !== false;
  const list = (arr, max = 8) => arr.slice(0, max).map((f) => `\`${tilde(f.path)}\``).join(", ") + (arr.length > max ? ` _+${arr.length - max} more_` : "");
  const viaLauncher = report.sensitiveFiles.filter((f) => f.launcher && graded(f));
  const own = report.sensitiveFiles.filter((f) => !f.launcher && f.ownNamespace && graded(f));
  const third = report.sensitiveFiles.filter((f) => !f.launcher && !f.ownNamespace && graded(f));
  const ungraded = report.sensitiveFiles.filter((f) => !graded(f));
  const parts = [];
  if (third.length) parts.push(`**third-party (${third.length}):** ` + third.map((f) => `\`${tilde(f.path)}\`${f.procs?.length ? ` (${f.procs.slice(0, 2).join(", ")})` : ""}`).join(", "));
  if (own.length) {
    const byProc = new Map();
    for (const f of own) {
      const k = f.procs?.length ? f.procs.slice(0, 2).join("+") : "tool";
      byProc.set(k, (byProc.get(k) ?? 0) + 1);
    }
    parts.push(`own config (${own.length}, not penalised; by ${[...byProc].map(([k, v]) => `${k}: ${v}`).join(", ")}): ` + list(own, 6));
  }
  if (ungraded.length) parts.push(`system trust store, opened during TLS, not graded (${ungraded.length}): ` + list(ungraded, 4));
  if (viaLauncher.length) parts.push(`npx itself, not graded (${viaLauncher.length}): ` + list(viaLauncher));
  if (!parts.length) parts.push("none");
  const other = report.otherDotfiles?.length ?? 0;
  if (other) parts.push(`_+${other} other dotfile${other === 1 ? "" : "s"} under ~ (not on the watchlist)_`);
  const probed = report.probedFiles ?? [];
  if (probed.length) parts.push(`_probed but absent, not graded: ${list(probed, 6)}_`);
  if (report.leftoverProcesses?.length) parts.push(`_left running after exit, stopped by narcx: ${report.leftoverProcesses.join(", ")}_`);
  return parts.join("<br>");
}

// ---------------------------------------------------------------------------
// RESULTS.md
// ---------------------------------------------------------------------------
const lines = [];
lines.push(`# AI coding CLI privacy audit — narcx v${manifest.narcVersion}`);
lines.push("");
lines.push(`Generated ${manifest.generatedAt} on ${manifest.platform}, Node ${manifest.node}. Every value below is read from the \`<tool>.json\` narcx reports in this folder; nothing is inferred.`);
lines.push("");
lines.push("| Tool & exact version | Runtime | Audit mode | Telemetry domains hit | Other outbound domains hit | Sensitive files touched (own vs third-party) | Grade |");
lines.push("| --- | --- | --- | --- | --- | --- | --- |");
for (const { id, t, report } of rows) {
  const name = `**${t.name}** ${t.version ?? ""}`.trim();
  if (!report) {
    lines.push(`| ${md(name)} | ${md(t.runtime ?? "")} | — | — | — | — | ${t.skipped ? `_skipped: ${md(t.skipped)}_` : "_no report_"} |`);
    continue;
  }
  const tel = report.hosts.filter((h) => h.category === "TELEMETRY");
  const other = [...report.hosts.filter((h) => h.category !== "TELEMETRY" && !h.launcher), ...report.hosts.filter((h) => h.category !== "TELEMETRY" && h.launcher)];
  const suppressed = report.suppressedHosts ?? [];
  const tracing = report.fileTracing ?? { coverage: t.needsDeepTrace ? "none" : "full", untraced: [] };
  const untraced = (list) => (list.length <= 1 ? list[0] ?? "" : `${list[0]} +${list.length - 1} more`);
  const mode =
    t.mode +
    (tracing.coverage === "none"
      ? `<br>\`NEEDS_DEEP_TRACE\` — file reads not traced (native binary${tracing.untraced.length ? ": " + untraced(tracing.untraced) : ""})`
      : tracing.coverage === "partial"
        ? `<br>\`NEEDS_DEEP_TRACE\` — partial: ${untraced(tracing.untraced)} not hooked`
        : "");
  const otherCell = other.length ? other.map((h) => hostLabel(h) + (h.category === "UNKNOWN" ? "" : ` — ${CAT[h.category]}`)).join("<br>") : "none";
  const suppCell = suppressed.length ? `<br>_raw IPs seen only by lsof, not graded (dedup): ${suppressed.map((h) => `\`${h.host}\``).join(", ")}_` : "";
  lines.push(
    `| ${md(name)} | ${md(t.runtime)} | ${mode} | ${tel.length ? tel.map(hostLabel).join("<br>") : "none"} | ${otherCell}${suppCell} | ${filesCell(report)} | **${report.score.grade}** (${report.score.score}/100) |`,
  );
}
lines.push("");
lines.push("## How this was run");
lines.push("");
lines.push(`- Command per target (see \`manifest.json\` for the exact argv, exit codes and the SIGINT ladder used): \`node dist/cli.js --card <tool>.png --json <tool>.json [--deep] -- <target>\`, run from \`${manifest.sandbox}\` by \`scripts/audit.mjs\`: inside a fresh pty for standard runs, on the terminal where sudo was granted for \`--deep\` runs (sudo tickets are per-tty).`);
if (manifest.extraEnv) lines.push(`- **Variant run:** the target was started with ${Object.entries(manifest.extraEnv).map(([k, v]) => `\`${k}=${v}\``).join(", ")} in its environment, on top of the defaults described below.`);
lines.push(`- Targets ran with their default environment. No telemetry opt-out flags were set. ${manifest.scrubbedEnv?.length ? `The harness removed ${manifest.scrubbedEnv.length} \`CLAUDE*\` variable${manifest.scrubbedEnv.length === 1 ? "" : "s"} that only exist${manifest.scrubbedEnv.length === 1 ? "s" : ""} because it was launched from inside Claude Code.` : ""} A no-op \`open\`/\`xdg-open\` shim was first on PATH so tools could not launch a browser.`);
lines.push("- Interactive tools were allowed to boot for ~10-12 s and then received Ctrl-C; one-shot runs (`claude -p`, `codex exec`) were allowed to finish on their own.");
lines.push("- npm-distributed targets (T3 Code, Gemini CLI) were installed once into `/tmp/narc-audit-tools` outside narcx, pinned to the version resolved at audit time, and their bin was executed directly. Nothing `npx` does (registry lookups, `~/.npmrc`, `~/.gitconfig`) can therefore appear in their reports.");
lines.push("- Loopback traffic (`127.0.0.1`, `::1`, `localhost`) is never counted as an outbound host. Raw IPs seen only by the lsof socket poller while the proxy was already naming hosts are listed as *dedup* and not graded, since they are almost always the same connections.");
lines.push("- Host categories: **telemetry** (analytics / error-reporting / metrics vendors, including `ab.chatgpt.com` and `play.googleapis.com`) costs 25 points each; **other** (unclassified) costs 10; **LLM** backends (`api.anthropic.com`, `mcp-proxy.anthropic.com`, `chatgpt.com`, `api.openai.com`, Google Gemini endpoints, …) and **auth** endpoints (`oauth2.googleapis.com`, `accounts.google.com`, …) cost nothing.");
if (manifest.sandboxIsGitRepo) lines.push("- The sandbox is an empty git repository (`git init`) because `codex exec` refuses to run in an untrusted non-git directory.");
lines.push("- Files are attributed to the process that opened them. A helper reading its own config (`git` reading `~/.gitconfig`/`~/.netrc`, a spawned `codex` reading `~/.codex/**`) counts as *own config*; the audited tool reading another tool's files is third-party. macOS keychain files are opened by every TLS-speaking process for trust evaluation and are listed as *trust store*, never graded.");
lines.push("- Coding agents (`claude`, `codex`, `gemini`, `t3`, …) may read `~/.gitconfig` without penalty: git identity is part of their job, as it is for `git` itself. Any other tool reading it is still third-party.");
lines.push("- The preload hook reports what a tool *tries* to open; a watchlist path that does not exist on this machine is listed as *probed but absent* and never graded.");
lines.push("- Grading: 100 − 25 per telemetry host − 30 per sensitive file read outside the tool's own namespace − 10 per other host. A native binary audited without `--deep` is reported as *not traced*, never as clean. Reads of a tool's **own** config (`claude` → `~/.claude*`, `codex` → `~/.codex`, `gemini` → `~/.gemini`, `npx` → `~/.npmrc`) are labelled OWN CONFIG and not penalised; one tool reading another tool's credentials is.");
lines.push("- Shared assets are scrubbed by `scripts/mask.mjs`: home directories appear as `~`, Codex plugin names as `<plugin>`, and UUIDs (such as Claude plugin-sync ids) as `<uuid>`. Hostnames, request paths and byte counts are untouched; unmasked originals stay in `audit-results/raw/`.");
lines.push("- Hosts marked `(ip)` were seen only by the lsof layer (a raw socket from a non-Node binary); narcx does no reverse DNS, so they stay as addresses. `via hook` = exact URL from the in-process hook, `via proxy` = CONNECT tunnel, `via lsof` = socket poller.");
lines.push(`- sudo was ${manifest.sudoCached ? "available" : "not available without a password"} during this run${manifest.sudoCached ? "" : ", so native binaries were audited in standard mode: their network activity is captured (proxy + lsof) but file reads inside the binary are not. Run `./audit-results/run-deep.sh` to upgrade those reports with kernel-level tracing."}`);
lines.push("");
fs.writeFileSync(path.join(OUT, "RESULTS.md"), lines.join("\n"));
console.log(`wrote ${tilde(path.join(OUT, "RESULTS.md"))}`);

// ---------------------------------------------------------------------------
// run-deep.sh
// ---------------------------------------------------------------------------
const deepIds = rows.filter(({ t }) => t.needsDeepTrace).map(({ id }) => id);
const sh = `#!/usr/bin/env bash
# Re-audit the native-binary targets with narcx --deep (fs_usage kernel tracing).
# Asks for your sudo password once, then runs each target as your own user.
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build >/dev/null
sudo -v
# keep the sudo ticket fresh for the whole run (macOS tickets expire after 5 minutes)
( while true; do sudo -n -v 2>/dev/null || exit; sleep 50; done ) &
KEEPALIVE=$!
trap 'kill $KEEPALIVE 2>/dev/null' EXIT
node scripts/audit.mjs --deep --only ${deepIds.join(",") || "claude-code,codex-cli,t3code"}
node scripts/mask.mjs
node scripts/report.mjs
echo "Deep reports written to ./audit-results (see RESULTS.md)."
`;
fs.writeFileSync(path.join(OUT, "run-deep.sh"), sh, { mode: 0o755 });
console.log(`wrote ${tilde(path.join(OUT, "run-deep.sh"))} (${deepIds.join(", ") || "no targets currently need deep tracing"})`);

// ---------------------------------------------------------------------------
// twitter-grid.png
// ---------------------------------------------------------------------------
const topArg = flag("--top", null);
const top = (topArg ? topArg.split(",") : ORDER).filter((id) => rows.find((r) => r.id === id && r.report && fs.existsSync(path.join(OUT, `${id}.png`)))).slice(0, 4);
if (top.length) {
  const W = 1600;
  const H = 900;
  const CW = 600;
  const CH = Math.round((CW * 675) / 1200); // 338
  const xs = [170, 830];
  const ys = [112, 506];
  const BG = "#EAE6DC";
  const INK = "#111111";
  const MUTED = "#66625B";
  const FRAME = "#C9C3B8";
  const SANS = "IBM Plex Sans";
  const MONO = "IBM Plex Mono";
  const date = manifest.generatedAt.slice(0, 10);
  const parts = [];
  parts.push(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">`);
  parts.push(`<rect width="${W}" height="${H}" fill="${BG}"/>`);
  parts.push(`<text x="170" y="60" font-family="${SANS}" font-size="28" font-weight="700" fill="${INK}" letter-spacing="1">AI coding CLIs · privacy audit</text>`);
  parts.push(`<text x="1430" y="58" font-family="${MONO}" font-size="13" fill="${MUTED}" text-anchor="end" letter-spacing="1">NARCX  /  ${esc(date)}  /  OUT-OF-THE-BOX DEFAULTS  /  NO TLS INTERCEPTION</text>`);
  parts.push(`<rect x="170" y="76" width="1260" height="2" fill="${INK}"/>`);
  top.forEach((id, i) => {
    const { t } = rows.find((r) => r.id === id);
    const x = xs[i % 2];
    const y = ys[Math.floor(i / 2)];
    const png = fs.readFileSync(path.join(OUT, `${id}.png`)).toString("base64");
    const label = `${t.name} ${t.version}`;
    const rt = /wrapper/i.test(t.runtime) && /native/i.test(t.runtime) ? "node wrapper + native" : /native/i.test(t.runtime) ? "native binary" : "node";
    const sub = `${rt} · ${t.mode}${t.needsDeepTrace ? " · needs --deep" : ""}`;
    parts.push(`<text x="${x}" y="${y - 12}" font-family="${SANS}" font-size="18" font-weight="700" fill="${INK}">${esc(label)}</text>`);
    parts.push(`<text x="${x + CW}" y="${y - 12}" font-family="${MONO}" font-size="11" fill="${MUTED}" text-anchor="end" letter-spacing="0.5">${esc(sub.slice(0, 62).toUpperCase())}</text>`);
    parts.push(`<image x="${x}" y="${y}" width="${CW}" height="${CH}" preserveAspectRatio="xMidYMid meet" xlink:href="data:image/png;base64,${png}"/>`);
    parts.push(`<rect x="${x + 0.5}" y="${y + 0.5}" width="${CW - 1}" height="${CH - 1}" fill="none" stroke="${FRAME}" stroke-width="1"/>`);
  });
  parts.push(`<rect x="170" y="868" width="1260" height="1" fill="${FRAME}"/>`);
  parts.push(`<text x="170" y="889" font-family="${MONO}" font-size="12" fill="${MUTED}">narcx v${esc(manifest.narcVersion)} · proxy + preload hook + lsof · zero auditor network calls</text>`);
  parts.push(`<text x="1430" y="890" font-family="${MONO}" font-size="15" font-weight="700" fill="${INK}" text-anchor="end">npx narcx</text>`);
  parts.push("</svg>");
  const svg = parts.join("\n");
  const resvg = new Resvg(svg, {
    fitTo: { mode: "width", value: W },
    background: BG,
    font: { fontFiles: FONT_FILES, loadSystemFonts: true, defaultFontFamily: SANS, sansSerifFamily: SANS, monospaceFamily: MONO },
  });
  const out = path.join(OUT, "twitter-grid.png");
  fs.writeFileSync(out, resvg.render().asPng());
  console.log(`wrote ${tilde(out)} (${top.join(", ")})`);
} else {
  console.log("no scorecards available for the collage yet");
}
