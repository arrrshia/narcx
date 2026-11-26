#!/usr/bin/env node
/**
 * Scrub identifying path fragments from audit-results before sharing, then
 * re-render every scorecard PNG from the masked JSON with `narc --render`.
 *
 *   node scripts/mask.mjs [--out ./audit-results]
 *
 * Originals are kept once in audit-results/raw/ (gitignored with the rest).
 * Rules:
 *   - <plugin>  codex marketplace and plugin names under ~/.codex/plugins/cache/<market>/<plugin>,
 *               and the same names wherever else they appear as a whole path segment or word
 *   - <marketplace> git checkouts under ~/.codex/.tmp/marketplaces/<name>
 *   - <tool>    uv / pipx tool venvs (~/.local/share/uv/tools/<name>), often a personal MCP server
 *   - <uuid>    any UUID (e.g. Claude plugin-sync ids under ~/.claude/plugins/synced/)
 *   - <hash>    any bare hex id of 32+ digits (plugin trust records, git objects, cache keys)
 *   - ~         the home directory, wherever it appears (JSON paths, pty logs); a doubled
 *               home prefix (fs_usage column artifact) collapses to one
 *   - <process> untraced process names after the first (they may be personal MCP servers)
 * Hostnames, request paths and byte counts are never touched.
 */
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const NARC = path.join(ROOT, "dist", "cli.js");
const args = process.argv.slice(2);
const FROM_RAW = args.includes("--from-raw"); // restart from the unmasked originals (e.g. after widening the allow-list)
const i = args.indexOf("--out");
const OUT = path.resolve(i >= 0 && args[i + 1] ? args[i + 1] : path.join(ROOT, "audit-results"));
const RAW = path.join(OUT, "raw");
fs.mkdirSync(RAW, { recursive: true });

export const RULES = [
  // <marketplace>/<plugin>, with or without anything after; a path ending at the marketplace dir too
  [/(\/\.codex\/plugins\/cache\/)[^/"\s<]+\/[^/"\s<]+/g, "$1<plugin>/<plugin>"],
  [/(\/\.codex\/plugins\/cache\/)[^/"\s<]+/g, "$1<plugin>"],
  // everything inside an installed plugin is that plugin's own file tree, not the audited tool's business
  [/(\/\.codex\/plugins\/cache\/<plugin>\/<plugin>\/)[^"\s]+/g, "$1…"],
  [/(\/\.codex\/(?:\.tmp\/)?marketplaces\/)(?!\.)[^/"\s<]+/g, "$1<marketplace>"],
  [/(\/\.local\/share\/uv\/tools\/)[^/"\s<]+/g, "$1<tool>"],
  [/(\/\.local\/pipx\/venvs\/)[^/"\s<]+/g, "$1<tool>"],
  [/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:-[0-9a-f]{6,})*/gi, "<uuid>"],
  // any bare hex id of 32+ digits: plugin trust records, git objects, npm cache keys, server-info caches
  [/\b[0-9a-f]{32,}\b/g, "<hash>"],
];
// Literal plugin / marketplace / tool names. Applied only to strings that are paths or log
// lines (they contain "/" or whitespace), never to a bare hostname such as gmail.googleapis.com.
export const LITERAL_RULES = [];
// Process names that must never be treated as a plugin/tool name to mask (see KNOWN below).
const NEVER_LITERAL = new Set(["node", "npm", "npx", "git", "gh", "uv", "uvx", "pip", "pipx", "python", "python3", "bun", "deno", "codex", "claude", "gemini", "cursor", "t3", "sh", "bash", "zsh", "curl", "wget", "ssh", "open", "ps", "lsof", "security"]);
// Literal plugin names, collected from the (raw) reports, so a tool printing
// "loaded plugin foo" in its own output gets masked too, not just the path form.
const literals = new Map(); // name -> placeholder
for (const dir of [RAW, OUT]) {
  if (!fs.existsSync(dir)) continue;
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith(".json") || name === "manifest.json") continue;
    const text = fs.readFileSync(path.join(dir, name), "utf8");
    for (const m of text.matchAll(/\/\.codex\/plugins\/cache\/([^/"<\s]+)(?:\/([^/"<\s]+))?/g)) {
      literals.set(m[1], "<plugin>");
      if (m[2]) literals.set(m[2], "<plugin>");
    }
    for (const m of text.matchAll(/\/\.codex\/(?:\.tmp\/)?marketplaces\/([^/".<\s][^/"<\s]*)/g)) literals.set(m[1], "<marketplace>");
    for (const m of text.matchAll(/\/\.local\/(?:share\/uv\/tools|pipx\/venvs)\/([^/"<\s]+)/g)) {
      literals.set(m[1], "<tool>");
      literals.set(m[1].replace(/-/g, "_"), "<tool>"); // python module / dist-info spelling
    }
  }
}
const escapeRe = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// A literal is masked as a whole path segment or word, including "name.ext" and "x-name" forms
// inside a path, and never when it is also a well-known process name.
for (const [name, placeholder] of literals) {
  if (name.length < 3 || NEVER_LITERAL.has(name) || name.startsWith("<")) continue;
  LITERAL_RULES.push([new RegExp("(^|[/\\s\"'_-])" + escapeRe(name) + "(?=$|[/\\s\"'_.-])", "g"), "$1" + placeholder]);
}

// Home directory (both spellings on macOS) -> "~", so even the raw JSON and
// pty logs can be shared. `narc --render` understands "~/" paths.
const HOME = os.homedir();
let REAL_HOME = HOME;
try {
  REAL_HOME = fs.realpathSync(HOME);
} catch {
  /* ignore */
}
for (const h of new Set([HOME, REAL_HOME])) {
  // A home prefix glued onto an already-absolute path (an fs_usage column artifact) is one home, not two.
  RULES.push([new RegExp(escapeRe(h) + escapeRe(h) + "(?=/|$)", "g"), h]);
  // No lookbehind: in pty logs the path can follow an ANSI colour code ("\x1b[36m/Users/…").
  // A home prefix already turned into "~/Users/<user>" is collapsed by the rule below.
  RULES.push([new RegExp(escapeRe(h) + "(?=/|$)", "g"), "~"]);
}
RULES.push([/~\/Users\/[^/\s"]+(?=\/|$)/g, "~"]);
RULES.push([/~\/home\/[^/\s"]+(?=\/|$)/g, "~"]);
// Safety net for a username that survived as a path segment ("~/<user>/.local/…" from a
// truncated fs_usage column): it is the home directory, not a folder under it.
RULES.push([new RegExp("~/" + escapeRe(path.basename(REAL_HOME)) + "(?=/|$)", "g"), "~"]);
if (path.basename(HOME) !== path.basename(REAL_HOME)) RULES.push([new RegExp("~/" + escapeRe(path.basename(HOME)) + "(?=/|$)", "g"), "~"]);

const mask = (s) => {
  if (typeof s !== "string") return s;
  let out = RULES.reduce((acc, [re, rep]) => acc.replace(re, rep), s);
  if (/[/\s]/.test(out)) out = LITERAL_RULES.reduce((acc, [re, rep]) => acc.replace(re, rep), out);
  return out;
};

// A report we have masked before carries `masked: true`, so it can never be mistaken for a
// fresh original; logs have no such flag and fall back to "newer than our copy".
const isMaskedJson = (file) => {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")).masked === true;
  } catch {
    return false;
  }
};
const newerThan = (a, b) => fs.statSync(a).mtimeMs > fs.statSync(b).mtimeMs + 1000;
const keepRaw = (file) => {
  const dst = path.join(RAW, path.basename(file));
  if (!fs.existsSync(dst)) return fs.copyFileSync(file, dst);
  if (file.endsWith(".json") ? !isMaskedJson(file) && newerThan(file, dst) : newerThan(file, dst)) fs.copyFileSync(file, dst);
};

if (FROM_RAW && fs.existsSync(RAW)) {
  // Restore originals only where they belong to the current run: a source newer than its
  // raw copy is a fresh audit whose original has not been captured yet, so leave it alone.
  for (const name of fs.readdirSync(RAW)) {
    if (!(name.endsWith(".json") || name.endsWith(".log"))) continue;
    const src = path.join(OUT, name);
    const rawFile = path.join(RAW, name);
    const restore = name.endsWith(".json") ? isMaskedJson(src) : fs.statSync(rawFile).mtimeMs >= fs.statSync(src).mtimeMs - 1000;
    if (!fs.existsSync(src) || restore) fs.copyFileSync(rawFile, src);
  }
}
let changed = 0;
for (const name of fs.readdirSync(OUT)) {
  const file = path.join(OUT, name);
  if (name.endsWith(".json") && name !== "manifest.json") {
    const report = JSON.parse(fs.readFileSync(file, "utf8"));
    if (!report.score) continue;
    let touched = 0;
    const apply = (obj, key) => {
      const before = obj[key];
      const after = mask(before);
      if (after !== before) {
        obj[key] = after;
        touched++;
      }
    };
    const walkStrings = (v) => {
      if (typeof v === "string") return mask(v);
      if (Array.isArray(v)) return v.map(walkStrings);
      if (v && typeof v === "object") { for (const k of Object.keys(v)) v[k] = walkStrings(v[k]); return v; }
      return v;
    };
    // Generic rules (home dir, plugin names, UUIDs) apply to every string in the report;
    // hostnames never contain those patterns, so they are untouched.
    {
      const before = JSON.stringify(report);
      walkStrings(report);
      if (JSON.stringify(report) !== before) touched++;
    }
    for (const f of report.sensitiveFiles ?? []) apply(f, "path");
    for (const f of report.otherDotfiles ?? []) apply(f, "path");
    for (const e of report.events ?? []) if (e.kind === "file") apply(e, "path");
    for (const f of report.probedFiles ?? []) apply(f, "path");
    for (const d of report.score?.deductions ?? []) apply(d, "detail");
    // Process names: keep the audited tool, well-known agents and helpers; anything else
    // (the user's own MCP servers, for instance) becomes <process>.
    const KNOWN = new Set([
      "claude", "claude-code", "codex", "codex-code-mode-host", "gemini", "t3", "t3-resource-moni", "t3-resource-monitor", "cursor", "cursor-agent", "opencode", "aider", "copilot", "amp", "goose", "cline", "droid",
      "node", "nodejs", "bun", "bunx", "deno", "git", "git-remote-https", "git-remote-http", "git-credential-osxkeychain", "git-lfs", "gh", "curl", "wget", "sh", "bash", "zsh", "fish", "dash",
      "python3", "python", "uv", "uvx", "pip", "pip3", "pipx", "npm", "npx", "pnpm", "yarn", "corepack", "ssh", "ssh-agent", "scp", "rsync", "rg", "ripgrep", "fzf", "jq", "docker", "aws", "gcloud", "kubectl", "helm",
      "cargo", "rustc", "go", "make", "cmake", "swift", "xcodebuild", "open", "osascript", "security", "ps", "lsof", "unknown",
    ]);
    const lead = path.basename((report.command ?? [])[0] ?? "");
    const okName = (n) => KNOWN.has(n) || n === lead || n === "<process>";
    const maskProcs = (arr) => {
      for (const f of arr ?? []) {
        if (!Array.isArray(f.procs)) continue;
        const next = f.procs.map((n) => (okName(n) ? n : "<process>"));
        if (next.join() !== f.procs.join()) {
          f.procs = [...new Set(next)];
          touched++;
        }
      }
    };
    maskProcs(report.sensitiveFiles);
    maskProcs(report.otherDotfiles);
    maskProcs(report.probedFiles);
    const maskVia = (arr) => {
      for (const x of arr ?? []) {
        if (typeof x.via === "string" && x.via && !okName(x.via)) { x.via = "<process>"; touched++; }
        if (typeof x.processName === "string" && x.processName && !okName(x.processName)) { x.processName = "<process>"; touched++; }
        if (Array.isArray(x.processNames)) { const n = x.processNames.map((v) => (okName(v) ? v : "<process>")); if (n.join() !== x.processNames.join()) { x.processNames = [...new Set(n)]; touched++; } }
      }
    };
    maskVia(report.sensitiveFiles); maskVia(report.otherDotfiles); maskVia(report.probedFiles); maskVia(report.hosts); maskVia(report.suppressedHosts); maskVia(report.events);
    if (report.childActivity && typeof report.childActivity === "object") {
      const next = {};
      for (const [k, v] of Object.entries(report.childActivity)) {
        const key = okName(k) ? k : "<process>";
        if (key !== k) touched++;
        next[key] = { ...v, processName: okName(v.processName) ? v.processName : "<process>" };
      }
      report.childActivity = next;
    }
    if (Array.isArray(report.leftoverProcesses)) {
      const next = report.leftoverProcesses.map((n) => (okName(n) ? n : "<process>"));
      if (next.join() !== report.leftoverProcesses.join()) {
        report.leftoverProcesses = [...new Set(next)];
        touched++;
      }
    }
    for (const e of report.events ?? []) if (e.kind === "file" && e.proc && !okName(e.proc)) {
      e.proc = "<process>";
      touched++;
    }
    // Untraced process names beyond the first can be the user's own MCP servers: keep only the lead binary.
    if (Array.isArray(report.fileTracing?.untraced) && report.fileTracing.untraced.length > 1) {
      const lead = report.fileTracing.untraced[0];
      const rest = report.fileTracing.untraced.slice(1);
      if (rest.some((n) => n !== "<process>")) {
        report.fileTracing.untraced = [lead, ...rest.map(() => "<process>")];
        touched++;
      }
    }
    if (touched || report.masked !== true) {
      keepRaw(file);
      report.masked = true;
      fs.writeFileSync(file, JSON.stringify(report, null, 2));
      changed++;
    }
    const png = file.replace(/\.json$/, ".png");
    execFileSync(process.execPath, [NARC, "--render", file, "--card", png, "--quiet"], { stdio: "inherit" });
    console.log(`${name}: ${touched} path(s) masked, ${path.basename(png)} re-rendered`);
  } else if (name.endsWith(".log")) {
    const before = fs.readFileSync(file, "utf8");
    const after = mask(before);
    if (after !== before) {
      keepRaw(file);
      fs.writeFileSync(file, after);
      changed++;
      console.log(`${name}: masked`);
    }
  }
}
// manifest.json: the harness copies each report's fileTracing before masking.
const manifestPath = path.join(OUT, "manifest.json");
if (fs.existsSync(manifestPath)) {
  const before = fs.readFileSync(manifestPath, "utf8");
  const manifest = JSON.parse(before);
  const walk = (v) => {
    if (typeof v === "string") return mask(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      for (const k of Object.keys(v)) v[k] = walk(v[k]);
      return v;
    }
    return v;
  };
  walk(manifest);
  manifest.masked = true;
  for (const t of Object.values(manifest.targets ?? {})) {
    const u = t?.fileTracing?.untraced;
    if (Array.isArray(u) && u.length > 1) t.fileTracing.untraced = [u[0], ...u.slice(1).map(() => "<process>")];
  }
  const after = JSON.stringify(manifest, null, 2);
  if (after !== before) {
    keepRaw(manifestPath);
    fs.writeFileSync(manifestPath, after);
    changed++;
    console.log("manifest.json: masked");
  }
}
console.log(`${changed} file(s) rewritten; originals in ${path.relative(ROOT, RAW)}/`);
