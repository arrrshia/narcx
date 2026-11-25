#!/usr/bin/env node
/**
 * Scrub identifying path fragments from audit-results before sharing, then
 * re-render every scorecard PNG from the masked JSON with `narc --render`.
 *
 *   node scripts/mask.mjs [--out ./audit-results]
 *
 * Originals are kept once in audit-results/raw/ (gitignored with the rest).
 * Rules:
 *   - <plugin>  codex plugin names under ~/.codex/plugins/cache/<name>/<name>/
 *   - <uuid>    any UUID (e.g. Claude plugin-sync ids under ~/.claude/plugins/synced/)
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
const i = args.indexOf("--out");
const OUT = path.resolve(i >= 0 && args[i + 1] ? args[i + 1] : path.join(ROOT, "audit-results"));
const RAW = path.join(OUT, "raw");
fs.mkdirSync(RAW, { recursive: true });

export const RULES = [
  [/(\/\.codex\/plugins\/cache\/)[^/]+\/[^/]+\//g, "$1<plugin>/<plugin>/"],
  [/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "<uuid>"],
];
// Literal plugin names, collected from the (raw) reports, so a tool printing
// "loaded plugin foo" in its own output gets masked too, not just the path form.
const literals = new Set();
for (const dir of [RAW, OUT]) {
  if (!fs.existsSync(dir)) continue;
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith(".json") || name === "manifest.json") continue;
    const text = fs.readFileSync(path.join(dir, name), "utf8");
    for (const m of text.matchAll(/\/\.codex\/plugins\/cache\/([^/"<]+)\//g)) literals.add(m[1]);
  }
}
const escapeRe = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
for (const name of literals) RULES.push([new RegExp(escapeRe(name), "g"), "<plugin>"]);

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
  RULES.push([new RegExp("(?<![~\\w])" + escapeRe(h) + "(?=/|$)", "g"), "~"]);
}
RULES.push([/~\/Users\/[^/\s"]+(?=\/|$)/g, "~"]);
RULES.push([/~\/home\/[^/\s"]+(?=\/|$)/g, "~"]);

const mask = (s) => (typeof s === "string" ? RULES.reduce((acc, [re, rep]) => acc.replace(re, rep), s) : s);

const keepRaw = (file) => {
  const dst = path.join(RAW, path.basename(file));
  // Copy when missing or when the source is a newer run than the copy we hold.
  if (!fs.existsSync(dst) || fs.statSync(file).mtimeMs > fs.statSync(dst).mtimeMs + 1000) fs.copyFileSync(file, dst);
};

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
    for (const f of report.sensitiveFiles ?? []) apply(f, "path");
    for (const f of report.otherDotfiles ?? []) apply(f, "path");
    for (const e of report.events ?? []) if (e.kind === "file") apply(e, "path");
    for (const f of report.probedFiles ?? []) apply(f, "path");
    for (const d of report.score?.deductions ?? []) apply(d, "detail");
    // Process names: keep the audited tool, well-known agents and helpers; anything else
    // (the user's own MCP servers, for instance) becomes <process>.
    const KNOWN = new Set(["claude", "codex", "gemini", "t3", "t3-resource-moni", "t3-resource-monitor", "cursor", "cursor-agent", "opencode", "node", "bun", "git", "git-remote-https", "git-remote-http", "git-credential-osxkeychain", "curl", "sh", "bash", "zsh", "python3", "python", "uv", "npm", "npx", "ssh", "rg", "ripgrep"]);
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
    if (touched) {
      keepRaw(file);
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
