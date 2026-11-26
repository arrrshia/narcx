import pc from "picocolors";
import type { AuditReport, Grade, HostCategory, HostSummary } from "../core/types.js";
import { SensitiveMatcher } from "../core/watchlist.js";
import { fit, fitLeft, fmtBytes, fmtDuration, padEndAnsi, visibleWidth } from "./format.js";

function gradeBadge(grade: Grade): string[] {
  const label = ` ${grade.padEnd(2, " ")} `;
  const paint = (s: string) => {
    switch (grade) {
      case "A+":
      case "A":
        return pc.bold(pc.bgGreen(pc.black(s)));
      case "B":
        return pc.bold(pc.bgCyan(pc.black(s)));
      case "C":
        return pc.bold(pc.bgYellow(pc.black(s)));
      case "D":
        return pc.bold(pc.bgMagenta(pc.white(s)));
      default:
        return pc.bold(pc.bgRed(pc.white(s)));
    }
  };
  return [paint("      "), paint(label.padStart(5, " ").padEnd(6, " ")), paint("      ")];
}

const CAT_PAINT: Record<HostCategory, (s: string) => string> = {
  TELEMETRY: pc.red,
  UNKNOWN: pc.yellow,
  LLM_API: pc.green,
  AUTH: pc.cyan,
  USER_OTLP: pc.cyan,
};
const CAT_DOT: Record<HostCategory, string> = { TELEMETRY: "●", UNKNOWN: "▲", LLM_API: "✓", AUTH: "✓", USER_OTLP: "◆" };
const CAT_TITLE: Record<HostCategory, string> = { TELEMETRY: "TELEMETRY", UNKNOWN: "OTHER", LLM_API: "LLM API", AUTH: "AUTH", USER_OTLP: "USER OTLP" };

export interface ScorecardOptions {
  width?: number;
  cardPath?: string | null;
  jsonPath?: string | null;
  matcher: SensitiveMatcher;
}

export function renderScorecard(report: AuditReport, opts: ScorecardOptions): string {
  const cols = opts.width ?? Math.min(Math.max(process.stderr.columns || 80, 64), 110);
  const W = cols - 2; // interior width between the box borders
  const inner = W - 2; // after one-space padding on each side
  const lines: string[] = [];
  const bar = (n: number) => "─".repeat(Math.max(0, n));
  const row = (content: string) => lines.push(pc.dim("│") + " " + padEndAnsi(content, inner) + " " + pc.dim("│"));
  const blank = () => row("");
  const section = (title: string) => {
    const t = ` ${title} `;
    lines.push(pc.dim("├─") + pc.bold(t) + pc.dim(bar(W - 2 - visibleWidth(t)) + "┤"));
  };

  const score = report.score;
  const g = score.grade;
  const gradeColor = g === "A+" || g === "A" ? pc.green : g === "B" ? pc.cyan : g === "C" || g === "D" ? pc.yellow : pc.red;

  // header
  const title = " NARC · PRIVACY SCORECARD ";
  lines.push(pc.dim("┌─") + pc.bold(pc.white(title)) + pc.dim(bar(W - 2 - title.length) + "┐"));
  blank();

  const badge = gradeBadge(g);
  const leftW = inner - 8;
  const layersOn = Object.entries(report.layers)
    .filter(([, v]) => v)
    .map(([k]) => k);
  const status =
    report.signal ? `killed by ${report.signal}` : `exit ${report.exitCode ?? "?"}`;
  const left = [
    pc.bold(pc.white("$ ")) + pc.white(fit(report.commandLabel, leftW - 2)),
    pc.dim(`${status} · ${fmtDuration(report.durationMs)} · layers: ${layersOn.join(", ") || "none"}`),
    gradeColor(pc.bold(`score ${score.score}/100`)) + pc.dim(`  (${score.deductions.length} deduction${score.deductions.length === 1 ? "" : "s"})`),
  ];
  for (let i = 0; i < 3; i++) row(padEndAnsi(left[i] ?? "", leftW) + "  " + badge[i]);
  blank();

  // sensitive files (target only unless children are folded into the grade)
  const isGraded = (x: { attribution?: string }) => x.attribution === "target" || x.attribution === undefined || (report.includeChildren && x.attribution === "child");
  const sens = report.sensitiveFiles.filter(isGraded);
  const tracing = report.fileTracing;
  section(`SENSITIVE FILES TOUCHED (${sens.length})`);
  if (tracing.coverage === "none") {
    row(pc.yellow(`⚠ file reads not traced (native binary${tracing.untraced.length ? ": " + describeUntraced(tracing.untraced) : ""} — run with --deep)`));
  } else if (!sens.length) {
    row(pc.green("✓ none"));
  } else {
    const pathW = Math.min(Math.max(...sens.map((f) => opts.matcher.display(f.path).length)), Math.floor(inner * 0.55));
    const launcherName = report.launcher?.name ?? "launcher";
    for (const f of sens) {
      const ops = Object.entries(f.ops)
        .map(([k, v]) => `${k}×${v}`)
        .join(" ");
      const disp = fitLeft(opts.matcher.display(f.path), pathW);
      const kind = f.kind ?? (f.graded === false ? "config" : "secret");
      const quiet = f.ownNamespace || f.launcher || kind !== "secret";
      const who = f.procs.length ? ` · ${f.procs.slice(0, 3).join(", ")}` : "";
      const tag = f.launcher
        ? pc.dim(`via ${launcherName} · not graded`)
        : kind === "system"
          ? pc.dim(`${f.watch?.label ?? "system"} · not graded${who}`)
          : f.ownNamespace
            ? pc.cyan("OWN CONFIG") + pc.dim(` · not penalised${who}`)
            : kind === "config"
              ? pc.dim(`CONFIG · ${f.watch?.label ?? ""} · not graded${who}`)
              : pc.dim((f.watch?.label ?? "") + who);
      const mark = f.launcher || kind !== "secret" ? pc.dim("○") : f.ownNamespace ? pc.cyan("○") : pc.red("●");
      row(`${mark} ${quiet ? pc.dim(disp) : pc.bold(pc.red(disp))}${" ".repeat(Math.max(1, pathW - disp.length + 2))}${tag} ${pc.dim(ops)}`);
    }
  }
  const dots = report.otherDotfiles.length;
  if (dots) row(pc.dim(`  + ${dots} other dotfile${dots === 1 ? "" : "s"} under ~ (see --json)`));
  if (tracing.coverage === "partial") {
    row(pc.yellow(`⚠ not hooked: ${describeUntraced(tracing.untraced)} — reads inside those binaries are invisible (run with --deep)`));
  }
  const probed = report.probedFiles ?? [];
  if (probed.length) row(pc.dim(`  probed but absent (not graded): ${probed.map((f) => opts.matcher.display(f.path)).join(", ")}`));
  if (report.leftoverProcesses?.length) row(pc.yellow(`⚠ left running after exit, stopped by narc: ${report.leftoverProcesses.join(", ")}`));
  blank();

  // outbound (target only unless children are folded into the grade)
  const hosts = report.hosts.filter(isGraded);
  section(`OUTBOUND (${hosts.length} host${hosts.length === 1 ? "" : "s"})`);
  if (!hosts.length) {
    row(pc.green("✓ no network activity observed"));
  } else {
    for (const cat of ["TELEMETRY", "UNKNOWN", "USER_OTLP", "LLM_API", "AUTH"] as HostCategory[]) {
      const group = hosts.filter((h) => h.category === cat);
      if (!group.length) continue;
      row(CAT_PAINT[cat](pc.bold(CAT_TITLE[cat])) + pc.dim(` (${group.length})`));
      const hostW = Math.min(Math.max(...group.map((h) => h.host.length)), Math.floor(inner * 0.45));
      for (const h of group) row("  " + hostRow(h, hostW, inner - 2, report.launcher?.name));
    }
  }
  if (report.suppressedHosts.length) {
    row(pc.dim(`  raw IPs seen only by lsof, likely the hosts above (not graded): ${report.suppressedHosts.map((h) => h.host).join(", ")}`));
  }
  blank();

  // spawned external CLIs: fully transparent, excluded from the grade
  const children = Object.values(report.childActivity ?? {});
  const unattributed = report.unattributedHosts ?? [];
  if (unattributed.length) {
    row(pc.dim(`  unattributed (connection closed before its process could be resolved; not graded): ${unattributed.join(", ")}`));
  }
  if (children.length && !report.includeChildren) {
    section("SPAWNED CHILD PROCESSES (excluded from grade)");
    const byHost = new Map(report.hosts.map((h) => [h.host, h]));
    for (const c of children) {
      const hostBits = [...c.telemetryHosts.map((h) => pc.red(h)), ...c.otherHosts.map((h) => pc.yellow(h)), ...c.llmHosts.map((h) => pc.green(h)), ...c.authHosts.map((h) => pc.cyan(h))].map((painted) => {
        const plain = painted.replace(/\u001b\[[0-9;]*m/g, "");
        const bytes = byHost.get(plain)?.bytesOut ?? 0;
        return bytes ? `${painted} ${pc.dim(`(${fmtBytes(bytes)})`)}` : painted;
      });
      const files = c.filesAccessed.length ? pc.dim(` · ${c.filesAccessed.length} file${c.filesAccessed.length === 1 ? "" : "s"}`) : "";
      row(pc.dim("via ") + pc.bold(c.processName) + pc.dim(" -> ") + (hostBits.length ? hostBits.join(pc.dim(", ")) : pc.dim("no network")) + files);
      if (c.filesAccessed.length) row(pc.dim(`     ${fit(c.filesAccessed.join(", "), inner - 6)}`));
    }
    blank();
  }

  // deductions
  if (score.deductions.length) {
    section("DEDUCTIONS");
    for (const d of score.deductions) {
      const label =
        d.reason === "telemetry-host" ? "telemetry host" : d.reason === "sensitive-file" ? "sensitive file" : "unknown host";
      row(`${pc.red(pc.bold(String(d.points).padStart(4)))}  ${pc.dim(label.padEnd(15))} ${fit(d.detail, inner - 23)}`);
    }
    blank();
  }

  if (opts.cardPath || opts.jsonPath) {
    lines.push(pc.dim("├" + bar(W) + "┤"));
    if (opts.cardPath) row(`${pc.dim("PNG ")} ${pc.cyan(opts.cardPath)}`);
    if (opts.jsonPath) row(`${pc.dim("JSON")} ${pc.cyan(opts.jsonPath)}`);
  }
  lines.push(pc.dim("└" + bar(W) + "┘"));
  return lines.join("\n");
}

/** Name only the first untraced process; the rest may be the user's own MCP servers. */
export function describeUntraced(list: readonly string[]): string {
  if (!list.length) return "";
  return list.length === 1 ? list[0]! : `${list[0]} +${list.length - 1} more`;
}

function hostRow(h: HostSummary, hostW: number, maxW: number, launcherName?: string): string {
  const paint = h.launcher ? pc.dim : CAT_PAINT[h.category];
  const dot = paint(CAT_DOT[h.category]);
  const host = fit(h.host, hostW).padEnd(hostW);
  const req = `${h.requests} req`.padStart(8);
  const bytes = `${fmtBytes(h.bytesOut)} ↑ ${fmtBytes(h.bytesIn)} ↓`.padStart(20);
  const via = h.sources.map((s) => (s === "preload" ? "hook" : s)).join("+");
  let extra = "";
  if (h.paths.length) {
    const p = h.paths[0]!;
    extra = `  ${h.methods[0] ?? ""} ${p}${h.paths.length > 1 ? ` (+${h.paths.length - 1})` : ""}`;
  }
  const launcherTag = h.launcher ? pc.dim(` (${launcherName ?? "launcher"} itself, not graded)`) : "";
  const base = `${dot} ${paint(host)} ${pc.dim(req)} ${pc.dim(bytes)} ${pc.dim(`via ${via}`)}${launcherTag}`;
  const room = maxW - visibleWidth(base);
  return base + (room > 8 && extra ? pc.dim(fit(extra, room)) : "");
}
