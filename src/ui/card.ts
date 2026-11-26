/**
 * Shareable 1200x675 scorecard, rendered as a Swiss-editorial audit sheet:
 * warm paper, hairline rules, tabular mono data, one accent colour used only
 * for things that are actually bad. No cards-in-cards, no pills, no gradients.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditReport, FileSummary, HostCategory, HostSummary } from "../core/types.js";
import { SensitiveMatcher } from "../core/watchlist.js";
import { escapeXml, fit, fitLeft, fmtBytes } from "./format.js";
import { describeUntraced } from "./scorecard.js";

export const CARD_W = 1200;
export const CARD_H = 675;
const M = 56; // outer margin

export const PAPER = "#F4F1EA";
export const INK = "#111111";
export const MUTED = "#66625B";
export const RULE = "#D6D1C7";
export const ROW = "#E6E2D8";
export const RED = "#D92D20";
export const GREEN = "#1B6B3A";

export const SANS = "IBM Plex Sans";
export const MONO = "IBM Plex Mono";
const CH = 0.6; // Plex Mono advance width (600/1000 em)

// ---------------------------------------------------------------------------
// fonts
// ---------------------------------------------------------------------------

/** assets/fonts, resolved from either the bundle (dist/cli.js) or the sources. */
export function fontDir(): string | null {
  const here = path.dirname(fileURLToPath(import.meta.url));
  for (const cand of [path.join(here, "..", "assets", "fonts"), path.join(here, "..", "..", "assets", "fonts")]) {
    if (fs.existsSync(cand)) return cand;
  }
  return null;
}

export function fontFiles(): string[] {
  const dir = fontDir();
  if (!dir) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => /\.(ttf|otf)$/i.test(f))
    .map((f) => path.join(dir, f))
    .sort();
}

/** Font options for @resvg/resvg-js: bundled faces first, system fonts only as a last resort. */
export function resvgFontOptions(): {
  fontFiles: string[];
  loadSystemFonts: boolean;
  defaultFontFamily: string;
  sansSerifFamily: string;
  monospaceFamily: string;
  serifFamily: string;
} {
  return {
    fontFiles: fontFiles(),
    loadSystemFonts: true,
    defaultFontFamily: SANS,
    sansSerifFamily: SANS,
    monospaceFamily: MONO,
    serifFamily: SANS,
  };
}

// ---------------------------------------------------------------------------
// svg helpers
// ---------------------------------------------------------------------------

interface TextOpts {
  size: number;
  fill?: string;
  family?: string;
  weight?: 400 | 500 | 600 | 700;
  anchor?: "start" | "middle" | "end";
  italic?: boolean;
  spacing?: number;
  upper?: boolean;
}

function text(x: number, y: number, s: string, o: TextOpts): string {
  const attrs = [
    `x="${x}"`,
    `y="${y}"`,
    `font-family="${o.family ?? SANS}"`,
    `font-size="${o.size}"`,
    `fill="${o.fill ?? INK}"`,
  ];
  if (o.weight && o.weight !== 400) attrs.push(`font-weight="${o.weight}"`);
  if (o.anchor && o.anchor !== "start") attrs.push(`text-anchor="${o.anchor}"`);
  if (o.italic) attrs.push(`font-style="italic"`);
  if (o.spacing) attrs.push(`letter-spacing="${o.spacing}"`);
  return `<text ${attrs.join(" ")}>${escapeXml(o.upper ? s.toUpperCase() : s)}</text>`;
}

const hr = (x1: number, x2: number, y: number, color = RULE, h = 1) =>
  `<rect x="${x1}" y="${y}" width="${x2 - x1}" height="${h}" fill="${color}"/>`;
const vr = (x: number, y1: number, y2: number, color = RULE) =>
  `<rect x="${x}" y="${y1}" width="1" height="${y2 - y1}" fill="${color}"/>`;

const monoW = (chars: number, size: number) => chars * size * CH;

const TAG: Record<HostCategory, string> = { TELEMETRY: "TELEMETRY", UNKNOWN: "OTHER", LLM_API: "LLM", AUTH: "AUTH", USER_OTLP: "USER OTLP" };

/** `http-intake.logs.us5.datadoghq.com` -> `datadoghq.com` for the compact callout. */
function vendorDomain(host: string): string {
  const parts = host.split(".");
  return parts.length > 2 ? parts.slice(-2).join(".") : host;
}

function gradeColor(grade: string): string {
  if (grade === "A+" || grade === "A" || grade === "B") return GREEN;
  if (grade === "D" || grade === "F") return RED;
  return INK;
}

function commandLine(report: AuditReport): string {
  return "$ " + report.commandLabel;
}

// ---------------------------------------------------------------------------
// layout
// ---------------------------------------------------------------------------

export function renderCardSvg(report: AuditReport, matcher: SensitiveMatcher): string {
  const p: string[] = [];
  const R = CARD_W - M; // right edge
  const grade = report.score.grade;
  const gcol = gradeColor(grade);
  const tracing = report.fileTracing ?? { mode: "none", coverage: "none", untraced: [] };
  const launcher = report.launcher?.name ?? "launcher";
  const date = (report.endedAt || new Date().toISOString()).slice(0, 10);

  p.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${CARD_W}" height="${CARD_H}" viewBox="0 0 ${CARD_W} ${CARD_H}">`);
  p.push(`<rect width="${CARD_W}" height="${CARD_H}" fill="${PAPER}"/>`);

  // ---- top bar -------------------------------------------------------------
  const stampW = 120;
  const stampX = R - stampW;
  const stampY = M;
  p.push(text(M, M + 13, `NARCX PRIVACY AUDIT  /  ${date}`, { size: 13, family: MONO, fill: MUTED, spacing: 1.5, upper: true }));
  const titleMax = Math.floor((stampX - 24 - M) / (36 * 0.56));
  p.push(text(M, M + 62, fit(report.title, titleMax), { size: 36, weight: 700 }));
  const cmdMax = Math.floor((stampX - 24 - M) / (15 * CH));
  p.push(text(M, M + 92, fit(commandLine(report), cmdMax), { size: 15, family: MONO }));

  // grade stamp
  p.push(`<rect x="${stampX + 1}" y="${stampY + 1}" width="${stampW - 2}" height="${stampW - 2}" fill="none" stroke="${gcol}" stroke-width="2"/>`);
  p.push(text(stampX + stampW / 2, stampY + 88, grade, { size: 76, weight: 700, fill: gcol, anchor: "middle" }));
  p.push(text(R, stampY + stampW + 22, `${report.score.score} / 100`, { size: 13, family: MONO, fill: MUTED, anchor: "end", spacing: 1 }));

  const topRuleY = 212;
  p.push(hr(M, R, topRuleY, INK, 2));

  // ---- metrics strip (target only, unless --include-children) ----------------
  const isGraded = (x: { attribution?: string }) => x.attribution === "target" || x.attribution === undefined || (report.includeChildren && x.attribution === "child");
  const hosts = report.hosts.filter((h) => !h.launcher && isGraded(h));
  const telemetry = hosts.filter((h) => h.category === "TELEMETRY");
  const other = hosts.filter((h) => h.category === "UNKNOWN");
  const isSecret = (f: FileSummary) => (f.kind ?? (f.graded === false ? "config" : "secret")) === "secret";
  const thirdParty = report.sensitiveFiles.filter((f) => !f.ownNamespace && !f.launcher && isSecret(f) && isGraded(f));
  const children = report.includeChildren ? [] : Object.values(report.childActivity ?? {}).filter((c) => c.telemetryHosts.length + c.otherHosts.length + c.llmHosts.length + c.authHosts.length + c.filesAccessed.length > 0);
  const unattributed = report.unattributedHosts ?? [];
  const untracedFiles = tracing.coverage === "none";
  const metrics: Array<{ label: string; value: string; hot: boolean; note?: string }> = [
    { label: "Telemetry hosts", value: String(telemetry.length), hot: telemetry.length > 0 },
    {
      label: "3rd-party secrets",
      value: untracedFiles ? "—" : String(thirdParty.length),
      hot: !untracedFiles && thirdParty.length > 0,
      note: untracedFiles ? "not traced" : tracing.coverage === "partial" ? "partial trace" : undefined,
    },
    { label: "Other outbound", value: String(other.length), hot: false },
    { label: "Audit mode", value: tracing.mode === "deep" ? "--deep" : "standard", hot: false },
  ];
  const stripTop = topRuleY + 14;
  const stripBottom = 322;
  const colW = (R - M) / 4;
  metrics.forEach((m, i) => {
    const x = M + colW * i + (i === 0 ? 0 : 20);
    p.push(text(x, stripTop + 16, m.label, { size: 11, family: MONO, fill: MUTED, spacing: 1.5, upper: true }));
    const isDash = m.value === "—";
    const isWord = !isDash && Number.isNaN(Number(m.value));
    const size = isDash ? 40 : isWord ? 30 : 40;
    p.push(text(x, stripTop + 66, m.value, { size, weight: 700, fill: isDash ? MUTED : m.hot ? RED : INK, family: isWord ? MONO : SANS }));
    if (m.note) {
      const valueW = isDash ? 40 : isWord ? monoW(m.value.length, 30) : m.value.length * 40 * 0.58;
      p.push(text(x + valueW + 14, stripTop + 66, m.note, { size: 12, family: MONO, fill: MUTED, italic: true }));
    }
    if (i > 0) p.push(vr(M + colW * i, stripTop, stripBottom));
  });
  p.push(hr(M, R, stripBottom + 10));

  // ---- two data columns ------------------------------------------------------
  const colTop = 362;
  const gap = 48;
  const cw = (R - M - gap) / 2; // 520
  const lx = M;
  const rx = M + cw + gap;
  const rowH = 36;
  const maxRows = children.length || unattributed.length ? 5 : 6; // leave room for the callout
  const firstBaseline = colTop + 34;

  const header = (x: number, label: string, right?: string) => {
    p.push(text(x, colTop, label, { size: 11, family: MONO, fill: MUTED, spacing: 1.5, upper: true }));
    if (right) p.push(text(x + cw, colTop, right, { size: 11, family: MONO, fill: MUTED, spacing: 1.5, upper: true, anchor: "end" }));
    p.push(hr(x, x + cw, colTop + 10));
  };

  /** How many items fit when an overflow line may be needed, keeping `reserved` slots free. */
  const visibleCount = (n: number, reserved: number) => {
    const slots = maxRows - reserved;
    return n <= slots ? n : slots - 1;
  };

  // left: outbound hosts
  header(lx, "Outbound hosts", "bytes sent");
  const orderedHosts: HostSummary[] = [...hosts, ...report.hosts.filter((h) => h.launcher && isGraded(h))];
  if (!orderedHosts.length) {
    p.push(text(lx, firstBaseline, "No network activity observed", { size: 15, family: MONO, fill: MUTED, italic: true }));
  } else {
    const shownHosts = visibleCount(orderedHosts.length, 0);
    orderedHosts.slice(0, shownHosts).forEach((h, i) => {
      const y = firstBaseline + rowH * i;
      const bytes = fmtBytes(h.bytesOut);
      const tag = h.launcher ? launcher.toUpperCase() : TAG[h.category];
      const hot = !h.launcher && h.category === "TELEMETRY";
      const bytesW = monoW(bytes.length, 13);
      const tagW = monoW(tag.length, 12) + (hot ? 1 : 0) * tag.length;
      const tagX = lx + cw - bytesW - 18;
      const hostMax = Math.floor((tagX - tagW - 16 - lx) / (15 * CH));
      p.push(text(lx, y, fit(h.host, hostMax), { size: 15, family: MONO, fill: h.launcher ? MUTED : INK }));
      p.push(text(tagX, y, tag, { size: 12, family: MONO, fill: hot ? RED : MUTED, weight: hot ? 700 : 400, anchor: "end", spacing: 1 }));
      p.push(text(lx + cw, y, bytes, { size: 13, family: MONO, fill: MUTED, anchor: "end" }));
      p.push(hr(lx, lx + cw, y + 12, ROW));
    });
    if (orderedHosts.length > shownHosts) {
      p.push(text(lx, firstBaseline + rowH * shownHosts, `+ ${orderedHosts.length - shownHosts} more in the JSON report`, { size: 12, family: MONO, fill: MUTED, italic: true }));
    }
  }

  // right: files accessed
  header(rx, "Files accessed");
  if (untracedFiles) {
    const who = tracing.untraced.length ? `: ${describeUntraced(tracing.untraced)}` : "";
    p.push(text(rx, firstBaseline, fit(`File reads not traced (native binary${who} — run with --deep)`, Math.floor(cw / (15 * CH))), { size: 15, family: MONO, fill: MUTED, italic: true }));
  } else {
    const kindOf = (f: FileSummary) => f.kind ?? (f.graded === false ? "config" : "secret");
    const mine = report.sensitiveFiles.filter(isGraded);
    // Real third-party secrets first, then cross-tool configs, then own, launcher, system.
    const files: FileSummary[] = [
      ...mine.filter((f) => !f.ownNamespace && !f.launcher && kindOf(f) === "secret"),
      ...mine.filter((f) => !f.ownNamespace && !f.launcher && kindOf(f) === "config"),
      ...mine.filter((f) => f.ownNamespace && !f.launcher && kindOf(f) !== "system"),
      ...mine.filter((f) => f.launcher && kindOf(f) !== "system"),
      ...mine.filter((f) => kindOf(f) === "system"),
    ];
    const partial = tracing.coverage === "partial";
    const rowsAvail = visibleCount(files.length, partial ? 1 : 0);
    if (!files.length) {
      p.push(text(rx, firstBaseline, "No watchlist files read", { size: 15, family: MONO, fill: MUTED, italic: true }));
    } else {
      files.slice(0, rowsAvail).forEach((f, i) => {
        const y = firstBaseline + rowH * i;
        const k = kindOf(f);
        const tag = k === "system" ? "TRUST STORE" : f.launcher ? launcher.toUpperCase() : f.ownNamespace ? "OWN" : k === "config" ? "CONFIG" : "3RD-PARTY";
        const hot = !f.launcher && !f.ownNamespace && k === "secret";
        const tagW = monoW(tag.length, 12);
        const pathMax = Math.floor((cw - tagW - 24) / (15 * CH));
        p.push(text(rx, y, fitLeft(matcher.display(f.path), pathMax), { size: 15, family: MONO, fill: hot ? INK : MUTED }));
        p.push(text(rx + cw, y, tag, { size: 12, family: MONO, fill: hot ? RED : MUTED, weight: hot ? 700 : 400, anchor: "end", spacing: 1 }));
        p.push(hr(rx, rx + cw, y + 12, ROW));
      });
      if (files.length > rowsAvail) {
        p.push(text(rx, firstBaseline + rowH * rowsAvail, `+ ${files.length - rowsAvail} more in the JSON report`, { size: 12, family: MONO, fill: MUTED, italic: true }));
      }
    }
    if (partial) {
      // Always the last slot: rows (and a possible "+N more" line) never reach it.
      const y = firstBaseline + rowH * (maxRows - 1);
      const msg = `Not hooked: ${describeUntraced(tracing.untraced)} · needs --deep`;
      p.push(text(rx, y, fit(msg, Math.floor(cw / (13 * CH))), { size: 13, family: MONO, fill: MUTED, italic: true }));
    }
  }

  // ---- child-traffic callout: understated, above the footer -------------------
  if (children.length || unattributed.length) {
    const ranked = [...children].sort((a, b) => b.telemetryHosts.length - a.telemetryHosts.length || b.otherHosts.length - a.otherHosts.length);
    const spacing = 0.5;
    const maxChars = Math.floor((R - M) / (12 * CH + spacing));
    // Degrade gracefully: all children with file counts -> without file counts -> fewer children -> ellipsis.
    const build = (count: number, withFiles: boolean) => {
      const shown = ranked.slice(0, count);
      const parts = shown.map((c) => {
        const hostsShort = [...new Set([...c.telemetryHosts, ...c.otherHosts].map(vendorDomain))];
        const files = withFiles && c.filesAccessed.length ? ` (+${c.filesAccessed.length} file${c.filesAccessed.length === 1 ? "" : "s"})` : "";
        return `via ${c.processName}: ${hostsShort.length ? hostsShort.join(", ") : "no telemetry"}${files}`;
      });
      if (ranked.length > shown.length) parts.push(`+${ranked.length - shown.length} more`);
      if (unattributed.length) parts.push(`unattributed: ${[...new Set(unattributed.map(vendorDomain))].join(", ")}`);
      const head = ranked.length ? "CHILD TRAFFIC EXCLUDED FROM GRADE" : "EXCLUDED FROM GRADE";
      return `${head} · ${parts.join(" · ")}`;
    };
    let callout = build(ranked.length, true);
    if (callout.length > maxChars) callout = build(ranked.length, false);
    for (let n = ranked.length - 1; callout.length > maxChars && n >= 0; n--) callout = build(n, false);
    p.push(hr(M, R, 561));
    p.push(text(M, 580, fit(callout, maxChars), { size: 12, family: MONO, fill: MUTED, spacing }));
  }

  // ---- footer ----------------------------------------------------------------
  const footRule = 595;
  p.push(hr(M, R, footRule));
  const footer = report.footer || "out-of-the-box defaults · no TLS interception · zero auditor network calls";
  p.push(text(M, footRule + 24, fit(footer, Math.floor((R - M - 120) / (12 * CH))), { size: 12, family: MONO, fill: MUTED }));
  p.push(text(R, footRule + 24, "npx narcx", { size: 15, family: MONO, weight: 700, anchor: "end" }));

  p.push("</svg>");
  return p.join("\n");
}

export async function writeCardPng(report: AuditReport, matcher: SensitiveMatcher, outPath: string): Promise<string> {
  const svg = renderCardSvg(report, matcher);
  const { Resvg } = await import("@resvg/resvg-js");
  const resvg = new Resvg(svg, {
    fitTo: { mode: "width", value: CARD_W },
    background: PAPER,
    font: resvgFontOptions(),
  });
  const png = resvg.render().asPng();
  const abs = path.resolve(outPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, png);
  return abs;
}
