#!/usr/bin/env node
/**
 * Compare T3 Code's default audit with the telemetry-disabled variant and check
 * the attribution expectations:
 *   1. default:  ingest.t3.codes + axiom.co are TARGET telemetry; datadoghq.com + grafana.net are CHILD via claude
 *   2. variant:  zero TARGET telemetry hosts
 *
 *   node scripts/compare-t3.mjs [default-dir] [variant-dir]
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const A = path.resolve(process.argv[2] ?? path.join(ROOT, "audit-results"));
const B = path.resolve(process.argv[3] ?? path.join(ROOT, "audit-results-t3-telemetry-off"));
const load = (dir) => JSON.parse(fs.readFileSync(path.join(dir, "t3code.json"), "utf8"));
const a = load(A);
const b = load(B);

const show = (label, r) => {
  const tel = (att) => r.hosts.filter((h) => h.category === "TELEMETRY" && (att === "child" ? h.attribution === "child" : h.attribution !== "child"));
  console.log(`\n${label}: ${r.title} · grade ${r.score.grade} (${r.score.score}) · mode ${r.fileTracing.mode}`);
  for (const h of r.hosts) console.log(`  [${h.category.padEnd(9)}] ${h.host.padEnd(44)} ${h.attribution === "child" ? "child via " + h.via : "target"}`);
  console.log(`  target telemetry: ${tel("target").map((h) => h.host).join(", ") || "none"}`);
  console.log(`  child telemetry:  ${tel("child").map((h) => `${h.host} (${h.via})`).join(", ") || "none"}`);
  return { targetTel: tel("target").map((h) => h.host), childTel: tel("child") };
};
const ra = show("DEFAULT", a);
const rb = show("TELEMETRY DISABLED", b);

const checks = [
  ["default: ingest.t3.codes is target telemetry", ra.targetTel.includes("ingest.t3.codes")],
  ["default: axiom.co is target telemetry", ra.targetTel.some((h) => h.endsWith("axiom.co"))],
  ["default: datadoghq.com is child via claude", ra.childTel.some((h) => h.host.endsWith("datadoghq.com") && h.via === "claude")],
  ["default: grafana.net is child via claude", ra.childTel.some((h) => h.host.endsWith("grafana.net") && h.via === "claude")],
  ["telemetry disabled: zero target telemetry hosts", rb.targetTel.length === 0],
];
console.log("");
let ok = true;
for (const [name, pass] of checks) {
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${name}`);
  ok &&= pass;
}
process.exit(ok ? 0 : 1);
