import type { Deduction, Grade, ScoreResult } from "./types.js";

export const PENALTY = {
  TELEMETRY_HOST: 25,
  SENSITIVE_FILE: 30,
  UNKNOWN_HOST: 10,
} as const;

export interface ScoreInput {
  /** Unique telemetry hosts contacted. */
  telemetryHosts: string[];
  /** Unique sensitive files read outside the tool's own namespace. */
  sensitiveFiles: string[];
  /** Unique unknown outbound hosts. */
  unknownHosts: string[];
}

export function gradeFromScore(score: number): Grade {
  if (score >= 100) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

export function computeScore(input: ScoreInput): ScoreResult {
  const deductions: Deduction[] = [];
  for (const f of input.sensitiveFiles) {
    deductions.push({
      reason: "sensitive-file",
      points: -PENALTY.SENSITIVE_FILE,
      detail: f,
    });
  }
  for (const h of input.telemetryHosts) {
    deductions.push({ reason: "telemetry-host", points: -PENALTY.TELEMETRY_HOST, detail: h });
  }
  for (const h of input.unknownHosts) {
    deductions.push({ reason: "unknown-host", points: -PENALTY.UNKNOWN_HOST, detail: h });
  }
  const total = deductions.reduce((acc, d) => acc + d.points, 0);
  const score = Math.max(0, Math.min(100, 100 + total));
  return { score, grade: gradeFromScore(score), deductions };
}

export const GRADE_COLOR: Record<Grade, string> = {
  "A+": "#3fb950",
  A: "#3fb950",
  B: "#a5d63f",
  C: "#d29922",
  D: "#f0883e",
  F: "#f85149",
};
