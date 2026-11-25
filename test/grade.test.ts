import { describe, expect, it } from "vitest";
import { PENALTY, computeScore, gradeFromScore } from "../src/core/grade.js";

describe("gradeFromScore", () => {
  it("maps score bands to letters", () => {
    expect(gradeFromScore(100)).toBe("A+");
    expect(gradeFromScore(99)).toBe("A");
    expect(gradeFromScore(90)).toBe("A");
    expect(gradeFromScore(89)).toBe("B");
    expect(gradeFromScore(80)).toBe("B");
    expect(gradeFromScore(79)).toBe("C");
    expect(gradeFromScore(65)).toBe("C");
    expect(gradeFromScore(64)).toBe("D");
    expect(gradeFromScore(50)).toBe("D");
    expect(gradeFromScore(49)).toBe("F");
    expect(gradeFromScore(0)).toBe("F");
  });
});

describe("computeScore", () => {
  const none = { telemetryHosts: [], sensitiveFiles: [], unknownHosts: [] };

  it("starts at 100 / A+ with nothing observed", () => {
    const r = computeScore(none);
    expect(r.score).toBe(100);
    expect(r.grade).toBe("A+");
    expect(r.deductions).toEqual([]);
  });

  it("deducts 25 per telemetry host", () => {
    const r = computeScore({ ...none, telemetryHosts: ["posthog.com"] });
    expect(r.score).toBe(75);
    expect(r.grade).toBe("C");
    expect(r.deductions).toEqual([{ reason: "telemetry-host", points: -PENALTY.TELEMETRY_HOST, detail: "posthog.com" }]);
  });

  it("deducts 30 per sensitive file and 10 per unknown host", () => {
    const r = computeScore({ telemetryHosts: [], sensitiveFiles: ["~/.ssh/id_rsa"], unknownHosts: ["a.example", "b.example"] });
    expect(r.score).toBe(50);
    expect(r.grade).toBe("D");
    expect(r.deductions.map((d) => d.points)).toEqual([-30, -10, -10]);
  });

  it("one unknown host is still an A", () => {
    expect(computeScore({ ...none, unknownHosts: ["registry.npmjs.org"] }).grade).toBe("A");
  });

  it("clamps at zero", () => {
    const r = computeScore({ telemetryHosts: ["a", "b", "c", "d", "e"], sensitiveFiles: [], unknownHosts: [] });
    expect(r.score).toBe(0);
    expect(r.grade).toBe("F");
  });
});
