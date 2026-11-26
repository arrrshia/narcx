import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Collector, type Alert } from "../src/core/collector.js";
import { userOtlpHostsFromEnv } from "../src/core/classify.js";
import { SensitiveMatcher } from "../src/core/watchlist.js";
import { ProcessAttributor, processLabel, resolveTarget, scriptOf, type ProcRecord } from "../src/process-attribution.js";
import { parseLsofPorts, PortPidResolver } from "../src/layers/pidresolver.js";

// A throwaway install layout:
//   <root>/node_modules/t3/bin/t3.js            (wrapper the user runs)
//   <root>/node_modules/t3/dist/server.js       (bundled helper, target)
//   <root>/node_modules/@openai/codex/bin/codex.js + vendor/.../codex (bundled native, target)
//   <ext>/claude, <ext>/git                      (external binaries, child)
let root = "";
let ext = "";
beforeAll(() => {
  root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "narc-att-"));
  ext = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "narc-ext-"));
  const mk = (rel: string, content = "#!/bin/sh\n") => {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content, { mode: 0o755 });
    return p;
  };
  mk("node_modules/t3/package.json", '{"name":"t3"}');
  mk("node_modules/t3/bin/t3.js", "#!/usr/bin/env node\n");
  mk("node_modules/t3/dist/server.js", "");
  mk("node_modules/@openai/codex/package.json", '{"name":"@openai/codex"}');
  mk("node_modules/@openai/codex/bin/codex.js", "#!/usr/bin/env node\n");
  mk("node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex", "\xcf\xfa\xed\xfe");
  fs.mkdirSync(path.join(root, "node_modules/.bin"), { recursive: true });
  fs.symlinkSync("../t3/bin/t3.js", path.join(root, "node_modules/.bin/t3"));
  fs.symlinkSync("../@openai/codex/bin/codex.js", path.join(root, "node_modules/.bin/codex"));
  for (const b of ["claude", "git", "gh"]) fs.writeFileSync(path.join(ext, b), "#!/bin/sh\n", { mode: 0o755 });
});
afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(ext, { recursive: true, force: true });
});

describe("resolveTarget", () => {
  it("derives identity and install root from a .bin wrapper", () => {
    const t = resolveTarget([path.join(root, "node_modules/.bin/t3")]);
    expect(t.identity).toBe("t3");
    expect(t.root).toBe(path.join(root, "node_modules/t3"));
  });
  it("uses the script, not the interpreter, for `node script.js`", () => {
    const t = resolveTarget(["/usr/local/bin/node", path.join(root, "node_modules/t3/dist/server.js")]);
    expect(t.identity).toBe("server");
    expect(t.root).toBe(path.join(root, "node_modules/t3"));
  });
  it("keeps the typed name when the binary is a version string", () => {
    const vdir = path.join(root, ".local/share/claude/versions");
    fs.mkdirSync(vdir, { recursive: true });
    fs.writeFileSync(path.join(vdir, "2.1.323"), "\xcf\xfa\xed\xfe", { mode: 0o755 });
    fs.mkdirSync(path.join(root, ".local/bin"), { recursive: true });
    fs.symlinkSync(path.join(vdir, "2.1.323"), path.join(root, ".local/bin/claude"));
    const t = resolveTarget([path.join(root, ".local/bin/claude")]);
    expect(t.identity).toBe("claude");
    expect(t.root).toBe(path.join(root, ".local/share/claude"));
  });
});

describe("ProcessAttributor", () => {
  const procs = new Map<number, ProcRecord>();
  const attr = () => new ProcessAttributor(100, [path.join(root, "node_modules/.bin/t3")], (pid) => procs.get(pid));

  it("keeps the root, bundled scripts and bundled native binaries as target", () => {
    procs.clear();
    procs.set(100, { pid: 100, ppid: 1, exe: "/usr/local/bin/node", args: `node ${path.join(root, "node_modules/.bin/t3")}` });
    procs.set(101, { pid: 101, ppid: 100, exe: "/usr/local/bin/node", args: `node ${path.join(root, "node_modules/t3/dist/server.js")} --port 3773` });
    procs.set(102, { pid: 102, ppid: 101, exe: "/bin/sh", args: "sh -c echo hi" });
    const a = attr();
    expect(a.classify(100)).toMatchObject({ attribution: "target", processName: "t3" });
    expect(a.classify(101)).toMatchObject({ attribution: "target", processName: "server" });
    expect(a.classify(102)).toMatchObject({ attribution: "target" }); // inline shell belongs to whoever spawned it
  });

  it("keeps a bundled native binary target when auditing its Node wrapper", () => {
    procs.clear();
    const codexBin = path.join(root, "node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex");
    procs.set(200, { pid: 200, ppid: 1, exe: "/usr/local/bin/node", args: `node ${path.join(root, "node_modules/.bin/codex")} exec hi` });
    procs.set(201, { pid: 201, ppid: 200, exe: codexBin, args: `${codexBin} exec hi` });
    const a = new ProcessAttributor(200, [path.join(root, "node_modules/.bin/codex"), "exec", "hi"], (pid) => procs.get(pid));
    expect(a.classify(201)).toMatchObject({ attribution: "target", processName: "codex" });
  });

  it("classifies external CLIs the tool spawns as child, grouped under the first external binary", () => {
    procs.clear();
    procs.set(100, { pid: 100, ppid: 1, exe: "/usr/local/bin/node", args: `node ${path.join(root, "node_modules/.bin/t3")}` });
    procs.set(110, { pid: 110, ppid: 100, exe: path.join(ext, "claude"), args: "claude -p hi" });
    procs.set(111, { pid: 111, ppid: 110, exe: path.join(ext, "git"), args: "git status" });
    procs.set(120, { pid: 120, ppid: 100, exe: path.join(ext, "gh"), args: "gh auth status" });
    const a = attr();
    expect(a.classify(110)).toEqual({ pid: 110, attribution: "child", processName: "claude", via: "claude" });
    expect(a.classify(111)).toEqual({ pid: 111, attribution: "child", processName: "git", via: "claude" });
    expect(a.classify(120)).toEqual({ pid: 120, attribution: "child", processName: "gh", via: "gh" });
  });

  it("recognises the target's own helpers by name or data directory even outside the install root", () => {
    procs.clear();
    procs.set(100, { pid: 100, ppid: 1, exe: "/usr/local/bin/node", args: `node ${path.join(root, "node_modules/.bin/t3")}` });
    procs.set(130, { pid: 130, ppid: 100, exe: path.join(ext, "t3-resource-monitor"), args: "t3-resource-monitor" });
    procs.set(131, { pid: 131, ppid: 100, exe: path.join(ext, ".t3/runtime/versions/0.1.12/t3"), args: "t3 serve" });
    const a = attr();
    expect(a.classify(130).attribution).toBe("target");
    expect(a.classify(131).attribution).toBe("target");
  });

  it("falls back to target/unknown for a pid nobody can describe", () => {
    procs.clear();
    const a = attr();
    expect(a.classify(999999)).toMatchObject({ attribution: "target", processName: "unknown" });
  });

  it("classifies by accounting name using the processes it knows", () => {
    procs.clear();
    procs.set(100, { pid: 100, ppid: 1, exe: "/usr/local/bin/node", args: `node ${path.join(root, "node_modules/.bin/t3")}` });
    procs.set(110, { pid: 110, ppid: 100, exe: path.join(ext, "claude"), args: "claude" });
    const a = attr();
    expect(a.classifyName("claude", [...procs.values()])).toMatchObject({ attribution: "child", via: "claude" });
    expect(a.classifyName("nobody", [...procs.values()])).toBeNull();
  });

  it("names version-string executables after their product directory", () => {
    expect(processLabel({ exe: "/Users/u/.local/share/claude/versions/2.1.323", args: "" })).toBe("claude");
    expect(processLabel({ exe: "/opt/foo/releases/v1.2.3/bin/2.0.0", args: "" })).toBe("foo");
    expect(processLabel({ exe: "/usr/local/bin/codex", args: "codex exec" })).toBe("codex");
  });

  it("labels interpreter processes by their script", () => {
    expect(processLabel({ exe: "/usr/local/bin/node", args: "node /usr/lib/node_modules/npm/bin/npm-cli.js view x" })).toBe("npm");
    expect(scriptOf("node --require /x/preload.cjs /srv/app/server.mjs")).toBe("/srv/app/server.mjs");
    expect(scriptOf("node -e console.log(1)")).toBeNull();
  });
});

describe("Collector with attribution", () => {
  const HOME = "/Users/tester";
  const mk = (extra: Partial<ConstructorParameters<typeof Collector>[0]> = {}) =>
    new Collector({ matcher: new SensitiveMatcher(HOME), ownNamespaces: new Set(["t3"]), ...extra });
  const attributor = (pid: number) =>
    pid === 1 ? { pid, processName: "t3", attribution: "target" as const, via: "" } : { pid, processName: "claude", attribution: "child" as const, via: "claude" };

  it("does not grade a child's telemetry or its own config reads, but reports them", () => {
    const c = mk();
    c.setAttributor(attributor);
    const alerts: Alert[] = [];
    c.on("alert", (a: Alert) => alerts.push(a));
    c.addNet({ source: "proxy", pid: 2, host: "http-intake.logs.us5.datadoghq.com", port: 443, protocol: "https", method: "CONNECT", bytesOut: 100 });
    c.addNet({ source: "proxy", pid: 2, host: "api.anthropic.com", port: 443, protocol: "https", method: "CONNECT", bytesOut: 50 });
    c.addFile({ source: "preload", pid: 2, path: "/Users/tester/.claude.json", op: "readFileSync" });
    c.addNet({ source: "preload", pid: 1, host: "ingest.t3.codes", port: 443, protocol: "https", method: "POST", path: "/batch/", bytesOut: 10 });
    c.addFile({ source: "preload", pid: 1, path: "/Users/tester/.codex/auth.json", op: "readFile" });
    expect(c.score().deductions.map((d) => d.detail)).toEqual(["~/.codex/auth.json", "ingest.t3.codes"]);
    expect(c.score().score).toBe(45);
    expect(c.childActivity()).toEqual({
      claude: { processName: "claude", telemetryHosts: ["http-intake.logs.us5.datadoghq.com"], otherHosts: [], llmHosts: ["api.anthropic.com"], authHosts: [], filesAccessed: ["~/.claude.json"], bytesOut: 150 },
    });
    expect(c.hostSummaries().find((h) => h.host === "ingest.t3.codes")).toMatchObject({ attribution: "target" });
    expect(alerts.find((a) => a.kind === "net" && a.event.host.endsWith("datadoghq.com"))?.attribution?.attribution).toBe("child");
  });

  it("folds children into the grade with includeChildren", () => {
    const c = mk({ includeChildren: true });
    c.setAttributor(attributor);
    c.addNet({ source: "proxy", pid: 2, host: "http-intake.logs.us5.datadoghq.com", port: 443, protocol: "https", method: "CONNECT" });
    expect(c.score().score).toBe(75);
  });

  it("treats a host touched by both target and child as the target's", () => {
    const c = mk();
    c.setAttributor(attributor);
    c.addNet({ source: "proxy", pid: 2, host: "github.com", port: 443, protocol: "https", method: "CONNECT" });
    c.addNet({ source: "proxy", pid: 1, host: "github.com", port: 443, protocol: "https", method: "CONNECT" });
    expect(c.hostSummaries()[0]).toMatchObject({ attribution: "target", processNames: ["claude", "t3"] });
    expect(c.score().score).toBe(90);
  });

  it("attaches a pid learnt later by the proxy", () => {
    const c = mk();
    c.setAttributor(attributor);
    const ev = c.addNet({ source: "proxy", host: "http-intake.logs.us5.datadoghq.com", port: 443, protocol: "https", method: "CONNECT" })!;
    expect(c.hostSummaries()[0]!.attribution).toBe("target"); // unknown pid: counted against the target
    c.setNetPid(ev.id, 2);
    expect(c.hostSummaries()[0]!.attribution).toBe("child");
    expect(c.score().score).toBe(100);
  });

  it("honours explicit attribution carried by regraded events", () => {
    const c = mk();
    c.addFile({ source: "fs_usage", path: "/Users/tester/.aws/credentials", op: "open", attribution: { processName: "codex", attribution: "child", via: "codex" } });
    expect(c.sensitiveFiles()[0]).toMatchObject({ attribution: "child", via: "codex" });
    expect(c.score().score).toBe(100);
  });
});

describe("USER OTLP", () => {
  it("reads hostnames from the OTEL exporter variables", () => {
    expect(
      userOtlpHostsFromEnv({
        OTEL_EXPORTER_OTLP_ENDPOINT: "https://otlp-gateway-prod-us-east-3.grafana.net/otlp",
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "collector.internal:4318",
        OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: "http://localhost:4318",
      }),
    ).toEqual(["otlp-gateway-prod-us-east-3.grafana.net", "collector.internal"]);
    expect(userOtlpHostsFromEnv({})).toEqual([]);
  });

  it("tags a user-configured endpoint USER OTLP with no penalty", () => {
    const c = new Collector({ matcher: new SensitiveMatcher("/Users/tester"), ownNamespaces: new Set(), userOtlpHosts: ["otlp-gateway-prod-us-east-3.grafana.net"] });
    c.addNet({ source: "proxy", host: "otlp-gateway-prod-us-east-3.grafana.net", port: 443, protocol: "https", method: "CONNECT" });
    c.addNet({ source: "proxy", host: "http-intake.logs.us5.datadoghq.com", port: 443, protocol: "https", method: "CONNECT" });
    expect(c.hostSummaries().map((h) => [h.host, h.category])).toEqual([
      ["http-intake.logs.us5.datadoghq.com", "TELEMETRY"],
      ["otlp-gateway-prod-us-east-3.grafana.net", "USER_OTLP"],
    ]);
    expect(c.score()).toMatchObject({ score: 75, grade: "C" });
  });
});

describe("proxy port -> pid resolver", () => {
  it("parses lsof -F pn output for connections to the proxy port", () => {
    const out = ["p4242", "f12", "n127.0.0.1:50001->127.0.0.1:9999", "p4300", "f3", "n127.0.0.1:50002->127.0.0.1:9999", "f4", "n127.0.0.1:50003->127.0.0.1:8888", "p4400", "f5", "n[::1]:50004->[::1]:9999"].join("\n");
    const map = parseLsofPorts(out, 9999);
    expect([...map]).toEqual([
      [50001, 4242],
      [50002, 4300],
      [50004, 4400],
    ]);
  });

  it("resolves to null, not a wrong pid, when the connection is already gone", async () => {
    const r = new PortPidResolver({ pids: () => [process.pid], proxyPort: 1, attempts: 2 });
    const pid = await r.resolve(65534);
    expect(pid).toBeNull();
  });
});
