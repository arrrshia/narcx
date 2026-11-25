import { describe, expect, it } from "vitest";
import { Collector, type Alert } from "../src/core/collector.js";
import { SensitiveMatcher } from "../src/core/watchlist.js";

const HOME = "/Users/tester";
const mk = (own: string[] = [], ignore: number[] = []) =>
  new Collector({ matcher: new SensitiveMatcher(HOME), ownNamespaces: new Set(own), ignoreLocalPorts: ignore });

describe("Collector files", () => {
  it("records sensitive reads once per path and emits a high alert on first sight", () => {
    const c = mk();
    const alerts: Alert[] = [];
    c.on("alert", (a: Alert) => alerts.push(a));
    c.addFile({ source: "preload", pid: 1, path: "/Users/tester/.ssh/id_rsa", op: "readFileSync" });
    c.addFile({ source: "preload", pid: 1, path: "/Users/tester/.ssh/id_rsa", op: "open" });
    c.addFile({ source: "preload", pid: 1, path: "/Users/tester/project/src/a.ts", op: "readFileSync" });
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.level).toBe("high");
    const files = c.sensitiveFiles();
    expect(files).toHaveLength(1);
    expect(files[0]!.ops).toEqual({ readFileSync: 1, open: 1 });
    expect(c.score().score).toBe(70);
  });

  it("does not penalise a tool's own namespace", () => {
    const c = mk(["claude"]);
    c.addFile({ source: "preload", path: "/Users/tester/.claude.json", op: "readFileSync" });
    c.addFile({ source: "preload", path: "/Users/tester/.aws/credentials", op: "readFileSync" });
    expect(c.sensitiveFiles().map((f) => [f.path.split("/").pop(), f.ownNamespace])).toEqual([["credentials", false], [".claude.json", true]]);
    expect(c.score().score).toBe(70);
  });

  it("lists probes of absent watchlist paths separately and does not grade them", () => {
    const c = mk();
    const alerts: Alert[] = [];
    c.on("alert", (a: Alert) => alerts.push(a));
    c.addFile({ source: "preload", pid: 1, path: "/Users/tester/project/.npmrc", op: "promises.readFile", exists: false });
    c.addFile({ source: "preload", pid: 1, path: "/Users/tester/.aws/credentials", op: "readFileSync", exists: true });
    c.addFile({ source: "preload", pid: 1, path: "/Users/tester/.ssh/id_rsa", op: "readFileSync" }); // no flag = exists
    expect(alerts).toHaveLength(2);
    expect(c.sensitiveFiles().map((f) => f.path.split("/").pop())).toEqual(["credentials", "id_rsa"]);
    expect(c.probedFiles().map((f) => f.path.split("/").pop())).toEqual([".npmrc"]);
    expect(c.score().score).toBe(40);
  });

  it("keeps non-sensitive dotfiles as low-priority context", () => {
    const c = mk();
    c.addFile({ source: "preload", path: "/Users/tester/.zshrc", op: "readFileSync" });
    expect(c.sensitiveFiles()).toHaveLength(0);
    expect(c.otherDotfiles().map((f) => f.path)).toEqual(["/Users/tester/.zshrc"]);
    expect(c.score().score).toBe(100);
  });
});

describe("Collector per-process ownership", () => {
  it("treats a helper reading its own config as own, not third-party", () => {
    const c = mk(); // audited tool: unknown
    c.addFile({ source: "fs_usage", path: "/Users/tester/.gitconfig", op: "open", proc: "git-remote-https" });
    c.addFile({ source: "fs_usage", path: "/Users/tester/.netrc", op: "open", proc: "git" });
    c.addFile({ source: "fs_usage", path: "/Users/tester/.codex/auth.json", op: "open", proc: "codex" });
    c.addFile({ source: "fs_usage", path: "/Users/tester/.aws/credentials", op: "open", proc: "codex" });
    const files = c.sensitiveFiles();
    expect(files.map((f) => [f.path.split("/").pop(), f.ownNamespace, f.procs])).toEqual([
      ["credentials", false, ["codex"]],
      ["auth.json", true, ["codex"]],
      [".gitconfig", true, ["git-remote-https"]],
      [".netrc", true, ["git"]],
    ]);
    expect(c.score().deductions.map((d) => d.detail)).toEqual(["~/.aws/credentials"]);
  });

  it("resolves hook pids to process names and requires every toucher to own the file", () => {
    const c = mk();
    c.setProcessResolver((pid) => ({ 1: "t3", 2: "codex" })[pid]);
    c.addFile({ source: "preload", pid: 2, path: "/Users/tester/.codex/config.toml", op: "readFile" });
    c.addFile({ source: "preload", pid: 1, path: "/Users/tester/.codex/models_cache.json", op: "readFile" });
    c.addFile({ source: "preload", pid: 2, path: "/Users/tester/.codex/models_cache.json", op: "readFile" });
    const files = c.sensitiveFiles();
    expect(files.map((f) => [f.path.split("/").pop(), f.ownNamespace])).toEqual([
      ["config.toml", true],
      ["models_cache.json", false],
    ]);
  });

  it("reports keychain trust-store opens without grading them", () => {
    const c = mk();
    c.addFile({ source: "fs_usage", path: "/Users/tester/Library/Keychains/login.keychain-db", op: "open", proc: "codex" });
    c.addFile({ source: "fs_usage", path: "/Library/Keychains/System.keychain", op: "open", proc: "codex" });
    expect(c.sensitiveFiles().map((f) => f.graded)).toEqual([false, false]);
    expect(c.score().score).toBe(100);
  });
});

describe("Collector loopback, dedup and auth rules", () => {
  it("never records loopback as an outbound host", () => {
    const c = mk();
    expect(c.addNet({ source: "preload", host: "localhost", port: 11434, protocol: "http", method: "POST", path: "/api/generate" })).toBeNull();
    expect(c.addNet({ source: "lsof", host: "127.0.0.1", port: 5000, protocol: "tcp" })).toBeNull();
    expect(c.addNet({ source: "lsof", host: "::1", port: 5000, protocol: "tcp" })).toBeNull();
    expect(c.hostSummaries()).toEqual([]);
    expect(c.score().score).toBe(100);
  });

  it("suppresses raw IPs from lsof when the proxy already named hosts in the run", () => {
    const c = mk();
    c.addNet({ source: "proxy", host: "chatgpt.com", port: 443, protocol: "https", method: "CONNECT", bytesOut: 10 });
    c.addNet({ source: "lsof", host: "104.18.38.10", port: 443, protocol: "tcp" });
    c.addNet({ source: "lsof", host: "151.101.0.223", port: 443, protocol: "tcp" });
    expect(c.hostSummaries().map((h) => h.host)).toEqual(["chatgpt.com"]);
    expect(c.suppressedHosts().map((h) => h.host).sort()).toEqual(["104.18.38.10", "151.101.0.223"]);
    expect(c.score().score).toBe(100);
  });

  it("still grades raw IPs when nothing else could name the connection", () => {
    const c = mk();
    c.addNet({ source: "lsof", host: "104.18.38.10", port: 443, protocol: "tcp" });
    expect(c.hostSummaries().map((h) => h.host)).toEqual(["104.18.38.10"]);
    expect(c.suppressedHosts()).toEqual([]);
    expect(c.score().score).toBe(90);
  });

  it("does not penalise LLM and auth backends", () => {
    const c = mk();
    c.addNet({ source: "proxy", host: "chatgpt.com", port: 443, protocol: "https", method: "CONNECT" });
    c.addNet({ source: "proxy", host: "mcp-proxy.anthropic.com", port: 443, protocol: "https", method: "CONNECT" });
    c.addNet({ source: "preload", host: "oauth2.googleapis.com", port: 443, protocol: "https", method: "POST", path: "/token" });
    c.addNet({ source: "proxy", host: "ab.chatgpt.com", port: 443, protocol: "https", method: "CONNECT" });
    expect(c.hostSummaries().map((h) => [h.host, h.category])).toEqual([
      ["ab.chatgpt.com", "TELEMETRY"],
      ["chatgpt.com", "LLM_API"],
      ["mcp-proxy.anthropic.com", "LLM_API"],
      ["oauth2.googleapis.com", "AUTH"],
    ]);
    expect(c.score()).toMatchObject({ score: 75, grade: "C" });
  });
});

describe("Collector launcher attribution", () => {
  it("reports but does not grade activity that only the package runner did", () => {
    const c = mk();
    c.setLauncher(100, "npx");
    c.addFile({ source: "preload", pid: 100, path: "/Users/tester/.gitconfig", op: "readFileSync" });
    c.addFile({ source: "preload", pid: 200, path: "/Users/tester/.ssh/id_rsa", op: "readFileSync" });
    c.addNet({ source: "preload", pid: 100, host: "registry.npmjs.org", port: 443, protocol: "https", method: "GET", path: "/foo" });
    c.addNet({ source: "proxy", host: "registry.npmjs.org", port: 443, protocol: "https", method: "CONNECT" });
    c.addNet({ source: "preload", pid: 200, host: "cdn.vendor.io", port: 443, protocol: "https", method: "GET", path: "/x" });
    const files = c.sensitiveFiles();
    expect(files.map((f) => [f.path.split("/").pop(), f.launcher])).toEqual([[".gitconfig", true], ["id_rsa", false]]);
    const hosts = c.hostSummaries();
    expect(hosts.map((h) => [h.host, h.launcher])).toEqual([["cdn.vendor.io", false], ["registry.npmjs.org", true]]);
    expect(c.score().deductions.map((d) => d.detail)).toEqual(["~/.ssh/id_rsa", "cdn.vendor.io"]);
  });

  it("still grades a host the tool itself also contacted", () => {
    const c = mk();
    c.setLauncher(100, "npx");
    c.addNet({ source: "preload", pid: 100, host: "registry.npmjs.org", port: 443, protocol: "https", method: "GET", path: "/t3" });
    c.addNet({ source: "preload", pid: 300, host: "registry.npmjs.org", port: 443, protocol: "https", method: "GET", path: "/@openai%2fcodex" });
    expect(c.hostSummaries()[0]!.launcher).toBe(false);
    expect(c.score().score).toBe(90);
  });

  it("does nothing without a launcher", () => {
    const c = mk();
    c.addFile({ source: "preload", pid: 100, path: "/Users/tester/.gitconfig", op: "readFileSync" });
    expect(c.sensitiveFiles()[0]!.launcher).toBe(false);
    expect(c.score().score).toBe(70);
  });
});

describe("Collector hosts", () => {
  it("classifies, counts and ignores narc's own loopback ports", () => {
    const c = mk([], [5555]);
    c.addNet({ source: "lsof", host: "127.0.0.1", port: 5555, protocol: "tcp" });
    c.addNet({ source: "preload", host: "us.i.posthog.com", port: 443, protocol: "https", method: "POST", path: "/batch/", bytesOut: 100 });
    c.addNet({ source: "preload", host: "US.I.POSTHOG.COM", port: 443, protocol: "https", method: "POST", path: "/batch/", bytesOut: 50 });
    c.addNet({ source: "proxy", host: "example.com", port: 443, protocol: "https", method: "CONNECT", bytesOut: 10 });
    c.addNet({ source: "preload", host: "api.anthropic.com", port: 443, protocol: "https", method: "POST", path: "/v1/messages" });
    const hosts = c.hostSummaries();
    expect(hosts.map((h) => [h.host, h.category, h.requests, h.bytesOut])).toEqual([
      ["us.i.posthog.com", "TELEMETRY", 2, 150],
      ["example.com", "UNKNOWN", 1, 10],
      ["api.anthropic.com", "LLM_API", 1, 0],
    ]);
    expect(c.score()).toMatchObject({ score: 65, grade: "C" });
  });

  it("upgrades a host to TELEMETRY when a later request reveals a telemetry path", () => {
    const c = mk();
    const alerts: Alert[] = [];
    c.on("alert", (a: Alert) => alerts.push(a));
    c.addNet({ source: "preload", host: "www.googleapis.com", port: 443, protocol: "https", method: "GET", path: "/drive/v3/files" });
    expect(c.hostSummaries()[0]!.category).toBe("UNKNOWN");
    c.addNet({ source: "preload", host: "www.googleapis.com", port: 443, protocol: "https", method: "POST", path: "/log?format=json" });
    expect(c.hostSummaries()[0]!.category).toBe("TELEMETRY");
    expect(alerts.map((a) => a.level)).toEqual(["warn", "high"]);
    expect(c.score().deductions.map((d) => d.reason)).toEqual(["telemetry-host"]);
  });

  it("prefers high-fidelity sources when the same host is seen by several layers", () => {
    const c = mk();
    c.addNet({ source: "lsof", host: "1.2.3.4", port: 443, protocol: "tcp" });
    c.addNet({ source: "lsof", host: "1.2.3.4", port: 443, protocol: "tcp" });
    c.addDns({ source: "preload", host: "api.openai.com", addresses: ["1.2.3.4"] });
    c.addNet({ source: "lsof", host: "1.2.3.4", port: 443, protocol: "tcp" });
    c.addNet({ source: "preload", host: "api.openai.com", port: 443, protocol: "https", method: "POST", path: "/v1/chat", bytesOut: 42 });
    const hosts = c.hostSummaries();
    // the un-mapped IP seen before the DNS answer stays separate; the mapped one merges
    const openai = hosts.find((h) => h.host === "api.openai.com")!;
    expect(openai.requests).toBe(1);
    expect(openai.primarySource).toBe("preload");
    expect(openai.sources.sort()).toEqual(["lsof", "preload"]);
    expect(openai.bytesOut).toBe(42);
  });

  it("applies byte updates to the originating event and host", () => {
    const c = mk();
    const ev = c.addNet({ source: "proxy", host: "metrics.vendor.io", port: 443, protocol: "https", method: "CONNECT", bytesOut: 0 })!;
    c.updateNet(ev.id, 500, 200);
    c.updateNet(ev.id, 800, 300);
    const h = c.hostSummaries()[0]!;
    expect(h.bytesOut).toBe(800);
    expect(h.bytesIn).toBe(300);
    expect(ev.bytesOut).toBe(800);
  });

  it("falls back to proxy byte counts when the hook saw no bytes", () => {
    const c = mk();
    c.addNet({ source: "preload", host: "cdn.vendor.io", port: 443, protocol: "https", method: "GET", path: "/x" });
    c.addNet({ source: "proxy", host: "cdn.vendor.io", port: 443, protocol: "https", method: "CONNECT", bytesOut: 999, bytesIn: 1 });
    const h = c.hostSummaries()[0]!;
    expect(h.primarySource).toBe("preload");
    expect(h.bytesOut).toBe(999);
  });
});
