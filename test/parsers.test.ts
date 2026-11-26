import { describe, expect, it } from "vitest";
import { parseLsof } from "../src/layers/lsof.js";
import { parseFsUsageLine, reconstructPath } from "../src/layers/fsusage.js";
import { parseStraceLine, straceEvent } from "../src/layers/strace.js";
import { splitHostPort } from "../src/layers/proxy.js";
import { PidTree } from "../src/layers/pidtree.js";

describe("parseLsof", () => {
  it("extracts remote endpoints and skips listeners", () => {
    const out = [
      "p123",
      "cnode",
      "f15",
      "PTCP",
      "n127.0.0.1:49275",
      "f16",
      "PTCP",
      "n127.0.0.1:49275->93.184.216.34:443",
      "p456",
      "cpython3",
      "f3",
      "PUDP",
      "n192.168.1.5:50000->8.8.8.8:53",
      "f4",
      "PTCP",
      "n[::1]:5000->[2606:4700::1111]:443 (ESTABLISHED)",
    ].join("\n");
    const conns = parseLsof(out);
    expect(conns).toEqual([
      { pid: 123, command: "node", protocol: "tcp", localHost: "127.0.0.1", localPort: 49275, remoteHost: "93.184.216.34", remotePort: 443 },
      { pid: 456, command: "python3", protocol: "udp", localHost: "192.168.1.5", localPort: 50000, remoteHost: "8.8.8.8", remotePort: 53 },
      { pid: 456, command: "python3", protocol: "tcp", localHost: "::1", localPort: 5000, remoteHost: "2606:4700::1111", remotePort: 443 },
    ]);
  });
});

describe("strace parsing", () => {
  it("parses openat lines with pid prefixes", () => {
    const l = parseStraceLine('12345 openat(AT_FDCWD, "/home/u/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 3');
    expect(l).toEqual({ pid: 12345, syscall: "openat", args: 'AT_FDCWD, "/home/u/.ssh/id_rsa", O_RDONLY|O_CLOEXEC', result: "3" });
    const ev = straceEvent('[pid  777] openat(AT_FDCWD, "/home/u/.aws/credentials", O_RDONLY) = 5');
    expect(ev).toEqual({ pid: 777, kind: "file", path: "/home/u/.aws/credentials" });
  });

  it("drops failed opens", () => {
    expect(straceEvent('1 openat(AT_FDCWD, "/home/u/.netrc", O_RDONLY) = -1 ENOENT (No such file or directory)')).toBeNull();
  });

  it("parses IPv4 and IPv6 connect calls", () => {
    expect(
      straceEvent('42 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0'),
    ).toEqual({ pid: 42, kind: "net", host: "1.2.3.4", port: 443, protocol: "tcp" });
    expect(
      straceEvent('42 connect(5, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:4700::1111", &sin6_addr), sin6_scope_id=0}, 28) = 0'),
    ).toEqual({ pid: 42, kind: "net", host: "2606:4700::1111", port: 53, protocol: "udp" });
    expect(straceEvent('42 connect(6, {sa_family=AF_UNIX, sun_path="/tmp/x.sock"}, 110) = 0')).toBeNull();
  });

  it("handles unfinished lines and C escapes", () => {
    expect(straceEvent('9 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.9")}, 16 <unfinished ...>')).toEqual({
      pid: 9,
      kind: "net",
      host: "10.0.0.9",
      port: 80,
      protocol: "tcp",
    });
    expect(straceEvent('9 openat(AT_FDCWD, "/home/u/.config/gh/ho\\x73ts.yml", O_RDONLY) = 3')?.path).toBe("/home/u/.config/gh/hosts.yml");
  });
});

describe("fs_usage parsing", () => {
  it("parses wide-format lines", () => {
    const l = parseFsUsageLine("22:31:05.123456  open              F=5        (R_____)  /Users/x/.ssh/id_rsa       0.000012   node.1234567");
    expect(l).toEqual({ call: "open", pathTail: "/Users/x/.ssh/id_rsa", procName: "node", tid: 1234567, errno: null });
    const w = parseFsUsageLine("22:31:05.123456  openat            [  2]      (R_____)  rshia/.aws/credentials      0.000050 W python3.99");
    expect(w).toEqual({ call: "openat", pathTail: "rshia/.aws/credentials", procName: "python3", tid: 99, errno: 2 });
    const e = parseFsUsageLine("22:31:05.123456  open              F=-1  [  2]  (R_____)  /Users/x/.npmrc      0.000010   node.5");
    expect(e).toEqual({ call: "open", pathTail: "/Users/x/.npmrc", procName: "node", tid: 5, errno: 2 });
    expect(parseFsUsageLine("garbage")).toBeNull();
  });

  it("reconstructs left-trimmed paths under HOME", () => {
    expect(reconstructPath("/abs/path", "/Users/x")).toBe("/abs/path");
    expect(reconstructPath("rshia/.aws/credentials", "/Users/arshia")).toBe("/Users/arshia/.aws/credentials");
    expect(reconstructPath("credentials", "/Users/arshia")).toBeNull();
  });

  it("keeps an absolute path that follows a stray token and never doubles the home dir", () => {
    expect(reconstructPath("0x1a2b /Users/arshia/.claude.json", "/Users/arshia")).toBe("/Users/arshia/.claude.json");
    expect(reconstructPath("F=-2/Users/arshia/.claude.json", "/Users/arshia")).toBe("/Users/arshia/.claude.json");
    expect(reconstructPath("Users/arshia/.claude.json", "/Users/arshia")).toBe("/Users/arshia/.claude.json");
    expect(reconstructPath("D=0x12 O=0x0 /private/tmp/x/.env", "/Users/arshia")).toBe("/private/tmp/x/.env");
    expect(reconstructPath("junk/private/tmp/x/.env", "/Users/arshia")).toBe("/private/tmp/x/.env");
    expect(reconstructPath("rshia/Library/Application Support/x", "/Users/arshia")).toBe("/Users/arshia/Library/Application Support/x");
    expect(reconstructPath("/Library/Keychains/System.keychain", "/Users/arshia")).toBe("/Library/Keychains/System.keychain");
    // cut inside "/Users/": the username segment is part of the home prefix, not a directory under it
    expect(reconstructPath("s/arshia/.local/share/uv/tools/x/y.pyc", "/Users/arshia")).toBe("/Users/arshia/.local/share/uv/tools/x/y.pyc");
    expect(reconstructPath("arshia/.codex/config.toml", "/Users/arshia")).toBe("/Users/arshia/.codex/config.toml");
    // cut after the home prefix: unknowable, dropped
    expect(reconstructPath("ocal/share/x", "/Users/arshia")).toBeNull();
  });

  it("accepts AT_FDCWD style negative descriptors in the fd column", () => {
    const w = parseFsUsageLine("22:31:05.123456  openat            F=-2       (R_____)  /Users/x/.claude.json      0.000050 W claude.99");
    expect(w).toEqual({ call: "openat", pathTail: "/Users/x/.claude.json", procName: "claude", tid: 99, errno: null });
  });
});

describe("splitHostPort", () => {
  it("splits host:port with and without brackets", () => {
    expect(splitHostPort("example.com:443")).toEqual(["example.com", 443]);
    expect(splitHostPort("[::1]:8443")).toEqual(["::1", 8443]);
    expect(splitHostPort("example.com")).toEqual(["example.com", 0]);
  });
});

describe("PidTree", () => {
  it("computes descendants from ps output", () => {
    const t = new PidTree(100);
    t.ingest(["  1     0 /sbin/launchd", "100     1 node", "101   100 bash", "102   101 curl", "200     1 other", "201   200 node"].join("\n"));
    expect(t.pids().sort()).toEqual([100, 101, 102]);
    expect(t.has(201)).toBe(false);
    expect([...t.names()].sort()).toEqual(["bash", "curl", "node"]);
  });

  it("remembers every process it ever saw in the tree, with accounting names", () => {
    const t = new PidTree(100);
    t.ingest(["100     1 /usr/bin/node", "101   100 /Users/u/.local/bin/claude"].join("\n"), ["100 node", "101 2.1.323"].join("\n"));
    expect([...t.names()].sort()).toEqual(["2.1.323", "claude", "node"]);
    expect(t.nameOf(101)).toBe("claude"); // "2.1.323" is a version string, not a name
    expect(t.displayNameFor("2.1.323")).toBe("claude");
    expect(t.displayNameFor("node")).toBe("node");
    expect(t.displayNameFor("unknownproc")).toBe("unknownproc");
    t.ingest(["100     1 /usr/bin/node"].join("\n"), "100 node"); // 101 exited
    expect(t.pids()).toEqual([100]);
    expect(t.seenProcesses().map((p) => p.ucomm)).toEqual(["node", "2.1.323"]);
  });

  it("names interpreter processes by the script they run", () => {
    const mk = (comm: string, ucomm: string, args: string) => ({ pid: 1, ppid: 0, comm, ucomm, args });
    expect(PidTree.displayName(mk("/usr/local/bin/node", "node", "/usr/local/bin/node /usr/local/lib/node_modules/npm/bin/npm-cli.js view @openai/codex"))).toBe("npm");
    expect(PidTree.displayName(mk("/usr/local/bin/node", "node", "node /tmp/tools/node_modules/.bin/t3"))).toBe("t3");
    expect(PidTree.displayName(mk("/usr/local/bin/node", "node", "node --require /x/preload.cjs /srv/app/server.mjs"))).toBe("server");
    expect(PidTree.displayName(mk("/usr/local/bin/node", "node", "node -e console.log(1)"))).toBe("node");
    expect(PidTree.displayName(mk("/bin/bash", "bash", "bash -c sleep 1"))).toBe("bash");
    expect(PidTree.displayName(mk("/Users/u/.local/bin/claude", "2.1.323", "claude -p hi"))).toBe("claude");
    expect(PidTree.displayName(mk("/opt/codex/bin/codex", "codex", "codex exec hi"))).toBe("codex");
  });

  it("finds processes the tool left running after it exited", () => {
    const t = new PidTree(100);
    t.ingest(["100     1 /usr/bin/node", "101   100 /opt/t3/t3"].join("\n"), ["100 node", "101 t3"].join("\n"));
    // root exited; 101 daemonised (reparented to launchd); 102 is an unrelated process that reused a pid
    t.ingest(["101     1 /opt/t3/t3", "100     1 /usr/bin/vim"].join("\n"), ["101 t3", "100 vim"].join("\n"));
    expect(t.leftovers().map((p) => p.pid)).toEqual([101]);
  });
});
