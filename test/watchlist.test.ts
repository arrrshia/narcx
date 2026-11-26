import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { SensitiveMatcher, globToRegExp, ownNamespaces } from "../src/core/watchlist.js";

const HOME = "/Users/tester";
const m = new SensitiveMatcher(HOME);

describe("globToRegExp", () => {
  it("handles *, ** and ?", () => {
    expect(globToRegExp("/a/*.txt").test("/a/b.txt")).toBe(true);
    expect(globToRegExp("/a/*.txt").test("/a/b/c.txt")).toBe(false);
    expect(globToRegExp("/a/**/c").test("/a/c")).toBe(true);
    expect(globToRegExp("/a/**/c").test("/a/b/x/c")).toBe(true);
    expect(globToRegExp(".env.?").test(".env.1")).toBe(true);
    expect(globToRegExp(".env.?").test(".env.12")).toBe(false);
    expect(globToRegExp("/a/.ssh/**").test("/a/.ssh")).toBe(true);
    expect(globToRegExp("/a/.ssh/**").test("/a/.ssh/id_rsa")).toBe(true);
    expect(globToRegExp("/a/.ssh/**").test("/a/.sshx")).toBe(false);
  });

  it("escapes regex metacharacters", () => {
    expect(globToRegExp("/a/.claude.json").test("/a/xclaudexjson")).toBe(false);
    expect(globToRegExp("/a/(b)+c").test("/a/(b)+c")).toBe(true);
  });
});

describe("SensitiveMatcher", () => {
  it("matches the credential watchlist under ~", () => {
    const cases: Array<[string, string]> = [
      ["~/.claude/.credentials.json", "claude-creds"],
      ["~/.codex/auth.json", "codex-creds"],
      ["~/.gemini/oauth_creds.json", "gemini-creds"],
      ["~/.git-credentials", "git-credentials"],
      ["~/.claude.json", "claude"],
      ["~/.claude/settings.json", "claude"],
      ["~/.claude/projects/x/y.jsonl", "claude"],
      ["~/.codex/config.toml", "codex"],
      ["~/.cursor/mcp.json", "cursor"],
      ["~/.gemini/settings.json", "gemini"],
      ["~/.config/opencode/auth.json", "opencode"],
      ["~/.local/share/opencode/auth.json", "opencode"],
      ["~/.config/gh/hosts.yml", "gh"],
      ["~/.ssh/id_ed25519", "ssh"],
      ["~/.ssh", "ssh"],
      ["~/.aws/credentials", "aws"],
      ["~/.gitconfig", "gitconfig"],
      ["~/.npmrc", "npmrc"],
      ["~/.netrc", "netrc"],
      ["~/.pypirc", "pypirc"],
      ["~/.gnupg/private-keys-v1.d/abc.key", "gnupg-keys"],
      ["~/.docker/config.json", "docker"],
      ["~/.kube/config", "kube"],
      ["~/.config/gcloud/credentials.db", "gcloud-creds"],
      ["~/Library/Keychains/login.keychain-db", "keychain"],
      ["~/Library/Application Support/Google/Chrome/Default/Cookies", "browser"],
      ["~/Library/Application Support/Firefox/Profiles/abc.default/cookies.sqlite", "browser"],
      ["~/.config/google-chrome/Profile 1/Cookies", "browser"],
      ["~/.mozilla/firefox/xyz/logins.json", "browser"],
    ];
    for (const [p, id] of cases) {
      expect(m.match(p)?.id, p).toBe(id);
    }
  });

  it("matches .env files anywhere, by basename, except templates", () => {
    expect(m.match("/srv/app/.env")?.id).toBe("env");
    expect(m.match("/srv/app/.env.local")?.id).toBe("env");
    expect(m.match("/srv/app/.env.production")?.id).toBe("env");
    expect(m.match("/srv/app/.env.example")).toBeNull();
    expect(m.match("/srv/app/.env.sample")).toBeNull();
    expect(m.match("/srv/app/.env.template")).toBeNull();
    expect(m.match("/srv/app/env")).toBeNull();
    expect(m.match("/srv/app/.environment")).toBeNull();
    expect(m.match("/srv/app/.npmrc")?.id).toBe("npmrc");
  });

  it("separates secrets from configs", () => {
    const kind = (p: string) => m.match(p)?.kind;
    expect(kind("~/.ssh/id_ed25519")).toBe("secret");
    expect(kind("~/.ssh/id_rsa.pub")).toBe("config");
    expect(kind("~/.ssh/known_hosts")).toBe("config");
    expect(kind("~/.ssh/config")).toBe("config");
    expect(kind("~/.ssh")).toBe("config");
    expect(kind("~/.aws/credentials")).toBe("secret");
    expect(kind("~/.aws/config")).toBe("config");
    expect(kind("~/.kube/config")).toBe("secret");
    expect(kind("~/.claude.json")).toBe("config");
    expect(kind("~/.claude/settings.json")).toBe("config");
    expect(kind("~/.claude/skills")).toBe("config");
    expect(kind("~/.claude/.credentials.json")).toBe("secret");
    expect(kind("~/.codex")).toBe("config");
    expect(kind("~/.codex/models_cache.json")).toBe("config");
    expect(kind("~/.codex/config.toml")).toBe("config");
    expect(kind("~/.codex/auth.json")).toBe("secret");
    expect(kind("~/.gemini/GEMINI.md")).toBe("config");
    expect(kind("~/.gemini/google_accounts.json")).toBe("config");
    expect(kind("~/.gemini/oauth_creds.json")).toBe("secret");
    expect(kind("~/.gitconfig")).toBe("config");
    expect(kind("~/Library/Keychains/login.keychain-db")).toBe("system");
  });

  it("flags generic secret file names outside package and cache trees", () => {
    expect(m.match("/srv/app/service-account.pem")?.id).toBe("generic-secret");
    expect(m.match("/srv/app/gcp_creds.json")?.id).toBe("generic-secret");
    expect(m.match("/srv/app/refresh_token.json")?.id).toBe("generic-secret");
    expect(m.match("/srv/app/server.key")?.id).toBe("generic-secret");
    expect(m.match("/srv/app/node_modules/foo/test/credentials.json")).toBeNull();
    expect(m.match("/Users/tester/.npm/_cacache/content-v2/sha512/ab/credentials")).toBeNull();
    expect(m.match("/srv/app/server.key.pub")).toBeNull();
  });

  it("knows which config namespace a path lives in", () => {
    expect(m.ownerOf("/Users/tester/.claude/.credentials.json")).toBe("claude");
    expect(m.ownerOf("/Users/tester/.codex/auth.json")).toBe("codex");
    expect(m.ownerOf("/srv/app/.env")).toBeNull();
  });

  it("does not flag ordinary files or look-alikes", () => {
    expect(m.match("/Users/tester/project/src/index.ts")).toBeNull();
    expect(m.match("/Users/tester/.sshx/notes")).toBeNull();
    expect(m.match("/Users/other/.ssh/id_rsa")?.id).toBe("generic-secret"); // another user's key is still a key
    expect(m.match("/Users/tester/.config/ghx/hosts.yml")).toBeNull();
    expect(m.match("/Users/tester/.config/shady-ai/settings.json")).toBeNull();
  });

  it("expands ~ and resolves relative/odd paths", () => {
    expect(m.normalize("~/.ssh/../.ssh/id_rsa")).toBe("/Users/tester/.ssh/id_rsa");
    expect(m.match("/Users/tester/.aws//credentials")?.id).toBe("aws");
    expect(m.display("/Users/tester/.ssh/id_rsa")).toBe("~/.ssh/id_rsa");
    expect(m.display("/etc/hosts")).toBe("/etc/hosts");
    expect(m.display("/Users/tester")).toBe("~");
  });

  it("recognises other dotfiles under ~ but not node_modules", () => {
    expect(m.isDotfileUnderHome("/Users/tester/.zshrc")).toBe(true);
    expect(m.isDotfileUnderHome("/Users/tester/.config/foo/bar")).toBe(true);
    expect(m.isDotfileUnderHome("/Users/tester/project/node_modules/.bin/x")).toBe(false);
    expect(m.isDotfileUnderHome("/Users/tester/project/src/a.ts")).toBe(false);
    expect(m.isDotfileUnderHome("/etc/.hidden")).toBe(false);
  });

  it("treats symlinked spellings of HOME as the same home", () => {
    const real = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "narc-home-"));
    const link = real + "-link";
    fs.symlinkSync(real, link);
    const mm = new SensitiveMatcher(link);
    afterAll(() => {
      fs.rmSync(link, { force: true });
      fs.rmSync(real, { recursive: true, force: true });
    });
    expect(mm.homes.length).toBe(2);
    expect(mm.match(path.join(real, ".ssh/id_rsa"))?.id).toBe("ssh");
    expect(mm.match(path.join(link, ".ssh/id_rsa"))?.id).toBe("ssh");
    expect(mm.display(path.join(real, ".aws/credentials"))).toBe("~/.aws/credentials");
  });
});

describe("ownNamespaces", () => {
  it("maps well-known tools to the entries they own", () => {
    expect(ownNamespaces(["claude", "-p", "hi"])).toEqual(new Set(["claude", "gitconfig"]));
    expect(ownNamespaces(["npx", "@anthropic-ai/claude-code"])).toEqual(new Set(["npmrc", "claude", "gitconfig"]));
    expect(ownNamespaces(["/opt/homebrew/bin/gh", "pr", "list"])).toEqual(new Set(["gh"]));
    expect(ownNamespaces(["git", "push"])).toEqual(new Set(["gitconfig", "ssh", "netrc"]));
    expect(ownNamespaces(["git-remote-https"])).toEqual(new Set(["gitconfig", "ssh", "netrc"]));
    expect(ownNamespaces(["curl"])).toEqual(new Set(["netrc"]));
    expect(ownNamespaces(["aws", "s3", "ls"])).toEqual(new Set(["aws"]));
    expect(ownNamespaces(["codex", "exec"])).toEqual(new Set(["codex", "gitconfig"]));
    expect(ownNamespaces(["kubectl", "get", "pods"])).toEqual(new Set(["kube"]));
    expect(ownNamespaces(["npx", "-y", "@google/gemini-cli"])).toEqual(new Set(["npmrc", "gemini", "gitconfig"]));
    expect(ownNamespaces(["gemini"])).toEqual(new Set(["gemini", "gitconfig"]));
    expect(ownNamespaces(["opencode"])).toEqual(new Set(["opencode", "gitconfig"]));
    expect(ownNamespaces(["npx", "-y", "t3@latest"])).toEqual(new Set(["npmrc", "gitconfig"]));
    expect(ownNamespaces(["/tmp/tools/node_modules/.bin/t3"])).toEqual(new Set(["gitconfig"]));
  });

  it("ignores directory names in paths", () => {
    expect(ownNamespaces(["/Users/me/Claude/tools/node", "/x/shady-ai-tool.cjs"])).toEqual(new Set());
    expect(ownNamespaces(["node", "/home/me/.cursor/extensions/thing.js"])).toEqual(new Set());
  });

  it("returns an empty set for unknown tools", () => {
    expect(ownNamespaces(["some-random-cli", "--flag"])).toEqual(new Set());
  });
});
