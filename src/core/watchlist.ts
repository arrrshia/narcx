import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { WatchEntry } from "./types.js";

/**
 * Sensitive file watchlist. Patterns starting with "~/" are relative to the
 * home directory. Patterns without a slash match a basename anywhere.
 * Glob syntax: `*` (no slash), `**` (any depth), `?` single char.
 */
export const WATCHLIST: readonly WatchEntry[] = [
  { id: "claude", label: "Claude Code config", patterns: ["~/.claude.json", "~/.claude/**"] },
  { id: "codex", label: "Codex config", patterns: ["~/.codex/**"] },
  { id: "cursor", label: "Cursor config", patterns: ["~/.cursor/**"] },
  { id: "gemini", label: "Gemini CLI auth", patterns: ["~/.gemini/**"] },
  { id: "opencode", label: "OpenCode config", patterns: ["~/.config/opencode/**", "~/.local/share/opencode/**"] },
  { id: "gh", label: "GitHub CLI auth", patterns: ["~/.config/gh/**"] },
  { id: "ssh", label: "SSH keys", patterns: ["~/.ssh/**"] },
  { id: "aws", label: "AWS credentials", patterns: ["~/.aws/**"] },
  { id: "gitconfig", label: "Git config", patterns: ["~/.gitconfig", "~/.config/git/credentials"] },
  { id: "npmrc", label: "npm auth", patterns: ["~/.npmrc", ".npmrc"] },
  { id: "netrc", label: "netrc credentials", patterns: ["~/.netrc", "~/_netrc"] },
  { id: "pypirc", label: "PyPI credentials", patterns: ["~/.pypirc"] },
  { id: "env", label: "dotenv secrets", patterns: [".env", ".env.*"] },
  { id: "gnupg", label: "GPG keyring", patterns: ["~/.gnupg/**"] },
  { id: "docker", label: "Docker auth", patterns: ["~/.docker/config.json"] },
  { id: "kube", label: "Kubernetes config", patterns: ["~/.kube/**"] },
  { id: "gcloud", label: "gcloud credentials", patterns: ["~/.config/gcloud/**"] },
  {
    id: "keychain",
    label: "macOS keychain (TLS trust store)",
    patterns: ["~/Library/Keychains/**", "/Library/Keychains/**"],
    // Every process that evaluates a TLS certificate chain through Security.framework opens
    // these files; secrets inside are only reachable through securityd. Reported, not graded.
    graded: false,
  },
  {
    id: "browser",
    label: "Browser cookies/logins",
    patterns: [
      // macOS
      "~/Library/Cookies/**",
      "~/Library/Application Support/Google/Chrome/**/Cookies",
      "~/Library/Application Support/Google/Chrome/**/Login Data",
      "~/Library/Application Support/Chromium/**/Cookies",
      "~/Library/Application Support/BraveSoftware/**/Cookies",
      "~/Library/Application Support/Microsoft Edge/**/Cookies",
      "~/Library/Application Support/Arc/**/Cookies",
      "~/Library/Application Support/Firefox/Profiles/**/cookies.sqlite",
      "~/Library/Application Support/Firefox/Profiles/**/logins.json",
      "~/Library/Safari/Cookies.binarycookies",
      // Linux
      "~/.config/google-chrome/**/Cookies",
      "~/.config/chromium/**/Cookies",
      "~/.config/BraveSoftware/**/Cookies",
      "~/.mozilla/firefox/**/cookies.sqlite",
      "~/.mozilla/firefox/**/logins.json",
      // Windows-ish paths seen through WSL/Git Bash
      "~/AppData/Local/Google/Chrome/User Data/**/Cookies",
    ],
  },
];

function escapeRe(s: string): string {
  return s.replace(/[.+^${}()|[\]\\]/g, "\\$&");
}

/** Compile a glob pattern to a RegExp. Anchored at both ends. */
export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "/" && glob[i + 1] === "*" && glob[i + 2] === "*" && i + 3 === glob.length) {
      // trailing "/**": match the directory itself and anything below it.
      re += "(?:/.*)?";
      i += 2;
    } else if (c === "*") {
      if (glob[i + 1] === "*") {
        // "**" — any depth, including zero segments.
        const next = glob[i + 2];
        if (next === "/") {
          re += "(?:.*/)?";
          i += 2;
        } else {
          re += ".*";
          i += 1;
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += escapeRe(c);
    }
  }
  return new RegExp("^" + re + "$");
}

interface Compiled {
  entry: WatchEntry;
  anchored: RegExp[];
  basename: RegExp[];
}

export class SensitiveMatcher {
  readonly home: string;
  /** All spellings of the home dir (e.g. macOS `/var/...` vs `/private/var/...`). */
  readonly homes: string[];
  private compiled: Compiled[];

  constructor(home: string = os.homedir()) {
    this.home = path.resolve(home);
    const variants = new Set<string>([this.home]);
    try {
      variants.add(fs.realpathSync.native(this.home));
    } catch {
      /* home may not exist yet */
    }
    this.homes = [...variants];
    this.compiled = WATCHLIST.map((entry) => {
      const anchored: RegExp[] = [];
      const basename: RegExp[] = [];
      for (const p of entry.patterns) {
        if (p.startsWith("~/")) {
          for (const h of this.homes) anchored.push(globToRegExp(path.join(h, p.slice(2))));
        } else if (p.includes("/")) {
          anchored.push(globToRegExp(p));
        } else {
          basename.push(globToRegExp(p));
        }
      }
      return { entry, anchored, basename };
    });
  }

  /** Normalize a path for matching: absolute, no trailing slash, expand ~. */
  normalize(p: string): string {
    let s = p;
    if (s.startsWith("~/")) s = path.join(this.home, s.slice(2));
    s = path.resolve(s);
    if (s.length > 1 && s.endsWith("/")) s = s.slice(0, -1);
    return s;
  }

  match(filePath: string): WatchEntry | null {
    const p = this.normalize(filePath);
    const base = path.basename(p);
    for (const c of this.compiled) {
      for (const re of c.anchored) if (re.test(p)) return c.entry;
      for (const re of c.basename) if (re.test(base)) return c.entry;
    }
    return null;
  }

  isSensitive(filePath: string): boolean {
    return this.match(filePath) !== null;
  }

  /** True if the path lives under the home dir and has a dot-segment (a dotfile/dotdir). */
  /** The home-dir spelling this path lives under, or null. */
  private homeOf(p: string): string | null {
    for (const h of this.homes) if (p === h || p.startsWith(h + path.sep)) return h;
    return null;
  }

  isDotfileUnderHome(filePath: string): boolean {
    const p = this.normalize(filePath);
    const h = this.homeOf(p);
    if (!h || p === h) return false;
    if (p.includes("/node_modules/")) return false;
    const rel = p.slice(h.length + 1);
    return rel.split("/").some((seg) => seg.startsWith(".") && seg.length > 1);
  }

  /** Pretty-print with ~ for home. */
  display(filePath: string): string {
    const p = this.normalize(filePath);
    const h = this.homeOf(p);
    if (!h) return p;
    return p === h ? "~" : "~" + p.slice(h.length);
  }
}

/**
 * Map a command line to the watchlist entries it legitimately owns, so that
 * e.g. running `claude` does not get penalised for reading ~/.claude.json.
 */
export function ownNamespaces(command: readonly string[]): Set<string> {
  const own = new Set<string>();
  // Only look at executable basenames and bare package-ish tokens
  // (`@anthropic-ai/claude-code`), never at directory names in paths.
  const tokens: string[] = [];
  for (const c of command) {
    const t = c.toLowerCase();
    if (t.startsWith("-")) continue;
    if (t.startsWith("@") || !t.includes("/")) tokens.push(t.replace(/@[^/]*$/, ""));
    else tokens.push(path.basename(t).replace(/\.(c|m)?js$/, ""));
  }
  const bases = tokens;
  const has = (re: RegExp) => bases.some((b) => re.test(b));

  if (has(/^(@anthropic-ai\/)?claude(-code)?$/)) own.add("claude");
  if (has(/^(@openai\/)?codex$/)) own.add("codex");
  if (has(/^cursor(-agent)?$/)) own.add("cursor");
  if (has(/^(@google\/)?gemini(-cli)?$/)) own.add("gemini");
  if (has(/^opencode(-ai)?$/)) own.add("opencode");
  if (has(/^gh$/)) own.add("gh");
  if (has(/^(npm|npx|pnpm|pnpx|yarn|bun|bunx|corepack)$/)) own.add("npmrc");
  if (bases.includes("aws") || has(/^aws-/)) own.add("aws");
  if (has(/^git(-[a-z0-9-]+)?$/)) {
    // git itself and its helpers (git-remote-https, git-credential-*) read these by design.
    own.add("gitconfig");
    own.add("ssh");
    own.add("netrc");
  }
  if (has(/^(curl|wget)$/)) own.add("netrc");
  if (has(/^(ssh|scp|sftp|ssh-add|ssh-agent|rsync|mosh)$/)) own.add("ssh");
  if (has(/^(pip|pip3|twine|poetry|uv|pipx|hatch|flit)$/)) own.add("pypirc");
  if (bases.includes("docker") || bases.includes("docker-compose")) own.add("docker");
  if (has(/^(kubectl|helm|k9s|kustomize|minikube|kind)$/)) own.add("kube");
  if (bases.includes("gcloud") || bases.includes("gsutil")) own.add("gcloud");
  if (has(/^(gpg|gpg2|gpg-agent)$/)) own.add("gnupg");
  // Coding agents read git identity (~/.gitconfig) as part of their job, like git itself does.
  if (has(CODING_AGENT)) own.add("gitconfig");
  return own;
}

/** Tools whose purpose is to drive git on the user's behalf. */
export const CODING_AGENT =
  /^((@anthropic-ai\/)?claude(-code)?|(@openai\/)?codex|cursor(-agent)?|(@google\/)?gemini(-cli)?|opencode(-ai)?|t3(code)?|aider|(@github\/)?copilot(-cli)?|amp|goose|cline|droid|jules)$/;
