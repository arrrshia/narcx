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
  // ---- secrets: files that actually hold keys, tokens or credentials (graded) ----
  { id: "env", label: "dotenv secrets", kind: "secret", patterns: [".env", ".env.*"], exclude: [".env.example", ".env.sample", ".env.template", ".env.dist", ".env.schema"] },
  {
    id: "ssh",
    label: "SSH private keys",
    kind: "secret",
    patterns: ["~/.ssh/**"],
    exclude: ["*.pub", "known_hosts", "known_hosts.old", "known_hosts2", "config", "authorized_keys", "authorized_keys2", "environment", "rc", "~/.ssh"],
  },
  { id: "aws", label: "AWS credentials", kind: "secret", patterns: ["~/.aws/credentials", "~/.aws/sso/cache/**"] },
  { id: "kube", label: "Kubernetes config", kind: "secret", patterns: ["~/.kube/config"] },
  { id: "netrc", label: "netrc credentials", kind: "secret", patterns: ["~/.netrc", "~/_netrc"] },
  { id: "npmrc", label: "npm auth", kind: "secret", patterns: ["~/.npmrc", ".npmrc"] },
  { id: "pypirc", label: "PyPI credentials", kind: "secret", patterns: ["~/.pypirc"] },
  { id: "docker", label: "Docker auth", kind: "secret", patterns: ["~/.docker/config.json"] },
  { id: "git-credentials", label: "Git credentials", kind: "secret", patterns: ["~/.git-credentials", "~/.config/git/credentials"], owner: "gitconfig" },
  { id: "gh", label: "GitHub CLI auth", kind: "secret", patterns: ["~/.config/gh/hosts.yml"] },
  { id: "claude-creds", label: "Claude Code credentials", kind: "secret", patterns: ["~/.claude/.credentials.json"], owner: "claude" },
  { id: "codex-creds", label: "Codex credentials", kind: "secret", patterns: ["~/.codex/auth.json"], owner: "codex" },
  { id: "gemini-creds", label: "Gemini CLI credentials", kind: "secret", patterns: ["~/.gemini/oauth_creds.json"], owner: "gemini" },
  { id: "gnupg-keys", label: "GPG private keys", kind: "secret", patterns: ["~/.gnupg/private-keys-v1.d/**", "~/.gnupg/secring.gpg"], owner: "gnupg" },
  {
    id: "gcloud-creds",
    label: "gcloud credentials",
    kind: "secret",
    patterns: ["~/.config/gcloud/credentials.db", "~/.config/gcloud/access_tokens.db", "~/.config/gcloud/application_default_credentials.json", "~/.config/gcloud/legacy_credentials/**"],
    owner: "gcloud",
  },
  {
    id: "generic-secret",
    label: "credential file",
    kind: "secret",
    // Generic secret file names, anywhere outside package/cache trees.
    patterns: ["*credentials*", "*_creds.json", "*token*.json", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"],
    exclude: ["*.pub", "package.json"],
  },
  {
    id: "browser",
    label: "Browser cookies/logins",
    kind: "secret",
    patterns: [
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
      "~/.config/google-chrome/**/Cookies",
      "~/.config/chromium/**/Cookies",
      "~/.config/BraveSoftware/**/Cookies",
      "~/.mozilla/firefox/**/cookies.sqlite",
      "~/.mozilla/firefox/**/logins.json",
      "~/AppData/Local/Google/Chrome/User Data/**/Cookies",
    ],
  },
  // ---- configs, prompts, caches and directory probes (shown with a CONFIG tag, never graded) ----
  { id: "claude", label: "Claude Code config", kind: "config", patterns: ["~/.claude.json", "~/.claude/**"] },
  { id: "codex", label: "Codex config", kind: "config", patterns: ["~/.codex/**"] },
  { id: "cursor", label: "Cursor config", kind: "config", patterns: ["~/.cursor/**"] },
  { id: "gemini", label: "Gemini CLI config", kind: "config", patterns: ["~/.gemini/**"] },
  { id: "opencode", label: "OpenCode config", kind: "config", patterns: ["~/.config/opencode/**", "~/.local/share/opencode/**"] },
  { id: "gh", label: "GitHub CLI config", kind: "config", patterns: ["~/.config/gh/**"] },
  { id: "ssh", label: "SSH config", kind: "config", patterns: ["~/.ssh", "~/.ssh/config", "~/.ssh/known_hosts*", "~/.ssh/*.pub", "~/.ssh/authorized_keys*"] },
  { id: "aws", label: "AWS config", kind: "config", patterns: ["~/.aws/**"] },
  { id: "gitconfig", label: "Git config", kind: "config", patterns: ["~/.gitconfig", "~/.config/git/**"] },
  { id: "gnupg", label: "GPG keyring", kind: "config", patterns: ["~/.gnupg/**"] },
  { id: "docker", label: "Docker config", kind: "config", patterns: ["~/.docker/**"] },
  { id: "kube", label: "Kubernetes config", kind: "config", patterns: ["~/.kube/**"] },
  { id: "gcloud", label: "gcloud config", kind: "config", patterns: ["~/.config/gcloud/**"] },
  // ---- system files every TLS-speaking process opens (reported, never graded) ----
  { id: "keychain", label: "macOS keychain (TLS trust store)", kind: "system", patterns: ["~/Library/Keychains/**", "/Library/Keychains/**"] },
];

/** Path fragments under which generic secret-looking names are build artefacts or caches, not credentials. */
const GENERIC_SKIP = ["/node_modules/", "/.npm/_cacache/", "/.npm/_npx/", "/.cache/", "/Library/Caches/", "/.cargo/registry/", "/.rustup/", "/site-packages/", "/.pnpm/", "/.yarn/", "/.bun/install/"];

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
  excludeAnchored: RegExp[];
  excludeBasename: RegExp[];
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
    const compile = (patterns: readonly string[]) => {
      const anchored: RegExp[] = [];
      const basename: RegExp[] = [];
      for (const p of patterns) {
        if (p.startsWith("~/")) {
          for (const h of this.homes) anchored.push(globToRegExp(path.join(h, p.slice(2))));
        } else if (p.includes("/")) {
          anchored.push(globToRegExp(p));
        } else {
          basename.push(globToRegExp(p));
        }
      }
      return { anchored, basename };
    };
    this.compiled = WATCHLIST.map((entry) => {
      const inc = compile(entry.patterns);
      const exc = compile(entry.exclude ?? []);
      return { entry, anchored: inc.anchored, basename: inc.basename, excludeAnchored: exc.anchored, excludeBasename: exc.basename };
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

  private hits(c: Compiled, p: string, base: string): boolean {
    const excluded = c.excludeAnchored.some((re) => re.test(p)) || c.excludeBasename.some((re) => re.test(base));
    if (excluded) return false;
    if (c.anchored.some((re) => re.test(p))) return true;
    if (c.basename.some((re) => re.test(base))) {
      // Generic names (credentials, *.pem, *token*.json) are ignored inside package and cache trees.
      if (c.entry.id === "generic-secret" && GENERIC_SKIP.some((frag) => p.includes(frag))) return false;
      return true;
    }
    return false;
  }

  /** First matching entry; secrets are listed before configs, so a credential inside a config dir is a secret. */
  match(filePath: string): WatchEntry | null {
    const p = this.normalize(filePath);
    const base = path.basename(p);
    for (const c of this.compiled) if (this.hits(c, p, base)) return c.entry;
    return null;
  }

  /** The config namespace a path lives in (claude, codex, gemini, …), used for ownership. */
  ownerOf(filePath: string): string | null {
    const p = this.normalize(filePath);
    const base = path.basename(p);
    for (const c of this.compiled) {
      if (c.entry.kind !== "config") continue;
      if (this.hits(c, p, base)) return c.entry.id;
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
