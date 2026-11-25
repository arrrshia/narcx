import type { HostCategory } from "./types.js";

/**
 * Model / agent backends a coding tool is expected to talk to. Matched exactly
 * or as a subdomain. Never penalised.
 */
export const LLM_API_HOSTS: readonly string[] = [
  "api.anthropic.com",
  "mcp-proxy.anthropic.com",
  "api.openai.com",
  "chatgpt.com",
  "generativelanguage.googleapis.com",
  "cloudcode-pa.googleapis.com",
  "openrouter.ai",
  "api.githubcopilot.com",
  "copilot-proxy.githubusercontent.com",
  "api.x.ai",
  "api.mistral.ai",
  "api.deepseek.com",
  "api.groq.com",
  "api.cohere.com",
  "api.together.xyz",
  "api.fireworks.ai",
];

/** Sign-in / token-refresh endpoints. Never penalised. */
export const AUTH_HOSTS: readonly string[] = [
  "oauth2.googleapis.com",
  "accounts.google.com",
  "auth.openai.com",
  "auth0.openai.com",
  "console.anthropic.com",
  "login.microsoftonline.com",
  "github.com/login",
];

/**
 * Telemetry vendors and product-analytics endpoints. A host matches if it
 * equals the entry or is a subdomain of it. Checked BEFORE the LLM/AUTH lists
 * so that e.g. `ab.chatgpt.com` (Codex's Statsig/OTLP metrics endpoint) is
 * telemetry even though `chatgpt.com` is an LLM backend.
 */
export const TELEMETRY_DOMAINS: readonly string[] = [
  "posthog.com",
  "sentry.io",
  "segment.io",
  "segment.com",
  "mixpanel.com",
  "amplitude.com",
  "datadoghq.com",
  // vendor-specific metrics / experiment endpoints
  "ab.chatgpt.com",
  "play.googleapis.com",
  "statsigapi.net",
  "featuregates.org",
  "firebaselogging-pa.googleapis.com",
  // observability / error-reporting / product-analytics vendors
  "grafana.net",
  "honeycomb.io",
  "newrelic.com",
  "nr-data.net",
  "bugsnag.com",
  "rollbar.com",
  "logrocket.com",
  "fullstory.com",
  "hotjar.com",
  "crashlytics.com",
  "raygun.io",
  "loggly.com",
  "sumologic.com",
  "axiom.co",
  "google-analytics.com",
  "googletagmanager.com",
  "app-measurement.com",
];

/**
 * Generic hosts that are only telemetry on specific paths. Used when a layer
 * can see the request path (the preload hook, or plain-HTTP via the proxy).
 */
export const TELEMETRY_ENDPOINTS: ReadonlyArray<{ host: string; pathPrefix: string; note: string }> = [
  { host: "www.googleapis.com", pathPrefix: "/log", note: "Google Clearcut logging" },
  { host: "clients4.google.com", pathPrefix: "/log", note: "Google Clearcut logging" },
];

/**
 * Telemetry label markers. A host matches if any DNS label equals one of
 * these, which covers `telemetry.example.com`, `us.ingest.foo.io`,
 * `events.statsig.com`, `otlp-gateway.vendor.net`, etc.
 */
export const TELEMETRY_LABELS: readonly string[] = [
  "telemetry",
  "ingest",
  "analytics",
  "metrics",
  "statsig",
  "launchdarkly",
  "otlp",
  "otel",
];

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0", "::", "[::1]"]);

export function normalizeHost(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.endsWith(".")) h = h.slice(0, -1);
  return h;
}

/** Loopback traffic is never an "outbound host"; the collector drops it entirely. */
export function isLoopback(host: string): boolean {
  const h = normalizeHost(host);
  if (LOOPBACK.has(h)) return true;
  if (h.startsWith("127.")) return true;
  if (h.endsWith(".localhost")) return true;
  return false;
}

export function isIpAddress(host: string): boolean {
  const h = normalizeHost(host);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  if (h.includes(":") && /^[0-9a-f:.]+$/i.test(h)) return true;
  return false;
}

const matchesDomain = (h: string, list: readonly string[]) => list.some((d) => h === d || h.endsWith("." + d));

export function classifyHost(host: string): HostCategory {
  const h = normalizeHost(host);
  if (!h) return "UNKNOWN";
  if (isLoopback(h)) return "LLM_API";
  if (matchesDomain(h, TELEMETRY_DOMAINS)) return "TELEMETRY";
  if (h.split(".").some((l) => TELEMETRY_LABELS.includes(l))) return "TELEMETRY";
  if (matchesDomain(h, AUTH_HOSTS)) return "AUTH";
  if (matchesDomain(h, LLM_API_HOSTS)) return "LLM_API";
  return "UNKNOWN";
}

/** Classify a request when the path is known (upgrades generic hosts on telemetry paths). */
export function classifyRequest(host: string, path?: string): HostCategory {
  const base = classifyHost(host);
  if (base === "TELEMETRY" || !path) return base;
  const h = normalizeHost(host);
  for (const e of TELEMETRY_ENDPOINTS) {
    if (h === e.host && path.startsWith(e.pathPrefix)) return "TELEMETRY";
  }
  return base;
}

export const CATEGORY_LABEL: Record<HostCategory, string> = {
  LLM_API: "LLM",
  AUTH: "AUTH",
  TELEMETRY: "TELEMETRY",
  UNKNOWN: "OTHER",
};
