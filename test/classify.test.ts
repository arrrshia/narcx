import { describe, expect, it } from "vitest";
import { classifyHost, classifyRequest, isIpAddress, isLoopback, normalizeHost } from "../src/core/classify.js";

describe("classifyHost", () => {
  it("recognises LLM API hosts (exact or subdomain)", () => {
    for (const h of [
      "api.anthropic.com",
      "mcp-proxy.anthropic.com",
      "api.openai.com",
      "chatgpt.com",
      "generativelanguage.googleapis.com",
      "cloudcode-pa.googleapis.com",
      "openrouter.ai",
      "api.githubcopilot.com",
      "localhost",
    ]) {
      expect(classifyHost(h), h).toBe("LLM_API");
    }
  });

  it("recognises auth endpoints and never penalises them", () => {
    for (const h of ["oauth2.googleapis.com", "accounts.google.com", "auth.openai.com", "console.anthropic.com"]) {
      expect(classifyHost(h), h).toBe("AUTH");
    }
  });

  it("puts vendor metrics endpoints under telemetry even when the parent domain is an LLM backend", () => {
    expect(classifyHost("ab.chatgpt.com")).toBe("TELEMETRY");
    expect(classifyHost("chatgpt.com")).toBe("LLM_API");
    expect(classifyHost("play.googleapis.com")).toBe("TELEMETRY");
    expect(classifyHost("generativelanguage.googleapis.com")).toBe("LLM_API");
  });

  it("treats loopback addresses as local", () => {
    expect(classifyHost("127.0.0.1")).toBe("LLM_API");
    expect(classifyHost("::1")).toBe("LLM_API");
    expect(classifyHost("[::1]")).toBe("LLM_API");
    expect(classifyHost("ollama.localhost")).toBe("LLM_API");
    expect(isLoopback("127.0.0.53")).toBe(true);
    expect(isLoopback("10.0.0.1")).toBe(false);
  });

  it("flags telemetry vendors including subdomains", () => {
    for (const h of [
      "posthog.com",
      "us.i.posthog.com",
      "o123456.ingest.sentry.io",
      "api.segment.io",
      "cdn.segment.com",
      "api.mixpanel.com",
      "api2.amplitude.com",
      "http-intake.logs.datadoghq.com",
    ]) {
      expect(classifyHost(h), h).toBe("TELEMETRY");
    }
  });

  it("flags telemetry-looking labels anywhere in the host", () => {
    for (const h of [
      "telemetry.example.com",
      "ingest.example-ai.dev",
      "analytics.foo.io",
      "metrics.cursor.sh",
      "events.statsig.com",
      "app.launchdarkly.com",
      "eu.telemetry.vendor.net",
    ]) {
      expect(classifyHost(h), h).toBe("TELEMETRY");
    }
  });

  it("flags observability vendors and OTLP collectors", () => {
    for (const h of ["otlp-gateway-prod-us-east-3.grafana.net", "api.honeycomb.io", "collector.newrelic.com", "otel.example.com", "notify.bugsnag.com", "www.google-analytics.com", "us-east-1.aws.edge.axiom.co"]) {
      expect(classifyHost(h), h).toBe("TELEMETRY");
    }
  });

  it("upgrades generic hosts on known telemetry paths", () => {
    expect(classifyHost("www.googleapis.com")).toBe("UNKNOWN");
    expect(classifyRequest("www.googleapis.com", "/log?format=json&hasfast=true")).toBe("TELEMETRY");
    expect(classifyRequest("www.googleapis.com", "/drive/v3/files")).toBe("UNKNOWN");
    expect(classifyRequest("api.anthropic.com", "/log")).toBe("LLM_API");
    expect(classifyRequest("us.i.posthog.com")).toBe("TELEMETRY");
  });

  it("does not match telemetry words as substrings of other labels", () => {
    expect(classifyHost("mymetrics.example.com")).toBe("UNKNOWN");
    expect(classifyHost("notposthog.com")).toBe("UNKNOWN");
    expect(classifyHost("posthog.community")).toBe("UNKNOWN");
  });

  it("falls back to UNKNOWN", () => {
    expect(classifyHost("registry.npmjs.org")).toBe("UNKNOWN");
    expect(classifyHost("example.com")).toBe("UNKNOWN");
    expect(classifyHost("93.184.216.34")).toBe("UNKNOWN");
    expect(classifyHost("")).toBe("UNKNOWN");
  });

  it("normalises case, brackets and trailing dots", () => {
    expect(normalizeHost("API.Anthropic.COM.")).toBe("api.anthropic.com");
    expect(normalizeHost("[::1]")).toBe("::1");
    expect(classifyHost("US.I.POSTHOG.COM")).toBe("TELEMETRY");
  });

  it("detects IP literals", () => {
    expect(isIpAddress("1.2.3.4")).toBe(true);
    expect(isIpAddress("2606:4700::1111")).toBe(true);
    expect(isIpAddress("example.com")).toBe(false);
  });
});
