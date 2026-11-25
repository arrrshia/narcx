import pc from "picocolors";
import type { Alert, Collector } from "../core/collector.js";
import type { NetEvent } from "../core/types.js";
import { fmtBytes } from "./format.js";

export interface LiveOptions {
  quiet: boolean;
  verbose: boolean;
  out?: NodeJS.WritableStream;
}

const TAG_HIGH = pc.bold(pc.red("[NARC 🚨]"));
const TAG_WARN = pc.bold(pc.yellow("[NARC ⚠️ ]"));
const TAG_INFO = pc.dim("[NARC ··]");

function netLine(ev: NetEvent): string {
  const target = ev.url ?? `${ev.host}:${ev.port}`;
  const method = ev.method ? ev.method + " " : "";
  const via = ev.source === "preload" ? "hook" : ev.source;
  const pid = ev.pid ? ` pid ${ev.pid}` : "";
  const bytes = ev.bytesOut ? ` ${fmtBytes(ev.bytesOut)}↑` : "";
  return `${method}${target}${bytes} ${pc.dim(`(${ev.protocol} · via ${via}${pid})`)}`;
}

/** Streams alerts to stderr as they happen without touching the child's stdout. */
export function attachLiveFeed(collector: Collector, opts: LiveOptions): void {
  if (opts.quiet) return;
  const out = opts.out ?? process.stderr;
  const write = (s: string) => out.write(s + "\n");

  collector.on("alert", (a: Alert) => {
    if (a.launcher) {
      if (opts.verbose) {
        const what = a.kind === "file" ? a.display : netLine(a.event);
        write(`${TAG_INFO} ${pc.dim("launcher")}  ${what}  ${pc.dim("(not graded)")}`);
      }
      return;
    }
    if (a.kind === "file") {
      if (a.level === "high") {
        const pid = a.event.pid ? ` · pid ${a.event.pid}` : "";
        write(
          `${TAG_HIGH} ${pc.red(pc.bold("READ"))}  ${pc.bold(a.display)}  ${pc.dim(
            `(${a.watch.label} · ${a.event.op}${pid})`,
          )}`,
        );
      } else if (opts.verbose) {
        write(`${TAG_INFO} ${pc.dim("dotfile")}  ${a.display}  ${pc.dim(`(${a.event.op})`)}`);
      }
      return;
    }
    const ev = a.event;
    if (a.level === "high") {
      write(`${TAG_HIGH} ${pc.red(pc.bold("TELEMETRY"))}  ${netLine(ev)}`);
    } else if (a.level === "warn") {
      write(`${TAG_WARN} ${pc.yellow(pc.bold("UNKNOWN HOST"))}  ${netLine(ev)}`);
    } else if (opts.verbose) {
      write(`${TAG_INFO} ${pc.green("llm api")}  ${netLine(ev)}`);
    }
  });

  if (opts.verbose) {
    collector.on("request", (ev: NetEvent) => {
      if (ev.category === "LLM_API") return;
      const color = ev.category === "TELEMETRY" ? pc.red : pc.yellow;
      write(`${TAG_INFO} ${color("↳")} ${netLine(ev)}`);
    });
  }
}
