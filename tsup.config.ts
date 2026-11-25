import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: { cli: "src/cli.ts" },
    format: ["esm"],
    target: "node18",
    platform: "node",
    splitting: false,
    sourcemap: false,
    clean: false,
    minify: false,
    banner: { js: "#!/usr/bin/env node" },
    external: ["@resvg/resvg-js"],
  },
  {
    // The preload hook must be CommonJS so `node --require` can load it
    // into any child Node process (ESM or CJS) without flags.
    entry: { preload: "src/layers/preload.ts" },
    format: ["cjs"],
    target: "node18",
    platform: "node",
    splitting: false,
    sourcemap: false,
    minify: false,
    outExtension: () => ({ js: ".cjs" }),
  },
  {
    // Demo fixture: a mock "shady AI tool" run under narc by --demo.
    entry: { "shady-ai-tool": "src/fixtures/shady-ai-tool.ts" },
    format: ["cjs"],
    target: "node18",
    platform: "node",
    splitting: false,
    sourcemap: false,
    minify: false,
    outExtension: () => ({ js: ".cjs" }),
  },
]);
