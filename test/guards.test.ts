// What src/ may never do, checked by scanning every file: read the wall clock,
// use real timers, reach the network, import Node-only modules (the code must
// also run in Cloudflare Workers), load code dynamically, or name an address
// outside example.test. Clocks, keys and stores come from the caller.
//
// WebCrypto (crypto.subtle) is allowed: signing and hashing are what this code
// is for. Key generation is randomness, so callers in a deterministic lab pass
// their own keys.

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)],
  );
}

const FORBIDDEN: [RegExp, string][] = [
  [/\bDate\.now\b/, "Date.now"],
  [/new\s+Date\s*\(\s*\)/, "new Date() with no argument"],
  [/(?<!new\s)\bDate\s*\(/, "Date() called as a function"],
  [/\bperformance\b/, "performance"],
  [/\bprocess\b/, "process"],
  [/\b(setTimeout|setInterval|setImmediate|queueMicrotask)\b/, "real timers"],
  [/\bMath\.random\b/, "Math.random"],
  [/\bfetch\s*\(/, "fetch"],
  [/\b(XMLHttpRequest|WebSocket|EventSource|navigator)\b/, "browser network APIs"],
  [/from\s+["']node:/, "a node: import (src/ must also run in Workers)"],
  [
    /from\s+["'](http|https|http2|net|tls|dgram|dns|child_process|worker_threads|fs)["']/,
    "a Node module",
  ],
  [/\b(require|import)\s*\(/, "dynamic import or require"],
];

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

test("no file under src/ reads the clock, uses timers, reaches the network or imports Node-only modules", () => {
  const found: string[] = [];
  const all = files(SRC).filter((f) => f.endsWith(".ts"));
  assert.ok(all.length > 0);
  for (const file of all) {
    readFileSync(file, "utf8")
      .split("\n")
      .forEach((line, i) => {
        const t = line.trim();
        if (t.startsWith("//") || t.startsWith("*")) return;
        for (const [pattern, what] of FORBIDDEN) {
          if (pattern.test(line)) found.push(`${file.slice(SRC.length)}:${i + 1}: ${what}`);
        }
      });
  }
  assert.deepEqual(found, []);
});

test("no file in src/, test/ or the docs names an address outside example.test", () => {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const scanned = [
    ...files(SRC),
    ...files(join(root, "test")),
    ...files(join(root, "docs")),
    join(root, "README.md"),
    join(root, "CLAUDE.md"),
  ];
  const bad: string[] = [];
  for (const file of scanned) {
    for (const e of readFileSync(file, "utf8").match(EMAIL) ?? []) {
      if (!e.endsWith("@example.test")) bad.push(`${file.slice(root.length)}: ${e}`);
    }
  }
  assert.deepEqual(bad, []);
});
