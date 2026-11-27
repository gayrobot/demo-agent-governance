// The audit hash chain. Ported from helpdesk-agent's web/test/approvals.test.ts at
// dc26b4e (the ts_i4_* chain tests). There the trail comes from the helpdesk's gate;
// here records go straight into the chain, so the checks don't depend on any one
// demo's tools. The file-backed sink stays in the helpdesk.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  auditTimestamp,
  clip,
  GENESIS,
  HashChain,
  MAX_FIELD_CHARS,
  MemoryAudit,
  recordHash,
  verifyChain,
} from "../src/audit.ts";

/** A fixed clock that ticks a second per read. */
function clock(start = "2026-12-01T09:00:00.000Z") {
  let t = Date.parse(start);
  return () => {
    const d = new Date(t);
    t += 1000;
    return d;
  };
}

async function trail() {
  const audit = new MemoryAudit(clock());
  await audit.record("tool_call", { tool: "lookup_user", decision: "allowed" });
  await audit.record("tool_call", { tool: "reset_mfa", decision: "approved" });
  await audit.record("tool_call", { tool: "search_runbooks", decision: "allowed" });
  return audit;
}

test("ts_i4_every_record_links_to_the_one_before", async () => {
  const audit = await trail();
  assert.equal(audit.records[0]?.prev, GENESIS);
  assert.equal(audit.records[1]?.prev, audit.records[0]?.hash);
  assert.deepEqual(await verifyChain(audit.records), { ok: true, records: audit.records.length });
});

test("ts_i4_verify_catches_an_edited_record", async () => {
  const records = (await trail()).records.map((r) => ({ ...r }));
  (records[1] as Record<string, unknown>).decision = "allowed";
  assert.deepEqual(await verifyChain(records), {
    ok: false,
    brokenAt: 1,
    why: "hash does not match the record",
  });
});

test("ts_i4_verify_catches_a_deleted_and_a_reordered_record", async () => {
  const records = (await trail()).records;
  const deleted = [...records.slice(0, 1), ...records.slice(2)];
  assert.deepEqual(await verifyChain(deleted), {
    ok: false,
    brokenAt: 1,
    why: "prev does not match the record before",
  });
  const swapped = [records[1], records[0], ...records.slice(2)] as typeof records;
  assert.equal((await verifyChain(swapped)).ok, false);
  const truncatedHead = records.slice(1);
  assert.equal((await verifyChain(truncatedHead)).ok, false);
});

test("ts_i4_memory_audit_chains_overlapping_writes_in_order", async () => {
  const audit = new MemoryAudit(clock());
  await Promise.all([1, 2, 3, 4].map((n) => audit.record("tool_call", { n })));
  assert.deepEqual(
    audit.records.map((r) => r.n),
    [1, 2, 3, 4],
  );
  assert.equal((await verifyChain(audit.records)).ok, true);
});

test("a chain restarted from its last hash carries on, as after a process restart", async () => {
  const first = await trail();
  const resumed = new HashChain(first.records.at(-1)?.hash as string);
  const next = await resumed.link({ ts: "2026-12-01T09:00:03.000+00:00", event: "tool_call" });
  assert.equal((await verifyChain([...first.records, next])).ok, true);
});

test("the hash ignores key order and covers prev", async () => {
  const a = { ts: "t", event: "e", x: { b: 1, a: 2 }, prev: GENESIS };
  const b = { prev: GENESIS, x: { a: 2, b: 1 }, event: "e", ts: "t" };
  assert.equal(await recordHash(a), await recordHash(b));
  assert.notEqual(await recordHash(a), await recordHash({ ...a, prev: "1".repeat(64) }));
});

test("records use the caller's clock, in the helpdesk's timestamp format", async () => {
  const audit = new MemoryAudit(clock("2026-12-01T09:00:00.000Z"));
  await audit.record("tool_call", {});
  await audit.record("tool_call", {});
  assert.deepEqual(
    audit.records.map((r) => r.ts),
    ["2026-12-01T09:00:00.000+00:00", "2026-12-01T09:00:01.000+00:00"],
  );
  assert.equal(auditTimestamp(new Date("2026-12-01T00:00:00Z")), "2026-12-01T00:00:00.000+00:00");
});

test("long strings are clipped to 300 code points, at any depth, never mid-character", () => {
  const long = "🍜".repeat(MAX_FIELD_CHARS + 5);
  const out = clip({ a: long, b: [long], c: { d: long }, n: 3 }) as Record<string, unknown>;
  const clipped = `${"🍜".repeat(MAX_FIELD_CHARS)}…[truncated]`;
  assert.equal(out.a, clipped);
  assert.deepEqual(out.b, [clipped]);
  assert.deepEqual(out.c, { d: clipped });
  assert.equal(out.n, 3);
  assert.equal(clip("short"), "short");
});
