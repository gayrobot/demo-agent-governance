// Approval receipts. Ported from helpdesk-agent's web/test/approvals.test.ts at dc26b4e
// (the ts_i4_receipt_refused tests there). In the helpdesk these run through a tool
// handler; here they check the receipt authority directly, which is where each refusal
// happens. The self-approval refusal belongs to the gate and moves with it.

import assert from "node:assert/strict";
import { test } from "node:test";

import { b64urlDecode, type KeyPair, TokenError } from "../src/identity.ts";
import { argsSha256, canonicalJson, RECEIPT_SECONDS, ReceiptAuthority } from "../src/receipts.ts";

const THEO = "theo.lindqvist@example.test";
const JAMIE = "jamie@example.test";
const MORGAN = "morgan.hale@example.test";
const REF = "T-TEST";

function setup() {
  let clock = 1_800_000_000;
  const authority = new ReceiptAuthority(() => clock);
  return {
    authority,
    advance: (s: number) => {
      clock += s;
    },
    now: () => clock,
  };
}

test("ts_i4_receipt_refused[approved for one target, run for another]", async () => {
  const { authority } = setup();
  const { token } = await authority.sign(THEO, REF, "reset_mfa", { email: JAMIE });
  await assert.rejects(
    authority.verify(token, REF, "reset_mfa", { email: MORGAN }),
    /different arguments/,
  );
});

test("ts_i4_receipt_refused[approved for one group, run for another]", async () => {
  const { authority } = setup();
  const approved = { email: JAMIE, group: "figma-users" };
  const { token } = await authority.sign(THEO, REF, "add_to_group", approved);
  await assert.rejects(
    authority.verify(token, REF, "add_to_group", { email: JAMIE, group: "crm-users" }),
    /different arguments/,
  );
});

test("ts_i4_receipt_refused[missing, reused, expired, other ref, tool or signer]", async () => {
  const args = { email: JAMIE };
  const { authority, advance, now } = setup();
  const run = (token: unknown, a: ReceiptAuthority = authority) =>
    a.verify(token, REF, "reset_mfa", args);
  for (const missing of [undefined, null, "", 42]) {
    await assert.rejects(run(missing), /no approval receipt/);
  }
  // Used once.
  const once = (await authority.sign(THEO, REF, "reset_mfa", args)).token;
  const receipt = await run(once);
  assert.deepEqual(
    { approver: receipt.approver, ref: receipt.ref, tool: receipt.tool },
    { approver: THEO, ref: REF, tool: "reset_mfa" },
  );
  await assert.rejects(run(once), /already used/);
  // Expired: 120 seconds plus skew.
  const old = (await authority.sign(THEO, REF, "reset_mfa", args)).token;
  advance(200);
  await assert.rejects(run(old), /expired/);
  // Another ref, another tool, another signer.
  const other = (await authority.sign(THEO, "T-OTHER", "reset_mfa", args)).token;
  await assert.rejects(run(other), /another ref/);
  const tool = (await authority.sign(THEO, REF, "add_to_group", args)).token;
  await assert.rejects(run(tool), /another tool/);
  const forger = new ReceiptAuthority(now);
  const forged = (await forger.sign(THEO, REF, "reset_mfa", args)).token;
  await assert.rejects(run(forged), /bad signature/);
});

test("a receipt lives 120 seconds, and only an approval receipt counts", async () => {
  const { authority } = setup();
  const { token } = await authority.sign(THEO, REF, "reset_mfa", {});
  const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(token.split(".")[1] ?? "")));
  assert.equal(claims.exp - claims.iat, RECEIPT_SECONDS);
  assert.equal(claims.ref, REF);
  // The header type is part of the check: an edited header breaks the signature.
  const [, p, s] = token.split(".");
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" })).toString("base64url");
  await assert.rejects(authority.verify(`${header}.${p}.${s}`, REF, "reset_mfa", {}), TokenError);
});

test("arguments hash the same in any key order, and differently for any change", async () => {
  assert.equal(
    await argsSha256({ email: JAMIE, group: "figma-users" }),
    await argsSha256({ group: "figma-users", email: JAMIE }),
  );
  assert.notEqual(await argsSha256({ email: JAMIE }), await argsSha256({ email: MORGAN }));
  assert.equal(canonicalJson({ b: { d: 1, c: 2 }, a: [3] }), '{"a":[3],"b":{"c":2,"d":1}}');
});

test("keys and receipt ids can come from the caller, for a deterministic lab", async () => {
  const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ])) as KeyPair;
  let n = 0;
  const a = new ReceiptAuthority(() => 1_800_000_000, { keys, newId: () => `r-${++n}` });
  const b = new ReceiptAuthority(() => 1_800_000_000, { keys });
  const { token, receipt } = await a.sign(THEO, REF, "reset_mfa", {});
  assert.equal(receipt.jti, "r-1");
  // Same key pair, so the other authority accepts it, once.
  assert.equal((await b.verify(token, REF, "reset_mfa", {})).jti, "r-1");
  await assert.rejects(b.verify(token, REF, "reset_mfa", {}), /already used/);
});
