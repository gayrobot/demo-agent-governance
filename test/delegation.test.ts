// The handler side: no call runs without a verified grant, and no write without its
// receipt. Ported from helpdesk-agent's web/test/delegation.test.ts and
// approvals.test.ts at dc26b4e (the handler tests of identity phases I2 and I4 there),
// against the helpdesk-shaped and lifecycle-shaped rules in helpers/gate.ts, plus the
// checks a per-call mapping needs: the grant is worked out from the exact arguments
// about to run.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  type Call,
  GrantError,
  type HandlerCall,
  neededGrant,
  runWithGrant,
} from "../src/delegation.ts";
import { DevIssuer } from "../src/identity.ts";
import { ReceiptAuthority } from "../src/receipts.ts";
import { HELPDESK } from "./helpers/config.ts";
import {
  finding,
  HelpdeskWorld,
  JAMIE,
  LEAD,
  LifecycleWorld,
  MORGAN,
  NOW,
  RILEY,
  SAAS_OWNER,
  THEO,
  TICKET,
} from "./helpers/gate.ts";

const DIR = "savory-air-directory";

/** A handler-level setup in the helpdesk world: a grant for one call, and a receipt authority. */
async function helpdesk(tool: "lookup_user" | "reset_mfa" | "add_to_group", requester = JAMIE) {
  const world = new HelpdeskWorld();
  const signIn = await world.issuer.signIn(requester);
  const needed = neededGrant(world.rules, { tool, kind: "read", args: {}, ref: TICKET });
  const authority = new ReceiptAuthority(() => world.clock);
  const grant = () => signIn.grant(needed.audience, needed.scope, TICKET);
  let ran = 0;
  const handler = (
    args: Record<string, unknown>,
    token: unknown,
    approval: HandlerCall<unknown>["approval"] = null,
  ) =>
    runWithGrant({
      call: { tool, kind: tool === "lookup_user" ? "read" : "write", args, ref: TICKET },
      requester,
      token,
      resources: signIn.resources,
      checks: world.rules,
      approval,
      run: () => {
        ran++;
        return "ran";
      },
    });
  return { world, signIn, authority, grant, handler, ran: () => ran };
}

test("ts_i2_every_call_needs_a_grant_its_resource_offers", () => {
  const world = new HelpdeskWorld();
  for (const tool of ["lookup_user", "reset_mfa", "add_to_group"]) {
    const { audience, scope } = neededGrant(world.rules, {
      tool,
      kind: "read",
      args: {},
      ref: TICKET,
    });
    assert.ok(HELPDESK.resources[audience]?.includes(scope), `${audience} ${scope}`);
  }
  for (const tool of ["rm_rf", "__proto__", "constructor"]) {
    assert.throws(
      () => neededGrant(world.rules, { tool, kind: "read", args: {}, ref: TICKET }),
      (e: Error) => e instanceof GrantError && /no grant is defined/.test(e.message),
    );
  }
});

test("ts_i2_handler_refuses_without_a_valid_grant_and_runs_nothing", async () => {
  const h = await helpdesk("lookup_user");
  for (const token of [undefined, "", "not.a.token", 42]) {
    await assert.rejects(h.handler({ email: JAMIE }, token), GrantError);
  }
  assert.equal(h.ran(), 0);
});

test("ts_i2_a_well_formed_grant_runs_the_call_once", async () => {
  const h = await helpdesk("lookup_user");
  const token = await h.grant();
  const { result, grant, receipt } = await h.handler({ email: JAMIE }, token);
  assert.equal(result, "ran");
  assert.deepEqual(
    [grant.sub, grant.aud, grant.scope, grant.ref],
    [JAMIE, DIR, "directory:read", TICKET],
  );
  assert.equal(receipt, null);
  await assert.rejects(h.handler({ email: JAMIE }, token), /grant refused: token already used/);
  assert.equal(h.ran(), 1);
});

test("ts_i2_handler_refuses_a_grant_for_another_requester_or_a_disabled_account", async () => {
  // Morgan's grant, presented in Jamie's call.
  const h = await helpdesk("lookup_user");
  const morgan = await h.world.issuer.signIn(MORGAN);
  const token = await morgan.grant(DIR, "directory:read", TICKET);
  await assert.rejects(h.handler({ email: JAMIE }, token), /grant is for someone else/);
  // A disabled requester: the caller's check runs at call time, not when the token was made.
  const r = await helpdesk("lookup_user", RILEY);
  await assert.rejects(
    r.handler({ email: RILEY }, await r.grant()),
    /grant refused: the requester's account is not active/,
  );
  // And a requester disabled after their token was minted.
  const j = await helpdesk("lookup_user");
  const minted = await j.grant();
  const jamie = j.world.directory.get(JAMIE);
  assert.ok(jamie);
  jamie.status = "disabled";
  await assert.rejects(j.handler({ email: JAMIE }, minted), /not active/);
  assert.equal(h.ran() + r.ran() + j.ran(), 0);
});

test("ts_i2_a_grant_from_another_issuer_is_refused", async () => {
  const h = await helpdesk("lookup_user");
  const other = new DevIssuer({ config: HELPDESK, now: () => NOW });
  const token = await (await other.signIn(JAMIE)).grant(DIR, "directory:read", TICKET);
  await assert.rejects(h.handler({ email: JAMIE }, token), /grant refused: bad signature/);
});

test("ts_i2_a_grant_for_another_scope_or_ref_is_refused", async () => {
  const h = await helpdesk("reset_mfa");
  const { token } = await h.authority.sign(THEO, TICKET, "reset_mfa", { email: JAMIE });
  const approval = { token, authority: h.authority };
  const read = await h.signIn.grant(DIR, "directory:read", TICKET);
  await assert.rejects(h.handler({ email: JAMIE }, read, approval), /grant refused: wrong scope/);
  const other = await h.signIn.grant(DIR, "directory:mfa.reset", "T-OTHER");
  await assert.rejects(h.handler({ email: JAMIE }, other, approval), /token is for another ref/);
  assert.equal(h.ran(), 0);
});

// ---------------------------------------------------------------- receipts

test("ts_i4_receipt_refused[approved for one target, run for another]", async () => {
  const h = await helpdesk("reset_mfa");
  const { token } = await h.authority.sign(THEO, TICKET, "reset_mfa", { email: JAMIE });
  await assert.rejects(
    h.handler({ email: MORGAN }, await h.grant(), { token, authority: h.authority }),
    /receipt refused: receipt is for different arguments/,
  );
});

test("ts_i4_receipt_refused[approved for one group, run for another]", async () => {
  const h = await helpdesk("add_to_group");
  const approved = { email: JAMIE, group: "figma-users" };
  const { token } = await h.authority.sign(THEO, TICKET, "add_to_group", approved);
  await assert.rejects(
    h.handler({ email: JAMIE, group: "crm-users" }, await h.grant(), {
      token,
      authority: h.authority,
    }),
    /different arguments/,
  );
});

test("ts_i4_receipt_refused[missing, reused, expired, other ref, tool or signer]", async () => {
  const args = { email: JAMIE };
  const h = await helpdesk("reset_mfa");
  const run = async (token: unknown, authority = h.authority) =>
    h.handler(args, await h.grant(), { token, authority });
  await assert.rejects(h.handler(args, await h.grant(), null), /no approval receipt/);
  await assert.rejects(run(undefined), /no approval receipt/);
  // Used once.
  const once = (await h.authority.sign(THEO, TICKET, "reset_mfa", args)).token;
  await run(once);
  await assert.rejects(run(once), /already used/);
  // Expired: 120 seconds plus skew. Grants live 60 seconds, so mint one after the jump.
  const old = (await h.authority.sign(THEO, TICKET, "reset_mfa", args)).token;
  h.world.clock += 200;
  await assert.rejects(run(old), /expired/);
  // Another ref, another tool, another signer.
  const other = (await h.authority.sign(THEO, "T-OTHER", "reset_mfa", args)).token;
  await assert.rejects(run(other), /another ref/);
  const tool = (await h.authority.sign(THEO, TICKET, "add_to_group", args)).token;
  await assert.rejects(run(tool), /another tool/);
  const forger = new ReceiptAuthority(() => h.world.clock);
  const forged = (await forger.sign(THEO, TICKET, "reset_mfa", args)).token;
  await assert.rejects(run(forged), /bad signature/);
  // Signed for the requester's own request.
  const self = (await h.authority.sign(JAMIE, TICKET, "reset_mfa", args)).token;
  await assert.rejects(
    run(self),
    (e: Error) => e instanceof GrantError && /approved their own request/.test(e.message),
  );
  assert.equal(h.ran(), 1);
});

// ---------------------------------------------------------------- lifecycle-shaped

async function lifecycle() {
  const world = await new LifecycleWorld().setUp();
  const signIn = await world.issuer.signIn(LEAD);
  const authority = new ReceiptAuthority(() => world.clock);
  let ran = 0;
  const handler = (call: Call, token: unknown, receipt: string | null) =>
    runWithGrant({
      call,
      requester: LEAD,
      token,
      resources: signIn.resources,
      checks: world.rules,
      approval: receipt === null ? null : { token: receipt, authority },
      run: () => {
        ran++;
        return "ran";
      },
    });
  const write = (system: string, account: string, ref = finding(system, account)): Call => ({
    tool: "deactivate_account",
    kind: "write",
    args: { system, account },
    ref,
  });
  return { world, signIn, authority, handler, write, ran: () => ran };
}

test("lifecycle: the audience comes from the system the call names", async () => {
  const l = await lifecycle();
  const call = l.write("saas", "SAAS-00008");
  assert.deepEqual(neededGrant(l.world.rules, call), {
    audience: "savory-air-saas",
    scope: "accounts:deactivate",
  });
  assert.throws(() => neededGrant(l.world.rules, l.write("payroll", "P-1")), GrantError);
  const grant = await l.signIn.grant("savory-air-saas", "accounts:deactivate", call.ref);
  const { token } = await l.authority.sign(SAAS_OWNER, call.ref, call.tool, call.args);
  assert.equal((await l.handler(call, grant, token)).result, "ran");
});

test("lifecycle: a grant minted for one system is refused for a call on another", async () => {
  const l = await lifecycle();
  // Minted for SaaS; the call that arrives names the ad platform.
  const call = l.write("ads", "ADS-00002", finding("saas", "SAAS-00008"));
  const grant = await l.signIn.grant("savory-air-saas", "accounts:deactivate", call.ref);
  const { token } = await l.authority.sign(SAAS_OWNER, call.ref, call.tool, call.args);
  await assert.rejects(l.handler(call, grant, token), /grant refused: wrong audience/);
  assert.equal(l.ran(), 0);
});

test("lifecycle: a write approved for one system is refused on another", async () => {
  const l = await lifecycle();
  const approved = l.write("saas", "SAAS-00008");
  const { token } = await l.authority.sign(SAAS_OWNER, approved.ref, approved.tool, approved.args);
  const swapped: Call = { ...approved, args: { system: "ads", account: "SAAS-00008" } };
  const grant = await l.signIn.grant("savory-air-ads", "accounts:deactivate", approved.ref);
  await assert.rejects(l.handler(swapped, grant, token), /receipt is for different arguments/);
  assert.equal(l.ran(), 0);
});

test("lifecycle: a grant and a receipt for one finding are refused on another", async () => {
  const l = await lifecycle();
  const first = l.write("saas", "SAAS-00008");
  const second = l.write("saas", "SAAS-00008", "run-0001/saas/SAAS-00008/admin_role");
  const grant = await l.signIn.grant("savory-air-saas", "accounts:deactivate", first.ref);
  const { token } = await l.authority.sign(SAAS_OWNER, first.ref, first.tool, first.args);
  await assert.rejects(l.handler(second, grant, token), /token is for another ref/);
  const fresh = await l.signIn.grant("savory-air-saas", "accounts:deactivate", second.ref);
  await assert.rejects(l.handler(second, fresh, token), /receipt is for another ref/);
  assert.equal(l.ran(), 0);
});
