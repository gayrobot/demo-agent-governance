// The approval gate. Ported from helpdesk-agent's web/test/approvals.test.ts,
// governance.test.ts and delegation.test.ts at dc26b4e (the gate tests of identity
// phases I1, I2 and I4 there): who may ask, who may approve, self-approval, approve then
// swap, the approval recorded before acting, a grant per call audited by id. Plus the
// lifecycle demo's shape: approvers per system, and an approval decided earlier and used
// once at call time.
import assert from "node:assert/strict";
import { test } from "node:test";
import { MemoryAudit, verifyChain } from "../src/audit.ts";
import { ApprovalGate, ApprovedBy, denyAll, type GateOutcome, grantFields } from "../src/gate.ts";
import { Principal, SignIn } from "../src/identity.ts";
import { argsSha256, ReceiptAuthority } from "../src/receipts.ts";
import {
  ADS_OWNER,
  DANA,
  FIXED_DATE,
  HelpdeskWorld,
  JAMIE,
  LEAD,
  LifecycleWorld,
  MORGAN,
  RecordingApprover,
  SAAS_OWNER,
  SAM,
  THEO,
  TICKET,
} from "./helpers/gate.ts";

const JWT = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;
const status = (o: GateOutcome<unknown>) => o.status;

// ---------------------------------------------------------------- who may ask, who may approve

const refusedBeforePrompt = [
  ["approver is the requester (self-approval)", THEO, THEO, THEO, /own request/],
  ["approver is the target", SAM, THEO, THEO, /own account/],
  ["approver is not in it-support", JAMIE, JAMIE, MORGAN, /not an active member/],
] as const;

for (const [name, requester, target, operator, why] of refusedBeforePrompt) {
  test(`ts_i4_refused_before_the_prompt[${name}]`, async () => {
    const world = new HelpdeskWorld();
    const approver = new RecordingApprover(true);
    const { gate } = await world.gate({ requester, operator, approver: approver.approve });
    const before = world.snapshot(target);
    const outcome = await gate.execute(world.request("reset_mfa", { email: target }));
    assert.equal(outcome.status, "refused");
    assert.ok(outcome.status === "refused" && why.test(outcome.reason), JSON.stringify(outcome));
    assert.deepEqual(approver.proposals, [], "never asked");
    assert.equal(world.snapshot(target), before);
  });
}

test("ts_i1_a_requester_who_may_not_ask_is_refused_before_anyone_is_asked", async () => {
  const world = new HelpdeskWorld();
  const approver = new RecordingApprover(true);
  const { gate } = await world.gate({ requester: DANA, approver: approver.approve });
  const outcome = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
  assert.equal(outcome.status, "refused");
  assert.ok(
    outcome.status === "refused" && /not the requester or someone who reports/.test(outcome.reason),
  );
  assert.deepEqual(approver.proposals, []);
});

test("ts_i1_the_callers_own_check_runs_after_may_request_and_before_the_prompt", async () => {
  const world = new HelpdeskWorld();
  const approver = new RecordingApprover(true);
  const order: string[] = [];
  const mayRequest = world.rules.mayRequest;
  world.rules.mayRequest = (r, c) => {
    order.push("mayRequest");
    return mayRequest(r, c);
  };
  const { gate } = await world.gate({ approver: approver.approve });
  const policy = new Error("privileged group");
  const outcome = await gate.execute({
    ...world.request("add_to_group", { email: JAMIE, group: "admins" }),
    check: () => {
      order.push("check");
      throw policy;
    },
  });
  assert.deepEqual(outcome, {
    status: "threw",
    approval: "not_asked",
    stage: "check",
    error: policy,
  });
  assert.deepEqual(order, ["mayRequest", "check"]);
  assert.deepEqual(approver.proposals, []);
});

test("ts_i4_an_approval_without_a_verified_approver_is_not_honoured", async () => {
  const world = new HelpdeskWorld();
  const { gate } = await world.gate({
    operator: null,
    approver: new RecordingApprover(true).approve,
  });
  const before = world.snapshot(JAMIE);
  const outcome = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
  assert.equal(outcome.status, "denied");
  assert.ok(outcome.status === "denied" && /no verified approver/.test(outcome.reason));
  assert.equal(world.snapshot(JAMIE), before);
});

test("ts_i4_an_approver_who_loses_the_role_while_deciding_is_not_honoured", async () => {
  const world = new HelpdeskWorld();
  const { gate } = await world.gate({
    approver: async () => {
      const theo = world.directory.get(THEO);
      if (theo) theo.groups = theo.groups.filter((g) => g !== "it-support");
      return true;
    },
  });
  const before = world.snapshot(JAMIE);
  const outcome = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
  assert.equal(outcome.status, "denied");
  assert.ok(
    outcome.status === "denied" &&
      /approval not honoured: .*not an active member/.test(outcome.reason),
  );
  assert.equal(world.snapshot(JAMIE), before);
});

for (const answer of [1, "y", "yes", null, {}, "true", [true], false, undefined]) {
  test(`test_only_literal_true_from_approver_counts[${JSON.stringify(answer)}]`, async () => {
    const world = new HelpdeskWorld();
    const { gate } = await world.gate({ approver: async () => answer });
    const outcome = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
    assert.equal(outcome.status, "denied");
    assert.equal(world.directory.get(JAMIE)?.mfaEnrolled, true);
  });
}

test("test_approver_exception_fails_closed", async () => {
  for (const approver of [
    () => {
      throw new Error("terminal went away");
    },
    async () => {
      throw new Error("page went away");
    },
  ]) {
    const world = new HelpdeskWorld();
    const { gate } = await world.gate({ approver });
    const outcome = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
    assert.equal(outcome.status, "threw");
    assert.ok(
      outcome.status === "threw" &&
        outcome.stage === "approver" &&
        outcome.approval === "not_asked",
    );
    assert.equal(world.directory.get(JAMIE)?.mfaEnrolled, true);
  }
});

test("test_deny_all_is_the_eval_default", async () => {
  const world = new HelpdeskWorld();
  const { gate } = await world.gate({ approver: denyAll });
  const outcome = await gate.execute(
    world.request("add_to_group", { email: JAMIE, group: "figma-users" }),
  );
  assert.equal(outcome.status, "denied");
  assert.ok(!world.directory.get(JAMIE)?.groups.includes("figma-users"));
});

test("ts_a_write_without_describe_never_reaches_the_approver", async () => {
  const world = new HelpdeskWorld();
  const approver = new RecordingApprover(true);
  const { gate } = await world.gate({ approver: approver.approve });
  const { describe: _d, ...request } = world.request("reset_mfa", { email: JAMIE });
  const outcome = await gate.execute(request);
  assert.ok(outcome.status === "threw" && outcome.stage === "describe");
  assert.deepEqual(approver.proposals, []);
});

test("ts_gate_refuses_anything_but_a_sign_in_from_an_issuer", async () => {
  const world = new HelpdeskWorld();
  const real = await world.issuer.signIn(JAMIE);
  const gateFor = (signIn: unknown) =>
    new ApprovalGate({
      signIn: signIn as SignIn,
      rules: world.rules,
      approver: denyAll,
      audit: new MemoryAudit(() => FIXED_DATE),
      receipts: new ReceiptAuthority(() => world.clock),
    });
  assert.doesNotThrow(() => gateFor(real));
  for (const forged of [
    JAMIE,
    real.principal,
    { principal: real.principal },
    { ...real },
    JSON.parse(JSON.stringify(real)),
    Object.create(SignIn.prototype),
    Object.assign(Object.create(SignIn.prototype), { principal: real.principal }),
    Object.create(Principal.prototype),
  ]) {
    assert.throws(() => gateFor(forged), TypeError, JSON.stringify(forged));
  }
});

test("ts_an_approver_that_is_not_a_sign_in_is_never_asked", async () => {
  const world = new HelpdeskWorld();
  const approver = new RecordingApprover(true);
  const { gate } = await world.gate({ approver: approver.approve });
  const real = await world.issuer.signIn(THEO);
  world.rules.approversFor = () => ({ principal: real.principal }) as unknown as SignIn;
  const outcome = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
  assert.ok(outcome.status === "threw" && outcome.stage === "rules");
  assert.deepEqual(approver.proposals, []);
  world.rules.approversFor = () => [{ principal: real.principal }] as unknown as SignIn[];
  const again = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
  assert.ok(again.status === "threw" && again.stage === "rules");
  assert.deepEqual(approver.proposals, []);
  assert.equal(world.directory.get(JAMIE)?.mfaEnrolled, true);
});

// ---------------------------------------------------------------- receipts and the audit

test("ts_i4_an_approved_write_carries_a_receipt_audited_by_id", async () => {
  const world = new HelpdeskWorld();
  const { gate, audit } = await world.gate({ approver: new RecordingApprover(true).approve });
  const outcome = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
  assert.equal(outcome.status, "ran");
  assert.ok(outcome.status === "ran" && outcome.approval === "approved" && outcome.receipt);
  assert.equal(world.directory.get(JAMIE)?.mfaEnrolled, false);
  const approved = audit.records.find((r) => r.event === "write_approved");
  assert.ok(approved);
  assert.equal(approved.ticket_id, TICKET);
  assert.equal(approved.approver, THEO);
  assert.equal(approved.effect, `reset_mfa for ${JAMIE}`);
  assert.equal(approved.args_sha256, await argsSha256({ email: JAMIE }));
  assert.equal(approved.receipt_jti, outcome.receipt.jti);
  assert.ok(!JWT.test(JSON.stringify(audit.records)), "no receipt or token in the audit");
});

test("ts_i4_the_proposal_shows_exactly_what_will_run_and_cannot_be_changed", async () => {
  const world = new HelpdeskWorld();
  const approver = new RecordingApprover(false);
  const { gate } = await world.gate({ approver: approver.approve });
  await gate.execute(world.request("add_to_group", { email: JAMIE, group: "figma-users" }));
  const [proposal] = approver.proposals;
  assert.ok(proposal);
  assert.deepEqual(proposal.args, { email: JAMIE, group: "figma-users" });
  assert.equal(proposal.requester, JAMIE);
  assert.equal(proposal.ref, TICKET);
  assert.deepEqual(proposal.details, { target: JAMIE });
  assert.ok(Object.isFrozen(proposal) && Object.isFrozen(proposal.args));
});

test("ts_i4_approve_then_swap_at_the_gate_runs_only_what_was_approved", async () => {
  const world = new HelpdeskWorld();
  const args: Record<string, unknown> = { email: JAMIE };
  const { gate } = await world.gate({
    approver: async (proposal) => {
      args.email = DANA; // swap the caller's object after the prompt
      try {
        (proposal.args as Record<string, unknown>).email = DANA; // and the proposal's
      } catch {}
      return true;
    },
  });
  const dana = world.snapshot(DANA);
  assert.equal((await gate.execute(world.request("reset_mfa", args))).status, "ran");
  assert.equal(world.directory.get(JAMIE)?.mfaEnrolled, false, "the approved target changed");
  assert.equal(world.snapshot(DANA), dana);
});

test("ts_i4_nested_arguments_are_frozen_too", async () => {
  const world = new HelpdeskWorld();
  const nested = { email: JAMIE, extra: { group: "figma-users" } };
  let seen: unknown;
  const { gate } = await world.gate({
    approver: async (proposal) => {
      nested.extra.group = "admins";
      assert.throws(() => {
        (proposal.args.extra as { group: string }).group = "admins";
      }, TypeError);
      return true;
    },
  });
  await gate.execute({ ...world.request("add_to_group", nested), run: (a) => (seen = a) });
  assert.deepEqual(seen, { email: JAMIE, extra: { group: "figma-users" } });
});

test("test_audit_failure_blocks_the_write", async () => {
  const world = new HelpdeskWorld();
  const audit = {
    records: [],
    record: async () => {
      throw new Error("disk full");
    },
  } as unknown as MemoryAudit;
  const { gate } = await world.gate({ approver: async () => true, audit });
  await assert.rejects(gate.execute(world.request("reset_mfa", { email: JAMIE })), /disk full/);
  assert.equal(world.directory.get(JAMIE)?.mfaEnrolled, true);
});

test("ts_i4_the_audit_chain_holds_across_approved_writes", async () => {
  const world = new HelpdeskWorld();
  const { gate, audit } = await world.gate({ approver: async () => true });
  await gate.execute(world.request("reset_mfa", { email: JAMIE }));
  await gate.execute(world.request("add_to_group", { email: JAMIE, group: "figma-users" }));
  assert.equal(audit.records.length, 2);
  assert.deepEqual(await verifyChain(audit.records), { ok: true, records: 2 });
});

// ---------------------------------------------------------------- grants

test("ts_i2_every_call_runs_under_a_fresh_grant_given_back_by_id", async () => {
  const world = new HelpdeskWorld();
  const { gate } = await world.gate({ approver: async () => true });
  const read = await gate.execute(world.request("lookup_user", { email: JAMIE }));
  const write = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
  assert.ok(read.status === "ran" && write.status === "ran");
  assert.equal(read.approval, "not_required");
  assert.equal(read.receipt, null);
  assert.deepEqual(
    [read, write].map((o) => grantFields(o.grant).scope),
    ["directory:read", "directory:mfa.reset"],
  );
  assert.notEqual(read.grant.jti, write.grant.jti, "a fresh grant per call");
  assert.ok(!JWT.test(JSON.stringify([grantFields(read.grant), grantFields(write.grant)])));
});

test("ts_i2_refused_calls_get_no_grant_and_run_nothing", async () => {
  const world = new HelpdeskWorld();
  const { gate } = await world.gate();
  let ran = 0;
  const counted = (r: ReturnType<HelpdeskWorld["request"]>) => ({ ...r, run: () => ran++ });
  const outcomes = [
    await gate.execute(counted(world.request("reset_mfa", { email: JAMIE }))), // denied
    await gate.execute({ ...counted(world.request("rm_rf", { email: JAMIE })), kind: "read" }), // no grant
    await gate.execute({
      ...counted(world.request("lookup_user", { email: JAMIE })),
      ref: "bad ref!",
    }),
  ];
  assert.deepEqual(outcomes.map(status), ["denied", "failed", "failed"]);
  for (const o of outcomes) assert.ok(!("grant" in o));
  assert.equal(ran, 0);
});

test("ts_i2_a_refused_grant_fails_closed_and_says_why", async () => {
  const world = new HelpdeskWorld();
  const { gate } = await world.gate({ approver: async () => true });
  // The requester is disabled after the gate was built: the handler side refuses.
  const jamie = world.directory.get(JAMIE);
  assert.ok(jamie);
  jamie.status = "disabled";
  const before = world.snapshot(JAMIE);
  const outcome = await gate.execute(world.request("lookup_user", { email: JAMIE }));
  assert.deepEqual(outcome, {
    status: "failed",
    approval: "not_required",
    reason: "grant refused: the requester's account is not active",
    errorType: "GrantError",
  });
  assert.equal(world.snapshot(JAMIE), before);
});

test("ts_a_tool_that_throws_is_given_back_to_the_caller_after_the_approval", async () => {
  const world = new HelpdeskWorld();
  const { gate } = await world.gate({ approver: async () => true });
  const outcome = await gate.execute(world.request("reset_mfa", { email: "nobody@example.test" }));
  assert.ok(
    outcome.status === "threw" && outcome.stage === "run" && outcome.approval === "approved",
  );
  assert.match(String(outcome.error), /no such user/);
});

// ---------------------------------------------------------------- lifecycle-shaped

test("lifecycle: each system's owner approves for that system only", async () => {
  const world = await new LifecycleWorld().setUp();
  const saasOwner = world.owners.get("saas");
  assert.ok(saasOwner);
  const approver = new RecordingApprover(true);
  const gate = await world.gate(approver.approve);
  // One owner per system: a plain true approves, as the registry's named owner.
  const saas = await gate.execute(world.deactivate("saas", "SAAS-00008"));
  assert.ok(saas.status === "ran" && saas.receipt?.approver === SAAS_OWNER);
  assert.equal(saas.grant.aud, "savory-air-saas");
  assert.equal(world.accounts.get("saas/SAAS-00008"), "deactivated");
  // The SaaS owner's sign-in can't approve the ad platform.
  const ads = await (await world.gate(async () => new ApprovedBy(saasOwner))).execute(
    world.deactivate("ads", "ADS-00002"),
  );
  assert.ok(ads.status === "denied" && /no verified approver/.test(ads.reason));
  assert.equal(world.accounts.get("ads/ADS-00002"), "active");
});

test("lifecycle: an approval decided days earlier is used once, signed at the moment of use", async () => {
  const world = await new LifecycleWorld().setUp();
  const adsOwner = world.owners.get("ads");
  assert.ok(adsOwner);
  // The desk record: decided on day 1 for this exact action, used once.
  const desk = new Map([[`ads/ADS-00002`, { by: adsOwner, used: false }]]);
  const fromDesk = async (p: { args: Record<string, unknown> }) => {
    const r = desk.get(`${String(p.args.system)}/${String(p.args.account)}`);
    if (!r || r.used) return false;
    r.used = true;
    return new ApprovedBy(r.by);
  };
  world.clock += 3 * 86_400; // three days later, far past a receipt's 120 seconds
  const gate = await world.gate(fromDesk);
  const first = await gate.execute(world.deactivate("ads", "ADS-00002"));
  assert.ok(first.status === "ran" && first.receipt?.approver === ADS_OWNER);
  const approved = world.audit.records.find((r) => r.event === "write_approved");
  assert.equal(approved?.requester, LEAD);
  assert.equal(approved?.ref, "run-0001/ads/ADS-00002/active_account");
  const again = await gate.execute(world.deactivate("ads", "ADS-00002"));
  assert.equal(again.status, "denied");
  // With several approvers for the system, a plain true is not honoured.
  world.rules.approversFor = (_r, call) => (call.args.system === "ads" ? [adsOwner] : null);
  world.accounts.set("ads/ADS-00002", "active");
  const plain = await (await world.gate(async () => true)).execute(
    world.deactivate("ads", "ADS-00002"),
  );
  assert.ok(plain.status === "denied" && /no verified approver/.test(plain.reason));
  assert.equal(world.accounts.get("ads/ADS-00002"), "active");
});

test("lifecycle: the run's lead can't approve their own run", async () => {
  const world = await new LifecycleWorld().setUp();
  world.owners.set("saas", await world.issuer.signIn(LEAD));
  const approver = new RecordingApprover(true);
  const outcome = await (await world.gate(approver.approve)).execute(
    world.deactivate("saas", "SAAS-00008"),
  );
  assert.ok(outcome.status === "refused" && /started this run/.test(outcome.reason));
  assert.deepEqual(approver.proposals, []);
});

test("ts_i2_a_write_with_no_grant_defined_is_never_put_to_the_approver", async () => {
  const world = await new LifecycleWorld().setUp();
  const approver = new RecordingApprover(true);
  world.rules.approversFor = () => world.owners.get("saas") ?? null;
  const gate = await world.gate(approver.approve);
  const outcome = await gate.execute(world.deactivate("payroll", "P-1"));
  assert.deepEqual(outcome, {
    status: "failed",
    approval: "not_asked",
    reason: "no grant is defined for deactivate_account",
    errorType: "GrantError",
  });
  assert.deepEqual(approver.proposals, []);
  assert.deepEqual(world.audit.records, []);
});

test("ts_i2_a_handler_refusal_after_an_approval_fails_closed", async () => {
  const world = new HelpdeskWorld();
  const { gate, audit } = await world.gate({
    approver: async () => {
      const jamie = world.directory.get(JAMIE);
      if (jamie) jamie.status = "disabled"; // the requester is disabled while Theo decides
      return true;
    },
  });
  const outcome = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
  assert.deepEqual(outcome, {
    status: "failed",
    approval: "approved",
    reason: "grant refused: the requester's account is not active",
    errorType: "GrantError",
  });
  assert.equal(world.directory.get(JAMIE)?.mfaEnrolled, true, "nothing changed");
  assert.equal(audit.records.filter((r) => r.event === "write_approved").length, 1);
});

test("ts_t2_gate_honours_only_its_own_approvers_by_the_sign_in_itself", async () => {
  const world = new HelpdeskWorld();
  const outsider = await world.issuer.signIn(THEO); // a valid sign-in for Theo, but not the gate's
  const { gate } = await world.gate({ approver: async () => new ApprovedBy(outsider) });
  const one = await gate.execute(world.request("reset_mfa", { email: JAMIE }));
  assert.ok(one.status === "denied" && /no verified approver/.test(one.reason));
  // The gate's own operator, named: honoured.
  const own = world.operator;
  assert.ok(own);
  const { gate: named } = await world.gate({ approver: async () => new ApprovedBy(own) });
  world.operator = own;
  assert.equal((await named.execute(world.request("reset_mfa", { email: JAMIE }))).status, "ran");
});

test("ts_changing_the_approver_list_while_asked_changes_nothing", async () => {
  const world = await new LifecycleWorld().setUp();
  const intruder = await world.issuer.signIn("eve@example.test");
  const owner = world.owners.get("saas");
  assert.ok(owner);
  const list: SignIn[] = [owner];
  world.rules.approversFor = () => list;
  const gate = await world.gate(async () => {
    list.push(intruder);
    return new ApprovedBy(intruder);
  });
  const outcome = await gate.execute(world.deactivate("saas", "SAAS-00008"));
  assert.equal(outcome.status, "denied");
  assert.equal(world.accounts.get("saas/SAAS-00008"), "active");
});
