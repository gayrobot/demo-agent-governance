/**
 * The approval gate: who may ask, who may approve, and the receipt and grant every call
 * runs under. From the approval and receipt flow of `helpdesk-agent/web/src/governance.ts`
 * at `dc26b4e` (identity phases I1, I2 and I4 there).
 *
 * What stays with each demo: the allowlist, argument validation, its own policy checks,
 * what a read may show, and the audit record of each call. What the caller supplies here
 * (`GateRules`): who may request a write, who may answer it, whether each of them may
 * approve it, which grant a call needs, and whether the requester may still act. The
 * gate fixes the order, so no caller can skip a step:
 *
 * 1. A write the requester may not ask for is refused (`mayRequest`).
 * 2. The caller's own check runs (`check`), if it gave one.
 * 3. A write that none of this call's approvers may approve is refused before anyone is
 *    asked.
 * 4. A write is put to the approver, with a frozen deep copy of the arguments: what the
 *    approver sees is what runs. The approval counts only from a signed-in approver for
 *    this call who still passes `mayApprove` once they've answered.
 * 5. The gate signs a receipt over exactly what was approved, and records the approval
 *    before acting. If the audit sink rejects, nothing runs.
 * 6. A fresh delegated token for exactly this call, verified by the handler side
 *    (`runWithGrant`) before the tool runs.
 *
 * Changes from the helpdesk: approvers come per call, not per gate (the lifecycle demo's
 * registry names one per system); the ref comes per call (a run and a finding there, a
 * ticket in the helpdesk); the receipt authority is passed in, so a deterministic lab can
 * supply its keys; and nothing defaults to the wall clock. The gate returns an outcome
 * and leaves the per-call audit record and the words the model sees to the caller.
 */
import type { AuditSink } from "./audit.ts";
import {
  type Args,
  type Call,
  type CallKind,
  GrantError,
  type HandlerChecks,
  neededGrant,
  runWithGrant,
} from "./delegation.ts";
import { type Grant, SignIn, TokenError } from "./identity.ts";
import type { Receipt, ReceiptAuthority } from "./receipts.ts";

export const Approval = {
  NOT_REQUIRED: "not_required", // a read
  NOT_ASKED: "not_asked", // stopped before anyone was asked
  APPROVED: "approved",
  DENIED: "denied",
} as const;
export type Approval = (typeof Approval)[keyof typeof Approval];

/** What the approver is shown. */
export interface Proposal {
  readonly tool: string;
  readonly args: Args;
  readonly ref: string;
  readonly requester: string;
  readonly description: string;
  /** Anything else the caller shows its approver (the helpdesk: the target). */
  readonly details: Readonly<Record<string, unknown>>;
}

/**
 * Resolves to `true` (one approver for the call) or an `ApprovedBy` (several) to
 * approve. Any other value, a rejection or a throw is not an approval.
 */
export type Approver = (proposal: Proposal) => Promise<unknown> | unknown;

/** Approver for evals and CI: every write is denied, so nothing is ever changed. */
export const denyAll: Approver = async () => false;

/**
 * Names which of the call's approvers answered, when there are several and which one is
 * known only when they answer. Honoured only if that sign-in is one of them.
 */
export class ApprovedBy {
  readonly approver: SignIn;
  constructor(approver: SignIn) {
    this.approver = approver;
    Object.freeze(this);
  }
}

/**
 * Who answers a write: one sign-in (a plain `true` approves), several (only an
 * `ApprovedBy` naming one of them approves), or nobody (no approval is honoured).
 */
export type Approvers = SignIn | readonly SignIn[] | null;

/** The caller's rules. Each refusal is a reason in words; null means allowed. */
export interface GateRules extends HandlerChecks {
  /** Why this requester may not ask for this write, or null. Writes only. */
  mayRequest(requester: string, call: Call): string | null;
  /** Who may answer this write. */
  approversFor(requester: string, call: Call): Approvers;
  /** Why this approver may not approve this write, or null. Checked before and after asking. */
  mayApprove(approver: string, requester: string, call: Call): string | null;
}

export interface GateOptions {
  /** Who is asking, signed in. Never a string; the model never supplies it. */
  signIn: SignIn;
  rules: GateRules;
  approver: Approver;
  audit: AuditSink;
  receipts: ReceiptAuthority;
}

export interface GateRequest<R> {
  tool: string;
  kind: CallKind;
  /** A plain object. The gate copies and freezes it before anything sees it. */
  args: Record<string, unknown>;
  ref: string;
  /** The caller's own check, run after `mayRequest` and before anyone is asked. Throw to stop. */
  check?: (call: Call) => void;
  /** What a write will do, for the approver. Required for writes. */
  describe?: (call: Call) => string;
  /** Shown to the approver alongside the description. */
  details?: Readonly<Record<string, unknown>>;
  /** Extra fields for the approval's audit record (the helpdesk: the ticket). */
  auditFields?: Readonly<Record<string, unknown>>;
  run: (args: Args) => Promise<R> | R;
}

/** Where a caller-supplied function threw. */
export type Stage = "rules" | "check" | "describe" | "approver" | "run";

export type GateOutcome<R> =
  /** The call ran under a verified grant (and, for a write, a receipt). */
  | {
      status: "ran";
      approval: "not_required" | "approved";
      result: R;
      grant: Grant;
      receipt: Receipt | null;
    }
  /** Refused by the rules before anyone was asked. */
  | { status: "refused"; approval: "not_asked"; reason: string }
  /** The approver said no, or the approval couldn't be honoured. Nothing ran. */
  | { status: "denied"; approval: "denied"; reason: string }
  /** The gate's own machinery refused (grant, receipt). Nothing ran. */
  | { status: "failed"; approval: Approval; reason: string; errorType: string }
  /** Something the caller supplied threw; the caller decides what it means. */
  | { status: "threw"; approval: Approval; stage: Stage; error: unknown };

/** The approval's audit fields, by id and hash only: never the receipt itself. */
export function receiptFields(receipt: Receipt) {
  return {
    approver: receipt.approver,
    args_sha256: receipt.argsSha256,
    receipt_jti: receipt.jti,
  };
}

/** A grant's audit fields, by id: never the token itself. */
export function grantFields(grant: Grant) {
  return { sub: grant.sub, act: grant.act, aud: grant.aud, scope: grant.scope, jti: grant.jti };
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const v of Object.values(value)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

export class ApprovalGate {
  readonly requester: string;
  readonly #signIn: SignIn;
  readonly #rules: GateRules;
  readonly #approver: Approver;
  readonly #audit: AuditSink;
  readonly #receipts: ReceiptAuthority;

  constructor(options: GateOptions) {
    if (!SignIn.is(options.signIn)) {
      throw new TypeError("the gate needs a SignIn from an issuer, not a string or a copy");
    }
    this.#signIn = options.signIn;
    this.requester = options.signIn.principal.sub;
    this.#rules = options.rules;
    this.#approver = options.approver;
    this.#audit = options.audit;
    this.#receipts = options.receipts;
  }

  async execute<R>(request: GateRequest<R>): Promise<GateOutcome<R>> {
    if (!isPlainObject(request.args)) throw new TypeError("args must be a plain object");
    if (request.kind !== "read" && request.kind !== "write") throw new TypeError("bad kind");
    // What anyone sees is what runs: a frozen deep copy, taken before the first rule.
    const call: Call = Object.freeze({
      tool: request.tool,
      kind: request.kind,
      args: deepFreeze(structuredClone(request.args)),
      ref: request.ref,
    });
    const write = call.kind === "write";
    const rules = this.#rules;
    const requester = this.requester;
    const threw = (stage: Stage, error: unknown, approval: Approval = Approval.NOT_ASKED) =>
      ({ status: "threw", approval, stage, error }) as const;
    const refused = (reason: string) =>
      ({ status: "refused", approval: "not_asked", reason }) as const;
    const denied = (reason: string) => ({ status: "denied", approval: "denied", reason }) as const;

    // 1. May this requester ask for this write at all?
    let approvers: Approvers = null;
    if (write) {
      let refusal: string | null;
      try {
        refusal = rules.mayRequest(requester, call);
        approvers = rules.approversFor(requester, call);
      } catch (exc) {
        return threw("rules", exc);
      }
      if (refusal !== null) return refused(refusal);
    }

    // 2. The caller's own check.
    if (request.check) {
      try {
        request.check(call);
      } catch (exc) {
        return threw("check", exc);
      }
    }

    let approval: Approval = Approval.NOT_REQUIRED;
    let proof: { token: string; authority: ReceiptAuthority } | null = null;
    if (write) {
      // 3. Refused before the prompt when nobody who could answer may approve it.
      const candidates: readonly unknown[] =
        approvers === null ? [] : SignIn.is(approvers) ? [approvers] : approvers;
      if (!Array.isArray(candidates) || !candidates.every((a) => SignIn.is(a))) {
        return threw("rules", new TypeError("every approver must be a SignIn from an issuer"));
      }
      if (approvers !== null) {
        let refusals: (string | null)[];
        try {
          refusals = (candidates as readonly SignIn[]).map((a) =>
            rules.mayApprove(a.principal.sub, requester, call),
          );
        } catch (exc) {
          return threw("rules", exc);
        }
        if (refusals.every((r) => r !== null)) {
          return refused(refusals.join(" ") || "nobody here may approve writes.");
        }
      }

      // 4. Ask.
      let proposal: Proposal;
      try {
        if (!request.describe) throw new TypeError("a write needs describe");
        proposal = Object.freeze({
          tool: call.tool,
          args: call.args,
          ref: call.ref,
          requester,
          description: request.describe(call),
          details: deepFreeze(structuredClone(request.details ?? {})),
        });
      } catch (exc) {
        return threw("describe", exc);
      }
      let answer: unknown;
      try {
        answer = await this.#approver(proposal);
      } catch (exc) {
        return threw("approver", exc);
      }
      let approvedBy: SignIn | null;
      if (answer instanceof ApprovedBy) {
        approvedBy =
          Array.isArray(approvers) && approvers.includes(answer.approver) ? answer.approver : null;
      } else if (answer === true) {
        approvedBy = SignIn.is(approvers) ? approvers : null;
      } else {
        return denied("the approver did not approve");
      }
      if (approvedBy === null) {
        return denied("approval not honoured: the approval came with no verified approver");
      }
      let refusal: string | null;
      try {
        refusal = rules.mayApprove(approvedBy.principal.sub, requester, call);
      } catch (exc) {
        return threw("rules", exc, Approval.DENIED);
      }
      if (refusal !== null) return denied(`approval not honoured: ${refusal}`);

      // 5. The receipt, then the approval on record, before acting.
      let token: string;
      let receipt: Receipt;
      try {
        ({ token, receipt } = await this.#receipts.sign(
          approvedBy.principal.sub,
          call.ref,
          call.tool,
          call.args,
        ));
      } catch (exc) {
        return failed(exc, Approval.APPROVED);
      }
      approval = Approval.APPROVED;
      await this.#audit.record("write_approved", {
        ...request.auditFields,
        tool: call.tool,
        args: call.args,
        effect: proposal.description,
        ...receiptFields(receipt),
      });
      proof = { token, authority: this.#receipts };
    }

    // 6. A fresh delegated token for exactly this call, checked by the handler side.
    let token: string;
    try {
      const needed = neededGrant(rules, call);
      try {
        token = await this.#signIn.grant(needed.audience, needed.scope, call.ref);
      } catch (exc) {
        if (exc instanceof TokenError) throw new GrantError(`exchange refused: ${exc.message}`);
        throw exc;
      }
    } catch (exc) {
      return exc instanceof GrantError ? failed(exc, approval) : threw("rules", exc, approval);
    }
    let ranTool = false;
    try {
      const ran = await runWithGrant({
        call,
        requester,
        token,
        resources: this.#signIn.resources,
        checks: rules,
        approval: proof,
        run: (args) => {
          ranTool = true;
          return request.run(args);
        },
      });
      return {
        status: "ran",
        approval: approval as "not_required" | "approved",
        result: ran.result,
        grant: ran.grant,
        receipt: ran.receipt,
      };
    } catch (exc) {
      if (ranTool) return threw("run", exc, approval);
      return exc instanceof GrantError ? failed(exc, approval) : threw("rules", exc, approval);
    }
  }
}

function failed(exc: unknown, approval: Approval) {
  return {
    status: "failed",
    approval,
    reason: exc instanceof Error ? exc.message : String(exc),
    errorType: exc instanceof Error ? exc.name : typeof exc,
  } as const;
}
