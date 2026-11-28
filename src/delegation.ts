/**
 * The handler side of a call: no tool runs without a delegated token. From
 * `helpdesk-agent/web/src/delegation.ts` at `dc26b4e` (identity phase I2 and I4 there).
 * Changes on the way: there's no fixed table of tools. The caller maps each call to the
 * audience and scope it needs (`grantFor`), so the audience can depend on the call's
 * arguments (the lifecycle demo has one audience per system). The check that the
 * requester's account is still active becomes a caller check too (`subjectRefusal`).
 *
 * Before the tool runs, `runWithGrant` verifies the token for this call: the audience
 * and scope the caller's mapping gives for the exact arguments about to run (worked out
 * here, never taken from the side that minted the token), this ref, the agent acting
 * for this requester, unexpired and never used before. Then the caller's check on the
 * requester, made now and not when the token was minted. A write also needs the
 * approval receipt, covering exactly this ref, tool and arguments, approved by someone
 * other than the requester, used once. Anything else throws `GrantError` and nothing
 * runs.
 */
import { type Grant, type Resources, TokenError } from "./identity.ts";
import type { Receipt, ReceiptAuthority } from "./receipts.ts";

/** A call's arguments: a plain object, frozen once the gate has copied it. */
export type Args = Readonly<Record<string, unknown>>;

export type CallKind = "read" | "write";

/** One tool call, as the gate and the handler see it. */
export interface Call {
  readonly tool: string;
  readonly kind: CallKind;
  readonly args: Args;
  /** What the call is for: the caller's ticket, run or finding. Tokens and receipts name it. */
  readonly ref: string;
}

export interface NeededGrant {
  readonly audience: string;
  readonly scope: string;
}

/** The caller's half of the handler check. */
export interface HandlerChecks {
  /** The audience and scope this call needs, or null if no grant is defined for it. */
  grantFor(call: Call): NeededGrant | null;
  /** Why this subject may not act now (say, a disabled account), or null. */
  subjectRefusal?(subject: string): string | null;
}

export class GrantError extends Error {
  override name = "GrantError";
}

/** The grant a call needs, or `GrantError`. */
export function neededGrant(checks: HandlerChecks, call: Call): NeededGrant {
  const needed = checks.grantFor(call);
  if (!needed) throw new GrantError(`no grant is defined for ${call.tool}`);
  return needed;
}

/** A write's approval receipt and the authority that signed it. */
export interface ApprovalProof {
  token: unknown;
  authority: ReceiptAuthority;
}

export interface HandlerCall<R> {
  call: Call;
  /** Whose call this is: the signed-in requester. */
  requester: string;
  token: unknown;
  resources: Resources;
  checks: HandlerChecks;
  approval?: ApprovalProof | null;
  run: (args: Args) => Promise<R> | R;
}

/**
 * Verify `token` (and, for a write, the approval receipt) for this call, then run it.
 * Returns the result plus the verified grant and receipt, for the audit record.
 */
export async function runWithGrant<R>(
  h: HandlerCall<R>,
): Promise<{ result: R; grant: Grant; receipt: Receipt | null }> {
  const { call } = h;
  const needed = neededGrant(h.checks, call);
  let grant: Grant;
  try {
    grant = await h.resources.get(needed.audience).verify(h.token, needed.scope, call.ref);
  } catch (exc) {
    if (exc instanceof TokenError) throw new GrantError(`grant refused: ${exc.message}`);
    throw exc;
  }
  if (grant.sub !== h.requester) throw new GrantError("grant refused: grant is for someone else");
  const refusal = h.checks.subjectRefusal?.(grant.sub) ?? null;
  if (refusal !== null) throw new GrantError(`grant refused: ${refusal}`);
  let receipt: Receipt | null = null;
  if (call.kind === "write") {
    if (!h.approval) throw new GrantError("receipt refused: no approval receipt");
    try {
      receipt = await h.approval.authority.verify(h.approval.token, call.ref, call.tool, call.args);
    } catch (exc) {
      if (exc instanceof TokenError) throw new GrantError(`receipt refused: ${exc.message}`);
      throw exc;
    }
    if (receipt.approver === grant.sub) {
      throw new GrantError("receipt refused: the requester approved their own request");
    }
  }
  return { result: await h.run(call.args), grant, receipt };
}
