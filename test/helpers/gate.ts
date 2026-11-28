// Two rule sets for the gate, one per demo, small enough to read in one go.
//
// HelpdeskWorld mirrors the helpdesk's directory rules at dc26b4e (authz.ts there): you
// may ask for a change to your own account or a report's; IT support may reset MFA for
// ordinary active accounts; only an active member of it-support who is neither the
// requester nor the target approves; one operator answers for the whole gate.
//
// LifecycleWorld is shaped like the lifecycle demo: every call names a system, the
// audience is that system's, the ref is a run and a finding, and the registry names who
// approves for each system.

import { MemoryAudit } from "../../src/audit.ts";
import type { Args, Call, NeededGrant } from "../../src/delegation.ts";
import {
  ApprovalGate,
  type Approver,
  type Approvers,
  denyAll,
  type GateRules,
  type Proposal,
} from "../../src/gate.ts";
import { DevIssuer, type SignIn } from "../../src/identity.ts";
import { ReceiptAuthority } from "../../src/receipts.ts";
import { HELPDESK, LIFECYCLE } from "./config.ts";

export const NOW = 1_800_000_000;
export const FIXED_DATE = new Date("2026-11-25T16:01:43.091Z");

export const JAMIE = "jamie@example.test";
export const THEO = "theo.park@example.test"; // it-support
export const SAM = "sam.whitfield@example.test"; // Theo's manager
export const MORGAN = "morgan.hale@example.test"; // Jamie's manager, not it-support
export const DANA = "dana.ito@example.test";
export const RILEY = "riley.okafor@example.test"; // disabled
export const TICKET = "T-TEST";

export interface Person {
  groups: string[];
  status: "active" | "disabled";
  manager: string | null;
  mfaEnrolled: boolean;
}

export function people(): Map<string, Person> {
  const p = (groups: string[], manager: string | null, status: Person["status"] = "active") => ({
    groups,
    status,
    manager,
    mfaEnrolled: true,
  });
  return new Map([
    [JAMIE, p(["staff"], MORGAN)],
    [THEO, p(["staff", "it-support"], SAM)],
    [SAM, p(["staff"], null)],
    [MORGAN, p(["staff"], null)],
    [DANA, p(["staff"], MORGAN)],
    [RILEY, p(["staff"], MORGAN, "disabled")],
  ]);
}

const HELPDESK_GRANTS: Record<string, NeededGrant> = {
  lookup_user: { audience: "savory-air-directory", scope: "directory:read" },
  reset_mfa: { audience: "savory-air-directory", scope: "directory:mfa.reset" },
  add_to_group: { audience: "savory-air-directory", scope: "directory:group.add" },
};

export class HelpdeskWorld {
  readonly directory = people();
  readonly issuer: DevIssuer;
  clock = NOW;
  operator: SignIn | null = null;

  constructor() {
    this.issuer = new DevIssuer({ config: HELPDESK, now: () => this.clock });
  }

  #helpdesk(email: string): boolean {
    const u = this.directory.get(email);
    return !!u && u.status === "active" && u.groups.includes("it-support");
  }

  readonly rules: GateRules = {
    mayRequest: (requester, call) => {
      const target = this.directory.get(String(call.args.email));
      if (!target) return null; // the tool's own "no such user"
      if (call.args.email === requester || target.manager === requester) return null;
      if (call.tool === "reset_mfa" && this.#helpdesk(requester) && target.status === "active") {
        return null;
      }
      return `${String(call.args.email)} is not the requester or someone who reports to them.`;
    },
    approversFor: () => this.operator,
    mayApprove: (approver, requester, call) => {
      if (!this.#helpdesk(approver)) {
        return `${approver} is not an active member of it-support, so they can't approve writes.`;
      }
      if (approver === requester) {
        return `${approver} filed this request, and nobody approves their own request.`;
      }
      if (approver === call.args.email) {
        return `${approver} is the account being changed, and nobody approves a change to their own account.`;
      }
      return null;
    },
    grantFor: (call) =>
      Object.hasOwn(HELPDESK_GRANTS, call.tool) ? (HELPDESK_GRANTS[call.tool] ?? null) : null,
    subjectRefusal: (subject) =>
      this.directory.get(subject)?.status === "disabled"
        ? "the requester's account is not active"
        : null,
  };

  /** The tools, as the helpdesk runs them: a read, and two writes on the directory. */
  run(tool: string): (args: Args) => Record<string, unknown> {
    return (args) => {
      const user = this.directory.get(String(args.email));
      if (!user) throw new Error(`no such user ${String(args.email)}`);
      if (tool === "reset_mfa") user.mfaEnrolled = false;
      if (tool === "add_to_group") user.groups.push(String(args.group));
      return { email: args.email, groups: [...user.groups], mfa: user.mfaEnrolled };
    };
  }

  request(tool: string, args: Record<string, unknown>, ref = TICKET) {
    return {
      tool,
      kind: tool === "lookup_user" ? ("read" as const) : ("write" as const),
      args,
      ref,
      describe: (call: Call) => `${tool} for ${String(call.args.email)}`,
      details: { target: args.email },
      auditFields: { ticket_id: ref },
      run: this.run(tool),
    };
  }

  async gate(
    options: {
      requester?: string;
      operator?: string | null;
      approver?: Approver;
      receipts?: ReceiptAuthority;
      audit?: MemoryAudit;
    } = {},
  ) {
    const audit = options.audit ?? new MemoryAudit(() => FIXED_DATE);
    const receipts = options.receipts ?? new ReceiptAuthority(() => this.clock);
    this.operator =
      options.operator === null ? null : await this.issuer.signIn(options.operator ?? THEO);
    const gate = new ApprovalGate({
      signIn: await this.issuer.signIn(options.requester ?? JAMIE),
      rules: this.rules,
      approver: options.approver ?? denyAll,
      audit,
      receipts,
    });
    return { gate, audit, receipts };
  }

  snapshot(email: string): string {
    return JSON.stringify(this.directory.get(email));
  }
}

export class RecordingApprover {
  readonly proposals: Proposal[] = [];
  readonly answer: unknown;
  constructor(answer: unknown) {
    this.answer = answer;
  }
  approve: Approver = async (proposal) => {
    this.proposals.push(proposal);
    return this.answer;
  };
}

// ---------------------------------------------------------------- lifecycle-shaped

export const LEAD = "lena.ortiz@example.test"; // who started the offboarding run
export const SAAS_OWNER = "priya.nair@example.test";
export const ADS_OWNER = "omar.haddad@example.test";
export const finding = (system: string, account: string) =>
  `run-0001/${system}/${account}/active_account`;

export class LifecycleWorld {
  readonly issuer: DevIssuer;
  readonly accounts = new Map<string, "active" | "deactivated">([
    ["saas/SAAS-00008", "active"],
    ["ads/ADS-00002", "active"],
  ]);
  /** Who approves for each system, as the registry names them. */
  owners = new Map<string, SignIn>();
  clock = NOW;

  constructor() {
    this.issuer = new DevIssuer({ config: LIFECYCLE, now: () => this.clock });
  }

  readonly rules: GateRules = {
    mayRequest: () => null,
    approversFor: (_requester, call): Approvers =>
      this.owners.get(String(call.args.system)) ?? null,
    mayApprove: (approver, requester) =>
      approver === requester ? `${approver} started this run, so they don't approve it.` : null,
    grantFor: (call) => {
      const system = String(call.args.system);
      const scope = call.tool === "deactivate_account" ? "accounts:deactivate" : null;
      if (!scope || !LIFECYCLE.resources[`savory-air-${system}`]) return null;
      return { audience: `savory-air-${system}`, scope };
    },
  };

  async setUp() {
    this.owners = new Map([
      ["saas", await this.issuer.signIn(SAAS_OWNER)],
      ["ads", await this.issuer.signIn(ADS_OWNER)],
    ]);
    return this;
  }

  deactivate(system: string, account: string) {
    return {
      tool: "deactivate_account",
      kind: "write" as const,
      args: { system, account },
      ref: finding(system, account),
      describe: (call: Call) =>
        `Deactivate ${String(call.args.account)} in ${String(call.args.system)}`,
      run: (args: Args) => {
        this.accounts.set(`${String(args.system)}/${String(args.account)}`, "deactivated");
        return { ok: true };
      },
    };
  }

  audit = new MemoryAudit(() => FIXED_DATE);

  async gate(approver: Approver) {
    return new ApprovalGate({
      signIn: await this.issuer.signIn(LEAD),
      rules: this.rules,
      approver,
      audit: this.audit,
      receipts: new ReceiptAuthority(() => this.clock),
    });
  }
}
