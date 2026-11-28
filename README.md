# demo-agent-governance

Shared governance code for the Savory Air agent demos:

- [`helpdesk-agent`](https://github.com/gayrobot/helpdesk-agent), the IT helpdesk agent
- `identity-lifecycle-agent`, the leaver and mover demo

Both demos need the same things to prove an agent is governed: an audit trail that can't be quietly edited, approvals that become single-use receipts over the exact arguments, an agent identity with short-lived tokens scoped to one system, and a gate that decides who may ask and who may approve. This repo holds that code once.

Savory Air is a fictional company. Everything here is synthetic.

## Status

Every module has arrived, copied from `helpdesk-agent/web/src` at `dc26b4e` with its tests. Neither demo uses this repo yet: the lifecycle demo adopts it at its L4, and the helpdesk switches over in its own PR.

| Module | What changed on the way |
| --- | --- |
| `audit.ts` | Uses `text.ts` instead of the helpdesk's Python-compatibility helpers; the clock is required |
| `receipts.ts` | A receipt names a `ref` the caller defines (a ticket, or a run and a finding); the clock is required |
| `identity.ts` | Issuer, client id and the table of resources and scopes are configuration; clocks are required |
| `delegation.ts` | No fixed table of tools: the caller maps each call to its audience and scope, from the exact arguments about to run. The "requester's account is still active" check is the caller's too |
| `gate.ts`, the approval flow from `governance.ts` | A seam (`GateRules`) where the caller says who may request, who answers each call, whether they may approve, and which grant a call needs. Approvers and the ref come per call. The receipt authority is passed in |

The gate fixes the order: may the requester ask; the caller's own check; refuse before asking if no approver for this call may approve; ask, with a frozen deep copy of the arguments; honour only a signed-in approver for this call who still passes the rules; sign the receipt and record the approval before acting; mint a fresh grant for exactly this call, which the handler side checks before the tool runs.

What stays in each demo: the allowlist, argument validation, its own policy checks, what a read may show, the audit record of each call and the words the model sees. The gate returns an outcome (`ran`, `refused`, `denied`, `failed`, or `threw` when something the caller supplied threw) and the caller turns it into those.

For the helpdesk's switch-over, its adapter must:

- turn its approval rules (`authz.ts`) and tool table into `GateRules`, and its `operator` or `operators` into `approversFor`;
- rebuild its `Proposal`: `target` and `requesterIsTarget` now travel in `proposal.details` (read in `session.ts` and several tests), and `ApprovedBy.operator` is now `ApprovedBy.approver`;
- turn each outcome into its `Decision` and audit record, classifying what `threw` (its `PolicyDenied` and `ToolError`);
- pass its clock and a `ReceiptAuthority` in.

Messages that change: `another ticket` is now `another ref`; the gate's own denial reasons are worded generically (`the approver did not approve` instead of `operator did not type y`); and the approval record gains `ref`. One behaviour widens: with a single operator, an `ApprovedBy` naming that same sign-in is now honoured (no helpdesk test asserts otherwise).

## Using it

Each demo adds it as a submodule pinned to a commit:

```bash
git submodule add https://github.com/gayrobot/demo-agent-governance.git vendor/demo-agent-governance
```

and imports it by relative path, as TypeScript:

```ts
import { codePointLength } from "../vendor/demo-agent-governance/src/text.ts";
```

Clone a demo with `--recurse-submodules`, or run `git submodule update --init` afterwards; `npm ci` doesn't fetch submodules. CI checkout needs `submodules: true`. Moving to a newer commit here is a deliberate pin bump in the demo, in its own PR.

Why a submodule and not an npm package: Node won't run TypeScript from `node_modules`, and both demos turn install scripts off, so a package would need a build step and committed compiled output. A submodule keeps every repo running TypeScript directly.

## Rules

`src/` never reads the wall clock and never touches the network: callers pass in clocks, keys and stores. It uses only platform APIs (WebCrypto, `TextEncoder`), so it runs in Node 24 and in Cloudflare Workers. There are no runtime dependencies. See `CLAUDE.md` for the rest.

## Commands

```bash
npm ci && npm run check   # lint, type check, unit tests (no key)
gitleaks git -v           # scan history for secrets
pre-commit install        # once per clone
```

## Licence

MIT. The code comes from `helpdesk-agent`, which is MIT too.
