# demo-agent-governance

Shared governance code for the Savory Air agent demos:

- [`helpdesk-agent`](https://github.com/gayrobot/helpdesk-agent), the IT helpdesk agent
- `identity-lifecycle-agent`, the leaver and mover demo

Both demos need the same things to prove an agent is governed: an audit trail that can't be quietly edited, approvals that become single-use receipts over the exact arguments, an agent identity with short-lived tokens scoped to one system, and a gate that decides who may ask and who may approve. This repo holds that code once.

Savory Air is a fictional company. Everything here is synthetic.

## Status

The harness only: safety rules, CI, guard tests, and the first helper. The modules arrive by PR, as copies from `helpdesk-agent/web/src` at `dc26b4e`, with their tests:

| Module | What changes on the way |
| --- | --- |
| `audit.ts` | Uses `text.ts` instead of the helpdesk's Python-compatibility helpers; the clock becomes required |
| `receipts.ts` | A receipt names a subject the caller defines; the clock becomes required |
| `identity.ts` | Issuer, client id and the table of resources and scopes become configuration; clocks become required |
| `delegation.ts` | The caller maps each call to its audience and scope |
| The approval gate from `governance.ts` | A seam where the caller supplies who may request, who may approve and which grant a call needs |

The helpdesk's token and receipt attack tests come with them and must pass before either demo uses this repo.

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
