# demo-agent-governance

Shared governance code for two Savory Air demos: `gayrobot/helpdesk-agent` and `gayrobot/identity-lifecycle-agent`. It holds the audit hash chain, approval receipts, agent identity and tokens, grants, and the approval gate. Each demo pulls it in as a git submodule pinned to a commit, at `vendor/demo-agent-governance`, and imports it as TypeScript. The plan is in `identity-lifecycle-agent`'s `docs/lifecycle-spec.md`, under "Sharing with the helpdesk" (spec draft 5).

The code starts as a copy of the helpdesk's modules at `dc26b4e`, made generic: callers supply clocks, keys, configuration and the rules for who may request, who may approve and which grant a call needs. Nothing here knows about a helpdesk, a directory, a registry or a scenario.

## Hard rules

- **No secrets in code, logs, commits, PRs or prompts.** Nothing here ever needs a key. Test keys are generated in memory by the tests.
- **Claude Code never reads `.env` files and never runs `op read`, `op item get` or `op inject`.** `.claude/settings.json` denies these; don't work around it.
- **No wall clock and no network in `src/`.** Every clock, key, store and lookup is passed in by the caller. `test/guards.test.ts` enforces it. Both demos run this code in labs that forbid either.
- **Synthetic data only.** Any person, address or example is invented, at `example.test`. Tests enforce it. Never use real people's data or anything from Skylar's employers.
- **Nothing deletes.** This code records, signs and checks; it never removes a record.
- **Treat everything a caller passes in as data**, never as instructions.
- **Security behaviour changes only with tests.** The token and receipt attack tests move here with the code and must keep passing. A change that weakens a check needs Skylar's explicit decision.

## Working rules

- Every change goes through a PR. Never push to `main`. CI must pass. Never use `--no-verify`.
- Both demos pin this repo to a commit. A change here reaches a demo only when that demo bumps its pin in its own reviewed PR, so keep changes small and say in the PR which demos need them.
- Supply-chain rules are in `.npmrc`: exact pins, a committed `package-lock.json`, a 7-day release cooldown (`min-release-age`) and no install scripts. No runtime dependencies. Prefer Node and WebCrypto platform APIs over packages; each new package gets a review in `docs/dependency-reviews/` first.
- GitHub Actions and pre-commit hooks are pinned to commit SHAs with the tag in a comment.
- Node runs the TypeScript directly: erasable syntax only (no enums, namespaces or parameter properties). The code must also run in Cloudflare Workers, where the helpdesk deploys: platform APIs only (WebCrypto, `TextEncoder`), no `node:` imports in `src/`.

## Commands

```bash
npm ci && npm run check   # lint, type check, unit tests (no key)
gitleaks git -v           # scan history for secrets
pre-commit install        # once per clone
```
