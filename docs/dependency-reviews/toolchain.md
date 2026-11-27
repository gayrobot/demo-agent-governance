# Dependency review: toolchain

Status: **accepted with the first commit**. Dev dependencies only.

The same three packages, at the same exact versions, that `gayrobot/helpdesk-agent` reviewed for its `web/` toolchain on 2026-11-25 (`docs/dependency-reviews/web-toolchain.md` there, at `db17b92`), and that `identity-lifecycle-agent` adopted at its L0. That review covers maintainers, download counts, licences, native binaries and alternatives; it isn't repeated here.

| Package | Version | Why |
| --- | --- | --- |
| `typescript` | 7.0.2 | Type check (`tsc --noEmit`). |
| `@biomejs/biome` | 2.6.8 | Lint and format. |
| `@types/node` | 24.19.2 | Types for `node:test`, `node:assert`, `node:fs` in the tests. `src/` uses no `node:` modules. |

The lockfile is `identity-lifecycle-agent`'s, unchanged except for the package name: the same 34 packages, each with an integrity hash. `test/toolchain.test.ts` checks that.

No runtime dependencies. Signing, verifying and hashing use WebCrypto, which Node 24 and Cloudflare Workers both provide.
