// Delegated tokens: the grant, the exchange and the replay cache. Ported from
// helpdesk-agent's web/test/delegation.test.ts at dc26b4e (identity phase I2 there),
// configured with the helpdesk's values. Every attack on a grant fails closed. The
// tests that go through the helpdesk's gate and tool handlers move with the gate.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AgentIdentity,
  b64urlEncode,
  DevIssuer,
  GRANT_SECONDS,
  GrantVerifier,
  type KeyPair,
  ReplayCache,
  Resources,
  signJws,
  TokenError,
} from "../src/identity.ts";
import { HELPDESK, JAMIE, LIFECYCLE } from "./helpers/config.ts";

const DEV_ISSUER = HELPDESK.issuer;
const AGENT_AUDIENCE = HELPDESK.agentAudience;
const AGENT_CLIENT_ID = HELPDESK.agentClientId;

const DIR = "savory-air-directory";
const TICKET = "T-TEST";
const NOW = 1_800_000_000;
const now = () => NOW;
const issuer = (options: { agent?: AgentIdentity } = {}) =>
  new DevIssuer({ config: HELPDESK, now, ...options });
const agent = () => new AgentIdentity(AGENT_CLIENT_ID, now);

const newKeys = () =>
  crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]) as Promise<KeyPair>;

/** A resource-side verifier with a test key, so tests can sign any token they like. */
async function fixture() {
  const keys = await newKeys();
  const replay = new ReplayCache();
  const verifier = new GrantVerifier({
    issuer: DEV_ISSUER,
    audience: DIR,
    key: keys.publicKey,
    replay,
    agentClientId: AGENT_CLIENT_ID,
    subjectPattern: HELPDESK.subjectPattern,
    now,
  });
  const claims = (over: Record<string, unknown> = {}) => ({
    iss: DEV_ISSUER,
    sub: JAMIE,
    act: { sub: AGENT_CLIENT_ID },
    aud: DIR,
    scope: "directory:read",
    ref: TICKET,
    iat: NOW,
    exp: NOW + GRANT_SECONDS,
    jti: b64urlEncode(crypto.getRandomValues(new Uint8Array(16))),
    ...over,
  });
  const sign = (c: Record<string, unknown>, header: Record<string, unknown> = { typ: "at+jwt" }) =>
    signJws(header, c, keys.privateKey, "ES256");
  return { keys, verifier, replay, claims, sign };
}

test("ts_i2_a_well_formed_grant_verifies_once", async () => {
  const f = await fixture();
  const token = await f.sign(f.claims());
  const grant = await f.verifier.verify(token, "directory:read", TICKET);
  assert.equal(grant.sub, JAMIE);
  assert.equal(grant.act, AGENT_CLIENT_ID);
  await assert.rejects(f.verifier.verify(token, "directory:read", TICKET), /already used/);
});

const strip = (c: Record<string, unknown>, name: string) => {
  const { [name]: _gone, ...rest } = c;
  return rest;
};

const BAD_CLAIMS: [string, (c: Record<string, unknown>) => Record<string, unknown>, RegExp][] = [
  ["expired", (c) => ({ ...c, iat: NOW - 200, exp: NOW - 100 }), /expired/],
  ["not yet valid", (c) => ({ ...c, nbf: NOW + 120 }), /not yet valid/],
  ["issued in the future", (c) => ({ ...c, iat: NOW + 120, exp: NOW + 150 }), /future/],
  ["lives too long", (c) => ({ ...c, exp: NOW + 3600 }), /too long/],
  ["wrong issuer", (c) => ({ ...c, iss: "https://evil.example.test" }), /wrong issuer/],
  ["wrong audience", (c) => ({ ...c, aud: "savory-air-runbooks" }), /wrong audience/],
  ["audience as an array", (c) => ({ ...c, aud: [DIR] }), /wrong audience/],
  ["read scope used for a write", (c) => c, /wrong scope/], // verified for mfa.reset below
  ["two scopes", (c) => ({ ...c, scope: "directory:read directory:mfa.reset" }), /wrong scope/],
  ["no act", (c) => strip(c, "act"), /missing claim act/],
  ["act is not the agent", (c) => ({ ...c, act: { sub: "someone-else" } }), /not acting/],
  ["act is a string", (c) => ({ ...c, act: AGENT_CLIENT_ID }), /not acting/],
  ["another ref", (c) => ({ ...c, ref: "T-OTHER" }), /another ref/],
  ["no jti", (c) => strip(c, "jti"), /missing claim jti/],
  ["subject not an email", (c) => ({ ...c, sub: "Jamie@Example.test" }), /subject not allowed/],
];

for (const [name, edit, error] of BAD_CLAIMS) {
  test(`ts_i2_grant_refused[${name}]`, async () => {
    const f = await fixture();
    const scope = name === "read scope used for a write" ? "directory:mfa.reset" : "directory:read";
    const token = await f.sign(edit(f.claims()));
    await assert.rejects(f.verifier.verify(token, scope, TICKET), error);
  });
}

test("ts_i2_grant_refused[missing]", async () => {
  const f = await fixture();
  for (const token of [undefined, null, "", 42]) {
    await assert.rejects(f.verifier.verify(token, "directory:read", TICKET), /no grant/);
  }
});

test("ts_i2_grant_refused[alg none and HS256]", async () => {
  const f = await fixture();
  const body = b64urlEncode(new TextEncoder().encode(JSON.stringify(f.claims())));
  for (const alg of ["none", "HS256", "RS256"]) {
    const head = b64urlEncode(new TextEncoder().encode(JSON.stringify({ alg, typ: "at+jwt" })));
    await assert.rejects(
      f.verifier.verify(`${head}.${body}.`, "directory:read", TICKET),
      /algorithm not allowed/,
    );
  }
});

test("ts_i2_grant_refused[edited payload]", async () => {
  const f = await fixture();
  const [h, , s] = (await f.sign(f.claims())).split(".");
  const edited = b64urlEncode(
    new TextEncoder().encode(JSON.stringify(f.claims({ sub: "morgan.hale@example.test" }))),
  );
  await assert.rejects(
    f.verifier.verify(`${h}.${edited}.${s}`, "directory:read", TICKET),
    /bad signature/,
  );
});

test("ts_i2_grant_refused[signed by another key]", async () => {
  const f = await fixture();
  const other = await newKeys();
  const token = await signJws({ typ: "at+jwt" }, f.claims(), other.privateKey, "ES256");
  await assert.rejects(f.verifier.verify(token, "directory:read", TICKET), /bad signature/);
});

test("ts_i2_grant_refused[subject token presented at a tool]", async () => {
  const f = await fixture();
  // A subject token is typed JWT, names the agent as its audience and has no act.
  const subject = await f.sign(
    { iss: DEV_ISSUER, sub: JAMIE, aud: AGENT_AUDIENCE, iat: NOW, exp: NOW + 900, jti: "s1" },
    { typ: "JWT" },
  );
  await assert.rejects(f.verifier.verify(subject, "directory:read", TICKET), /not a delegated/);
  // Even typed as a grant, it fails on its claims.
  const retyped = await f.sign({
    iss: DEV_ISSUER,
    sub: JAMIE,
    aud: AGENT_AUDIENCE,
    iat: NOW,
    exp: NOW + 900,
    jti: "s2",
  });
  await assert.rejects(f.verifier.verify(retyped, "directory:read", TICKET), /missing claim/);
});

test("ts_i2_replay_cache_forgets_expired_tokens_only", () => {
  const cache = new ReplayCache();
  cache.use("a", NOW + 60, NOW);
  assert.throws(() => cache.use("a", NOW + 60, NOW + 10), /already used/);
  cache.use("b", NOW + 200, NOW + 200); // "a" expired long ago and is dropped
  assert.equal(cache.size, 1);
});

// ---------------------------------------------------------------- the exchange

test("ts_i2_exchange_issues_one_scope_for_one_audience_and_ref", async () => {
  const signIn = await issuer().signIn(JAMIE);
  const token = await signIn.grant(DIR, "directory:read", TICKET);
  const grant = await signIn.resources.get(DIR).verify(token, "directory:read", TICKET);
  assert.deepEqual(
    { sub: grant.sub, aud: grant.aud, scope: grant.scope, act: grant.act },
    { sub: JAMIE, aud: DIR, scope: "directory:read", act: AGENT_CLIENT_ID },
  );
  // The same grant at another resource, for another scope or ticket: refused.
  const again = await signIn.grant(DIR, "directory:read", TICKET);
  await assert.rejects(
    signIn.resources.get("savory-air-tickets").verify(again, "tickets:escalate", TICKET),
    /wrong audience/,
  );
});

test("ts_i2_exchange_refuses_scopes_a_resource_does_not_offer", async () => {
  const signIn = await issuer().signIn(JAMIE);
  await assert.rejects(signIn.grant("savory-air-runbooks", "directory:read", TICKET), /scope not/);
  await assert.rejects(signIn.grant("savory-air-hr", "hr:read", TICKET), /unknown resource/);
  await assert.rejects(signIn.grant(DIR, "directory:*", TICKET), /scope not/);
  await assert.rejects(signIn.grant(DIR, "directory:read", "T 1\n"), /bad ref/);
  await assert.rejects(signIn.grant("__proto__", "x", TICKET), /unknown resource/);
});

test("ts_i2_exchange_needs_the_registered_agent_and_a_valid_subject_token", async () => {
  const dev = issuer();
  const subject = await dev.mint(JAMIE);
  const request = (actorToken: string, subjectToken = subject) => ({
    subjectToken,
    actorToken,
    audience: DIR,
    scope: "directory:read",
    ref: TICKET,
  });
  // An assertion from some other agent key.
  const impostor = agent();
  await assert.rejects(
    dev.exchange(request(await impostor.assertion(DEV_ISSUER))),
    /bad signature/,
  );
  // The other issuer's subject token, with this issuer's agent: refused.
  const issuer2 = issuer();
  const registered = agent();
  const withAgent = issuer({ agent: registered });
  await assert.rejects(
    withAgent.exchange(request(await registered.assertion(DEV_ISSUER), await issuer2.mint(JAMIE))),
    /bad signature/,
  );
  // An assertion for another issuer, and a replayed assertion.
  await assert.rejects(
    withAgent.exchange(request(await registered.assertion("https://other.example.test"))),
    /another issuer/,
  );
  const good = await withAgent.mint(JAMIE);
  const assertion = await registered.assertion(DEV_ISSUER);
  await withAgent.exchange(request(assertion, good));
  await assert.rejects(withAgent.exchange(request(assertion, good)), /already used/);
  // A grant presented as the subject token.
  const grant = await withAgent.exchange(request(await registered.assertion(DEV_ISSUER), good));
  await assert.rejects(
    withAgent.exchange(request(await registered.assertion(DEV_ISSUER), grant)),
    TokenError,
  );
});

test("ts_i2_resources_reject_unknown_audiences", () => {
  assert.throws(() => new Resources([]).get(DIR), /unknown resource/);
});

// ---------------------------------------------------------------- what changed on the way

test("a lifecycle-shaped deployment: one audience per system, a grant for one run and finding", async () => {
  const dev = new DevIssuer({ config: LIFECYCLE, now });
  const signIn = await dev.signIn(JAMIE);
  const ref = "run-0001/saas/SAAS-00008/active_account";
  const token = await signIn.grant("savory-air-saas", "accounts:deactivate", ref);
  const grant = await signIn.resources
    .get("savory-air-saas")
    .verify(token, "accounts:deactivate", ref);
  assert.deepEqual(
    { aud: grant.aud, scope: grant.scope, ref: grant.ref, act: grant.act },
    {
      aud: "savory-air-saas",
      scope: "accounts:deactivate",
      ref,
      act: "lifecycle-agent",
    },
  );
  // A grant for one system's account is no good at another system, or for another finding.
  const other = await signIn.grant("savory-air-saas", "accounts:deactivate", ref);
  await assert.rejects(
    signIn.resources.get("savory-air-ads").verify(other, "accounts:deactivate", ref),
    /wrong audience/,
  );
  const third = await signIn.grant("savory-air-saas", "accounts:deactivate", ref);
  await assert.rejects(
    signIn.resources
      .get("savory-air-saas")
      .verify(third, "accounts:deactivate", "run-0001/saas/SAAS-00009/active_account"),
    /another ref/,
  );
  await assert.rejects(signIn.grant("savory-air-saas", "accounts:deactivate", "T-TEST"), /bad ref/);
  // The helpdesk's agent can't act in the lifecycle deployment.
  await assert.rejects(
    dev.exchange({
      subjectToken: await dev.mint(JAMIE),
      actorToken: await agent().assertion(LIFECYCLE.issuer),
      audience: "savory-air-saas",
      scope: "accounts:deactivate",
      ref,
    }),
    TokenError,
  );
});
