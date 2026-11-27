/**
 * Who is asking, and what the agent may do for them. From
 * `helpdesk-agent/web/src/identity.ts` at `dc26b4e` (identity phases I1 and I2 there),
 * made generic. Built on Web Crypto only: no JOSE library.
 *
 * - `Principal`: a verified requester. The only way to get one is `TokenVerifier.verify`
 *   on a signed token. It cannot be built from a string, a look-alike object, a copy or
 *   a JSON round trip.
 * - `DevIssuer`: mints subject tokens for synthetic users, with an ES256 key held in
 *   memory, and runs the token exchange.
 * - `TokenVerifier`: one issuer, one audience, one algorithm, one key, all fixed by
 *   configuration and never taken from the token. Strict about the encoding and every
 *   claim.
 * - `AgentIdentity`: the agent as its own client, with its own key. For every call it
 *   exchanges the requester's subject token plus its own signed client assertion for a
 *   60-second token naming one audience, one scope and one `ref` (the RFC 8693 shape).
 * - `GrantVerifier`: the resource side. It accepts only such tokens, each `jti` once.
 *
 * Changes from the helpdesk:
 * - Everything the helpdesk fixed as a constant is the caller's `IssuerConfig`: the
 *   issuer name, the agent's audience and client id, the resources and their scopes,
 *   which subjects may hold a token, and what a grant may be for.
 * - A grant is for a caller-defined `ref` (a ticket id in the helpdesk, a run and
 *   finding in the lifecycle demo), carried in the `ref` claim.
 * - Every clock is required. Keys and token ids may be passed in, so a deterministic lab
 *   can supply its own; by default keys are generated in memory and ids are random.
 * - Okta's sign-in verifier stays in the helpdesk, with the rest of its Okta code.
 *
 * Tokens never go to the model, the logs, a page or storage.
 */

/** What a deployment of this code fixes, instead of constants. */
export interface IssuerConfig {
  /** The issuer name in every token. */
  issuer: string;
  /** The audience of subject tokens: the agent's own service. */
  agentAudience: string;
  /** The agent's client id: `act.sub` in every grant. */
  agentClientId: string;
  /** Resource servers (token audiences) and the scopes each one accepts. */
  resources: Readonly<Record<string, readonly string[]>>;
  /** Which subjects may hold a token, e.g. directory-shaped emails. */
  subjectPattern: RegExp;
  /** What a grant may be for, e.g. a ticket id pattern. */
  refPattern: RegExp;
}

/** Ways to make a key pair or a token id deterministic. Both default to random. */
export interface Determinism {
  keys?: KeyPair | Promise<KeyPair>;
  newId?: () => string;
}

export const SUBJECT_TOKEN_SECONDS = 15 * 60;
export const MAX_CLOCK_SKEW_SECONDS = 30;
/** The algorithms a verifier can be configured with. ES256 for our own keys; RS256 only
 * because Okta signs with it (identity phase I5). The caller picks one; the token never does. */
const ALGORITHMS = {
  ES256: { name: "ECDSA", hash: "SHA-256" },
  RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
} as const;
export type Algorithm = keyof typeof ALGORITHMS;
/** The smallest RSA key accepted anywhere. */
export const MIN_RSA_BITS = 2048;

/** The exact signature length for this algorithm and key, or throw if the key doesn't fit. */
function signatureBytes(algorithm: Algorithm, key: Key): number {
  const keyAlg = key.algorithm as { name?: string; namedCurve?: string; modulusLength?: number };
  if (keyAlg.name !== ALGORITHMS[algorithm].name)
    throw new TokenError("key does not match algorithm");
  if (algorithm === "ES256") {
    if (keyAlg.namedCurve !== "P-256") throw new TokenError("key does not match algorithm");
    return 64;
  }
  const bits = keyAlg.modulusLength ?? 0;
  if (bits < MIN_RSA_BITS || bits % 8 !== 0) throw new TokenError("RSA key too small");
  return bits / 8;
}

/** Web Crypto key types, named here so the code compiles under Node and Workers types. */
export type Key = Awaited<ReturnType<typeof crypto.subtle.importKey>>;
export interface KeyPair {
  privateKey: Key;
  publicKey: Key;
}

export class TokenError extends Error {
  override name = "TokenError";
}

// ---------------------------------------------------------------- base64url

const B64URL = /^[A-Za-z0-9_-]*$/;

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict: the base64url alphabet only, no padding, no impossible lengths. */
export function b64urlDecode(text: string): Uint8Array {
  if (!B64URL.test(text) || text.length % 4 === 1) throw new TokenError("bad base64url");
  const padded =
    text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  // Reject non-canonical encodings (stray bits in the last character).
  if (b64urlEncode(out) !== text) throw new TokenError("non-canonical base64url");
  return out;
}

const utf8 = new TextEncoder();
const fromUtf8 = (b: Uint8Array) =>
  new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(b);

function decodeJsonSegment(segment: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(fromUtf8(b64urlDecode(segment)));
  } catch (exc) {
    if (exc instanceof TokenError) throw exc;
    throw new TokenError("segment is not JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TokenError("segment is not a JSON object");
  }
  return value as Record<string, unknown>;
}

// ---------------------------------------------------------------- JWS (compact, ES256 or RS256)

/** Public keys looked up by the header's `kid`, from a key set fixed by configuration
 * (Okta's JWKS, `okta.ts`). Never a key the token supplies or points at. */
export interface KeySet {
  key(kid: string): Promise<Key>;
}

const KID = /^[A-Za-z0-9_-]{1,128}$/;

/** As `verifyJwsSignature`, with the key chosen from `keys` by the header's `kid`. */
export async function verifyJwsWithKeySet(
  token: string,
  keys: KeySet,
  algorithm: Algorithm,
): Promise<{ header: Record<string, unknown>; payload: Uint8Array }> {
  if (typeof token !== "string") throw new TokenError("token is not a string");
  const header = decodeJsonSegment(token.split(".")[0] ?? "");
  if (typeof header.kid !== "string" || !KID.test(header.kid)) throw new TokenError("bad kid");
  return verifyJwsSignature(token, await keys.key(header.kid), algorithm);
}

/** Verify a compact JWS signature only (no claim checks). The algorithm comes from the
 * caller, never the header; a header naming anything else is refused. */
export async function verifyJwsSignature(
  token: string,
  key: Key,
  algorithm: Algorithm,
): Promise<{ header: Record<string, unknown>; payload: Uint8Array }> {
  if (typeof token !== "string") throw new TokenError("token is not a string");
  const parts = token.split(".");
  if (parts.length !== 3) throw new TokenError("a JWS has three segments");
  const [h, p, s] = parts as [string, string, string];
  const header = decodeJsonSegment(h);
  if (header.alg !== algorithm) throw new TokenError("algorithm not allowed");
  for (const field of ["jwk", "jku", "x5u", "x5c", "crit"]) {
    if (field in header) throw new TokenError(`header field ${field} not allowed`);
  }
  const signature = b64urlDecode(s);
  const alg = ALGORITHMS[algorithm];
  if (signature.length !== signatureBytes(algorithm, key)) {
    throw new TokenError("bad signature length");
  }
  const ok = await crypto.subtle.verify(
    { name: alg.name, hash: alg.hash },
    key,
    signature,
    utf8.encode(`${h}.${p}`),
  );
  if (!ok) throw new TokenError("bad signature");
  return { header, payload: b64urlDecode(p) };
}

export async function signJws(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  key: Key,
  algorithm: Algorithm,
): Promise<string> {
  const alg = ALGORITHMS[algorithm];
  const h = b64urlEncode(utf8.encode(JSON.stringify({ ...header, alg: algorithm })));
  const p = b64urlEncode(utf8.encode(JSON.stringify(claims)));
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: alg.name, hash: alg.hash }, key, utf8.encode(`${h}.${p}`)),
  );
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

// ---------------------------------------------------------------- Principal

const MINT = Symbol("principal-mint");

/** A verified requester. Only `TokenVerifier.verify` can make one. */
export class Principal {
  readonly #brand = true;
  readonly sub: string;
  readonly issuer: string;
  /** The token's id, for audit records; never the token itself. */
  readonly jti: string;

  constructor(key: symbol, sub: string, issuer: string, jti: string) {
    if (key !== MINT) throw new TypeError("a Principal comes only from a verified token");
    this.sub = sub;
    this.issuer = issuer;
    this.jti = jti;
    Object.freeze(this);
  }

  /** True only for objects this module constructed. Copies and look-alikes fail. */
  static is(value: unknown): value is Principal {
    return typeof value === "object" && value !== null && #brand in value;
  }

  toJSON() {
    return { sub: this.sub, issuer: this.issuer };
  }
}

// ---------------------------------------------------------------- verifier

export interface VerifierConfig {
  issuer: string;
  audience: string;
  algorithm: Algorithm;
  key: Key;
  /** Which subjects may hold a token. */
  subjectPattern: RegExp;
  /** Seconds since the epoch. The caller's clock. */
  now: () => number;
}

const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);

export class TokenVerifier {
  private readonly config: VerifierConfig;

  constructor(config: VerifierConfig) {
    this.config = { ...config };
  }

  /** Verify a subject token and return the principal it names, or throw TokenError. */
  async verify(token: string): Promise<Principal> {
    const { issuer, audience, algorithm, key, subjectPattern, now } = this.config;
    const { payload } = await verifyJwsSignature(token, key, algorithm);
    let claims: Record<string, unknown>;
    try {
      const parsed = JSON.parse(fromUtf8(payload));
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
      claims = parsed;
    } catch {
      throw new TokenError("claims are not a JSON object");
    }
    for (const name of ["iss", "sub", "aud", "exp", "iat", "jti"]) {
      if (!(name in claims)) throw new TokenError(`missing claim ${name}`);
    }
    if (claims.iss !== issuer) throw new TokenError("wrong issuer");
    if (claims.aud !== audience) throw new TokenError("wrong audience"); // exactly, not an array
    if (typeof claims.sub !== "string" || !subjectPattern.test(claims.sub)) {
      throw new TokenError("subject not allowed");
    }
    if (typeof claims.jti !== "string" || !claims.jti) throw new TokenError("bad jti");
    if (!isInt(claims.exp) || !isInt(claims.iat))
      throw new TokenError("exp and iat must be integers");
    const t = now();
    if (claims.exp <= t - MAX_CLOCK_SKEW_SECONDS) throw new TokenError("token expired");
    if (claims.iat > t + MAX_CLOCK_SKEW_SECONDS) throw new TokenError("token issued in the future");
    if ("nbf" in claims) {
      if (!isInt(claims.nbf)) throw new TokenError("nbf must be an integer");
      if (claims.nbf > t + MAX_CLOCK_SKEW_SECONDS) throw new TokenError("token not yet valid");
    }
    return new Principal(MINT, claims.sub, issuer, claims.jti);
  }
}

// ---------------------------------------------------------------- delegated tokens (I2)

export const GRANT_SECONDS = 60;
const ASSERTION_SECONDS = 60;
const GRANT_TYPE = "at+jwt"; // RFC 9068, so a subject token can't pass as a grant
const ASSERTION_TYPE = "client-assertion+jwt";

const randomJti = () => b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));

const newKeyPair = () =>
  crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]) as Promise<KeyPair>;

export function parseClaims(payload: Uint8Array): Record<string, unknown> {
  try {
    const parsed = JSON.parse(fromUtf8(payload));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed;
  } catch {
    throw new TokenError("claims are not a JSON object");
  }
}

export function requireClaims(claims: Record<string, unknown>, names: string[]) {
  for (const name of names) {
    if (!(name in claims)) throw new TokenError(`missing claim ${name}`);
  }
}

/** exp, iat and nbf checks shared by assertions and grants. */
export function checkTimes(claims: Record<string, unknown>, now: number, maxLifetime: number) {
  if (!isInt(claims.exp) || !isInt(claims.iat))
    throw new TokenError("exp and iat must be integers");
  if (claims.exp <= now - MAX_CLOCK_SKEW_SECONDS) throw new TokenError("token expired");
  if (claims.iat > now + MAX_CLOCK_SKEW_SECONDS) throw new TokenError("token issued in the future");
  if (claims.exp - claims.iat > maxLifetime) throw new TokenError("token lives too long");
  if ("nbf" in claims) {
    if (!isInt(claims.nbf)) throw new TokenError("nbf must be an integer");
    if (claims.nbf > now + MAX_CLOCK_SKEW_SECONDS) throw new TokenError("token not yet valid");
  }
}

/** Remembers each `jti` until its token has expired; a second use is refused. */
export class ReplayCache {
  private readonly seen = new Map<string, number>();

  use(jti: string, exp: number, now: number) {
    for (const [id, until] of this.seen) {
      if (until + MAX_CLOCK_SKEW_SECONDS < now) this.seen.delete(id);
    }
    if (this.seen.has(jti)) throw new TokenError("token already used");
    this.seen.set(jti, exp);
  }

  get size() {
    return this.seen.size;
  }
}

/**
 * The agent as its own identity: a client with an ES256 key generated in memory, which
 * signs short client assertions for the token exchange. It never holds a token that can
 * act on its own.
 */
export class AgentIdentity {
  readonly clientId: string;
  private keys: Promise<KeyPair> | null;
  private readonly now: () => number;
  private readonly newId: () => string;

  constructor(clientId: string, now: () => number, options: Determinism = {}) {
    this.clientId = clientId;
    this.now = now;
    this.keys = options.keys === undefined ? null : Promise.resolve(options.keys);
    this.newId = options.newId ?? randomJti;
  }

  private keyPair(): Promise<KeyPair> {
    this.keys ??= newKeyPair();
    return this.keys;
  }

  /** The public half, which the issuer registers for this client. */
  async publicKey(): Promise<Key> {
    return (await this.keyPair()).publicKey;
  }

  /** A single-use client assertion for `audience` (the issuer's token endpoint). */
  async assertion(audience: string): Promise<string> {
    const iat = this.now();
    return signJws(
      { typ: ASSERTION_TYPE },
      {
        iss: this.clientId,
        sub: this.clientId,
        aud: audience,
        iat,
        exp: iat + ASSERTION_SECONDS,
        jti: this.newId(),
      },
      (await this.keyPair()).privateKey,
      "ES256",
    );
  }
}

/** What a verified delegated token says. No token text is kept. */
export interface Grant {
  readonly sub: string;
  readonly act: string;
  readonly aud: string;
  readonly scope: string;
  /** What the grant is for: the caller's ticket, run or finding. */
  readonly ref: string;
  readonly jti: string;
}

export interface GrantVerifierConfig {
  issuer: string;
  audience: string;
  key: Key | Promise<Key>;
  replay: ReplayCache;
  /** The one client a grant may act for. */
  agentClientId: string;
  /** Which subjects may hold a token. */
  subjectPattern: RegExp;
  now: () => number;
}

/**
 * A resource server's check of a delegated token: one issuer, one audience, ES256, typed
 * `at+jwt`, acting for the agent, exactly the scope this call needs, for this ref, at
 * most 60 seconds long, and each `jti` once.
 */
export class GrantVerifier {
  readonly audience: string;
  private readonly config: GrantVerifierConfig;

  constructor(config: GrantVerifierConfig) {
    this.audience = config.audience;
    this.config = { ...config };
  }

  async verify(token: unknown, scope: string, ref: string): Promise<Grant> {
    const { issuer, audience, key, replay, agentClientId, subjectPattern, now } = this.config;
    if (typeof token !== "string" || !token) throw new TokenError("no grant");
    const { header, payload } = await verifyJwsSignature(token, await key, "ES256");
    if (header.typ !== GRANT_TYPE) throw new TokenError("not a delegated token");
    const claims = parseClaims(payload);
    requireClaims(claims, ["iss", "sub", "aud", "exp", "iat", "jti", "act", "scope", "ref"]);
    if (claims.iss !== issuer) throw new TokenError("wrong issuer");
    if (claims.aud !== audience) throw new TokenError("wrong audience");
    if (typeof claims.sub !== "string" || !subjectPattern.test(claims.sub)) {
      throw new TokenError("subject not allowed");
    }
    const act = claims.act as Record<string, unknown> | null;
    if (!act || typeof act !== "object" || Array.isArray(act) || act.sub !== agentClientId) {
      throw new TokenError("not acting for the agent");
    }
    if (claims.scope !== scope) throw new TokenError("wrong scope");
    if (claims.ref !== ref) throw new TokenError("token is for another ref");
    if (typeof claims.jti !== "string" || !claims.jti) throw new TokenError("bad jti");
    const t = now();
    checkTimes(claims, t, GRANT_SECONDS);
    replay.use(claims.jti, claims.exp as number, t);
    return {
      sub: claims.sub,
      act: agentClientId,
      aud: audience,
      scope,
      ref,
      jti: claims.jti,
    };
  }
}

/** The resource servers' verifiers, sharing one replay cache. */
export class Resources {
  private readonly verifiers: ReadonlyMap<string, GrantVerifier>;

  constructor(verifiers: GrantVerifier[]) {
    this.verifiers = new Map(verifiers.map((v) => [v.audience, v]));
  }

  get(audience: string): GrantVerifier {
    const v = this.verifiers.get(audience);
    if (!v) throw new TokenError("unknown resource");
    return v;
  }
}

export interface ExchangeRequest {
  subjectToken: string;
  actorToken: string;
  audience: string;
  scope: string;
  ref: string;
}

const SIGN_IN = Symbol("sign-in");

/**
 * A signed-in requester as the harness holds it: the verified principal, and privately
 * the subject token, which only ever goes to the issuer's token exchange. The model, the
 * logs and the page see none of it.
 */
export class SignIn {
  readonly #token: string;
  readonly #issuer: DevIssuer;
  readonly #agent: AgentIdentity;
  readonly principal: Principal;

  constructor(
    key: symbol,
    token: string,
    principal: Principal,
    issuer: DevIssuer,
    agent: AgentIdentity,
  ) {
    if (key !== SIGN_IN) throw new TypeError("a SignIn comes only from an issuer");
    this.#token = token;
    this.principal = principal;
    this.#issuer = issuer;
    this.#agent = agent;
    Object.freeze(this);
  }

  static is(value: unknown): value is SignIn {
    return typeof value === "object" && value !== null && #token in value;
  }

  /** The resource servers that accept this issuer's grants. */
  get resources(): Resources {
    return this.#issuer.resources();
  }

  /** A fresh delegated token for one call: one audience, one scope, this ref. */
  async grant(audience: string, scope: string, ref: string): Promise<string> {
    return this.#issuer.exchange({
      subjectToken: this.#token,
      actorToken: await this.#agent.assertion(this.#issuer.name),
      audience,
      scope,
      ref,
    });
  }

  toJSON() {
    return SignIn.is(this) ? this.principal.toJSON() : {};
  }
}

// ---------------------------------------------------------------- dev issuer

export interface DevIssuerOptions extends Determinism {
  config: IssuerConfig;
  /** Seconds since the epoch. The caller's clock. */
  now: () => number;
  /** A real issuer's URL, if one is configured. The dev issuer refuses to run alongside one. */
  realIssuer?: string | undefined;
  /** The one client allowed to exchange tokens. A new in-memory agent by default. */
  agent?: AgentIdentity;
}

/**
 * Mints subject tokens for synthetic users and runs the token exchange. Its signing key
 * is generated in memory on first use (or passed in) and never leaves this object.
 */
export class DevIssuer {
  private readonly config: IssuerConfig;
  private readonly now: () => number;
  private readonly agent: AgentIdentity;
  private readonly newId: () => string;
  private keys: Promise<KeyPair> | null;
  private resourceSet: Resources | null = null;
  private readonly assertionReplay = new ReplayCache();
  private readonly grantReplay = new ReplayCache();

  constructor(options: DevIssuerOptions) {
    if (options.realIssuer) {
      throw new Error("the dev issuer refuses to start while a real issuer is configured");
    }
    this.config = Object.freeze({
      ...options.config,
      resources: Object.freeze({ ...options.config.resources }),
    });
    this.now = options.now;
    this.newId = options.newId ?? randomJti;
    this.keys = options.keys === undefined ? null : Promise.resolve(options.keys);
    this.agent = options.agent ?? new AgentIdentity(this.config.agentClientId, this.now);
    if (this.agent.clientId !== this.config.agentClientId) {
      throw new Error("the agent's client id doesn't match the configuration");
    }
  }

  /** The issuer name tokens carry. */
  get name(): string {
    return this.config.issuer;
  }

  private keyPair(): Promise<KeyPair> {
    // Generated lazily, not in a constructor, so it works inside a Durable Object.
    this.keys ??= newKeyPair();
    return this.keys;
  }

  /** A token for `subject`, which the caller has checked is one of its users. */
  async mint(subject: string): Promise<string> {
    if (!this.config.subjectPattern.test(subject)) throw new TokenError("subject not allowed");
    const iat = this.now();
    const claims = {
      iss: this.config.issuer,
      sub: subject,
      aud: this.config.agentAudience,
      iat,
      exp: iat + SUBJECT_TOKEN_SECONDS,
      jti: this.newId(),
    };
    return signJws({ typ: "JWT" }, claims, (await this.keyPair()).privateKey, "ES256");
  }

  /** The verifier for this issuer's subject tokens. */
  async verifier(now?: () => number): Promise<TokenVerifier> {
    return new TokenVerifier({
      issuer: this.config.issuer,
      audience: this.config.agentAudience,
      algorithm: "ES256",
      key: (await this.keyPair()).publicKey,
      subjectPattern: this.config.subjectPattern,
      now: now ?? this.now,
    });
  }

  /** Mint and verify in one step: the usual way a harness gets a principal. */
  async principalFor(subject: string): Promise<Principal> {
    return (await this.verifier()).verify(await this.mint(subject));
  }

  /** Sign `subject` in: the principal plus the subject token, held for the exchange. */
  async signIn(subject: string): Promise<SignIn> {
    const token = await this.mint(subject);
    const principal = await (await this.verifier()).verify(token);
    return new SignIn(SIGN_IN, token, principal, this, this.agent);
  }

  /**
   * Token exchange (RFC 8693 shape): a valid subject token plus the registered agent's
   * client assertion buys one delegated token for one audience and one scope, for one
   * ref, for 60 seconds. Anything else throws TokenError.
   */
  async exchange(request: ExchangeRequest): Promise<string> {
    const { subjectToken, actorToken, audience, scope, ref } = request;
    const { issuer, agentClientId, resources, refPattern } = this.config;
    const t = this.now();
    // The agent authenticates itself with its own key.
    const { header, payload } = await verifyJwsSignature(
      actorToken,
      await this.agent.publicKey(),
      "ES256",
    );
    if (header.typ !== ASSERTION_TYPE) throw new TokenError("not a client assertion");
    const assertion = parseClaims(payload);
    requireClaims(assertion, ["iss", "sub", "aud", "exp", "iat", "jti"]);
    if (assertion.iss !== agentClientId || assertion.sub !== agentClientId) {
      throw new TokenError("unknown client");
    }
    if (assertion.aud !== issuer) throw new TokenError("assertion for another issuer");
    if (typeof assertion.jti !== "string" || !assertion.jti) throw new TokenError("bad jti");
    checkTimes(assertion, t, ASSERTION_SECONDS);
    // The requester's subject token: same checks as at sign-in.
    const principal = await (await this.verifier()).verify(subjectToken);
    const scopes = Object.hasOwn(resources, audience) ? resources[audience] : undefined;
    if (!scopes) throw new TokenError("unknown resource");
    if (typeof scope !== "string" || !scopes.includes(scope)) {
      throw new TokenError("scope not offered by that resource");
    }
    if (typeof ref !== "string" || !refPattern.test(ref)) {
      throw new TokenError("bad ref");
    }
    this.assertionReplay.use(assertion.jti, assertion.exp as number, t);
    return signJws(
      { typ: GRANT_TYPE },
      {
        iss: issuer,
        sub: principal.sub,
        act: { sub: agentClientId },
        aud: audience,
        scope,
        ref,
        iat: t,
        exp: t + GRANT_SECONDS,
        jti: this.newId(),
      },
      (await this.keyPair()).privateKey,
      "ES256",
    );
  }

  /** The resource servers' verifiers for this issuer's grants (one shared replay cache). */
  resources(): Resources {
    this.resourceSet ??= new Resources(
      Object.keys(this.config.resources).map(
        (audience) =>
          new GrantVerifier({
            issuer: this.config.issuer,
            audience,
            key: this.keyPair().then((k) => k.publicKey),
            replay: this.grantReplay,
            agentClientId: this.config.agentClientId,
            subjectPattern: this.config.subjectPattern,
            now: this.now,
          }),
      ),
    );
    return this.resourceSet;
  }
}
