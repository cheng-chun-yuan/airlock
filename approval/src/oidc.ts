import { createHash, randomBytes } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";

/**
 * World ID for Agents — Human Continuity IdP (OIDC, sandbox.auth.world.org for the event).
 *
 * Authorization code + PKCE (S256). The OIDC `nonce` is a hash of the exact
 * operation (approval id + payloadHash, or the enrollment signal), so the ID
 * token World signs commits to that one operation: a token minted for one
 * payload can't approve another. `state` and the pending entry are single-use.
 *
 * The approver's identity is `sub` for this client. We derive a stable
 * pseudo-nullifier H(iss|sub) and store only commitment(nullifier) in ENS,
 * the same way as IDKit nullifiers.
 */
export interface OidcConfig {
  issuer: string; // https://sandbox.auth.world.org
  clientId: string;
  clientSecret: string;
  redirectUri: string; // …/oidc/callback
  /** Max age of the human authentication (auth_time) when the token is redeemed. */
  maxAuthAgeS?: number;
  /** Tests inject a key set; otherwise the issuer's jwks_uri is used. */
  jwks?: JWTVerifyGetKey;
}

export type OidcKind = "approve" | "enroll";

export interface OidcPending {
  kind: OidcKind;
  ref: string; // approval id, or the approver name for enrollment
  approverName: string;
  binding: string; // payloadHash, or the enrollment signal
  nonce: string;
  verifier: string;
  createdAt: number;
}

export type OidcResult =
  | { ok: true; pending: OidcPending; nullifier: string; sub: string; acr?: string; authTime?: number }
  | { ok: false; error: string; pending?: OidcPending };

const b64url = (b: Buffer) => b.toString("base64url");
const sha256 = (s: string | Buffer) => createHash("sha256").update(s).digest();

export class WorldOidc {
  readonly mode = "oidc" as const;
  private pending = new Map<string, OidcPending>();
  private meta?: { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string };
  private jwks?: JWTVerifyGetKey;

  constructor(private cfg: OidcConfig) {
    this.jwks = cfg.jwks;
  }

  private async discover() {
    if (!this.meta) {
      const res = await fetch(`${this.cfg.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`);
      if (!res.ok) throw new Error(`OIDC discovery ${res.status}`);
      this.meta = (await res.json()) as NonNullable<WorldOidc["meta"]>;
      this.jwks ??= createRemoteJWKSet(new URL(this.meta.jwks_uri));
    }
    return this.meta;
  }

  /** Build the authorize URL for one operation. */
  async start(kind: OidcKind, ref: string, approverName: string, binding: string): Promise<string> {
    const meta = await this.discover();
    const state = b64url(randomBytes(24));
    const verifier = b64url(randomBytes(32));
    const nonce = sha256(`airlock/oidc/v1|${kind}|${ref}|${binding}|${b64url(randomBytes(16))}`).toString("hex");
    this.pending.set(state, { kind, ref, approverName, binding, nonce, verifier, createdAt: Date.now() });
    for (const [s, p] of this.pending) if (Date.now() - p.createdAt > 15 * 60_000) this.pending.delete(s);
    const url = new URL(meta.authorization_endpoint);
    url.search = new URLSearchParams({
      client_id: this.cfg.clientId,
      redirect_uri: this.cfg.redirectUri,
      response_type: "code",
      scope: "openid",
      state,
      nonce,
      code_challenge: b64url(sha256(verifier)),
      code_challenge_method: "S256",
      max_age: String(this.cfg.maxAuthAgeS ?? 300),
    }).toString();
    return url.toString();
  }

  /** The approver backed out at World (e.g. error=access_denied): drop the request and say which operation it was. */
  cancel(state: string): OidcPending | undefined {
    const p = this.pending.get(state);
    this.pending.delete(state);
    return p;
  }

  /** Redeem the callback: exchange the code, verify the ID token, check the operation binding. */
  async finish(state: string, code: string): Promise<OidcResult> {
    const pending = this.pending.get(state);
    if (!pending) return { ok: false, error: "unknown or already used state" };
    this.pending.delete(state); // single use, whatever happens next
    if (Date.now() - pending.createdAt > 10 * 60_000) return { ok: false, error: "authorization request expired", pending };
    const meta = await this.discover();
    const res = await fetch(meta.token_endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(this.cfg.clientId)}:${encodeURIComponent(this.cfg.clientSecret)}`).toString("base64")}`,
      },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: this.cfg.redirectUri, code_verifier: pending.verifier }),
    });
    const tok = (await res.json().catch(() => ({}))) as { id_token?: string; error?: string; error_description?: string };
    if (!res.ok || !tok.id_token) return { ok: false, error: `token exchange failed: ${tok.error ?? res.status} ${tok.error_description ?? ""}`.trim(), pending };
    try {
      const { payload } = await jwtVerify(tok.id_token, this.jwks!, { issuer: meta.issuer, audience: this.cfg.clientId, algorithms: ["RS256"] });
      if (payload.nonce !== pending.nonce) return { ok: false, error: "ID token nonce does not match this operation", pending };
      const authTime = typeof payload.auth_time === "number" ? payload.auth_time : undefined;
      const maxAge = this.cfg.maxAuthAgeS ?? 300;
      if (authTime !== undefined && Date.now() / 1000 - authTime > maxAge + 60) return { ok: false, error: `human authentication is older than ${maxAge}s`, pending };
      if (!payload.sub) return { ok: false, error: "ID token has no sub", pending };
      const nullifier = "0x" + sha256(`airlock/oidc/v1|${meta.issuer}|${payload.sub}`).toString("hex");
      return { ok: true, pending, nullifier, sub: payload.sub, acr: payload.acr as string | undefined, authTime };
    } catch (e) {
      return { ok: false, error: `ID token rejected: ${(e as Error).message}`, pending };
    }
  }
}
