import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { WorldOidc } from "./oidc";

/** Minimal Human Continuity IdP: discovery, JWKS, authorize (remembered), token (PKCE-checked). */
async function mockIdp(opts: { audience?: (clientId: string) => string; nonce?: (n: string) => string } = {}) {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const codes = new Map<string, { nonce: string; challenge: string; clientId: string }>();
  let n = 0;
  const srv = createServer(async (req, res) => {
    const url = new URL(req.url!, base);
    res.setHeader("content-type", "application/json");
    if (url.pathname === "/.well-known/openid-configuration")
      return res.end(JSON.stringify({ issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, jwks_uri: `${base}/jwks` }));
    if (url.pathname === "/jwks") return res.end(JSON.stringify({ keys: [jwk] }));
    if (url.pathname === "/token") {
      let raw = ""; for await (const c of req) raw += c;
      const body = new URLSearchParams(raw);
      const clientId = decodeURIComponent(Buffer.from(req.headers.authorization!.split(" ")[1], "base64").toString().split(":")[0]);
      const c = codes.get(body.get("code")!);
      codes.delete(body.get("code")!);
      const pkceOk = c && createHash("sha256").update(body.get("code_verifier")!).digest("base64url") === c.challenge;
      if (!c || !pkceOk) { res.statusCode = 400; return res.end(JSON.stringify({ error: "invalid_grant" })); }
      const id_token = await new SignJWT({ nonce: opts.nonce ? opts.nonce(c.nonce) : c.nonce, auth_time: Math.floor(Date.now() / 1000), acr: "https://world.org/oidc/acr/orb-v3" })
        .setProtectedHeader({ alg: "RS256", kid: "k1" }).setIssuer(base).setAudience(opts.audience ? opts.audience(c.clientId) : c.clientId)
        .setSubject("human-123").setIssuedAt().setExpirationTime("5m").sign(privateKey);
      return res.end(JSON.stringify({ id_token, token_type: "Bearer" }));
    }
    res.statusCode = 404; res.end("{}");
  }).listen(0);
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  /** What the browser + World would do: authorize, then land on the callback with a code. */
  const authorize = (authUrl: string) => {
    const u = new URL(authUrl);
    const code = `code-${++n}`;
    codes.set(code, { nonce: u.searchParams.get("nonce")!, challenge: u.searchParams.get("code_challenge")!, clientId: u.searchParams.get("client_id")! });
    return { state: u.searchParams.get("state")!, code };
  };
  return { base, authorize, close: () => srv.close() };
}

const cfg = (issuer: string) => ({ issuer, clientId: "client-abc", clientSecret: "s3cret", redirectUri: "http://localhost:8787/oidc/callback" });

test("OIDC approval: PKCE code flow, ID token verified, nonce bound to the operation, stable identity", async () => {
  const idp = await mockIdp();
  const oidc = new WorldOidc(cfg(idp.base));
  const url = await oidc.start("approve", "appr-1", "alice.legal.approvers.airlock.eth", "0xpayload");
  const q = new URL(url).searchParams;
  assert.equal(q.get("code_challenge_method"), "S256");
  assert.equal(q.get("scope"), "openid");
  const { state, code } = idp.authorize(url);
  const r = await oidc.finish(state, code);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.pending.ref, "appr-1");
  assert.equal(r.acr, "https://world.org/oidc/acr/orb-v3");
  // same human → same pseudo-nullifier on a second, independent approval (needed for the ENS role check)
  const url2 = await oidc.start("approve", "appr-2", "alice.legal.approvers.airlock.eth", "0xother");
  const a2 = idp.authorize(url2);
  const r2 = await oidc.finish(a2.state, a2.code);
  assert.equal(r2.ok && r2.nullifier, r.nullifier);
  // state is single use
  assert.match((await oidc.finish(state, code) as any).error, /already used/);
  idp.close();
});

test("OIDC approval rejects a token whose nonce isn't this operation's", async () => {
  const idp = await mockIdp({ nonce: () => "some-other-operation" });
  const oidc = new WorldOidc(cfg(idp.base));
  const a = idp.authorize(await oidc.start("approve", "appr-1", "alice", "0xpayload"));
  assert.match((await oidc.finish(a.state, a.code) as any).error, /nonce does not match/);
  idp.close();
});

test("OIDC approval rejects a token minted for another client", async () => {
  const idp = await mockIdp({ audience: () => "someone-else" });
  const oidc = new WorldOidc(cfg(idp.base));
  const a = idp.authorize(await oidc.start("approve", "appr-1", "alice", "0xpayload"));
  assert.match((await oidc.finish(a.state, a.code) as any).error, /ID token rejected/);
  idp.close();
});

test("OIDC approval fails when the PKCE verifier doesn't match", async () => {
  const idp = await mockIdp();
  const oidc = new WorldOidc(cfg(idp.base));
  const url = await oidc.start("approve", "appr-1", "alice", "0xpayload");
  const u = new URL(url); u.searchParams.set("code_challenge", "tampered");
  const a = idp.authorize(u.toString());
  assert.match((await oidc.finish(a.state, a.code) as any).error, /token exchange failed: invalid_grant/);
  idp.close();
});
