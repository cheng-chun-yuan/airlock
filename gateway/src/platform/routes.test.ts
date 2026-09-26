import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono } from "hono";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { ApprovalStore } from "@airlock/approval";
import { SiweAuth } from "./auth";
import { buildPlatform, policyRecords } from "./routes";
import { PlatformStore, Vault, type Gateway } from "./store";
import type { Tenant, Tenants } from "./tenants";

/** A gateway API stand-in that echoes what the platform forwarded: path, identity headers and body. */
function echoTenant(gw: Gateway): Tenant {
  const approvals = new ApprovalStore(60_000);
  const app = new Hono();
  app.all("*", async (c) =>
    c.json({
      path: new URL(c.req.url).pathname,
      query: Object.fromEntries(new URL(c.req.url).searchParams),
      user: c.req.header("x-airlock-user"),
      requesterId: c.req.header("x-airlock-requester-id"),
      agent: c.req.header("x-airlock-agent") ?? null,
      body: c.req.method === "GET" ? null : await c.req.json().catch(() => null),
    }),
  );
  return { gw, app, approvals, audit: undefined as never, roles: {} as never, local: undefined as never, egress: undefined as never, config: { kind: gw.kind, slug: gw.slug } };
}

function setup() {
  const store = new PlatformStore(join(mkdtempSync(join(tmpdir(), "airlock-")), "platform.json"));
  const tenants = new Map<string, Tenant>();
  const fake = { get: (g: Gateway) => tenants.get(g.id) ?? tenants.set(g.id, echoTenant(g)).get(g.id)!, running: () => [...tenants.values()], drop() {} } as unknown as Tenants;
  const app = buildPlatform({
    store,
    auth: new SiweAuth("test-secret"),
    tenants: fake,
    vault: new Vault("test-secret"),
    root: "airlock.eth",
    allowPrivateUpstreams: true,
    maxGatewaysPerUser: 3,
    consoleHtml: () => "<html>",
    publicUrl: "http://localhost",
  });
  const people = Object.fromEntries(["owner", "bob", "eve", "mallory"].map((n) => [n, privateKeyToAccount(generatePrivateKey())]));
  const gw = store.add({
    slug: "acme",
    name: "Acme",
    kind: "user",
    owner: people.owner.address.toLowerCase(),
    local: { mode: "shared" },
    frontier: { provider: "anthropic", models: ["claude-*"], defaultModel: "claude-sonnet-5" },
    policy: { maxClass: "confidential", egress: "approval", highRiskQuorum: 2 },
    ens: { status: "live", state: { done: {} } },
    members: [{ address: people.owner.address.toLowerCase(), label: "owner", role: "admin", joinedAt: 0 }],
  });
  const cookies: Record<string, string> = {};
  async function login(name: string) {
    const acct = people[name];
    const r = await app.request("/api/auth/nonce", { method: "POST", headers: { host: "localhost", "content-type": "application/json" }, body: JSON.stringify({ address: acct.address, chainId: 11155111 }) });
    const { message } = (await r.json()) as { message: string };
    const v = await app.request("/api/auth/verify", { method: "POST", headers: { host: "localhost", "content-type": "application/json" }, body: JSON.stringify({ message, signature: await acct.signMessage({ message }) }) });
    assert.equal(v.status, 200, await v.clone().text());
    cookies[name] = v.headers.get("set-cookie")!.split(";")[0];
  }
  const as = (name: string) => async (method: string, path: string, body?: unknown, extra: Record<string, string> = {}) => {
    const r = await app.request(path, { method, headers: { host: "localhost", cookie: cookies[name] ?? "", "content-type": "application/json", ...extra }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, j: (await r.json().catch(() => null)) as any };
  };
  return { app, store, gw, people, login, as, tenants: fake };
}

test("sign-in: the domain is the server's own, and a nonce works once", async () => {
  const { app, people } = setup();
  const acct = people.eve;
  // A spoofed Host header doesn't change the domain the server asks you to sign for.
  const r = await app.request("/api/auth/nonce", { method: "POST", headers: { host: "evil.example", "x-forwarded-host": "evil.example", "content-type": "application/json" }, body: JSON.stringify({ address: acct.address, chainId: 1 }) });
  const { message } = (await r.json()) as { message: string };
  assert.match(message, /^localhost wants you to sign in/);
  // A message rewritten for another site (as a phishing page would show it) is refused, and burns the nonce.
  const phished = message.replace(/^localhost/, "evil.example");
  const bad = await app.request("/api/auth/verify", { method: "POST", headers: { host: "evil.example", "x-forwarded-host": "evil.example", "content-type": "application/json" }, body: JSON.stringify({ message: phished, signature: await acct.signMessage({ message: phished }) }) });
  assert.equal(bad.status, 401);
  const late = await app.request("/api/auth/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message, signature: await acct.signMessage({ message }) }) });
  assert.equal(late.status, 401, "nonce is single use even after a failed attempt");
});

test("invites: one use, a free label, and the role they carry", async () => {
  const { login, as, gw } = setup();
  await Promise.all(["owner", "bob", "eve"].map(login));
  const inv = await as("owner")("POST", "/api/gateways/acme/invites", { role: "approver", label: "bob" });
  assert.equal(inv.status, 201);
  const code = inv.j.url.split("/join/")[1];
  assert.equal((await as("eve")("POST", "/api/gateways/acme/invites", { role: "admin" })).status, 404, "non-members can't invite");
  assert.equal((await as("bob")("POST", `/api/invites/${code}/accept`, { label: "owner" })).status, 409, "label taken");
  assert.equal((await as("bob")("POST", `/api/invites/${code}/accept`, {})).status, 200);
  assert.equal((await as("eve")("POST", `/api/invites/${code}/accept`, { label: "eve" })).status, 410, "already used");
  assert.deepEqual(gw.members.map((m) => [m.label, m.role]), [["owner", "admin"], ["bob", "approver"]]);
});

test("into a gateway: identity is set by the platform, and roles gate each route", async () => {
  const { login, as, store, gw, people, tenants } = setup();
  await Promise.all(["owner", "bob", "eve", "mallory"].map(login));
  gw.members.push({ address: people.bob.address.toLowerCase(), label: "bob", role: "approver", joinedAt: 0 }, { address: people.eve.address.toLowerCase(), label: "eve", role: "member", joinedAt: 0 });
  store.save();
  const eve = as("eve"), bob = as("bob"), owner = as("owner");

  assert.equal((await as("mallory")("GET", "/g/acme/config")).status, 404, "non-members see nothing");
  const cfg = await eve("GET", "/g/acme/config");
  assert.equal(cfg.j.me.role, "member");
  assert.equal(cfg.j.me.approverName, undefined);

  // Members may send; spoofed identity and a foreign agent policy are replaced/dropped.
  const r = await eve("POST", "/g/acme/v1/chat/completions", { model: "airlock/claude-sonnet-5", messages: [] });
  assert.equal(r.status, 200);
  assert.equal(r.j.user, "eve");
  assert.equal(r.j.requesterId, people.eve.address.toLowerCase());

  // Approver-only and admin-only routes.
  assert.equal((await eve("POST", "/g/acme/approvals/x/deny", {})).status, 403);
  assert.equal((await eve("POST", "/g/acme/enroll", {})).status, 403);
  assert.equal((await eve("POST", "/g/acme/audit/anchor", {})).status, 403);
  assert.equal((await bob("POST", "/g/acme/audit/anchor", {})).status, 403);
  assert.equal((await owner("POST", "/g/acme/audit/anchor", {})).status, 200);
  assert.equal((await eve("GET", "/g/acme/some/unknown/route")).status, 404);

  // Approvers act under their own ENS name, whatever the request says.
  const v = await bob("POST", "/g/acme/approvals/x/verify", { approverName: "owner.approvers.acme.airlock.eth", proof: "p" });
  assert.equal(v.j.body.approverName, "bob.approvers.acme.airlock.eth");
  assert.equal(v.j.body.proof, "p");
  const o = await bob("GET", "/g/acme/enroll/oidc?approverName=owner.approvers.acme.airlock.eth");
  assert.equal(o.j.query.approverName, "bob.approvers.acme.airlock.eth");

  // Withdraw: only the requester (or an admin).
  const t = tenants.get(gw);
  void t.approvals.request({ id: "req-1", sessionId: "s", agent: "a", requiredRole: "r", payloadHash: "0x", viewHash: "0x", redactedPreview: "", originalPreview: "secret", mapping: { "<ORG_1>": "Kestrel" }, entities: {}, riskLevel: "low", findings: [], targetModel: "m", createdAt: Date.now(), expiresAt: Date.now() + 60_000, status: "pending", requesterId: people.eve.address.toLowerCase() });
  assert.equal((await bob("POST", "/g/acme/approvals/req-1/withdraw", {})).status, 403);
  assert.equal((await eve("POST", "/g/acme/approvals/req-1/withdraw", {})).status, 200);
  // The original text is for approvers and the requester only.
  void t.approvals.request({ id: "req-2", sessionId: "s", agent: "a", requiredRole: "r", payloadHash: "0x", viewHash: "0x", redactedPreview: "", originalPreview: "secret", entities: {}, riskLevel: "low", findings: [], targetModel: "m", createdAt: Date.now(), expiresAt: Date.now() + 60_000, status: "pending", requesterId: people.owner.address.toLowerCase() });
  assert.equal((await eve("GET", "/g/acme/approvals/req-2")).j.originalPreview, undefined);
  assert.equal((await bob("GET", "/g/acme/approvals/req-2")).j.originalPreview, "secret");
});

test("API keys: pick the gateway and member; die with the membership", async () => {
  const { app, login, as, store, gw, people } = setup();
  await Promise.all(["owner", "eve"].map(login));
  gw.members.push({ address: people.eve.address.toLowerCase(), label: "eve", role: "member", joinedAt: 0 });
  store.save();
  const k = await as("eve")("POST", "/api/gateways/acme/keys", { name: "bot" });
  assert.equal(k.status, 201);
  assert.match(k.j.secret, /^alk_/);
  assert.equal(JSON.stringify(store.all()).includes(k.j.secret), false, "only the hash is stored");
  const call = (key: string, h: Record<string, string> = {}) =>
    app.request("/v1/chat/completions", { method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json", ...h }, body: "{}" });
  assert.equal((await call("alk_nope")).status, 401);
  const ok = (await (await call(k.j.secret, { "x-airlock-user": "ceo", "x-airlock-agent": "contract-agent.agents.airlock.eth", "x-airlock-requester-id": "0xdead" })).json()) as any;
  assert.deepEqual([ok.user, ok.requesterId, ok.agent], ["eve", people.eve.address.toLowerCase(), "policy.acme.airlock.eth"], "a key without an agent runs under the gateway policy");
  // A key made for an agent runs as that agent, whatever the client claims; only this gateway's agents exist.
  assert.equal((await as("eve")("POST", "/api/gateways/acme/keys", { name: "x", agent: "intern-bot" })).status, 400);
  gw.agents = [{ label: "intern-bot", createdAt: 0 }];
  store.save();
  const kb = await as("eve")("POST", "/api/gateways/acme/keys", { name: "intern", agent: "intern-bot" });
  assert.equal(kb.j.agent, "intern-bot");
  const asBot = (await (await call(kb.j.secret, { "x-airlock-agent": "policy.other.airlock.eth" })).json()) as any;
  assert.equal(asBot.agent, "intern-bot.agents.acme.airlock.eth");
  assert.equal((await as("owner")("DELETE", "/api/gateways/acme/agents/intern-bot")).status, 409, "an agent with keys can't be deleted");
  // The Console may pick among the gateway's own agents, and nothing else.
  const pick = (agent: string) => as("eve")("POST", "/g/acme/v1/chat/completions", { model: "m", messages: [] }, { "x-airlock-agent": agent }).then((r) => r.j.agent);
  assert.equal(await pick("intern-bot.agents.acme.airlock.eth"), "intern-bot.agents.acme.airlock.eth");
  assert.equal(await pick("contract-agent.agents.airlock.eth"), "policy.acme.airlock.eth");
  assert.equal((await app.request("/v1/admin/revoke", { method: "POST", headers: { authorization: `Bearer ${k.j.secret}` } })).status, 404, "keys only reach the model routes");
  await as("owner")("DELETE", `/api/gateways/acme/members/${people.eve.address.toLowerCase()}`);
  assert.equal((await call(k.j.secret)).status, 401);
});

test("policy form → ENS records", () => {
  const g = { slug: "acme", frontier: { models: ["claude-*", "gpt-5"] }, policy: { maxClass: "confidential", egress: "approval", highRiskQuorum: 1 } } as unknown as Gateway;
  assert.deepEqual(policyRecords(g, "airlock.eth"), {
    maxClass: "confidential",
    egress: "approval",
    models: "claude-*,gpt-5",
    approverRole: "approvers.acme.airlock.eth",
    ownerRole: "approvers.acme.airlock.eth",
    highRiskQuorum: "",
  });
  g.policy.highRiskQuorum = 0;
  assert.equal(policyRecords(g, "airlock.eth").ownerRole, "", "0 = high risk never leaves");
  g.policy.highRiskQuorum = 2;
  assert.equal(policyRecords(g, "airlock.eth").highRiskQuorum, "2");
});

test("vault: sealed keys open with the same secret only", () => {
  const s = new Vault("a").seal("sk-ant-secret-1234");
  assert.equal(s.last4, "1234");
  assert.equal(new Vault("a").open(s), "sk-ant-secret-1234");
  assert.throws(() => new Vault("b").open(s));
});

test("abuse limits: chat per member per hour; no API keys on the shared demo", async () => {
  const store = new PlatformStore(join(mkdtempSync(join(tmpdir(), "airlock-")), "platform.json"));
  const tenants = new Map<string, Tenant>();
  const fake = { get: (g: Gateway) => tenants.get(g.id) ?? tenants.set(g.id, echoTenant(g)).get(g.id)! } as unknown as Tenants;
  const app = buildPlatform({ store, auth: new SiweAuth("s"), tenants: fake, vault: new Vault("s"), root: "airlock.eth", allowPrivateUpstreams: true, maxGatewaysPerUser: 3, consoleHtml: () => "", publicUrl: "http://localhost", limits: { demoChatPerHour: 2 } });
  store.add({ slug: "demo", name: "Demo", kind: "demo", owner: "0x0", local: { mode: "shared" }, frontier: { provider: "anthropic", models: ["x"], defaultModel: "x" }, policy: { maxClass: "confidential", egress: "approval", highRiskQuorum: 2 }, ens: { status: "live", state: { done: {} } } });
  const acct = privateKeyToAccount(generatePrivateKey());
  const { message } = (await (await app.request("/api/auth/nonce", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ address: acct.address }) })).json()) as { message: string };
  const v = await app.request("/api/auth/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message, signature: await acct.signMessage({ message }) }) });
  const cookie = v.headers.get("set-cookie")!.split(";")[0];
  const chat = () => app.request("/g/demo/v1/chat/completions", { method: "POST", headers: { cookie, "content-type": "application/json" }, body: "{}" });
  assert.deepEqual([(await chat()).status, (await chat()).status, (await chat()).status], [200, 200, 429]);
  assert.equal((await app.request("/api/gateways/demo/keys", { method: "POST", headers: { cookie, "content-type": "application/json" }, body: "{}" })).status, 403);
});
