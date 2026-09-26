import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { Hono, type Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Address, Hex } from "viem";
import { CLASS_ORDER, type DataClass } from "@airlock/core";
import { publicView } from "@airlock/approval";
import { checkSlug, gatewayNames, PROVISION_STEPS, type EnsProvisioner, type PolicyRecords } from "@airlock/registry";
import type { SiweAuth } from "./auth";
import { canApprove, LABEL_RE, ROLES, type FrontierConfig, type Gateway, type LocalConfig, type Member, type PlatformStore, type PolicyConfig, type Role, type Vault } from "./store";
import type { Tenants } from "./tenants";
import { checkUpstream } from "./upstream";

export interface PlatformDeps {
  store: PlatformStore;
  auth: SiweAuth;
  tenants: Tenants;
  vault: Vault;
  /** airlock.eth — every user gateway is a subname of it. */
  root: string;
  /** Unset when ENS isn't configured: then only the demo gateway exists. */
  provisioner?: EnsProvisioner;
  allowPrivateUpstreams: boolean;
  maxGatewaysPerUser: number;
  /** The platform's own local model, offered to gateways that don't run one. */
  sharedLocal?: { model: string };
  consoleHtml: () => string;
  publicUrl: string;
  /** World ID for Agents: one callback URL for every gateway. */
  oidcTenant?: (state: string) => string | undefined;
  /** Drop cached ENS policy reads after the platform changed a policy, so the next request obeys it. */
  policyChanged?: () => void;
}

const SESSION = "airlock_session";
const json = (c: Context, status: number, error: string) => c.json({ error }, status as 400);

/** What a signed-in person may call inside a gateway's API. Anything unlisted is refused. */
type Need = "member" | "approver" | "admin" | "requester";
function needFor(method: string, path: string): Need | undefined {
  const rules: [string, RegExp, Need][] = [
    ["GET", /^\/(config|status|audit|events\/poll|ens|ens\/approver|ens\/changes|approvers|approvals|v1\/models)$/, "member"],
    ["POST", /^\/v1\/chat\/completions$/, "member"],
    ["GET", /^\/approvals\/[\w-]+\/(worldid|oidc)$/, "approver"],
    ["POST", /^\/approvals\/[\w-]+\/(verify|deny)$/, "approver"],
    ["POST", /^\/approvals\/[\w-]+\/withdraw$/, "requester"],
    ["GET", /^\/enroll\/(worldid|oidc)$/, "approver"],
    ["POST", /^\/enroll$/, "approver"],
    ["POST", /^\/(admin\/revoke|audit\/anchor)$/, "admin"],
  ];
  return rules.find(([m, re]) => m === method && re.test(path))?.[2];
}

/** Policy form → ENS records. highRiskQuorum 0 = block high risk, 1 = one approver, 2+ = that many different humans. */
export function policyRecords(gw: Gateway, root: string): PolicyRecords {
  const n = gatewayNames(gw.slug, root);
  const q = gw.policy.highRiskQuorum;
  return {
    maxClass: gw.policy.maxClass,
    egress: gw.policy.egress,
    models: gw.frontier.models.join(","),
    approverRole: n.approverRole,
    ownerRole: q === 1 ? n.approverRole : "",
    highRiskQuorum: q >= 2 ? String(q) : "",
  };
}

export function buildPlatform(d: PlatformDeps) {
  const app = new Hono();
  const { store } = d;
  const provisioning = new Set<string>();

  const me = (c: Context) => d.auth.read(getCookie(c, SESSION));
  const host = (c: Context) => c.req.header("x-forwarded-host") ?? c.req.header("host") ?? new URL(c.req.url).host;
  const secure = (c: Context) => c.req.header("x-forwarded-proto") === "https" || new URL(c.req.url).protocol === "https:";

  // ---------- static ----------
  app.get("/health", (c) => c.json({ ok: true }));
  app.get("/", (c) => c.redirect("/console"));
  for (const p of ["/console", "/console/:slug", "/join/:code"]) app.get(p, (c) => c.html(d.consoleHtml()));
  // IDKit browser bundle + its WASM, served from node_modules (the CDN build fails WASM init; see docs/SETUP.md).
  const idkitDir = dirname(createRequire(import.meta.url).resolve("@worldcoin/idkit-core/hashing"));
  const vendor: Record<string, string> = { "idkit.global.js": "text/javascript", "idkit_wasm_bg.wasm": "application/wasm" };
  app.get("/vendor/idkit/:file", (c) => {
    const type = vendor[c.req.param("file")];
    if (!type) return c.notFound();
    return c.body(readFileSync(join(idkitDir, c.req.param("file"))), 200, { "content-type": type, "cache-control": "public, max-age=3600" });
  });

  // ---------- sign-in (SIWE) ----------
  app.post("/api/auth/nonce", async (c) => {
    const { address, chainId } = (await c.req.json().catch(() => ({}))) as { address?: string; chainId?: number };
    if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) return json(c, 400, "address required");
    const origin = `${secure(c) ? "https" : "http"}://${host(c)}`;
    return c.json({ message: d.auth.message({ address, chainId: Number(chainId) || 1, domain: host(c), uri: origin }) });
  });
  app.post("/api/auth/verify", async (c) => {
    const { message, signature } = (await c.req.json().catch(() => ({}))) as { message?: string; signature?: Hex };
    if (!message || !signature) return json(c, 400, "message and signature required");
    try {
      const address = await d.auth.verify(message, signature, host(c));
      const s = d.auth.session(address);
      setCookie(c, SESSION, s.value, { httpOnly: true, sameSite: "Lax", secure: secure(c), path: "/", maxAge: s.maxAge });
      return c.json({ address });
    } catch (e) {
      return json(c, 401, (e as Error).message);
    }
  });
  app.post("/api/auth/logout", (c) => {
    deleteCookie(c, SESSION, { path: "/" });
    return c.json({ ok: true });
  });

  const view = (g: Gateway, m: Member) => ({
    slug: g.slug,
    name: g.name,
    kind: g.kind,
    owner: g.owner,
    role: m.role,
    label: m.label,
    ens: { status: g.ens.status, step: g.ens.step, error: g.ens.error, name: g.kind === "user" ? gatewayNames(g.slug, d.root).base : undefined },
  });

  app.get("/api/me", (c) => {
    const address = me(c);
    const platform = { root: d.root, canCreate: !!d.provisioner, maxGateways: d.maxGatewaysPerUser, sharedLocal: d.sharedLocal ?? null, allowPrivateUpstreams: d.allowPrivateUpstreams };
    if (!address) return c.json({ address: null, platform }, 401);
    const gateways = store.forUser(address).map((g) => view(g, store.memberOf(g, address)!));
    return c.json({ address, gateways, platform });
  });

  // ---------- gateway settings (validation shared by create and update) ----------
  const allowedModel = (m: string) => /^[\w.:\/*-]{1,80}$/.test(m);
  async function readModels(body: { local?: Partial<LocalConfig> & { apiKey?: unknown }; frontier?: Partial<FrontierConfig> & { apiKey?: unknown; models?: unknown } }, prev?: Gateway) {
    const l = body.local ?? prev?.local ?? { mode: "shared" };
    const local: LocalConfig = { mode: l.mode === "custom" ? "custom" : "shared" };
    if (local.mode === "shared" && !d.sharedLocal) return { error: "this server has no shared local model; enter your own OpenAI-compatible endpoint" };
    if (local.mode === "custom") {
      const u = await checkUpstream(String(l.baseUrl ?? ""), d.allowPrivateUpstreams);
      if (u.error) return { error: `local model URL: ${u.error}` };
      if (!l.model || !allowedModel(String(l.model))) return { error: "local model name required" };
      local.baseUrl = u.url;
      local.model = String(l.model);
      local.apiKey = typeof l.apiKey === "string" ? (l.apiKey ? d.vault.seal(l.apiKey) : undefined) : prev?.local.mode === "custom" && prev.local.baseUrl === u.url ? prev.local.apiKey : undefined;
    }
    const f = body.frontier ?? prev?.frontier;
    if (!f) return { error: "frontier model settings required" };
    const provider = f.provider === "openai" ? "openai" : "anthropic";
    let baseUrl: string | undefined;
    if (f.baseUrl || provider === "openai") {
      const u = await checkUpstream(String(f.baseUrl ?? ""), d.allowPrivateUpstreams);
      if (u.error) return { error: `frontier base URL: ${u.error}` };
      baseUrl = u.url;
    }
    const models = (Array.isArray(f.models) ? f.models : String(f.models ?? "").split(",")).map((m) => String(m).trim()).filter(Boolean);
    if (!models.length || models.some((m) => !allowedModel(m))) return { error: "list at least one frontier model (letters, digits, . : / - and * globs)" };
    const concrete = models.filter((m) => !m.includes("*"));
    const defaultModel = String(f.defaultModel || concrete[0] || "");
    if (!defaultModel || defaultModel.includes("*")) return { error: "choose a default frontier model (a concrete name, not a glob)" };
    const sameUpstream = prev && prev.frontier.provider === provider && prev.frontier.baseUrl === baseUrl;
    const apiKey = typeof f.apiKey === "string" ? (f.apiKey ? d.vault.seal(f.apiKey) : undefined) : sameUpstream ? prev.frontier.apiKey : undefined;
    return { local, frontier: { provider, baseUrl, apiKey, models, defaultModel } as FrontierConfig };
  }
  function readPolicy(p: Partial<PolicyConfig> | undefined, prev?: PolicyConfig): PolicyConfig | { error: string } {
    const x = { ...(prev ?? { maxClass: "confidential", egress: "approval", highRiskQuorum: 2 }), ...(p ?? {}) } as PolicyConfig;
    if (!CLASS_ORDER.includes(x.maxClass as DataClass) || x.maxClass === "restricted") return { error: "maxClass must be public, internal or confidential (restricted never leaves)" };
    if (!["auto", "approval", "block"].includes(x.egress)) return { error: "egress must be auto, approval or block" };
    const q = Number(x.highRiskQuorum);
    if (!Number.isInteger(q) || q < 0 || q > 5) return { error: "high-risk quorum must be 0–5" };
    return { maxClass: x.maxClass, egress: x.egress, highRiskQuorum: q };
  }

  // ---------- gateways ----------
  app.get("/api/slug/:slug", async (c) => {
    const slug = c.req.param("slug");
    const bad = checkSlug(slug);
    if (bad) return c.json({ ok: false, error: bad });
    if (store.bySlug(slug)) return c.json({ ok: false, error: "taken" });
    if (d.provisioner) {
      const free = await d.provisioner.available(slug).catch(() => undefined);
      if (free === undefined) return c.json({ ok: false, error: "couldn't reach Sepolia to check; try again" });
      if (!free) return c.json({ ok: false, error: `${slug}.${d.root} is taken on ENS` });
    }
    return c.json({ ok: true, name: `${slug}.${d.root}` });
  });

  function startProvision(g: Gateway) {
    if (!d.provisioner || provisioning.has(g.id)) return;
    provisioning.add(g.id);
    g.ens.status = "provisioning";
    g.ens.error = undefined;
    store.save();
    const run = () =>
      d.provisioner!.provision({
        root: d.root,
        slug: g.slug,
        owner: g.owner as Address,
        policy: () => policyRecords(g, d.root),
        state: g.ens.state,
        save: () => store.save(),
        progress: (step, i, n) => {
          g.ens.step = `${step} (${Math.min(i + 1, n)}/${n})`;
        },
      });
    // Each step is idempotent, so a flaky RPC just means running again from where it stopped.
    const attempt = async (n: number): Promise<unknown> => {
      try {
        return await run();
      } catch (e) {
        if (n >= 3) throw e;
        console.warn(`[platform] provisioning ${g.slug}: ${(e as Error).message.split("\n")[0]}; retrying`);
        await new Promise((ok) => setTimeout(ok, 5000 * n));
        return attempt(n + 1);
      }
    };
    attempt(1)
      .then(() => {
        g.ens.status = "live";
        g.ens.step = undefined;
        console.log(`[platform] ${g.slug}.${d.root} is live on ENS`);
      })
      .catch((e) => {
        g.ens.status = "failed";
        g.ens.error = ((e as { shortMessage?: string }).shortMessage ?? (e as Error).message).split("\n")[0].slice(0, 200);
        console.warn(`[platform] provisioning ${g.slug} failed: ${g.ens.error}`);
      })
      .finally(() => {
        provisioning.delete(g.id);
        store.save();
      });
  }
  // Resume anything a restart interrupted.
  for (const g of store.all()) if (g.kind === "user" && g.ens.status === "provisioning") startProvision(g);

  app.post("/api/gateways", async (c) => {
    const address = me(c);
    if (!address) return json(c, 401, "sign in first");
    if (!d.provisioner) return json(c, 501, "this server has no ENS writer configured, so it can't create gateways");
    const owned = store.all().filter((g) => g.kind === "user" && g.owner === address).length;
    if (owned >= d.maxGatewaysPerUser) return json(c, 403, `you already own ${owned} gateway${owned === 1 ? "" : "s"} (limit ${d.maxGatewaysPerUser})`);
    const body = (await c.req.json().catch(() => ({}))) as Record<string, any>;
    const name = String(body.name ?? "").trim();
    if (!name || name.length > 60) return json(c, 400, "name required (up to 60 characters)");
    const slug = String(body.slug ?? "").trim().toLowerCase();
    const bad = checkSlug(slug);
    if (bad) return json(c, 400, `ENS name: ${bad}`);
    const free = store.bySlug(slug) ? false : await d.provisioner.available(slug).catch(() => undefined);
    if (free === undefined) return json(c, 503, "couldn't reach Sepolia to check the name; try again");
    if (!free) return json(c, 409, `${slug}.${d.root} is taken`);
    const label = String(body.label ?? "owner").trim().toLowerCase();
    if (!LABEL_RE.test(label)) return json(c, 400, "your name in the gateway: lowercase letters, digits and hyphens");
    const models = await readModels(body);
    if ("error" in models) return json(c, 400, models.error!);
    const policy = readPolicy(body.policy);
    if ("error" in policy) return json(c, 400, policy.error);
    const g = store.add({
      slug,
      name,
      kind: "user",
      owner: address,
      local: models.local!,
      frontier: models.frontier!,
      policy,
      ens: { status: "provisioning", state: { done: {} } },
      members: [{ address, label, role: "admin", joinedAt: Date.now() }],
    });
    startProvision(g);
    return c.json(view(g, g.members[0]), 201);
  });

  /** The gateway and the caller's membership, or an error response. */
  function access(c: Context, slug: string, need: "member" | "admin" = "member"): { g: Gateway; m: Member; address: string } | Response {
    const address = me(c);
    if (!address) return json(c, 401, "sign in first");
    const g = store.bySlug(slug);
    const m = g && store.memberOf(g, address);
    if (!g || !m) return json(c, 404, "no such gateway, or you're not a member");
    if (need === "admin" && m.role !== "admin") return json(c, 403, "admins only");
    return { g, m, address };
  }
  const secretsView = (g: Gateway) => ({
    local: { mode: g.local.mode, baseUrl: g.local.baseUrl, model: g.local.model, apiKey: g.local.apiKey ? `…${g.local.apiKey.last4}` : null },
    frontier: { provider: g.frontier.provider, baseUrl: g.frontier.baseUrl, models: g.frontier.models, defaultModel: g.frontier.defaultModel, apiKey: g.frontier.apiKey ? `…${g.frontier.apiKey.last4}` : null },
  });

  app.get("/api/gateways/:slug", (c) => {
    const a = access(c, c.req.param("slug"));
    if (a instanceof Response) return a;
    const { g, m } = a;
    return c.json({
      ...view(g, m),
      ...(g.kind === "user" && m.role === "admin" && { settings: { ...secretsView(g), policy: g.policy }, ensState: g.ens.state, steps: PROVISION_STEPS }),
      ...(g.kind === "user" && m.role !== "admin" && { settings: { policy: g.policy, frontier: { models: g.frontier.models, defaultModel: g.frontier.defaultModel } } }),
    });
  });

  app.patch("/api/gateways/:slug", async (c) => {
    const a = access(c, c.req.param("slug"), "admin");
    if (a instanceof Response) return a;
    const { g } = a;
    if (g.kind !== "user") return json(c, 403, "the demo gateway is configured by the server");
    const body = (await c.req.json().catch(() => ({}))) as Record<string, any>;
    const name = body.name === undefined ? g.name : String(body.name).trim();
    if (!name || name.length > 60) return json(c, 400, "name required (up to 60 characters)");
    const models = body.local || body.frontier ? await readModels(body, g) : { local: g.local, frontier: g.frontier };
    if ("error" in models) return json(c, 400, models.error!);
    const policy = readPolicy(body.policy, g.policy);
    if ("error" in policy) return json(c, 400, policy.error);
    const before = JSON.stringify(policyRecords(g, d.root));
    const next = { ...g, local: models.local!, frontier: models.frontier!, policy };
    const records = policyRecords(next, d.root);
    let tx: string | undefined;
    // Policy lives on ENS: write it first, and only keep the new settings if the chain took them.
    if (JSON.stringify(records) !== before && g.ens.status === "live" && d.provisioner && g.ens.state.resolver) {
      try {
        tx = await d.provisioner.writePolicy(g.ens.state.resolver, gatewayNames(g.slug, d.root).policy, records);
        d.policyChanged?.();
      } catch (e) {
        return json(c, 502, `ENS write failed, nothing changed: ${((e as { shortMessage?: string }).shortMessage ?? (e as Error).message).split("\n")[0]}`);
      }
    }
    Object.assign(g, { name, local: next.local, frontier: next.frontier, policy });
    store.save();
    d.tenants.get(g); // rebuild now, so the next request uses the new models
    return c.json({ ok: true, tx, settings: { ...secretsView(g), policy: g.policy } });
  });

  app.post("/api/gateways/:slug/provision", (c) => {
    const a = access(c, c.req.param("slug"), "admin");
    if (a instanceof Response) return a;
    if (a.g.kind !== "user" || a.g.ens.status === "live") return json(c, 409, "nothing to do");
    startProvision(a.g);
    return c.json({ ok: true });
  });

  /** Try the model settings without saving them: lists the local endpoint's models and checks the frontier key. */
  app.post("/api/models/test", async (c) => {
    const address = me(c);
    if (!address) return json(c, 401, "sign in first");
    const body = (await c.req.json().catch(() => ({}))) as Record<string, any>;
    const prev = body.slug ? store.bySlug(String(body.slug)) : undefined;
    if (prev && store.memberOf(prev, address)?.role !== "admin") return json(c, 403, "admins only");
    const models = await readModels(body, prev);
    if ("error" in models) return c.json({ local: { ok: false, detail: models.error }, frontier: { ok: false, detail: models.error } });
    const t = <T,>(p: Promise<T>) => Promise.race([p, new Promise<never>((_, no) => setTimeout(() => no(new Error("timeout")), 10_000))]);
    const local = await t(
      (async () => {
        if (models.local!.mode === "shared") return { ok: true, detail: `Airlock-hosted: ${d.sharedLocal?.model}`, models: [d.sharedLocal!.model] };
        const key = d.vault.open(models.local!.apiKey);
        const r = await fetch(`${models.local!.baseUrl}/models`, { redirect: "error", headers: key ? { authorization: `Bearer ${key}` } : {} });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const list = ((await r.json()) as { data?: { id: string }[] }).data?.map((x) => x.id) ?? [];
        return { ok: list.includes(models.local!.model!) || !list.length, detail: list.includes(models.local!.model!) ? `${models.local!.model} is served` : list.length ? `${models.local!.model} not served here; available: ${list.slice(0, 6).join(", ")}` : "reachable", models: list };
      })(),
    ).catch((e) => ({ ok: false, detail: (e as Error).message }));
    const f = models.frontier!;
    const key = d.vault.open(f.apiKey);
    const frontier = await t(
      (async () => {
        if (!key) throw new Error("no API key");
        const anthropic = f.provider === "anthropic";
        const base = f.baseUrl ?? (anthropic ? "https://api.anthropic.com" : "https://api.openai.com/v1");
        const r = await fetch(anthropic ? `${base}/v1/models` : `${base}/models`, {
          redirect: "error",
          headers: anthropic ? { "x-api-key": key, "anthropic-version": "2023-06-01", ...(f.baseUrl && { authorization: `Bearer ${key}` }) } : { authorization: `Bearer ${key}` },
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}${r.status === 401 ? " (key rejected)" : ""}`);
        return { ok: true, detail: `key accepted by ${new URL(base).host}` };
      })(),
    ).catch((e) => ({ ok: false, detail: (e as Error).message }));
    return c.json({ local, frontier });
  });

  // ---------- members ----------
  app.get("/api/gateways/:slug/members", async (c) => {
    const a = access(c, c.req.param("slug"));
    if (a instanceof Response) return a;
    const { g } = a;
    if (g.kind !== "user") return c.json([]);
    const n = gatewayNames(g.slug, d.root);
    const t = d.tenants.get(g);
    const list = await Promise.all(
      g.members.map(async (m) => ({
        address: m.address,
        label: m.label,
        role: m.role,
        joinedAt: m.joinedAt,
        owner: m.address === g.owner,
        approverName: canApprove(m.role) ? n.approver(m.label) : undefined,
        enrolled: canApprove(m.role) && g.ens.status === "live" && t.roles.isLiveApprover ? (await t.roles.isLiveApprover(n.approverRole, n.approver(m.label)).catch(() => "unknown")) === "valid" : false,
        keys: g.keys.filter((k) => k.member === m.address).length,
      })),
    );
    return c.json(list);
  });

  app.patch("/api/gateways/:slug/members/:address", async (c) => {
    const a = access(c, c.req.param("slug"), "admin");
    if (a instanceof Response) return a;
    const { g } = a;
    const target = g.members.find((m) => m.address === c.req.param("address").toLowerCase());
    if (!target) return json(c, 404, "not a member");
    const { role } = (await c.req.json().catch(() => ({}))) as { role?: Role };
    if (!role || !ROLES.includes(role)) return json(c, 400, "role must be admin, approver or member");
    if (target.address === g.owner && role !== "admin") return json(c, 403, "the owner stays an admin");
    const wasApprover = canApprove(target.role);
    target.role = role;
    store.save();
    // No longer allowed to approve: take the approver name off ENS too, or it would still pass the role check.
    if (wasApprover && !canApprove(role)) await revokeApprover(g, target).catch(() => {});
    return c.json({ ok: true });
  });

  async function revokeApprover(g: Gateway, m: Member) {
    const t = d.tenants.get(g);
    const n = gatewayNames(g.slug, d.root);
    if (g.ens.status !== "live" || !t.roles.revoke || !t.roles.isLiveApprover) return;
    if ((await t.roles.isLiveApprover(n.approverRole, n.approver(m.label))) === "valid") await t.roles.revoke(n.approver(m.label));
  }

  app.delete("/api/gateways/:slug/members/:address", async (c) => {
    const a = access(c, c.req.param("slug"));
    if (a instanceof Response) return a;
    const { g, m, address } = a;
    const who = c.req.param("address").toLowerCase();
    if (who !== address && m.role !== "admin") return json(c, 403, "admins only");
    const target = g.members.find((x) => x.address === who);
    if (!target) return json(c, 404, "not a member");
    if (target.address === g.owner) return json(c, 403, "the owner can't be removed");
    g.members = g.members.filter((x) => x !== target);
    g.keys = g.keys.filter((k) => k.member !== who); // their API keys stop working now
    store.save();
    await revokeApprover(g, target).catch((e) => console.warn(`[platform] revoking ${target.label}: ${(e as Error).message}`));
    return c.json({ ok: true });
  });

  // ---------- invites ----------
  app.get("/api/gateways/:slug/invites", (c) => {
    const a = access(c, c.req.param("slug"), "admin");
    if (a instanceof Response) return a;
    return c.json(a.g.invites.filter((i) => !i.usedBy && i.expiresAt > Date.now()).map(({ codeHash, ...i }) => i));
  });
  app.post("/api/gateways/:slug/invites", async (c) => {
    const a = access(c, c.req.param("slug"), "admin");
    if (a instanceof Response) return a;
    if (a.g.kind !== "user") return json(c, 403, "the demo gateway is open to everyone");
    const { role, label } = (await c.req.json().catch(() => ({}))) as { role?: Role; label?: string };
    if (!role || !ROLES.includes(role)) return json(c, 400, "role must be admin, approver or member");
    const l = label?.trim().toLowerCase() || undefined;
    if (l && !LABEL_RE.test(l)) return json(c, 400, "name: lowercase letters, digits and hyphens");
    const { invite, code } = store.createInvite(a.g, a.address, role, l);
    const { codeHash, ...rest } = invite;
    return c.json({ ...rest, url: `${d.publicUrl.replace(/\/$/, "")}/join/${code}` }, 201);
  });
  app.delete("/api/gateways/:slug/invites/:id", (c) => {
    const a = access(c, c.req.param("slug"), "admin");
    if (a instanceof Response) return a;
    a.g.invites = a.g.invites.filter((i) => i.id !== c.req.param("id"));
    store.save();
    return c.json({ ok: true });
  });

  app.get("/api/invites/:code", (c) => {
    const hit = store.findInvite(c.req.param("code"));
    if (!hit) return json(c, 404, "this invite link isn't valid");
    const { g, invite } = hit;
    const address = me(c);
    const inviter = g.members.find((m) => m.address === invite.createdBy);
    return c.json({
      gateway: { name: g.name, slug: g.slug, ens: gatewayNames(g.slug, d.root).base },
      role: invite.role,
      label: invite.label,
      invitedBy: inviter?.label,
      status: invite.usedBy ? "used" : invite.expiresAt < Date.now() ? "expired" : "open",
      alreadyMember: !!(address && g.members.some((m) => m.address === address)),
    });
  });
  app.post("/api/invites/:code/accept", async (c) => {
    const address = me(c);
    if (!address) return json(c, 401, "sign in first");
    const hit = store.findInvite(c.req.param("code"));
    if (!hit) return json(c, 404, "this invite link isn't valid");
    const { g, invite } = hit;
    if (invite.usedBy) return json(c, 410, "this invite was already used");
    if (invite.expiresAt < Date.now()) return json(c, 410, "this invite has expired; ask for a new one");
    if (g.members.some((m) => m.address === address)) return json(c, 409, "you're already a member");
    const { label } = (await c.req.json().catch(() => ({}))) as { label?: string };
    const l = String(label ?? invite.label ?? "").trim().toLowerCase();
    if (!LABEL_RE.test(l)) return json(c, 400, "your name: lowercase letters, digits and hyphens (it becomes part of your ENS name)");
    if (g.members.some((m) => m.label === l)) return json(c, 409, `"${l}" is taken in this gateway`);
    g.members.push({ address, label: l, role: invite.role, joinedAt: Date.now() });
    invite.usedBy = address;
    invite.usedAt = Date.now();
    store.save();
    return c.json({ slug: g.slug, role: invite.role, label: l });
  });

  // ---------- API keys ----------
  app.get("/api/gateways/:slug/keys", (c) => {
    const a = access(c, c.req.param("slug"));
    if (a instanceof Response) return a;
    const { g, m } = a;
    const label = (addr: string) => store.memberOf(g, addr)?.label ?? addr;
    return c.json(g.keys.filter((k) => m.role === "admin" && g.kind === "user" ? true : k.member === m.address).map(({ hash, ...k }) => ({ ...k, memberLabel: label(k.member), mine: k.member === m.address })));
  });
  app.post("/api/gateways/:slug/keys", async (c) => {
    const a = access(c, c.req.param("slug"));
    if (a instanceof Response) return a;
    const { name } = (await c.req.json().catch(() => ({}))) as { name?: string };
    const n = String(name ?? "").trim().slice(0, 40) || "agent";
    if (a.g.keys.filter((k) => k.member === a.m.address).length >= 20) return json(c, 403, "20 keys per member; delete one first");
    const { key, secret } = store.createKey(a.g, a.m.address, n);
    const { hash, ...rest } = key;
    return c.json({ ...rest, secret }, 201);
  });
  app.delete("/api/gateways/:slug/keys/:id", (c) => {
    const a = access(c, c.req.param("slug"));
    if (a instanceof Response) return a;
    const k = a.g.keys.find((x) => x.id === c.req.param("id"));
    if (!k) return json(c, 404, "no such key");
    if (k.member !== a.m.address && a.m.role !== "admin") return json(c, 403, "not your key");
    a.g.keys = a.g.keys.filter((x) => x !== k);
    store.save();
    return c.json({ ok: true });
  });

  // ---------- into a gateway ----------
  /**
   * Forward to the gateway's API with the caller's identity set by us: whatever a client claims in
   * x-airlock-user / x-airlock-requester-id is replaced. User gateways also drop x-airlock-agent, so a key can
   * only ever run under its own gateway's ENS policy.
   */
  async function forward(c: Context, g: Gateway, m: Member, path: string, o: { body?: unknown; query?: Record<string, string> } = {}) {
    const t = d.tenants.get(g);
    const { body } = o;
    const url = new URL(c.req.url);
    url.pathname = path;
    for (const [k, v] of Object.entries(o.query ?? {})) url.searchParams.set(k, v);
    const headers = new Headers(c.req.raw.headers);
    headers.delete("authorization");
    headers.delete("cookie");
    headers.delete("x-airlock-requester-id");
    if (g.kind === "user") {
      headers.delete("x-airlock-agent");
      headers.set("x-airlock-user", encodeURIComponent(m.label));
    } else if (!headers.get("x-airlock-user")) headers.set("x-airlock-user", encodeURIComponent(m.label));
    headers.set("x-airlock-requester-id", m.address);
    const init: RequestInit & { duplex?: string } = { method: c.req.method, headers, signal: c.req.raw.signal };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
      headers.set("content-type", "application/json");
      headers.delete("content-length");
    } else if (!["GET", "HEAD"].includes(c.req.method)) {
      init.body = c.req.raw.body;
      init.duplex = "half";
    }
    return t.app.fetch(new Request(url, init));
  }

  // Agents: `Authorization: Bearer alk_…` picks the gateway and the member; nothing else is needed.
  app.all("/v1/*", async (c) => {
    const bearer = c.req.header("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
    const hit = store.byKey(bearer);
    if (!hit) return c.json({ error: { message: "missing or invalid Airlock API key (create one on the Connect page)", type: "authentication_error" } }, 401);
    const path = new URL(c.req.url).pathname;
    if (!needFor(c.req.method, path)) return c.json({ error: { message: "not found", type: "invalid_request_error" } }, 404);
    return forward(c, hit.g, hit.member, path);
  });

  // The Console: /g/<slug>/… with the session cookie, checked against the member's role.
  app.all("/g/:slug/*", async (c) => {
    const slug = c.req.param("slug");
    const a = access(c, slug);
    if (a instanceof Response) return a;
    const { g, m } = a;
    const path = new URL(c.req.url).pathname.slice(`/g/${slug}`.length) || "/";
    const need = needFor(c.req.method, path);
    const t = d.tenants.get(g);
    const n = gatewayNames(g.slug, d.root);
    const myApproverName = g.kind === "user" && canApprove(m.role) ? n.approver(m.label) : undefined;

    if (c.req.method === "GET" && path === "/config") return c.json({ ...t.config, me: { address: m.address, label: m.label, role: m.role, approverName: myApproverName } });
    // Full request (original text, real names) only for those who decide on it, and for the one who asked.
    const one = c.req.method === "GET" && /^\/approvals\/([\w-]+)$/.exec(path);
    if (one) {
      const r = t.approvals.get(one[1]);
      if (!r) return json(c, 404, "not found");
      return c.json(canApprove(m.role) || r.requesterId === m.address ? r : publicView(r));
    }
    if (!need) return json(c, 404, "not found");
    if (g.kind === "demo") return forward(c, g, m, path); // the showcase: every signed-in visitor may play every part

    if (need === "admin" && m.role !== "admin") return json(c, 403, "admins only");
    if (need === "approver" && !canApprove(m.role)) return json(c, 403, "only approvers can do this; ask an admin for the approver role");
    if (need === "requester") {
      const r = t.approvals.get(path.split("/")[2]);
      if (!r) return json(c, 404, "not found");
      if (r.requesterId !== m.address && m.role !== "admin") return json(c, 403, "only the person who asked (or an admin) can withdraw it");
    }
    // Approvers act under their own ENS name only: the name comes from the membership, never from the request.
    if (myApproverName && c.req.method === "GET" && (/\/(oidc|worldid)$/.test(path) || path.startsWith("/enroll/"))) return forward(c, g, m, path, { query: { approverName: myApproverName } });
    if (myApproverName && c.req.method === "POST" && (/\/verify$/.test(path) || path === "/enroll")) {
      const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
      return forward(c, g, m, path, { body: { ...body, approverName: myApproverName } });
    }
    return forward(c, g, m, path);
  });

  // World sends every gateway's ceremony back here; the pending state says which gateway started it.
  app.get("/oidc/callback", (c) => {
    const slug = d.oidcTenant?.(c.req.query("state") ?? "");
    const g = (slug && store.bySlug(slug)) || store.all().find((x) => x.kind === "demo");
    if (!g) return c.text("no gateway", 404);
    return d.tenants.get(g).app.fetch(c.req.raw);
  });
  // MultiBaas pushes ENS events for the demo contracts (HMAC-signed; checked by the demo gateway).
  app.post("/multibaas/webhook", (c) => {
    const g = store.all().find((x) => x.kind === "demo");
    return g ? d.tenants.get(g).app.fetch(c.req.raw) : c.text("no gateway", 404);
  });

  return app;
}
