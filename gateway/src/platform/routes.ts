import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { Hono, type Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Address, Hex } from "viem";
import { CLASS_ORDER, type DataClass } from "@airlock/core";
import { publicView } from "@airlock/approval";
import { checkSlug, gatewayNames, PROVISION_STEPS, type EnsProvisioner, type PolicyRecords, type PolicyWrite } from "@airlock/registry";
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
  /**
   * Abuse limits for an open sign-up. Chat requests per member per hour (the demo spends the platform's own
   * frontier key, so it gets less), and new gateways per hour across everyone (each costs eight Sepolia txs).
   */
  limits?: { chatPerHour?: number; demoChatPerHour?: number; newGatewaysPerHour?: number };
}

/** Sliding one-hour window per key. In memory: a restart forgives everyone, which is fine for abuse limits. */
function hourly() {
  const hits = new Map<string, number[]>();
  return (key: string, max: number) => {
    const now = Date.now();
    const recent = (hits.get(key) ?? []).filter((t) => now - t < 3600_000);
    if (recent.length >= max) return Math.ceil((recent[0] + 3600_000 - now) / 60_000);
    recent.push(now);
    hits.set(key, recent);
    return 0;
  };
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
export function policyRecords(gw: Gateway, root: string, policy: PolicyConfig = gw.policy): PolicyRecords {
  const n = gatewayNames(gw.slug, root);
  const q = policy.highRiskQuorum;
  return {
    maxClass: policy.maxClass,
    egress: policy.egress,
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
  const limit = hourly();
  const L = { chatPerHour: 120, demoChatPerHour: 20, newGatewaysPerHour: 10, ...d.limits };

  const me = (c: Context) => d.auth.read(getCookie(c, SESSION));
  // The SIWE domain is this server's configured public origin, never a request header: a client can send any
  // Host / X-Forwarded-Host, and a message signed on another site must not log anyone in here.
  const origin = new URL(d.publicUrl);
  const secure = (c: Context) => origin.protocol === "https:" || c.req.header("x-forwarded-proto") === "https";

  // ---------- static ----------
  app.get("/health", (c) => c.json({ ok: true }));
  app.get("/", (c) => c.redirect("/console"));
  app.get("/favicon.ico", (c) => c.body(null, 204));
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
    return c.json({ message: d.auth.message({ address, chainId: Number(chainId) || 1, domain: origin.host, uri: origin.origin }) });
  });
  app.post("/api/auth/verify", async (c) => {
    const { message, signature } = (await c.req.json().catch(() => ({}))) as { message?: string; signature?: Hex };
    if (!message || !signature) return json(c, 400, "message and signature required");
    try {
      const address = await d.auth.verify(message, signature, origin.host);
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
    if (!address) return c.json({ address: null, platform });
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
    // A live gateway only has the hand-over steps left: it keeps serving while they run.
    const wasLive = g.ens.status === "live";
    if (!wasLive) g.ens.status = "provisioning";
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
        const error = ((e as { shortMessage?: string }).shortMessage ?? (e as Error).message).split("\n")[0].slice(0, 200);
        if (!wasLive) Object.assign(g.ens, { status: "failed", error });
        console.warn(`[platform] provisioning ${g.slug} failed: ${error}`);
      })
      .finally(() => {
        provisioning.delete(g.id);
        store.save();
      });
  }
  const handedOver = (g: Gateway) => !!g.ens.state.done["hand over registry"];
  /** Policy keys belong to the owner's wallet from this step on (the registry hand-over follows right after). */
  const ownerSignsPolicy = (g: Gateway) => !!g.ens.state.done["hand over policy"];
  // Resume anything a restart interrupted, and hand over gateways built before the platform gave up its roles.
  for (const g of store.all()) if (g.kind === "user" && (g.ens.status === "provisioning" || (g.ens.status === "live" && !handedOver(g)))) startProvision(g);

  app.post("/api/gateways", async (c) => {
    const address = me(c);
    if (!address) return json(c, 401, "sign in first");
    if (!d.provisioner) return json(c, 501, "this server has no ENS writer configured, so it can't create gateways");
    const created = store.all().filter((g) => g.kind === "user" && Date.now() - g.createdAt < 3600_000).length;
    if (created >= L.newGatewaysPerHour) return json(c, 429, "many gateways were created in the last hour; try again a bit later");
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
      ...(g.kind === "user" && m.role === "admin" && { settings: { ...secretsView(g), policy: g.policy }, ensState: g.ens.state, steps: PROVISION_STEPS, policySigner: ownerSignsPolicy(g) ? "owner" : "platform" }),
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
    // Policy lives on ENS: it changes on-chain first, and the new settings are kept only if the chain took them.
    // Named policies carry the model allowlist too, so a models change rewrites theirs in the same transaction.
    const n = gatewayNames(g.slug, d.root);
    const writes: PolicyWrite[] = [];
    if (JSON.stringify(records) !== before) writes.push({ name: n.policy, records });
    if (records.models !== JSON.parse(before).models) for (const p of g.policies ?? []) writes.push({ name: n.namedPolicy(p.label), records: { models: records.models } });
    const w = await writeRecords(c, g, a.address, writes, txsOf(body));
    if (w instanceof Response) return w;
    const { tx } = w;
    Object.assign(g, { name, local: next.local, frontier: next.frontier, policy });
    store.save();
    d.tenants.get(g); // rebuild now, so the next request uses the new models
    return c.json({ ok: true, tx, settings: { ...secretsView(g), policy: g.policy } });
  });

  const HASH = /^0x[0-9a-fA-F]{64}$/;
  /** Transaction hashes the owner's wallet sent for a change we asked it to sign. */
  const txsOf = (body: Record<string, any>): Hex[] => (Array.isArray(body.txs) ? body.txs.filter((h: unknown) => typeof h === "string" && HASH.test(h)).slice(0, 4) : []);
  const ensError = (e: unknown) => ((e as { shortMessage?: string }).shortMessage ?? (e as Error).message).split("\n")[0];
  const notOwner = (g: Gateway) => `Only the owner's wallet (${g.owner}) can do this: it's an ENS change, and the platform holds no rights to it.`;

  /**
   * Write policy records on the gateway's resolver. Until hand-over the platform writes them; after it, the owner's
   * wallet signs: without `txs` the Console gets `{ sign: [tx] }` back (202), and with them we check the
   * transaction wrote exactly these records. Resolves to the tx hash, or to the error Response to send.
   */
  async function writeRecords(c: Context, g: Gateway, address: string, writes: PolicyWrite[], txs: Hex[]): Promise<{ tx?: string } | Response> {
    const resolver = g.ens.state.resolver;
    if (!writes.length || !d.provisioner || !resolver) return {};
    try {
      if (!ownerSignsPolicy(g)) {
        // Provisioning writes whatever is saved by the time it gets to the policy.
        if (g.ens.status !== "live") return {};
        const tx = await d.provisioner.writePolicy(resolver, writes);
        d.policyChanged?.();
        return { tx };
      }
      if (!txs.length) {
        if (!(await d.provisioner.canWritePolicy(resolver, address as Address, writes[0].records))) return json(c, 403, notOwner(g));
        return c.json({ sign: [d.provisioner.policyTx(resolver, writes)] }, 202);
      }
      const wrong = await d.provisioner.checkPolicyTx(resolver, writes, txs[0]);
      if (wrong) return json(c, 409, `Nothing changed: ${wrong}.`);
      d.policyChanged?.();
      return { tx: txs[0] };
    } catch (e) {
      return json(c, 502, `ENS: ${ensError(e)}. Nothing changed.`);
    }
  }

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

  // ---------- agents and named policies ----------
  /**
   * Agents are <label>.agents.<slug>: a name that resolves through agents.<slug> (ENSIP-10 wildcard) to the
   * gateway's resolver. With no record of its own it reads the default record, linked to policy.<slug>; linked to a
   * named policy (<p>.policy.<slug>) it reads that one. API keys pick the agent, so the audit shows which ran.
   */
  async function agentsReady(g: Gateway): Promise<boolean> {
    const s = g.ens.state;
    if (s.agentsReady) return true;
    if (g.kind !== "user" || g.ens.status !== "live" || !d.provisioner || !s.resolver || !s.registry) return false;
    const left = await d.provisioner.agentsSetup(s, gatewayNames(g.slug, d.root), g.owner as Address).catch(() => undefined);
    if (left?.length !== 0) return false;
    s.agentsReady = true;
    store.save();
    return true;
  }
  const agentsView = (g: Gateway) => {
    const n = gatewayNames(g.slug, d.root);
    return {
      defaultPolicy: { name: n.policy, policy: g.policy },
      policies: (g.policies ?? []).map((p) => ({ ...p, name: n.namedPolicy(p.label), agents: (g.agents ?? []).filter((x) => x.policy === p.label).length })),
      agents: (g.agents ?? []).map((x) => ({ ...x, name: n.agent(x.label), keys: g.keys.filter((k) => k.agent === x.label).length })),
    };
  };
  /** The admin gateway, live on ENS with its resolver, or an error response. */
  function liveAdmin(c: Context) {
    const a = access(c, c.req.param("slug")!, "admin");
    if (a instanceof Response) return a;
    if (a.g.kind !== "user") return json(c, 403, "the demo gateway's agents are configured by the server");
    if (a.g.ens.status !== "live" || !a.g.ens.state.resolver || !d.provisioner) return json(c, 409, "wait until the gateway is live on ENS");
    return a;
  }

  app.get("/api/gateways/:slug/agents", async (c) => {
    const a = access(c, c.req.param("slug"));
    if (a instanceof Response) return a;
    return c.json({ ready: await agentsReady(a.g), ...agentsView(a.g) });
  });

  /** One-time ENS setup for gateways built before agents existed; the owner's wallet signs it. */
  app.post("/api/gateways/:slug/agents/setup", async (c) => {
    const a = liveAdmin(c);
    if (a instanceof Response) return a;
    const { g } = a;
    if (await agentsReady(g)) return c.json({ ok: true });
    const txs = txsOf((await c.req.json().catch(() => ({}))) as Record<string, any>);
    const n = gatewayNames(g.slug, d.root);
    try {
      if (!txs.length) {
        if (!(await d.provisioner!.canSetUpAgents(g.ens.state, a.address as Address))) return json(c, 403, notOwner(g));
        return c.json({ sign: await d.provisioner!.agentsSetup(g.ens.state, n, g.owner as Address) }, 202);
      }
      const wrong = await d.provisioner!.checkAgentsSetup(g.ens.state, n, g.owner as Address, txs);
      if (wrong) return json(c, 409, `Not ready yet: ${wrong}.`);
    } catch (e) {
      return json(c, 502, `ENS: ${ensError(e)}`);
    }
    g.ens.state.agentsReady = true;
    store.save();
    return c.json({ ok: true });
  });

  app.put("/api/gateways/:slug/policies/:label", async (c) => {
    const a = liveAdmin(c);
    if (a instanceof Response) return a;
    const { g } = a;
    const label = c.req.param("label");
    if (!LABEL_RE.test(label)) return json(c, 400, "policy name: lowercase letters, digits and hyphens");
    const body = (await c.req.json().catch(() => ({}))) as Record<string, any>;
    const prev = (g.policies ?? []).find((p) => p.label === label);
    if (!prev && (g.policies ?? []).length >= 20) return json(c, 403, "20 policies per gateway");
    const policy = readPolicy(body.policy, prev?.policy);
    if ("error" in policy) return json(c, 400, policy.error);
    const w = await writeRecords(c, g, a.address, [{ name: gatewayNames(g.slug, d.root).namedPolicy(label), records: policyRecords(g, d.root, policy) }], txsOf(body));
    if (w instanceof Response) return w;
    if (prev) prev.policy = policy;
    else (g.policies ??= []).push({ label, policy, createdAt: Date.now() });
    store.save();
    return c.json({ ok: true, tx: w.tx, ...agentsView(g) });
  });

  app.delete("/api/gateways/:slug/policies/:label", (c) => {
    const a = access(c, c.req.param("slug"), "admin");
    if (a instanceof Response) return a;
    const { g } = a;
    const label = c.req.param("label");
    const users = (g.agents ?? []).filter((x) => x.policy === label);
    if (users.length) return json(c, 409, `${users.map((x) => x.label).join(", ")} still use this policy; move them first`);
    // Its records stay on ENS, unused: nothing links to them any more.
    g.policies = (g.policies ?? []).filter((p) => p.label !== label);
    store.save();
    return c.json({ ok: true, ...agentsView(g) });
  });

  /** Create an agent or change its policy. Pointing it at a named policy (or back) is a link the owner signs. */
  app.put("/api/gateways/:slug/agents/:label", async (c) => {
    const a = liveAdmin(c);
    if (a instanceof Response) return a;
    const { g } = a;
    const label = c.req.param("label");
    if (!LABEL_RE.test(label)) return json(c, 400, "agent name: lowercase letters, digits and hyphens");
    if (!(await agentsReady(g))) return json(c, 409, "set up agents on ENS first");
    const body = (await c.req.json().catch(() => ({}))) as Record<string, any>;
    const policy = body.policy ? String(body.policy) : undefined;
    if (policy && !(g.policies ?? []).some((p) => p.label === policy)) return json(c, 400, `no policy "${policy}" in this gateway`);
    const prev = (g.agents ?? []).find((x) => x.label === label);
    if (!prev && (g.agents ?? []).length >= 50) return json(c, 403, "50 agents per gateway");
    const n = gatewayNames(g.slug, d.root);
    const [agentName, policyName] = [n.agent(label), policy ? n.namedPolicy(policy) : null];
    const txs = txsOf(body);
    try {
      if (!txs.length) {
        // Asked of the chain, not our store: a name reused after a delete may still carry an old link.
        const tx = await d.provisioner!.agentLinkTx(g.ens.state.resolver!, agentName, policyName);
        if (tx) {
          if (!(await d.provisioner!.canLink(g.ens.state.resolver!, a.address as Address))) return json(c, 403, notOwner(g));
          return c.json({ sign: [tx] }, 202);
        }
      } else {
        const wrong = await d.provisioner!.checkAgentLink(g.ens.state.resolver!, agentName, policyName, txs[0]);
        if (wrong) return json(c, 409, `Nothing changed: ${wrong}.`);
        d.policyChanged?.();
      }
    } catch (e) {
      return json(c, 502, `ENS: ${ensError(e)}`);
    }
    if (prev) prev.policy = policy;
    else (g.agents ??= []).push({ label, policy, createdAt: Date.now() });
    store.save();
    return c.json({ ok: true, tx: txs[0], ...agentsView(g) });
  });

  app.delete("/api/gateways/:slug/agents/:label", (c) => {
    const a = access(c, c.req.param("slug"), "admin");
    if (a instanceof Response) return a;
    const { g } = a;
    const label = c.req.param("label");
    const keys = g.keys.filter((k) => k.agent === label).length;
    if (keys) return json(c, 409, `${keys} API key${keys === 1 ? "" : "s"} run as this agent; delete ${keys === 1 ? "it" : "them"} first`);
    // An ENS link it had stays; recreating the agent reads the chain and re-links as needed.
    g.agents = (g.agents ?? []).filter((x) => x.label !== label);
    store.save();
    return c.json({ ok: true, ...agentsView(g) });
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
    if (a.g.kind === "demo") return json(c, 403, "the shared demo is for the Playground; create your own gateway to connect agents");
    const { name, agent } = (await c.req.json().catch(() => ({}))) as { name?: string; agent?: string };
    const n = String(name ?? "").trim().slice(0, 40) || "agent";
    if (agent && !(a.g.agents ?? []).some((x) => x.label === agent)) return json(c, 400, `no agent "${agent}" in this gateway`);
    if (a.g.keys.filter((k) => k.member === a.m.address).length >= 20) return json(c, 403, "20 keys per member; delete one first");
    const { key, secret } = store.createKey(a.g, a.m.address, n, agent || undefined);
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
   * x-airlock-user / x-airlock-requester-id is replaced. On user gateways x-airlock-agent is ours too: an API key
   * runs as the agent it was made for (`o.agent`: its label, or null for the gateway default), and the Console may
   * pick among this gateway's own agents. Nothing can name another gateway's policy.
   */
  async function forward(c: Context, g: Gateway, m: Member, path: string, o: { body?: unknown; query?: Record<string, string>; agent?: string | null } = {}) {
    if (path === "/v1/chat/completions") {
      const wait = limit(`${g.id}|${m.address}`, g.kind === "demo" ? L.demoChatPerHour : L.chatPerHour);
      if (wait) return c.json({ error: { message: `rate limit: too many requests this hour; try again in ${wait} min`, type: "rate_limit_error" } }, 429);
    }
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
      const n = gatewayNames(g.slug, d.root);
      const own = new Set((g.agents ?? []).map((x) => n.agent(x.label)));
      const asked = headers.get("x-airlock-agent") ?? "";
      const agent = o.agent !== undefined ? (o.agent && own.has(n.agent(o.agent)) ? n.agent(o.agent) : n.policy) : own.has(asked) ? asked : n.policy;
      headers.set("x-airlock-agent", agent);
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
    return forward(c, hit.g, hit.member, path, { agent: hit.key.agent ?? null });
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
