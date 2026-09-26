import { resolve } from "node:path";
import type { Hono } from "hono";
import type { Hex, PublicClient } from "viem";
import { LocalAttackScorer, llmRecognizer, PipelineRedactor, presidioRecognizer, ruleRecognizer, RuleRiskScorer, type Recognizer } from "@airlock/redactor";
import { ApprovalStore, type ProofVerifier, type WorldOidc } from "@airlock/approval";
import { commitmentOf, EnsInspector, EnsPolicyResolver, EnsRoleRegistry, EnsWriter, gatewayNames } from "@airlock/registry";
import { JsonlAuditLog } from "@airlock/audit";
import { ClaudeModel, LocalModel, OpenAICompatModel, type FrontierModel } from "../llm";
import { Pipeline } from "../pipeline";
import { buildApp } from "../app";
import { canApprove, type Gateway, type Vault } from "./store";

/** One running gateway: its own pipeline, approval queue, audit chain, ENS writer and API. */
export interface Tenant {
  gw: Gateway;
  app: Hono;
  approvals: ApprovalStore;
  audit: JsonlAuditLog;
  roles: EnsRoleRegistry | import("@airlock/core").RoleRegistry;
  local: LocalModel;
  egress: FrontierModel;
  /** Public Console config (the platform adds who is looking). */
  config: Record<string, unknown>;
}

/** What every user gateway shares: the chain, World ID, the platform's key and its own local model. */
export interface PlatformContext {
  root: string; // airlock.eth
  rpcUrl: string;
  client: PublicClient;
  policies: EnsPolicyResolver;
  platformKey: Hex;
  platformAddress: string;
  verifier: ProofVerifier;
  oidc?: WorldOidc;
  binding: "commitment" | "name";
  approveAction: string;
  vault: Vault;
  dataDir: string;
  gatewaySecret: string;
  commitmentSalt: string;
  publicUrl: string;
  sharedLocal?: LocalModel;
  /** The platform's own frontier upstream, for gateways that chose "hosted". */
  sharedFrontier?: FrontierModel;
  presidioUrl?: string;
  redactLlm: boolean;
  attackTest: boolean;
  approvalTimeoutMs: number;
  approvalScopeMs: number;
}

/**
 * What outlives a settings change: the approval queue (pending requests keep waiting) and the audit chain (one
 * instance per file). The ENS writer is looked up when anchoring, since the resolver appears after provisioning.
 */
export interface Durable {
  approvals: ApprovalStore;
  audit: JsonlAuditLog;
  writer?: EnsWriter;
}

export function durableFor(p: PlatformContext, gw: Gateway): Durable {
  const names = gatewayNames(gw.slug, p.root);
  const d: Durable = {
    approvals: new ApprovalStore(p.approvalTimeoutMs),
    audit: undefined as unknown as JsonlAuditLog,
  };
  d.audit = new JsonlAuditLog(resolve(p.dataDir, "gateways", gw.id, "audit.jsonl"), p.gatewaySecret, async (root) => {
    if (!d.writer) throw new Error("ENS is still being set up for this gateway");
    return d.writer.setText(names.audit, "airlock.auditRoot", root);
  });
  return d;
}

export function buildUserTenant(p: PlatformContext, gw: Gateway, durable: Durable): Tenant {
  const names = gatewayNames(gw.slug, p.root);
  // A key that no longer opens (the vault key changed) reads as "not set": the gateway keeps working, and its
  // status says the upstream needs a key again, instead of every request failing.
  const open = (s: Parameters<Vault["open"]>[0], what: string) => {
    try {
      return p.vault.open(s);
    } catch {
      console.warn(`[${gw.slug}] stored ${what} key can't be decrypted (was VAULT_KEY/GATEWAY_SECRET changed?); treating it as unset`);
      return undefined;
    }
  };
  const local =
    gw.local.mode === "custom" && gw.local.baseUrl && gw.local.model
      ? new LocalModel(gw.local.baseUrl, gw.local.model, true, open(gw.local.apiKey, "local model"))
      : p.sharedLocal ?? new LocalModel("http://127.0.0.1:9/v1", "none"); // no local model: requests fail loudly, nothing leaves
  const key = gw.frontier.provider === "hosted" ? undefined : open(gw.frontier.apiKey, "frontier");
  const egress: FrontierModel =
    gw.frontier.provider === "hosted" && p.sharedFrontier
      ? p.sharedFrontier
      : gw.frontier.provider === "openai" ? new OpenAICompatModel(key, gw.frontier.baseUrl ?? "https://api.openai.com/v1") : new ClaudeModel(key, gw.frontier.baseUrl ?? "https://api.anthropic.com");

  const ask = (system: string, user: string) => local.ask(system, user);
  const recognizers: Recognizer[] = [ruleRecognizer];
  if (p.presidioUrl) recognizers.push(presidioRecognizer(p.presidioUrl, "en"));
  if (p.redactLlm) recognizers.push(llmRecognizer(ask));
  const redactor = new PipelineRedactor(recognizers, (r, e) => console.warn(`[${gw.slug}] redactor ${r} failed: ${(e as Error).message}`));

  const st = gw.ens.state;
  const writer = st.resolver ? new EnsWriter(p.rpcUrl, p.platformKey, st.resolver, p.client, st.approverRegistry) : undefined;
  durable.writer = writer;
  const roles = new EnsRoleRegistry(p.client, writer);
  const { approvals, audit } = durable;
  const pipeline = new Pipeline({
    local,
    egress,
    redactor,
    risk: p.attackTest ? new LocalAttackScorer(ask, new RuleRiskScorer(), (e) => console.warn(`[${gw.slug}] attack test failed: ${(e as Error).message}`)) : new RuleRiskScorer(),
    policies: p.policies,
    roles,
    approvals,
    audit,
    defaultAgent: names.policy,
    defaultClaudeModel: gw.frontier.defaultModel,
    approvalTimeoutMs: p.approvalTimeoutMs,
    approvalScopeMs: p.approvalScopeMs,
  });
  const ens = st.resolver
    ? new EnsInspector(p.client, {
        resolver: st.resolver,
        agent: names.policy,
        auditName: names.audit,
        approverRegistry: st.approverRegistry,
        // Getters: read when the Policy page asks, so new agents show without rebuilding the tenant.
        get agents() { return [names.policy, ...(gw.agents ?? []).map((a) => names.agent(a.label))]; },
        get policies() { return (gw.policies ?? []).map((p) => names.namedPolicy(p.label)); },
        accounts: [
          { label: "owner", address: gw.owner as Hex },
          { label: "gateway", address: p.platformAddress as Hex },
        ],
      })
    : undefined;
  const salt = `${p.commitmentSalt}|${gw.id}`;
  // Globs (gpt-*) stay in the ENS allowlist; clients are offered the concrete names.
  const models = gw.frontier.models.filter((m) => !m.includes("*"));
  const config = {
    kind: gw.kind,
    slug: gw.slug,
    name: gw.name,
    org: names.base,
    defaultAgent: names.policy,
    approverRole: names.approverRole,
    auditName: names.audit,
    worldIdMode: p.verifier.mode,
    worldIdAgents: !!p.oidc,
    binding: p.binding,
    ensMode: "sepolia (read/write)",
    defaultClaudeModel: gw.frontier.defaultModel,
    claudeModels: models,
    egress: egress.configured ? egress.name : null,
    localModel: local.model,
    publicUrl: p.publicUrl,
    multibaas: false,
    mockApprovers: [],
  };
  const app = buildApp({
    pipeline,
    approvals,
    audit,
    roles,
    verifier: p.verifier,
    // One World callback URL serves every gateway: remember which one started the ceremony.
    oidc: p.oidc && { start: (k, ref, name, binding) => p.oidc!.start(k, ref, name, binding, gw.slug), cancel: (s) => p.oidc!.cancel(s), finish: (s, c) => p.oidc!.finish(s, c) },
    ens,
    binding: p.binding,
    localModel: local.model,
    claudeModels: models,
    approveAction: p.approveAction,
    consolePath: `/console/${gw.slug}`,
    commitment: (n) => commitmentOf(n, salt),
    ensLink: () => `https://app.ens.dev/${names.audit}`,
    publicConfig: config,
    status: async () => {
      const t = <T,>(pr: Promise<T>, ms = 8000) => Promise.race([pr, new Promise<never>((_, no) => setTimeout(() => no(new Error("timeout")), ms))]);
      const check = async (fn: () => Promise<string>, ms?: number) => { try { return { ok: true, detail: await t(fn(), ms) }; } catch (e) { return { ok: false, detail: (e as Error).message.slice(0, 120) }; } };
      const [l, f, e] = await Promise.all([
        check(async () => `${await local.ping()}${gw.local.mode === "shared" ? " (Airlock-hosted)" : ""}`),
        check(async () => `${await egress.ping()} → ${gw.frontier.defaultModel}`),
        check(async () => {
          if (gw.ens.status !== "live") throw new Error(`ENS ${gw.ens.status}${gw.ens.step ? `: ${gw.ens.step}` : ""}${gw.ens.error ? ` (${gw.ens.error})` : ""}`);
          const pol = await p.policies.resolve(names.policy);
          if (pol.unavailable) throw new Error(pol.unavailable);
          return `${names.policy}: egress=${pol.egress}`;
        }, 12000),
      ]);
      return {
        "Local model": l,
        "Frontier upstream": f,
        "World ID": { ok: p.verifier.mode !== "mock", detail: p.verifier.mode === "mock" ? "mock (dev only)" : `IDKit${p.oidc ? " + World ID for Agents" : ""}` },
        ENS: e,
      };
    },
    // The directory is the member list: everyone who may approve, with their live ENS status.
    approverDirectory: async () => {
      const last = new Map<string, number>();
      for (const r of audit.list()) for (const a of r.approvers ?? []) last.set(a, Math.max(last.get(a) ?? 0, r.timestamp));
      return Promise.all(
        gw.members
          .filter((m) => canApprove(m.role))
          .map(async (m) => {
            const name = names.approver(m.label);
            const status = gw.ens.status === "live" ? await roles.isLiveApprover(names.approverRole, name).then((s) => (s === "revoked" ? "not enrolled" : s)) : "unknown";
            return { name, status, lastSeen: last.get(name) };
          }),
      );
    },
  });
  return { gw, app, approvals, audit, roles, local, egress, config };
}

/** Builds tenants on first use and rebuilds one when its settings change. */
export class Tenants {
  private cache = new Map<string, { version: string; t: Tenant }>();
  private durable = new Map<string, Durable>();
  constructor(
    private p: PlatformContext | undefined,
    private demo?: Tenant,
  ) {}

  get(gw: Gateway): Tenant {
    if (gw.kind === "demo" && this.demo) return this.demo;
    if (!this.p) throw new Error("self-serve gateways are not configured on this server");
    // Settings that change the pipeline (models, keys, ENS contracts, ENS readiness) make a new tenant.
    const version = JSON.stringify([gw.local, gw.frontier, gw.ens.state.resolver, gw.ens.state.approverRegistry, gw.ens.status]);
    const hit = this.cache.get(gw.id);
    if (hit && hit.version === version) return hit.t;
    const durable = this.durable.get(gw.id) ?? this.durable.set(gw.id, durableFor(this.p!, gw)).get(gw.id)!;
    const t = buildUserTenant(this.p!, gw, durable);
    this.cache.set(gw.id, { version, t });
    return t;
  }

  /** Every running tenant (for finding which one holds an approval). */
  running(): Tenant[] {
    return [...(this.demo ? [this.demo] : []), ...[...this.cache.values()].map((x) => x.t)];
  }

  drop(id: string) {
    this.cache.delete(id);
    this.durable.delete(id);
  }
}
