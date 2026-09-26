import { copyFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { serve } from "@hono/node-server";
import type { Hex } from "viem";
import type { PolicyResolver, RoleRegistry } from "@airlock/core";
import { dictionaryRecognizer, llmRecognizer, LocalAttackScorer, PipelineRedactor, presidioRecognizer, ruleRecognizer, RuleRiskScorer, type Recognizer } from "@airlock/redactor";
import { ApprovalStore, MockVerifier, WorldIdVerifier, WorldOidc, type ProofVerifier } from "@airlock/approval";
import { describe, ensClient, EnsInspector, EnsPolicyResolver, EnsRoleRegistry, EnsWriter, GATEWAY_KEYS, MultiBaas, parseWebhook, POLICY_KEYS, StaticPolicyResolver, StaticRoleRegistry, toChainEvent, verifyWebhook, type ChainEvent, type NameBook } from "@airlock/registry";
import { namehash, parseAbi, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { JsonlAuditLog } from "@airlock/audit";
import { ClaudeModel, LocalModel, OpenAICompatModel, type FrontierModel } from "./llm";
import { Pipeline } from "./pipeline";
import { buildApp } from "./app";

const env = process.env;
const requireEnv = (k: string) => env[k] ?? (console.error(`${k} is required`), process.exit(1));
const root = resolve(import.meta.dirname, "../..");
const path = (p: string) => resolve(root, p);

const local = new LocalModel(env.LOCAL_BASE_URL ?? "http://localhost:8000/v1", env.LOCAL_MODEL ?? "Qwen/Qwen3.5-35B-A3B-FP8", env.LOCAL_THINKING !== "1");
// Egress: Anthropic directly, or a self-configured OpenAI-compatible upstream
// (e.g. your own LiteLLM / vLLM). No third-party gateway is used by default.
const egress: FrontierModel =
  env.EGRESS_PROVIDER === "openai"
    ? new OpenAICompatModel(env.EGRESS_API_KEY, requireEnv("EGRESS_BASE_URL"))
    : new ClaudeModel(env.EGRESS_API_KEY ?? env.ANTHROPIC_API_KEY, env.EGRESS_BASE_URL ?? "https://api.anthropic.com");
// Default frontier model for airlock/* and auto escalation (EGRESS_MODEL; CLAUDE_MODEL kept for compatibility).
const defaultClaudeModel = env.EGRESS_MODEL ?? env.CLAUDE_MODEL ?? "claude-sonnet-5";

// Redactor: rules → company dictionary → Presidio (optional sidecar)
const recognizers: Recognizer[] = [ruleRecognizer, dictionaryRecognizer(JSON.parse(readFileSync(path(env.DICTIONARY_FILE ?? "demo/dictionary.json"), "utf8")))];
if (env.PRESIDIO_URL) recognizers.push(presidioRecognizer(env.PRESIDIO_URL, env.PRESIDIO_LANGUAGE ?? "en"));
// Step 3: the local model tags indirect identifiers (opt-in: adds a local-model call per new message)
const ask = (system: string, user: string) => local.ask(system, user);
if (env.REDACT_LLM === "1") recognizers.push(llmRecognizer(ask));
const redactor = new PipelineRedactor(recognizers, (r, e) => console.warn(`[redactor] ${r} failed: ${(e as Error).message}`));

// Policy + roles: ENS (Sepolia) when SEPOLIA_RPC_URL is set, else local JSON
let policies: PolicyResolver, roles: RoleRegistry, writer: EnsWriter | undefined, ensMode: string, ens: EnsInspector | undefined, ensRead: PublicClient | undefined;
const defaultAgentName = env.DEFAULT_AGENT ?? "contract-agent.agents.acme.eth";
if (env.SEPOLIA_RPC_URL) {
  const client = ensClient(env.SEPOLIA_RPC_URL, env.ENS_UNIVERSAL_RESOLVER as Hex | undefined);
  ensRead = client;
  if (env.ENS_PRIVATE_KEY && env.ENS_RESOLVER) writer = new EnsWriter(env.SEPOLIA_RPC_URL, env.ENS_PRIVATE_KEY as Hex, env.ENS_RESOLVER as Hex, client, env.ENS_APPROVER_REGISTRY as Hex | undefined);
  policies = new EnsPolicyResolver(client);
  roles = new EnsRoleRegistry(client, writer);
  ensMode = writer ? "sepolia (read/write)" : "sepolia (read-only)";
  const accounts = [
    ...(env.ENS_PRIVATE_KEY ? [{ label: "gateway", address: privateKeyToAccount(env.ENS_PRIVATE_KEY as Hex).address }] : []),
    ...(env.ENS_SECURITY_ADDRESS ? [{ label: "security", address: env.ENS_SECURITY_ADDRESS as Hex }] : []),
  ];
  ens = new EnsInspector(client, {
    resolver: env.ENS_RESOLVER as Hex | undefined,
    agent: env.DEFAULT_AGENT ?? "contract-agent.agents.acme.eth",
    auditName: env.ENS_AUDIT_NAME ?? "audit.acme.eth",
    accounts,
    approverRegistry: env.ENS_APPROVER_REGISTRY as Hex | undefined,
    agents: (env.ENS_AGENTS ?? `${defaultAgentName},${defaultAgentName.replace(/^[^.]+/, "nda-agent")},${defaultAgentName.replace(/^[^.]+/, "intern-bot")}`).split(","),
    sharedPolicy: env.ENS_SHARED_POLICY ?? `legal.policies.${defaultAgentName.split(".").slice(-2).join(".")}`,
  });
} else {
  policies = new StaticPolicyResolver(path(env.POLICY_FILE ?? "demo/policies.json"));
  const approversFile = path(env.APPROVERS_FILE ?? "data/approvers.json");
  if (!existsSync(approversFile)) {
    mkdirSync(resolve(approversFile, ".."), { recursive: true });
    copyFileSync(path("demo/approvers.json"), approversFile); // seed: alice (mock nullifier 0x0a11ce)
  }
  roles = new StaticRoleRegistry(approversFile);
  ensMode = "static json";
}

// World ID: real (v4 verify API + RP-signed requests) when configured, else mock
const verifier: ProofVerifier =
  env.WORLD_APP_ID && env.WORLD_RP_ID && env.WORLD_RP_SIGNING_KEY
    ? new WorldIdVerifier({
        appId: env.WORLD_APP_ID as `app_${string}`,
        rpId: env.WORLD_RP_ID,
        signingKeyHex: env.WORLD_RP_SIGNING_KEY,
        environment: env.WORLD_ENV === "production" ? "production" : "staging",
        proof: env.WORLD_PROOF === "legacy" ? "legacy" : "v4",
        stagingToken: env.WORLD_STAGING_TOKEN,
        consumedFile: path("data/worldid-consumed.txt"),
      })
    : new MockVerifier();

// World ID for Agents: Human Continuity OIDC (sandbox.auth.world.org for the event)
const port = Number(env.PORT ?? 8787);
const oidc =
  env.WORLD_OIDC_CLIENT_ID && env.WORLD_OIDC_CLIENT_SECRET
    ? new WorldOidc({
        issuer: env.WORLD_OIDC_ISSUER ?? "https://sandbox.auth.world.org",
        clientId: env.WORLD_OIDC_CLIENT_ID,
        clientSecret: env.WORLD_OIDC_CLIENT_SECRET,
        redirectUri: env.WORLD_OIDC_REDIRECT_URI ?? `http://localhost:${port}/oidc/callback`,
      })
    : undefined;

const bindingMode: "commitment" | "name" =
  ((env.WORLD_BINDING ?? env.WORLD_OIDC_BINDING) as "commitment" | "name" | undefined) ??
  (verifier.mode === "worldid" && env.WORLD_ENV !== "production" ? "name" : oidc && /sandbox/.test(env.WORLD_OIDC_ISSUER ?? "https://sandbox.auth.world.org") ? "name" : "commitment");

const auditName = env.ENS_AUDIT_NAME ?? "audit.acme.eth";

// ---------- MultiBaas (Curvegrid): ENS events pushed to us, and an indexed change history ----------
const mb = env.MULTIBAAS_URL && env.MULTIBAAS_API_KEY ? new MultiBaas(env.MULTIBAAS_URL, env.MULTIBAAS_API_KEY) : undefined;
const orgRoot = defaultAgentName.split(".").slice(-2).join(".");
let book: NameBook | undefined;
/** Names Airlock knows, so event ids and hashes can be shown as names. */
async function nameBook(): Promise<NameBook> {
  if (book) return book;
  const deploy: Record<string, string> = (() => { try { return JSON.parse(readFileSync(path("data/ens-deploy.json"), "utf8")); } catch { return {}; } })();
  const people = ["alice", "bob", "carol", "dave"];
  // Shared records first: a record several names link to is named after the shared policy, not whichever agent came first.
  const names = [`legal.policies.${orgRoot}`, defaultAgentName, defaultAgentName.replace(/^[^.]+/, "nda-agent"), auditName, ...people.map((p) => `${p}.legal.approvers.${orgRoot}`)];
  const records: Record<string, string> = {};
  if (ensRead && env.ENS_RESOLVER) {
    const abi = parseAbi(["function getRecordId(bytes32 node) view returns (uint256)"]);
    for (const n of names) {
      const id = await ensRead.readContract({ address: env.ENS_RESOLVER as Hex, abi, functionName: "getRecordId", args: [namehash(n)] }).catch(() => 0n);
      if (id && !records[String(id)]) records[String(id)] = n;
    }
  }
  const reg = (k: string) => (deploy[k] ?? "").toLowerCase();
  const accounts: Record<string, string> = {};
  if (env.ENS_PRIVATE_KEY) accounts[privateKeyToAccount(env.ENS_PRIVATE_KEY as Hex).address.toLowerCase()] = "gateway";
  if (env.ENS_SECURITY_ADDRESS) accounts[env.ENS_SECURITY_ADDRESS.toLowerCase()] = "security";
  book = {
    records,
    registries: { [reg("registry:legal")]: `legal.approvers.${orgRoot}`, [reg("registry:agents")]: `agents.${orgRoot}`, [reg("registry:policies")]: `policies.${orgRoot}`, [reg("registry:approvers")]: `approvers.${orgRoot}`, [reg("registry:root")]: orgRoot },
    labels: [...people, "agents", "approvers", "legal", "audit", "policies", "contract-agent", "nda-agent"],
    keys: [...POLICY_KEYS, ...GATEWAY_KEYS],
    accounts,
  };
  return book;
}
const chain = mb
  ? {
      verify: (raw: string, sig?: string, ts?: string) => !!env.MULTIBAAS_WEBHOOK_SECRET && verifyWebhook(env.MULTIBAAS_WEBHOOK_SECRET, raw, sig, ts),
      async onEvents(body: unknown) {
        const evts = parseWebhook(body);
        const b = await nameBook();
        for (const e of evts) {
          if (e.name === "LabelRegistered" || e.name === "Linked") book = undefined; // new names/records: rebuild next time
          const d = describe(e, b);
          if (d.invalidates && policies instanceof EnsPolicyResolver) policies.invalidate();
          if (d.noise) continue;
          approvals.emitEvent({ type: "chain.event", kind: d.kind, text: d.text, tx: e.tx, at: e.at });
          console.log(`[multibaas] ${d.text}${e.tx ? `  tx ${e.tx}` : ""}`);
        }
        return evts.length;
      },
      async recent() {
        const b = await nameBook();
        const lists = await Promise.all(["airlockresolver", "airlockregistry"].map((label) => mb.events({ contract_label: label, limit: 50 }).catch(() => [])));
        return lists
          .flat()
          .map((raw) => toChainEvent(raw))
          .filter((e): e is ChainEvent => !!e)
          .map((e) => ({ ...describe(e, b), tx: e.tx, block: e.block, at: e.at }))
          .filter((x) => !x.noise)
          .sort((x, y) => (y.block ?? 0) - (x.block ?? 0));
      },
    }
  : undefined;
const audit = new JsonlAuditLog(path(env.AUDIT_FILE ?? "data/audit.jsonl"), env.GATEWAY_SECRET ?? "dev-secret-change-me", writer && ((root) => writer!.setText(auditName, "airlock.auditRoot", root)));
const approvalTimeoutMs = Number(env.APPROVAL_TIMEOUT_MS ?? 300_000);
const approvals = new ApprovalStore(approvalTimeoutMs);

const pipeline = new Pipeline({
  local,
  egress,
  redactor,
  // Local attack test (on by default): the local model tries to re-identify placeholders before anything leaves.
  risk: env.ATTACK_TEST === "0" ? new RuleRiskScorer() : new LocalAttackScorer(ask, new RuleRiskScorer(), (e) => console.warn(`[risk] attack test failed: ${(e as Error).message}`)),
  policies,
  roles,
  approvals,
  audit,
  defaultAgent: env.DEFAULT_AGENT ?? "contract-agent.agents.acme.eth",
  defaultClaudeModel,
  approvalTimeoutMs,
  approvalScopeMs: Number(env.APPROVAL_SCOPE_MS ?? 600_000),
});

const app = buildApp({
  pipeline,
  approvals,
  audit,
  roles,
  verifier,
  oidc,
  ens,
  chain,
  status: async () => {
    const t = <T,>(p: Promise<T>, ms = 4000) => Promise.race([p, new Promise<never>((_, no) => setTimeout(() => no(new Error("timeout")), ms))]);
    const check = async (fn: () => Promise<string>, ms?: number) => { try { return { ok: true, detail: await t(fn(), ms) }; } catch (e) { return { ok: false, detail: (e as Error).message.slice(0, 120) }; } };
    const [localModel, frontier, ensCheck, mbCheck] = await Promise.all([
      check(async () => { const r = await fetch(`${env.LOCAL_BASE_URL ?? "http://localhost:8000/v1"}/models`); if (!r.ok) throw new Error(`HTTP ${r.status}`); return local.model; }),
      check(async () => { if (!egress.configured) throw new Error("no API key"); return `${egress.name} → ${defaultClaudeModel}`; }),
      check(async () => { if (!ensRead) return "local JSON policies"; const p = await policies.resolve(defaultAgentName); return `${p.agent}: egress=${p.egress}`; }, 12000), // public RPC: slow when cold
      check(async () => { if (!mb) throw new Error("not configured"); await mb.webhooks(); return env.MULTIBAAS_URL!.replace(/^https?:\/\//, ""); }),
    ]);
    return {
      "Local model": localModel,
      "Frontier upstream": frontier,
      "World ID": { ok: verifier.mode !== "mock", detail: verifier.mode === "mock" ? "mock (dev only)" : `IDKit ${env.WORLD_ENV ?? "staging"}${oidc ? " + World ID for Agents" : ""}` },
      ENS: ensCheck,
      MultiBaas: mbCheck,
    };
  },
  approverDirectory: async () => {
    const seen = new Map<string, number>();
    const add = (n?: string, t = 0) => { for (const x of (n ?? "").split(/,\s*/)) if (x && x.includes(".")) seen.set(x, Math.max(seen.get(x) ?? 0, t)); };
    for (const r of audit.list()) for (const a of r.approvers ?? []) add(a, r.timestamp);
    for (const r of approvals.list()) for (const a of r.approvals ?? []) add(a.approverName, a.at);
    if (mb) {
      const b = await nameBook();
      const regs = await mb.events({ contract_label: "airlockregistry", limit: 50 }).catch(() => []);
      for (const raw of regs) { const e = toChainEvent(raw); if (e?.name === "LabelRegistered" && b.registries[e.contract]?.startsWith("legal.approvers")) add(`${e.args.label}.${b.registries[e.contract]}`); }
    }
    if (roles instanceof StaticRoleRegistry) for (const a of JSON.parse(readFileSync(path(env.APPROVERS_FILE ?? "data/approvers.json"), "utf8"))) add(a.name);
    const role = `legal.approvers.${orgRoot}`;
    return Promise.all([...seen].map(async ([name, lastSeen]) => ({ name, lastSeen: lastSeen || undefined, status: roles.isLiveApprover ? await roles.isLiveApprover(name.endsWith(role) ? role : name.split(".").slice(1).join("."), name) : "unknown" })));
  },
  // Test environments (World staging / the event sandbox) use test identities, so approvers are bound to their live
  // ENS name; production binds the World identity to the commitment enrolled on ENS. Override: WORLD_BINDING.
  binding: bindingMode,
  localModel: local.model,
  claudeModels: (env.EGRESS_MODELS ?? env.CLAUDE_MODELS ?? `${defaultClaudeModel},claude-opus-5-5`).split(","),
  consoleHtml: readFileSync(path("console/index.html"), "utf8"),
  approveAction: env.WORLD_ACTION ?? "airlock-approve",
  accessToken: env.AIRLOCK_ACCESS_TOKEN || undefined,
  ensLink: env.SEPOLIA_RPC_URL ? () => `https://app.ens.dev/${auditName}` : undefined,
  publicConfig: {
    worldIdMode: verifier.mode,
    publicUrl: env.PUBLIC_URL ?? `http://localhost:${port}`,
    org: orgRoot,
    defaultAgent: env.DEFAULT_AGENT ?? "contract-agent.agents.acme.eth",
    worldIdAgents: !!oidc,
    multibaas: !!mb,
    binding: bindingMode,
    ensMode,
    defaultClaudeModel,
    egress: egress.configured ? egress.name : null,
    // Mock people for local dev only; their commitments are pre-enrolled in data/approvers.json.
    mockApprovers: verifier.mode === "mock" ? [{ name: "alice.legal.approvers.acme.eth", nullifier: "0x0a11ce" }, { name: "mallory.legal.approvers.acme.eth", nullifier: "0x0bad" }] : [],
    demoPrompt: `Review this contract and list the three riskiest clauses for us as Provider:\n\n${readFileSync(path("demo/contract.md"), "utf8")}`,
  },
});

if (env.AUDIT_ANCHOR_INTERVAL_MS && writer)
  setInterval(() => audit.anchor().then((a) => console.log(`[audit] anchored ${a.root} tx=${a.tx}`)).catch((e) => console.warn(`[audit] anchor failed: ${e.message}`)), Number(env.AUDIT_ANCHOR_INTERVAL_MS));

serve({ fetch: app.fetch, port, hostname: env.HOST ?? "0.0.0.0" }, () => {
  console.log(`airlock gateway on :${port}  local=${local.model}  egress=${egress.configured ? `${egress.name} → ${defaultClaudeModel}` : "NOT CONFIGURED"}  worldid=${verifier.mode}  ens=${ensMode}`);
  console.log(`console → http://localhost:${port}/console`);
});
