import { copyFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { serve } from "@hono/node-server";
import type { Hex } from "viem";
import type { PolicyResolver, RoleRegistry } from "@airlock/core";
import { dictionaryRecognizer, llmRecognizer, LocalAttackScorer, PipelineRedactor, presidioRecognizer, ruleRecognizer, RuleRiskScorer, type Recognizer } from "@airlock/redactor";
import { ApprovalStore, MockVerifier, WorldIdVerifier, type ProofVerifier } from "@airlock/approval";
import { ensClient, EnsPolicyResolver, EnsRoleRegistry, EnsWriter, StaticPolicyResolver, StaticRoleRegistry } from "@airlock/registry";
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
const defaultClaudeModel = env.CLAUDE_MODEL ?? "claude-sonnet-5";

// Redactor: rules → company dictionary → Presidio (optional sidecar)
const recognizers: Recognizer[] = [ruleRecognizer, dictionaryRecognizer(JSON.parse(readFileSync(path(env.DICTIONARY_FILE ?? "demo/dictionary.json"), "utf8")))];
if (env.PRESIDIO_URL) recognizers.push(presidioRecognizer(env.PRESIDIO_URL, env.PRESIDIO_LANGUAGE ?? "en"));
// Step 3: the local model tags indirect identifiers (opt-in: adds a local-model call per new message)
const ask = (system: string, user: string) => local.ask(system, user);
if (env.REDACT_LLM === "1") recognizers.push(llmRecognizer(ask));
const redactor = new PipelineRedactor(recognizers, (r, e) => console.warn(`[redactor] ${r} failed: ${(e as Error).message}`));

// Policy + roles: ENS (Sepolia) when SEPOLIA_RPC_URL is set, else local JSON
let policies: PolicyResolver, roles: RoleRegistry, writer: EnsWriter | undefined, ensMode: string;
if (env.SEPOLIA_RPC_URL) {
  const client = ensClient(env.SEPOLIA_RPC_URL, env.ENS_UNIVERSAL_RESOLVER as Hex | undefined);
  if (env.ENS_PRIVATE_KEY && env.ENS_RESOLVER) writer = new EnsWriter(env.SEPOLIA_RPC_URL, env.ENS_PRIVATE_KEY as Hex, env.ENS_RESOLVER as Hex, client, env.ENS_APPROVER_REGISTRY as Hex | undefined);
  policies = new EnsPolicyResolver(client);
  roles = new EnsRoleRegistry(client, writer);
  ensMode = writer ? "sepolia (read/write)" : "sepolia (read-only)";
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
      })
    : new MockVerifier();

const auditName = env.ENS_AUDIT_NAME ?? "audit.acme.eth";
const audit = new JsonlAuditLog(path(env.AUDIT_FILE ?? "data/audit.jsonl"), env.GATEWAY_SECRET ?? "dev-secret-change-me", writer && ((root) => writer!.setText(auditName, "airlock.auditRoot", root)));
const approvalTimeoutMs = Number(env.APPROVAL_TIMEOUT_MS ?? 180_000);
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
  localModel: local.model,
  claudeModels: (env.CLAUDE_MODELS ?? `${defaultClaudeModel},claude-opus-5-5`).split(","),
  consoleHtml: readFileSync(path("console/index.html"), "utf8"),
  approveAction: env.WORLD_ACTION ?? "airlock-approve",
  ensLink: env.SEPOLIA_RPC_URL ? () => `https://app.ens.dev/${auditName}` : undefined,
  publicConfig: {
    worldIdMode: verifier.mode,
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

const port = Number(env.PORT ?? 8787);
serve({ fetch: app.fetch, port, hostname: env.HOST ?? "0.0.0.0" }, () => {
  console.log(`airlock gateway on :${port}  local=${local.model}  egress=${egress.configured ? `${egress.name} → ${defaultClaudeModel}` : "NOT CONFIGURED"}  worldid=${verifier.mode}  ens=${ensMode}`);
  console.log(`console → http://localhost:${port}/console`);
});
