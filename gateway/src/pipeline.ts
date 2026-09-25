import { randomUUID } from "node:crypto";
import { decide, hashOf, type ChatMessage, type Decision, type PolicyResolver, type RiskScorer, type Route, type Session } from "@airlock/core";
import { newSession, rehydrateMessage, type PipelineRedactor } from "@airlock/redactor";
import type { ApprovalStore } from "@airlock/approval";
import type { JsonlAuditLog } from "@airlock/audit";
import type { Completion, FrontierModel, LocalModel } from "./llm";

export interface Deps {
  local: LocalModel;
  egress: FrontierModel;
  redactor: PipelineRedactor;
  risk: RiskScorer;
  policies: PolicyResolver;
  approvals: ApprovalStore;
  audit: JsonlAuditLog;
  defaultAgent: string;
  defaultClaudeModel: string;
  approvalTimeoutMs: number;
}

export interface AirlockMeta {
  requestId: string;
  sessionId: string;
  route: Route["kind"] | "local" | "escalated";
  decision: string;
  reason?: string;
  sourceClass?: string;
  entities?: Record<string, number>;
  risk?: { level: string; findings: string[] };
  approvalId?: string;
  egressed: boolean;
}

export interface Result {
  completion: Completion;
  airlock: AirlockMeta;
}

const sessions = new Map<string, Session>();
const sessionFor = (id: string) => sessions.get(id) ?? sessions.set(id, newSession(id)).get(id)!;

const UNSURE = /\b(?:I (?:don't|do not) know|I'm not sure|I am not sure|cannot answer|can't answer|unable to answer)\b|無法回答|不確定|不知道/i;

export class Pipeline {
  constructor(private d: Deps) {}

  /** Router: dispatch on the `model` field. */
  async handle(model: string, messages: ChatMessage[], opts: { sessionId?: string; agent?: string; extra?: Record<string, unknown> }): Promise<Result> {
    const sessionId = opts.sessionId ?? randomUUID();
    if (model === "auto") {
      const localAnswer = await this.d.local.complete(messages, opts.extra);
      const text = localAnswer.message.content ?? "";
      if (text.trim() && !UNSURE.test(text) && localAnswer.finishReason !== "length")
        return { completion: localAnswer, airlock: { requestId: randomUUID(), sessionId, route: "local", decision: "local", egressed: false } };
      const r = await this.airlock(this.d.defaultClaudeModel, messages, sessionId, opts.agent);
      r.airlock.route = r.airlock.egressed ? "escalated" : r.airlock.route;
      return r;
    }
    if (model.startsWith("airlock/")) return this.airlock(model.slice("airlock/".length), messages, sessionId, opts.agent);
    // local/* (and anything unknown) stays on the box
    const completion = await this.d.local.complete(messages, opts.extra);
    return { completion, airlock: { requestId: randomUUID(), sessionId, route: "local", decision: "local", egressed: false } };
  }

  private async airlock(targetModel: string, messages: ChatMessage[], sessionId: string, agentId?: string): Promise<Result> {
    const { d } = this;
    const requestId = randomUUID();
    const session = sessionFor(sessionId);
    const sourceHash = hashOf(messages);

    const red = await d.redactor.redact(messages, session);
    const risk = await d.risk.score(red.payload);
    const policy = await d.policies.resolve(agentId ?? d.defaultAgent);
    const route = decide(red.sourceClass, risk, policy, targetModel);
    const payloadHash = hashOf({ model: targetModel, messages: red.payload });
    const meta: AirlockMeta = {
      requestId,
      sessionId,
      route: route.kind,
      decision: "",
      sourceClass: red.sourceClass,
      entities: red.entities,
      risk,
      egressed: false,
    };
    d.approvals.emitEvent({ type: "request.routed", requestId, route: route.kind, reason: route.kind === "block" ? route.reason : undefined });

    const fallback = async (decision: "denied" | "expired" | "blocked", reason: string, extra: Partial<Decision> = {}, viewHash?: string) => {
      d.audit.append({
        requestId,
        decision,
        reason,
        sourceHash,
        payloadHash,
        viewHash,
        approverCommitment: extra.approverCommitment,
        roleCheck: extra.roleCheck,
        worldIdVerified: extra.worldIdVerified ?? false,
        targetModel,
        agent: policy.agent,
      });
      const local = await d.local.complete(messages);
      local.message.content = `> ⚠️ Airlock: not sent to ${targetModel} — ${reason}. Answered by local model.\n\n${local.message.content ?? ""}`;
      return { completion: local, airlock: { ...meta, decision, reason } };
    };

    if (route.kind === "block") return fallback("blocked", route.reason);

    let decision: Decision | undefined;
    let viewHash: string | undefined;
    if (route.kind === "approval" || route.kind === "owner") {
      const redactedPreview = red.payload.map((m) => `[${m.role}] ${m.content ?? ""}`).join("\n\n");
      viewHash = hashOf({ redactedPreview, entities: red.entities, risk, targetModel, agent: policy.agent });
      const req = {
        id: randomUUID(),
        sessionId,
        agent: policy.agent,
        requiredRole: route.role,
        payloadHash,
        viewHash,
        redactedPreview,
        originalPreview: messages.map((m) => `[${m.role}] ${m.content ?? ""}`).join("\n\n"),
        entities: red.entities,
        riskLevel: risk.level,
        findings: risk.findings,
        targetModel,
        createdAt: Date.now(),
        expiresAt: Date.now() + d.approvalTimeoutMs,
        status: "pending" as const,
      };
      meta.approvalId = req.id;
      decision = await d.approvals.request(req);
      if (decision.status !== "approved") {
        const status = decision.status === "expired" ? "expired" : "denied";
        return fallback(status, decision.reason ?? decision.status, decision, viewHash);
      }
      // Approval is bound to this exact payload and must still be in its validity window.
      if (hashOf({ model: targetModel, messages: red.payload }) !== req.payloadHash) return fallback("denied", "payload hash mismatch", decision, viewHash);
      if (Date.now() > req.expiresAt) return fallback("expired", "approval expired before egress", decision, viewHash);
    }

    // Egress
    let completion: Completion;
    try {
      completion = await d.egress.complete(targetModel, red.payload);
    } catch (e) {
      return fallback("blocked", `egress failed: ${(e as Error).message.slice(0, 200)}`, decision ?? {}, viewHash);
    }
    // Rehydrator
    completion.message = rehydrateMessage(completion.message, session);

    d.audit.append({
      requestId,
      decision: route.kind === "auto" ? "auto" : "approved",
      sourceHash,
      payloadHash,
      viewHash,
      approverCommitment: decision?.approverCommitment,
      roleCheck: decision?.roleCheck,
      worldIdVerified: decision?.worldIdVerified ?? false,
      targetModel,
      agent: policy.agent,
      usage: completion.usage && { promptTokens: completion.usage.prompt_tokens, completionTokens: completion.usage.completion_tokens },
    });
    return { completion, airlock: { ...meta, decision: route.kind === "auto" ? "auto" : "approved", egressed: true } };
  }
}
