import { randomUUID } from "node:crypto";
import {
  decide,
  hashOf,
  type AuditRecord,
  type ChatMessage,
  type Decision,
  type PolicyResolver,
  type RiskLevel,
  type RoleRegistry,
  type RiskScorer,
  type Route,
  type Session,
} from "@airlock/core";
import { newSession, rehydrateMessage, StreamRehydrator, type PipelineRedactor } from "@airlock/redactor";
import type { ApprovalStore } from "@airlock/approval";
import type { JsonlAuditLog } from "@airlock/audit";
import type { Chunk, Completion, FrontierModel, LocalModel, Usage } from "./llm";

export interface Deps {
  local: LocalModel;
  egress: FrontierModel;
  redactor: PipelineRedactor;
  risk: RiskScorer;
  policies: PolicyResolver;
  roles: RoleRegistry;
  approvals: ApprovalStore;
  audit: JsonlAuditLog;
  defaultAgent: string;
  defaultClaudeModel: string;
  approvalTimeoutMs: number;
  /** How long an approval covers follow-up turns in the same session (0 = every turn needs a human). */
  approvalScopeMs: number;
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
  /** Approval this request reused instead of asking a human again. */
  scopeOf?: string;
  egressed: boolean;
}

export interface Result {
  completion: Completion;
  airlock: AirlockMeta;
}

export interface Streamed {
  model: string;
  airlock: AirlockMeta;
  chunks: AsyncGenerator<Chunk>;
}

type Draft = Omit<AuditRecord, "seq" | "prevHash" | "timestamp" | "hash" | "gatewaySig">;

/** What to do once all checks ran; executed either as one completion or as a stream. */
type Plan =
  | { kind: "local"; meta: AirlockMeta; model: string }
  | { kind: "answered"; meta: AirlockMeta; completion: Completion }
  | { kind: "fallback"; meta: AirlockMeta; notice: string }
  | { kind: "egress"; meta: AirlockMeta; session: Session; payload: ChatMessage[]; targetModel: string; audit: Draft };

/** An approval and what it covered, so later turns can ride on it (ARCHITECTURE §3, approval scope). */
interface Grant {
  approvalId: string;
  agent: string;
  targetModel: string;
  role: string;
  placeholders: Set<string>;
  risk: RiskLevel;
  decision: Decision;
  until: number;
}

const sessions = new Map<string, Session>();
const sessionFor = (id: string) => sessions.get(id) ?? sessions.set(id, newSession(id)).get(id)!;
const grants = new Map<string, Grant[]>();

const UNSURE = /\b(?:I (?:don't|do not) know|I'm not sure|I am not sure|cannot answer|can't answer|unable to answer)\b|無法回答|不確定|不知道/i;
const usageRec = (u?: Usage) => u && { promptTokens: u.prompt_tokens, completionTokens: u.completion_tokens };
const riskRank = (r: RiskLevel) => (r === "high" ? 1 : 0);

export class Pipeline {
  constructor(private d: Deps) {}

  private record(draft: Draft) {
    const r = this.d.audit.append(draft);
    this.d.approvals.emitEvent({ type: "audit.appended", seq: r.seq, decision: r.decision });
    return r;
  }

  /** Non-streaming entry point. */
  async handle(model: string, messages: ChatMessage[], opts: { sessionId?: string; agent?: string; extra?: Record<string, unknown> }): Promise<Result> {
    const plan = await this.plan(model, messages, opts);
    const { d } = this;
    switch (plan.kind) {
      case "answered":
        return { completion: plan.completion, airlock: plan.meta };
      case "local":
        return { completion: await d.local.complete(messages, opts.extra), airlock: plan.meta };
      case "fallback": {
        const local = await d.local.complete(messages);
        local.message.content = plan.notice + (local.message.content ?? "");
        return { completion: local, airlock: plan.meta };
      }
      case "egress":
        try {
          const completion = await d.egress.complete(plan.targetModel, plan.payload);
          completion.message = rehydrateMessage(completion.message, plan.session);
          this.record({ ...plan.audit, usage: usageRec(completion.usage) });
          return { completion, airlock: { ...plan.meta, egressed: true } };
        } catch (e) {
          const fb = this.egressFailed(plan, e);
          const local = await d.local.complete(messages);
          local.message.content = fb.notice + (local.message.content ?? "");
          return { completion: local, airlock: fb.meta };
        }
    }
  }

  /** Streaming entry point: all checks (and any approval) finish before the first byte is sent. */
  async stream(model: string, messages: ChatMessage[], opts: { sessionId?: string; agent?: string; extra?: Record<string, unknown>; signal?: AbortSignal }): Promise<Streamed> {
    const { signal } = opts;
    const plan = await this.plan(model, messages, opts);
    const { d } = this;
    const self = this;
    const localModel = `local/${d.local.model}`;
    switch (plan.kind) {
      case "answered":
        return {
          model: plan.completion.model,
          airlock: plan.meta,
          chunks: (async function* () {
            yield { text: plan.completion.message.content ?? "" };
            yield { finishReason: plan.completion.finishReason, usage: plan.completion.usage };
          })(),
        };
      case "local":
        return { model: localModel, airlock: plan.meta, chunks: d.local.stream(messages, opts.extra, signal) };
      case "fallback":
        return {
          model: localModel,
          airlock: plan.meta,
          chunks: (async function* () {
            yield { text: plan.notice };
            yield* d.local.stream(messages, {}, signal);
          })(),
        };
      case "egress":
        return {
          model: `airlock/${plan.targetModel}`,
          airlock: { ...plan.meta, egressed: true },
          chunks: (async function* () {
            const rh = new StreamRehydrator(plan.session);
            let usage: Usage | undefined, finishReason: string | undefined, started = false, recorded = false, completed = false;
            const record = (reason?: string) => {
              if (recorded) return;
              recorded = true;
              self.record({ ...plan.audit, ...(reason && { reason }), usage: usageRec(usage) });
            };
            try {
              try {
                for await (const c of d.egress.stream(plan.targetModel, plan.payload, signal)) {
                  if (c.text) {
                    started = true;
                    const t = rh.push(c.text);
                    if (t) yield { text: t };
                  }
                  usage = c.usage ?? usage;
                  finishReason = c.finishReason ?? finishReason;
                }
              } catch (e) {
                if (signal?.aborted) return; // client hung up; `finally` audits it
                if (!started) {
                  // Nothing reached the client yet: fall back to the local model, like the non-streaming path.
                  recorded = true;
                  const fb = self.egressFailed(plan, e);
                  yield { text: fb.notice };
                  yield* d.local.stream(messages, {}, signal);
                  return;
                }
                record(`stream interrupted: ${(e as Error).message.slice(0, 160)}`);
                yield { text: rh.flush() + "\n\n> ⚠️ Airlock: upstream stream interrupted." };
                yield { finishReason: "stop" };
                return;
              }
              const tail = rh.flush();
              if (tail) yield { text: tail };
              record();
              completed = true;
              yield { finishReason: finishReason ?? "stop", usage };
            } finally {
              // The payload already left: a client that hangs up mid-stream must not erase the audit trail.
              if (!completed) record("client disconnected mid-stream");
            }
          })(),
        };
    }
  }

  private egressFailed(plan: Extract<Plan, { kind: "egress" }>, e: unknown) {
    const reason = `egress failed: ${(e as Error).message.slice(0, 200)}`;
    this.record({ ...plan.audit, decision: "blocked", reason });
    return { meta: { ...plan.meta, decision: "blocked", reason, egressed: false }, notice: this.notice(plan.targetModel, reason) };
  }

  private notice(targetModel: string, reason: string) {
    return `> ⚠️ Airlock: not sent to ${targetModel} — ${reason}. Answered by local model.\n\n`;
  }

  /** Router: dispatch on the `model` field. */
  private async plan(model: string, messages: ChatMessage[], opts: { sessionId?: string; agent?: string; extra?: Record<string, unknown> }): Promise<Plan> {
    const sessionId = opts.sessionId ?? randomUUID();
    const localMeta = (): AirlockMeta => ({ requestId: randomUUID(), sessionId, route: "local", decision: "local", egressed: false });
    if (model === "auto") {
      const localAnswer = await this.d.local.complete(messages, opts.extra);
      const text = localAnswer.message.content ?? "";
      if (text.trim() && !UNSURE.test(text) && localAnswer.finishReason !== "length") return { kind: "answered", meta: localMeta(), completion: localAnswer };
      const p = await this.airlock(this.d.defaultClaudeModel, messages, sessionId, opts.agent);
      if (p.kind === "egress") p.meta.route = "escalated";
      return p;
    }
    if (model.startsWith("airlock/")) return this.airlock(model.slice("airlock/".length), messages, sessionId, opts.agent);
    // local/* (and anything unknown) stays on the box
    return { kind: "local", meta: localMeta(), model: `local/${this.d.local.model}` };
  }

  private async airlock(targetModel: string, messages: ChatMessage[], sessionId: string, agentId?: string): Promise<Plan> {
    const { d } = this;
    const requestId = randomUUID();
    const session = sessionFor(sessionId);
    const sourceHash = hashOf(messages);

    const red = await d.redactor.redact(messages, session);
    const risk = await d.risk.score(red.payload, red.mapping);
    const policy = await d.policies.resolve(agentId ?? d.defaultAgent);
    const route = decide(red.sourceClass, risk, policy, targetModel);
    const payloadHash = hashOf({ model: targetModel, messages: red.payload });
    const meta: AirlockMeta = { requestId, sessionId, route: route.kind, decision: "", sourceClass: red.sourceClass, entities: red.entities, risk, egressed: false };
    d.approvals.emitEvent({ type: "request.routed", requestId, route: route.kind, reason: route.kind === "block" ? route.reason : undefined });

    const base = { requestId, sourceHash, payloadHash, targetModel, agent: policy.agent };
    const fallback = (decision: "denied" | "expired" | "blocked", reason: string, extra: Partial<Decision> = {}, viewHash?: string): Plan => {
      this.record({
        ...base,
        decision,
        reason,
        viewHash,
        approverCommitment: extra.approverCommitment,
        roleCheck: extra.roleCheck,
        worldIdVerified: extra.worldIdVerified ?? false,
      });
      return { kind: "fallback", meta: { ...meta, decision, reason }, notice: this.notice(targetModel, reason) };
    };

    if (route.kind === "block") return fallback("blocked", route.reason);

    if (route.kind === "auto")
      return { kind: "egress", meta: { ...meta, decision: "auto" }, session, payload: red.payload, targetModel, audit: { ...base, decision: "auto", worldIdVerified: false } };

    // approval / owner — first see whether an earlier approval in this session already covers it
    const placeholders = Object.keys(red.mapping);
    const candidate = (grants.get(sessionId) ?? []).find(
      (g) =>
        g.until > Date.now() &&
        g.agent === policy.agent &&
        g.targetModel === targetModel &&
        g.role === route.role &&
        riskRank(risk.level) <= riskRank(g.risk) &&
        placeholders.every((p) => g.placeholders.has(p)),
    );
    // A grant is only as good as its approver: re-check the ENS role, so revocation also ends the scope.
    let grant: Grant | undefined;
    if (candidate) {
      const roleNow = await d.roles.isValidApprover(candidate.decision.approverCommitment ?? "", candidate.role, candidate.decision.approverName);
      if (roleNow === "valid") grant = candidate;
      else grants.set(sessionId, (grants.get(sessionId) ?? []).filter((g) => g !== candidate));
    }
    if (grant) {
      const reason = `within approved scope of ${grant.approvalId.slice(0, 8)} (no new entities, risk ≤ ${grant.risk})`;
      return {
        kind: "egress",
        meta: { ...meta, decision: "approved", reason, scopeOf: grant.approvalId },
        session,
        payload: red.payload,
        targetModel,
        audit: {
          ...base,
          decision: "approved",
          reason,
          scopeOf: grant.approvalId,
          approverCommitment: grant.decision.approverCommitment,
          roleCheck: grant.decision.roleCheck,
          worldIdVerified: grant.decision.worldIdVerified,
        },
      };
    }

    const redactedPreview = red.payload.map((m) => `[${m.role}] ${m.content ?? ""}`).join("\n\n");
    const viewHash = hashOf({ redactedPreview, entities: red.entities, risk, targetModel, agent: policy.agent });
    const req = {
      id: randomUUID(),
      sessionId,
      agent: policy.agent,
      requiredRole: route.role,
      payloadHash,
      viewHash,
      redactedPreview,
      originalPreview: messages.map((m) => `[${m.role}] ${m.content ?? ""}`).join("\n\n"),
      mapping: red.mapping,
      entities: red.entities,
      riskLevel: risk.level,
      findings: risk.findings,
      targetModel,
      createdAt: Date.now(),
      expiresAt: Date.now() + d.approvalTimeoutMs,
      status: "pending" as const,
    };
    meta.approvalId = req.id;
    const decision = await d.approvals.request(req);
    if (decision.status !== "approved") return fallback(decision.status === "expired" ? "expired" : "denied", decision.reason ?? decision.status, decision, viewHash);
    // Approval is bound to this exact payload and must still be in its validity window.
    if (hashOf({ model: targetModel, messages: red.payload }) !== req.payloadHash) return fallback("denied", "payload hash mismatch", decision, viewHash);
    if (Date.now() > req.expiresAt) return fallback("expired", "approval expired before egress", decision, viewHash);

    if (d.approvalScopeMs > 0)
      grants.set(sessionId, [
        ...(grants.get(sessionId) ?? []).filter((g) => g.until > Date.now()),
        { approvalId: req.id, agent: policy.agent, targetModel, role: route.role, placeholders: new Set(placeholders), risk: risk.level, decision, until: Date.now() + d.approvalScopeMs },
      ]);

    return {
      kind: "egress",
      meta: { ...meta, decision: "approved" },
      session,
      payload: red.payload,
      targetModel,
      audit: {
        ...base,
        decision: "approved",
        viewHash,
        approverCommitment: decision.approverCommitment,
        roleCheck: decision.roleCheck,
        worldIdVerified: decision.worldIdVerified,
      },
    };
  }
}
