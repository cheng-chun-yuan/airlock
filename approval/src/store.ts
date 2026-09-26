import { EventEmitter } from "node:events";
import type { ApprovalRequest, Approver, Decision } from "@airlock/core";

export type AirlockEvent =
  | { type: "approval.created"; request: ApprovalRequest }
  | { type: "approval.resolved"; request: ApprovalRequest; decision: Decision }
  | { type: "audit.appended"; seq: number; decision: string }
  | { type: "request.routed"; requestId: string; route: string; reason?: string }
  | { type: "approval.progress"; request: ApprovalRequest }
  | { type: "approval.refused"; requestId: string; approverName?: string; reason: string }
  | { type: "chain.event"; kind: string; text: string; tx?: string; at?: string };

/** In-memory approval queue. Also the event bus the Console's SSE stream listens on. */
export class ApprovalStore extends EventEmitter implements Approver {
  private requests = new Map<string, ApprovalRequest>();
  private waiters = new Map<string, (d: Decision) => void>();

  constructor(private timeoutMs = 120_000) {
    super();
    this.setMaxListeners(100);
  }

  emitEvent(e: AirlockEvent) {
    this.emit("event", e);
  }

  get(id: string) {
    return this.requests.get(id);
  }

  list(status?: string) {
    return [...this.requests.values()].filter((r) => !status || r.status === status).sort((a, b) => b.createdAt - a.createdAt);
  }

  request(req: ApprovalRequest): Promise<Decision> {
    this.requests.set(req.id, req);
    this.emitEvent({ type: "approval.created", request: publicView(req) });
    return new Promise((resolve) => {
      this.waiters.set(req.id, resolve);
      setTimeout(() => this.resolve(req.id, { status: "expired", reason: "approval timed out", worldIdVerified: false }), Math.max(0, req.expiresAt - Date.now()));
    });
  }

  /**
   * Count one approval toward the request's quorum. Each must come from a different human (World identity
   * commitment) and a different approver name; the request resolves once enough distinct humans approved.
   */
  count(id: string, a: { approverName?: string; commitment?: string; method?: Decision["method"]; identityBinding?: Decision["identityBinding"] }):
    | { result: "approved" | "partial"; have: number; need: number }
    | { result: "same-human" | "same-name" | "not-pending"; have: number; need: number } {
    const req = this.requests.get(id);
    const need = req?.quorum ?? 1;
    const list = (req && (req.approvals ??= [])) || [];
    if (!req || req.status !== "pending") return { result: "not-pending", have: list.length, need };
    if (a.commitment && list.some((x) => x.commitment === a.commitment)) return { result: "same-human", have: list.length, need };
    if (a.approverName && list.some((x) => x.approverName === a.approverName)) return { result: "same-name", have: list.length, need };
    list.push({ approverName: a.approverName, commitment: a.commitment, method: a.method, at: Date.now() });
    if (list.length < need) {
      this.emitEvent({ type: "approval.progress", request: publicView(req) });
      return { result: "partial", have: list.length, need };
    }
    this.resolve(id, {
      status: "approved",
      method: a.method,
      identityBinding: a.identityBinding,
      approverCommitment: a.commitment,
      approverName: list.map((x) => x.approverName).join(", "),
      approvers: list.map((x) => ({ name: x.approverName, commitment: x.commitment })),
      roleCheck: "valid",
      worldIdVerified: a.method !== "mock",
    });
    return { result: "approved", have: list.length, need };
  }

  /** First resolution wins; later ones are ignored. */
  resolve(id: string, decision: Decision): boolean {
    const req = this.requests.get(id);
    const waiter = this.waiters.get(id);
    if (!req || !waiter || req.status !== "pending") return false;
    req.status = decision.status;
    req.reason = decision.reason;
    this.waiters.delete(id);
    waiter(decision);
    this.emitEvent({ type: "approval.resolved", request: publicView(req), decision });
    return true;
  }

  get defaultTimeoutMs() {
    return this.timeoutMs;
  }
}

/** Events go to the Console only (local), but keep the original text out of the broadcast anyway. */
export function publicView(r: ApprovalRequest): ApprovalRequest {
  const { originalPreview, mapping, ...rest } = r;
  return rest as ApprovalRequest;
}
