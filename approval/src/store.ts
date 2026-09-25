import { EventEmitter } from "node:events";
import type { ApprovalRequest, Approver, Decision } from "@airlock/core";

export type AirlockEvent =
  | { type: "approval.created"; request: ApprovalRequest }
  | { type: "approval.resolved"; request: ApprovalRequest; decision: Decision }
  | { type: "audit.appended"; seq: number; decision: string }
  | { type: "request.routed"; requestId: string; route: string; reason?: string };

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
  const { originalPreview, ...rest } = r;
  return rest as ApprovalRequest;
}
