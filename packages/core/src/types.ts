export type DataClass = "public" | "internal" | "confidential" | "restricted";
export const CLASS_ORDER: DataClass[] = ["public", "internal", "confidential", "restricted"];

export type RiskLevel = "low" | "high";
export type RoleCheck = "valid" | "revoked" | "expired" | "unknown";

export interface ToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

export interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string | null;
  name?: string;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
}

/** Per-session placeholder table. Never leaves the gateway. */
export interface Session {
  id: string;
  forward: Map<string, string>; // lowercased real value -> placeholder
  reverse: Map<string, string>; // placeholder -> real value
  counters: Record<string, number>;
}

export interface RedactResult {
  payload: ChatMessage[];
  mapping: Record<string, string>; // placeholder -> real value
  entities: Record<string, number>; // type -> distinct count
  sourceClass: DataClass;
}

export interface RiskResult {
  level: RiskLevel;
  findings: string[];
}

export interface Policy {
  agent: string;
  maxClass: DataClass;
  egress: "auto" | "approval" | "block";
  models: string; // glob, e.g. "claude-*"
  approverRole: string;
  ownerRole?: string;
  /** High residual risk: how many *different* verified humans must approve (World ID proves they're distinct). */
  highRiskQuorum?: number;
  /** Set when the policy source couldn't be read: the gateway fails closed and says why. */
  unavailable?: string;
}

export type Route =
  | { kind: "auto" }
  | { kind: "approval"; role: string; quorum?: number }
  | { kind: "owner"; role: string }
  | { kind: "block"; reason: string };

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired" | "role_invalid" | "proof_invalid";

export interface ApprovalRequest {
  id: string;
  sessionId: string;
  agent: string;
  requiredRole: string;
  payloadHash: string; // hash of the redacted payload that will actually be sent
  viewHash: string; // hash of what the approver is shown
  redactedPreview: string;
  entities: Record<string, number>;
  riskLevel: RiskLevel;
  findings: string[];
  targetModel: string;
  expiresAt: number;
  createdAt: number;
  status: ApprovalStatus;
  reason?: string;
  /** Original text, local-only: shown side-by-side in the Console, never audited or sent out. */
  originalPreview?: string;
  /** Placeholder -> real value, local-only: lets the Console link redacted chips to the original text. */
  mapping?: Record<string, string>;
  /** Who asked (x-airlock-user) and why they need a frontier model (x-airlock-justification). */
  requester?: string;
  justification?: string;
  /** Distinct humans required, and the approvals counted so far. */
  quorum?: number;
  approvals?: { approverName?: string; commitment?: string; method?: string; at: number }[];
}

export interface Decision {
  status: Exclude<ApprovalStatus, "pending">;
  /** How the human proved themselves: IDKit (World ID 4.0), World ID for Agents (OIDC), or mock. */
  method?: "idkit" | "oidc" | "mock";
  identityBinding?: "commitment" | "name";
  /** Everyone who approved (quorum > 1). */
  approvers?: { name?: string; commitment?: string }[];
  reason?: string;
  approverCommitment?: string;
  approverName?: string;
  roleCheck?: RoleCheck;
  worldIdVerified: boolean;
}

export type AuditDecision = "approved" | "denied" | "expired" | "auto" | "blocked" | "local";

export interface AuditRecord {
  seq: number;
  prevHash: string;
  requestId: string;
  decision: AuditDecision;
  reason?: string;
  sourceHash: string;
  payloadHash?: string;
  viewHash?: string;
  approverCommitment?: string;
  roleCheck?: RoleCheck;
  worldIdVerified: boolean;
  approvalMethod?: string;
  /** How the approver was bound to the role: "commitment" (identity match) or "name" (sandbox: live subname only). */
  identityBinding?: string;
  targetModel?: string;
  /** Attribution: which agent policy the request ran under, and what egress cost in tokens. */
  agent?: string;
  usage?: { promptTokens: number; completionTokens: number };
  /** Set when this egress rode on an earlier approval in the same session (approval scope). */
  scopeOf?: string;
  /** Who asked, and how many fields were de-identified (counts only, never values). */
  requester?: string;
  deidentified?: number;
  /** Approver names when more than one human had to approve. */
  approvers?: string[];
  timestamp: number;
  hash: string;
  gatewaySig: string;
}

export interface Redactor {
  redact(msgs: ChatMessage[], session: Session): Promise<RedactResult>;
}
export interface RiskScorer {
  /** `mapping` (placeholder -> real value) is local ground truth, e.g. for grading a re-identification attack. */
  score(payload: ChatMessage[], mapping?: Record<string, string>): Promise<RiskResult> | RiskResult;
}
export interface PolicyResolver {
  resolve(agentId: string): Promise<Policy>;
}
export interface RoleRegistry {
  isValidApprover(commitment: string, role: string, approverName?: string): Promise<RoleCheck>;
  /** Name-only check (no identity match): is `approverName` a live, unrevoked approver under `role`? */
  isLiveApprover?(role: string, approverName: string): Promise<RoleCheck>;
  enroll?(approverName: string, commitment: string): Promise<void>;
  revoke?(approverName: string): Promise<void>;
}
export interface Approver {
  request(req: ApprovalRequest): Promise<Decision>;
}
export interface AuditSink {
  append(rec: Omit<AuditRecord, "seq" | "prevHash" | "timestamp" | "hash" | "gatewaySig">): AuditRecord;
  anchor(): Promise<{ root: string; tx?: string }>;
}
