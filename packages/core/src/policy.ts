import { CLASS_ORDER, type DataClass, type Policy, type RiskResult, type Route } from "./types";

const rank = (c: DataClass) => CLASS_ORDER.indexOf(c);

export function modelAllowed(glob: string, model: string): boolean {
  return glob
    .split(",")
    .map((g) => g.trim())
    .filter(Boolean)
    .some((g) => new RegExp("^" + g.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$").test(model));
}

/**
 * Decision table (docs/ARCHITECTURE.md §3):
 *   public / internal           -> auto (audit only)
 *   confidential + low risk     -> World ID + role check
 *   confidential + high risk    -> data owner approval, or block
 *   restricted                  -> always block (local only)
 */
export function decide(sourceClass: DataClass, risk: RiskResult, policy: Policy, model: string): Route {
  if (!modelAllowed(policy.models, model)) return { kind: "block", reason: `model ${model} not allowed by ${policy.agent}` };
  if (policy.egress === "block") return { kind: "block", reason: `egress disabled for ${policy.agent}` };
  if (sourceClass === "restricted") return { kind: "block", reason: "restricted data is local-only" };
  if (rank(sourceClass) > rank(policy.maxClass))
    return { kind: "block", reason: `${sourceClass} exceeds ${policy.agent} maxClass=${policy.maxClass}` };
  if (rank(sourceClass) <= rank("internal")) return { kind: "auto" };
  if (risk.level === "low") return { kind: "approval", role: policy.approverRole };
  if (policy.ownerRole) return { kind: "owner", role: policy.ownerRole };
  return { kind: "block", reason: `high residual risk (${risk.findings.join("; ")}) and no owner role` };
}
