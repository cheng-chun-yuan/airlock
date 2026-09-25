import { test } from "node:test";
import assert from "node:assert/strict";
import { decide, type Policy } from "./index";

const policy: Policy = { agent: "contract-agent.agents.acme.eth", maxClass: "confidential", egress: "approval", models: "claude-*", approverRole: "legal.approvers.acme.eth", ownerRole: "owners.acme.eth" };
const low = { level: "low" as const, findings: [] };
const high = { level: "high" as const, findings: ["a", "b"] };

test("decision table", () => {
  assert.deepEqual(decide("public", low, policy, "claude-sonnet-5"), { kind: "auto" });
  assert.deepEqual(decide("confidential", low, policy, "claude-sonnet-5"), { kind: "approval", role: "legal.approvers.acme.eth" });
  assert.deepEqual(decide("confidential", high, policy, "claude-sonnet-5"), { kind: "owner", role: "owners.acme.eth" });
  assert.equal(decide("confidential", high, { ...policy, ownerRole: undefined }, "claude-sonnet-5").kind, "block");
  assert.equal(decide("restricted", low, policy, "claude-sonnet-5").kind, "block");
  assert.equal(decide("public", low, policy, "gpt-5").kind, "block");
});
