import { test } from "node:test";
import assert from "node:assert/strict";
import type { ApprovalRequest } from "@airlock/core";
import { ApprovalStore } from "./store";

const req = (quorum: number): ApprovalRequest => ({
  id: `r-${quorum}-${Math.random()}`, sessionId: "s", agent: "contract-agent.agents.airlock.eth", requiredRole: "legal.approvers.airlock.eth",
  payloadHash: "0x1", viewHash: "0x2", redactedPreview: "", entities: {}, riskLevel: "high", findings: [], targetModel: "m",
  expiresAt: Date.now() + 60_000, createdAt: Date.now(), status: "pending", quorum, approvals: [],
});

test("two-person rule: the same human can't approve twice, even under another ENS name", async () => {
  const store = new ApprovalStore();
  const r = req(2);
  const decided = store.request(r);
  assert.equal(store.count(r.id, { approverName: "alice.legal.approvers.airlock.eth", commitment: "0xHUMAN_A", method: "idkit" }).result, "partial");
  // same World identity (nullifier → commitment) behind a different name: refused
  assert.equal(store.count(r.id, { approverName: "bob.legal.approvers.airlock.eth", commitment: "0xHUMAN_A", method: "idkit" }).result, "same-human");
  // same name again: refused
  assert.equal(store.count(r.id, { approverName: "alice.legal.approvers.airlock.eth", commitment: "0xHUMAN_C", method: "idkit" }).result, "same-name");
  assert.equal(r.status, "pending");
  // a genuinely different human with a different name completes the quorum
  assert.equal(store.count(r.id, { approverName: "bob.legal.approvers.airlock.eth", commitment: "0xHUMAN_B", method: "idkit" }).result, "approved");
  const d = await decided;
  assert.equal(d.status, "approved");
  assert.deepEqual(d.approvers?.map((a) => a.name), ["alice.legal.approvers.airlock.eth", "bob.legal.approvers.airlock.eth"]);
});

test("quorum 1 approves on the first valid approver", async () => {
  const store = new ApprovalStore();
  const r = req(1);
  const decided = store.request(r);
  assert.equal(store.count(r.id, { approverName: "alice", commitment: "0xA", method: "oidc" }).result, "approved");
  assert.equal((await decided).status, "approved");
});
