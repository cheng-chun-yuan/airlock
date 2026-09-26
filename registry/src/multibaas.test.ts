import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { keccak256, toBytes, toHex } from "viem";
import { packetToBytes } from "viem/ens";
import { describe, dnsDecode, parseWebhook, verifyWebhook, type NameBook } from "./multibaas";

const book: NameBook = {
  records: { "8": "legal.policies.airlock.eth", "5": "alice.legal.approvers.airlock.eth" },
  registries: { "0xlegal": "legal.approvers.airlock.eth" },
  labels: ["alice", "bob", "carol"],
  keys: ["airlock.models", "airlock.approver"],
  accounts: { "0xgateway": "gateway" },
};

test("webhook signature: HMAC-SHA256(secret, body + timestamp), fresh only", () => {
  const body = '[{"id":"1","event":"event.emitted","data":{}}]', ts = String(Math.floor(Date.now() / 1000));
  const sig = createHmac("sha256", "s3cret").update(body + ts).digest("hex");
  assert.equal(verifyWebhook("s3cret", body, sig, ts), true);
  assert.equal(verifyWebhook("s3cret", body + " ", sig, ts), false, "tampered body");
  assert.equal(verifyWebhook("wrong", body, sig, ts), false, "wrong secret");
  const old = String(Math.floor(Date.now() / 1000) - 3600);
  assert.equal(verifyWebhook("s3cret", body, createHmac("sha256", "s3cret").update(body + old).digest("hex"), old), false, "stale delivery");
});

test("events become sentences a reviewer can read", () => {
  const ev = (name: string, inputs: Record<string, string>, contract = "0xresolver") =>
    parseWebhook([{ id: "1", event: "event.emitted", data: { event: { name, contract: { address: contract }, inputs: Object.entries(inputs).map(([n, value]) => ({ name: n, value })) }, transaction: { txHash: "0xabc" } } }])[0];
  assert.equal(describe(ev("TextUpdated", { recordId: "8", key: "airlock.models", value: "claude-*" }), book).text, "legal.policies.airlock.eth: airlock.models = claude-*");
  const tokenId = ((BigInt(keccak256(toBytes("alice"))) >> 32n) << 32n) + 3n; // label hash with a version in the low 32 bits
  const d = describe(ev("LabelUnregistered", { tokenId: tokenId.toString() }, "0xlegal"), book);
  assert.equal(d.text, "alice.legal.approvers.airlock.eth unregistered (revoked)");
  assert.equal(d.kind, "approver");
  assert.equal(describe(ev("Linked", { recordId: "8", name: toHex(packetToBytes("nda-agent.agents.airlock.eth")) }), book).text, "nda-agent.agents.airlock.eth linked → legal.policies.airlock.eth (shared record)");
  assert.match(describe(ev("EACRolesChanged", { resource: BigInt(keccak256(toBytes("airlock.models"))).toString(), account: "0xGATEWAY", oldRoleBitmap: "16", newRoleBitmap: "0" }), book).text, /gateway lost write access on airlock.models/);
  assert.equal(dnsDecode(toHex(packetToBytes("a.b.eth"))), "a.b.eth");
});
