import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { hashSignal, WorldIdVerifier } from "./worldid";

const payloadHash = "0x" + "ab".repeat(32);
const key = "0x" + "11".repeat(32);

test("hex signals hash as raw bytes (IDKit semantics)", () => {
  assert.notEqual(hashSignal(payloadHash), hashSignal("not-hex"));
  assert.match(hashSignal(payloadHash), /^0x00[0-9a-f]{62}$/); // keccak >> 8
});

test("rp_context is signed for the fixed action", () => {
  const v = new WorldIdVerifier({ appId: "app_test", rpId: "rp_test", signingKeyHex: key, environment: "staging" });
  const ctx = v.requestContext("airlock-approve", payloadHash);
  assert.equal(ctx.signal, payloadHash);
  const rp = ctx.rp_context as any;
  assert.equal(rp.rp_id, "rp_test");
  assert.match(rp.signature, /^0x[0-9a-f]{130}$/i);
  assert(rp.expires_at > rp.created_at);
});

test("verify checks action + signal binding locally, forwards to portal, rejects replays", async () => {
  let calls = 0;
  const srv = createServer((req, res) => {
    calls++;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ success: true, nullifier: "0x0a11ce" }));
  }).listen(0);
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const v = new WorldIdVerifier({ appId: "app_test", rpId: "rp_test", signingKeyHex: key, environment: "staging", verifyBase: base });
  const proof = { protocol_version: "3.0" as const, nonce: "n1", action: "airlock-approve", responses: [{ identifier: "orb", nullifier: "0x0a11ce", signal_hash: hashSignal(payloadHash), proof: "0x", merkle_root: "0x" }] };

  assert.equal((await v.verify(proof, payloadHash, "other-action")).ok, false);
  assert.equal((await v.verify(proof, "0x" + "cd".repeat(32), "airlock-approve")).error, "signal does not match payloadHash");
  assert.equal(calls, 0, "local binding checks must run before calling the portal");
  assert.deepEqual(await v.verify(proof, payloadHash, "airlock-approve"), { ok: true, nullifier: "0x0a11ce", protocol: "3.0" });
  assert.equal((await v.verify(proof, payloadHash, "airlock-approve")).error, "proof already used");
  srv.close();
});
