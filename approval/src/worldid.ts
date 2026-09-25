import { hashSignal } from "@worldcoin/idkit-core/hashing";
import { signRequest } from "@worldcoin/idkit-core/signing";

/**
 * IDKit 4.x result, forwarded unchanged from the browser
 * (docs.world.org/world-id/reference/api). v3 = legacy proofs, v4 = World ID 4.0.
 */
export interface WorldIdProof {
  protocol_version?: "3.0" | "4.0";
  nonce?: string;
  action?: string;
  environment?: string;
  responses?: { identifier: string; nullifier: string; signal_hash?: string; proof: string | string[]; merkle_root?: string }[];
  /** Mock mode only (no WORLD_APP_ID): a fake stable nullifier standing in for a person. */
  mock?: boolean;
  nullifier?: string;
}

export interface VerifyResult {
  ok: boolean;
  nullifier?: string;
  protocol?: string;
  error?: string;
}

export interface ProofVerifier {
  readonly mode: "worldid" | "mock";
  /** What the browser needs to build the IDKit request for this action. */
  requestContext(action: string, signal: string): { app_id?: string; action: string; signal: string; environment: string; rp_context?: unknown; mode: string };
  verify(proof: WorldIdProof, expectedSignal: string, expectedAction: string): Promise<VerifyResult>;
}

export interface WorldIdConfig {
  appId: `app_${string}`;
  rpId: string;
  signingKeyHex: string;
  environment: "production" | "staging";
  verifyBase?: string; // default developer.world.org
}

/**
 * Role binding needs a *stable* per-person identifier: the gateway stores
 * commitment(nullifier) under the approver's ENS subname at enrollment and
 * compares at approval time. Legacy v3 nullifiers are stable per (app, action,
 * person); v4 uniqueness nullifiers are one-time-use. So we use ONE fixed
 * action for enroll + approve, request legacy proofs, and bind each approval
 * to its payload through the signal instead of the action.
 */
export class WorldIdVerifier implements ProofVerifier {
  readonly mode = "worldid" as const;
  private used = new Set<string>(); // replay guard: v4 returns success even on nullifier reuse

  constructor(private cfg: WorldIdConfig) {}

  requestContext(action: string, signal: string) {
    const s = signRequest({ signingKeyHex: this.cfg.signingKeyHex, action, ttl: 300 });
    return {
      mode: this.mode,
      app_id: this.cfg.appId,
      action,
      signal,
      environment: this.cfg.environment,
      rp_context: { rp_id: this.cfg.rpId, nonce: s.nonce, created_at: s.createdAt, expires_at: s.expiresAt, signature: s.sig },
    };
  }

  async verify(proof: WorldIdProof, expectedSignal: string, expectedAction: string): Promise<VerifyResult> {
    const r = proof.responses?.[0];
    if (!r) return { ok: false, error: "no responses in proof" };
    if (proof.action !== expectedAction) return { ok: false, error: `action mismatch (${proof.action})` };
    // The portal only checks the proof against the signal_hash we hand it, so check the binding ourselves.
    if (r.signal_hash !== hashSignal(expectedSignal)) return { ok: false, error: "signal does not match payloadHash" };
    const replayKey = `${proof.nonce}:${r.nullifier}:${r.signal_hash}`;
    if (this.used.has(replayKey)) return { ok: false, error: "proof already used" };

    const base = this.cfg.verifyBase ?? (this.cfg.environment === "staging" ? "https://staging-developer.worldcoin.org" : "https://developer.world.org");
    const res = await fetch(`${base}/api/v4/verify/${this.cfg.rpId}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(proof),
    });
    const j = (await res.json().catch(() => ({}))) as { success?: boolean; code?: string; detail?: string };
    if (!res.ok || !j.success) return { ok: false, error: j.code ? `${j.code}: ${j.detail ?? ""}` : `verify HTTP ${res.status}` };
    this.used.add(replayKey);
    if (proof.protocol_version === "4.0")
      // Still a verified human, but the nullifier won't match an enrollment made with another proof.
      return { ok: true, nullifier: r.nullifier, protocol: "4.0" };
    return { ok: true, nullifier: r.nullifier, protocol: proof.protocol_version };
  }
}

/** Local development without World App: a "proof" is just a declared nullifier. Never enable in a real deployment. */
export class MockVerifier implements ProofVerifier {
  readonly mode = "mock" as const;
  requestContext(action: string, signal: string) {
    return { mode: this.mode, action, signal, environment: "mock" };
  }
  async verify(proof: WorldIdProof): Promise<VerifyResult> {
    if (!proof.mock || !proof.nullifier) return { ok: false, error: "mock verifier expects { mock: true, nullifier }" };
    return { ok: true, nullifier: proof.nullifier, protocol: "mock" };
  }
}

export { hashSignal };
