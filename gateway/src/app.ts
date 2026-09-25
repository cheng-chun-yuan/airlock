import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import type { ChatMessage, Decision, RoleRegistry } from "@airlock/core";
import { publicView, type AirlockEvent, type ApprovalStore, type ProofVerifier, type WorldIdProof } from "@airlock/approval";
import { commitmentOf } from "@airlock/registry";
import type { JsonlAuditLog } from "@airlock/audit";
import type { Pipeline } from "./pipeline";

export interface AppDeps {
  pipeline: Pipeline;
  approvals: ApprovalStore;
  audit: JsonlAuditLog;
  roles: RoleRegistry;
  verifier: ProofVerifier;
  localModel: string;
  claudeModels: string[];
  consoleHtml: string;
  publicConfig: Record<string, unknown>;
  /** One fixed World ID action for enroll + approve, so the (legacy) nullifier is stable per person. */
  approveAction: string;
  ensLink?: (root: string) => string;
}

const enrollSignal = (name: string) => `airlock-enroll:${name}`;

export function buildApp(d: AppDeps) {
  const app = new Hono();

  // ---------- Gateway (clients) ----------
  app.get("/v1/models", (c) =>
    c.json({
      object: "list",
      data: [`local/${d.localModel}`, ...d.claudeModels.map((m) => `airlock/${m}`), "auto"].map((id) => ({ id, object: "model", owned_by: "airlock" })),
    }),
  );

  app.post("/v1/chat/completions", async (c) => {
    const body = await c.req.json();
    const { model = "auto", messages, stream, ...rest } = body as { model?: string; messages: ChatMessage[]; stream?: boolean };
    const extra: Record<string, unknown> = {};
    for (const k of ["temperature", "top_p", "max_tokens", "tools", "tool_choice", "stop"]) if (k in rest) extra[k] = (rest as any)[k];
    const opts = { sessionId: c.req.header("x-airlock-session") ?? undefined, agent: c.req.header("x-airlock-agent") ?? undefined, extra };
    const created = Math.floor(Date.now() / 1000);

    // Real token streaming. Requests with tools use the buffered path below (tool-call deltas aren't streamed yet).
    if (stream && !extra.tools) {
      const hangup = new AbortController();
      const { model: served, airlock, chunks } = await d.pipeline.stream(model, messages, { ...opts, signal: hangup.signal });
      const base = { id: `chatcmpl-${airlock.requestId}`, object: "chat.completion.chunk", created, model: served };
      c.header("x-airlock-route", airlock.route);
      c.header("x-airlock-decision", airlock.decision);
      return streamSSE(c, async (s) => {
        s.onAbort(() => hangup.abort());
        await s.writeSSE({ data: JSON.stringify({ ...base, choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }], airlock }) });
        for await (const ch of chunks) {
          if (s.aborted) break; // client hung up: stop pulling from upstream (the pipeline still audits the egress)
          if (ch.text) await s.writeSSE({ data: JSON.stringify({ ...base, choices: [{ index: 0, delta: { content: ch.text }, finish_reason: null }] }) });
          if (ch.finishReason) await s.writeSSE({ data: JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: ch.finishReason }], ...(ch.usage && { usage: ch.usage }) }) });
        }
        await s.writeSSE({ data: "[DONE]" });
      });
    }

    const { completion, airlock } = await d.pipeline.handle(model, messages, opts);
    const id = `chatcmpl-${airlock.requestId}`;
    c.header("x-airlock-route", airlock.route);
    c.header("x-airlock-decision", airlock.decision);
    if (!stream)
      return c.json({
        id,
        object: "chat.completion",
        created,
        model: completion.model,
        choices: [{ index: 0, message: completion.message, finish_reason: completion.finishReason }],
        usage: completion.usage,
        airlock,
      });
    return streamSSE(c, async (s) => {
      const base = { id, object: "chat.completion.chunk", created, model: completion.model };
      await s.writeSSE({ data: JSON.stringify({ ...base, choices: [{ index: 0, delta: { role: "assistant", content: completion.message.content ?? "", ...(completion.message.tool_calls && { tool_calls: completion.message.tool_calls.map((t, index) => ({ index, ...t })) }) }, finish_reason: null }] }) });
      await s.writeSSE({ data: JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: completion.finishReason }] }) });
      await s.writeSSE({ data: "[DONE]" });
    });
  });

  // ---------- Approval (Console / approvers) ----------
  app.get("/approvals", (c) => c.json(d.approvals.list(c.req.query("status")).map(publicView)));

  app.get("/approvals/:id", (c) => {
    const r = d.approvals.get(c.req.param("id"));
    return r ? c.json(r) : c.json({ error: "not found" }, 404);
  });

  /** Everything the Console needs to build the IDKit request: signal = payloadHash. */
  app.get("/approvals/:id/worldid", (c) => {
    const r = d.approvals.get(c.req.param("id"));
    return r ? c.json(d.verifier.requestContext(d.approveAction, r.payloadHash)) : c.json({ error: "not found" }, 404);
  });

  app.post("/approvals/:id/verify", async (c) => {
    const req = d.approvals.get(c.req.param("id"));
    if (!req) return c.json({ error: "not found" }, 404);
    if (req.status !== "pending") return c.json({ error: `already ${req.status}` }, 409);
    const body = (await c.req.json()) as WorldIdProof & { approverName?: string; payloadHash?: string };
    let decision: Decision;
    if (body.payloadHash && body.payloadHash !== req.payloadHash) {
      decision = { status: "proof_invalid", reason: "payload hash mismatch", worldIdVerified: false };
    } else {
      // The proof's signal must be this request's payloadHash: approving one payload can't be replayed on another.
      const v = await d.verifier.verify(body, req.payloadHash, d.approveAction);
      if (!v.ok) decision = { status: "proof_invalid", reason: `World ID proof rejected: ${v.error}`, worldIdVerified: false };
      else {
        const commitment = commitmentOf(v.nullifier!);
        const roleCheck = await d.roles.isValidApprover(commitment, req.requiredRole, body.approverName);
        decision =
          roleCheck === "valid"
            ? { status: "approved", approverCommitment: commitment, approverName: body.approverName, roleCheck, worldIdVerified: true }
            : { status: "role_invalid", reason: `verified human, but ENS role check failed: ${roleCheck} for ${req.requiredRole}`, approverCommitment: commitment, approverName: body.approverName, roleCheck, worldIdVerified: true };
      }
    }
    d.approvals.resolve(req.id, decision);
    return c.json(decision, decision.status === "approved" ? 200 : 403);
  });

  app.post("/approvals/:id/deny", async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const ok = d.approvals.resolve(c.req.param("id"), { status: "denied", reason: (body as any).reason ?? "denied by reviewer", worldIdVerified: false });
    return ok ? c.json({ ok }) : c.json({ error: "not pending" }, 409);
  });

  app.get("/events", (c) =>
    streamSSE(c, async (s) => {
      const on = (e: AirlockEvent) => void s.writeSSE({ event: e.type, data: JSON.stringify(e) });
      d.approvals.on("event", on);
      s.onAbort(() => void d.approvals.off("event", on));
      while (!s.aborted) {
        await s.writeSSE({ event: "ping", data: "{}" });
        await s.sleep(15_000);
      }
    }),
  );

  // ---------- Audit ----------
  app.get("/audit", (c) => {
    const root = d.audit.merkleRoot();
    return c.json({ records: d.audit.list(), chain: d.audit.verify(), merkleRoot: root, ensLink: d.ensLink?.(root) });
  });
  app.post("/audit/anchor", async (c) => {
    try {
      return c.json(await d.audit.anchor());
    } catch (e) {
      return c.json({ error: (e as Error).message }, 500);
    }
  });

  // ---------- Enrollment (before the demo) ----------
  app.get("/enroll/worldid", (c) => c.json(d.verifier.requestContext(d.approveAction, enrollSignal(c.req.query("approverName") ?? ""))));

  app.post("/enroll", async (c) => {
    const body = (await c.req.json()) as WorldIdProof & { approverName: string };
    if (!body.approverName) return c.json({ error: "approverName required" }, 400);
    const v = await d.verifier.verify(body, enrollSignal(body.approverName), d.approveAction);
    if (!v.ok) return c.json({ error: `World ID proof rejected: ${v.error}` }, 403);
    const commitment = commitmentOf(v.nullifier!);
    if (!d.roles.enroll) return c.json({ error: "role registry is read-only" }, 501);
    await d.roles.enroll(body.approverName, commitment);
    return c.json({ approverName: body.approverName, commitment });
  });

  app.post("/admin/revoke", async (c) => {
    const { approverName } = (await c.req.json()) as { approverName: string };
    if (!d.roles.revoke) return c.json({ error: "role registry is read-only" }, 501);
    await d.roles.revoke(approverName);
    return c.json({ revoked: approverName });
  });

  // ---------- Console ----------
  app.get("/config", (c) => c.json(d.publicConfig));
  app.get("/", (c) => c.redirect("/console"));
  app.get("/console", (c) => c.html(process.env.NODE_ENV === "production" ? d.consoleHtml : readFileSync(new URL("../../console/index.html", import.meta.url), "utf8")));
  app.get("/health", (c) => c.json({ ok: true }));

  // IDKit browser bundle + its WASM, served from node_modules (the CDN build fails WASM init; see docs/SETUP.md).
  const idkitDir = dirname(createRequire(import.meta.url).resolve("@worldcoin/idkit-core/hashing"));
  const vendor = { "idkit.global.js": "text/javascript", "idkit_wasm_bg.wasm": "application/wasm" } as Record<string, string>;
  app.get("/vendor/idkit/:file", (c) => {
    const type = vendor[c.req.param("file")];
    if (!type) return c.notFound();
    return c.body(readFileSync(join(idkitDir, c.req.param("file"))), 200, { "content-type": type, "cache-control": "public, max-age=3600" });
  });

  return app;
}
