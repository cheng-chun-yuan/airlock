import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { getCookie, setCookie } from "hono/cookie";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import type { ChatMessage, Decision, RoleRegistry } from "@airlock/core";
import { publicView, type AirlockEvent, type ApprovalStore, type ProofVerifier, type WorldIdProof, type WorldOidc } from "@airlock/approval";
import { commitmentOf } from "@airlock/registry";
import type { JsonlAuditLog } from "@airlock/audit";
import type { Pipeline } from "./pipeline";

export interface AppDeps {
  pipeline: Pipeline;
  approvals: ApprovalStore;
  audit: JsonlAuditLog;
  roles: RoleRegistry;
  verifier: ProofVerifier;
  /** World ID for Agents (Human Continuity OIDC); optional second way to approve/enroll. */
  oidc?: WorldOidc;
  /** "commitment": the World identity must match the enrolled one. "name": live ENS subname only (sandbox issues a new sub per sign-in). */
  oidcBinding?: "commitment" | "name";
  localModel: string;
  claudeModels: string[];
  consoleHtml: string;
  publicConfig: Record<string, unknown>;
  /** One fixed World ID action for enroll + approve, so the (legacy) nullifier is stable per person. */
  approveAction: string;
  ensLink?: (root: string) => string;
  /** When set, every route except health / static IDKit / OIDC callback needs this token. */
  accessToken?: string;
  /** Live ENS view for the Console (ENS mode only). */
  ens?: { status(localRoot: string): Promise<unknown>; approver(name: string, role?: string): Promise<unknown> };
}

const enrollSignal = (name: string) => `airlock-enroll:${name}`;

export function buildApp(d: AppDeps) {
  const app = new Hono();

  // Access gate for public deployments (e.g. behind a tunnel). Clients send `Authorization: Bearer <token>`;
  // browsers open /console?token=<token> once, which sets an HttpOnly cookie and strips the token from the URL.
  if (d.accessToken) {
    const want = Buffer.from(d.accessToken);
    const ok = (v?: string | null) => !!v && v.length === d.accessToken!.length && timingSafeEqual(Buffer.from(v), want);
    const open = (p: string) => p === "/health" || p === "/oidc/callback" || p.startsWith("/vendor/");
    app.use("*", async (c, next) => {
      const url = new URL(c.req.url);
      if (open(url.pathname)) return next();
      const q = url.searchParams.get("token");
      if (ok(q)) {
        const secure = c.req.header("x-forwarded-proto") === "https" || url.protocol === "https:";
        setCookie(c, "airlock_token", q!, { httpOnly: true, sameSite: "Lax", secure, path: "/", maxAge: 7 * 86400 });
        url.searchParams.delete("token");
        return c.redirect(url.pathname + (url.search || ""));
      }
      const bearer = c.req.header("authorization")?.replace(/^Bearer\s+/i, "");
      if (ok(bearer) || ok(getCookie(c, "airlock_token"))) return next();
      if (c.req.method === "GET" && (url.pathname === "/" || url.pathname === "/console"))
        return c.html(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Airlock</title><body style="font:15px/1.6 system-ui;max-width:420px;margin:18vh auto;padding:0 16px"><p style="font:500 11px ui-monospace,monospace;letter-spacing:.2em">AIRLOCK</p><h2 style="margin:.2em 0 12px">This console is locked</h2><form method="get" action="/console"><input name="token" type="password" placeholder="access token" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;font:14px ui-monospace,monospace"><button style="margin-top:10px;padding:9px 18px;border:0;border-radius:99px;background:#141414;color:#fff;font:600 14px system-ui">Enter</button></form></body>`, 401);
      return c.json({ error: { message: "missing or invalid Airlock access token", type: "authentication_error" } }, 401);
    });
  }

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
    // Headers are ASCII-only, so free text (names, justification in any language) arrives URI-encoded.
    const text = (h: string) => {
      const v = c.req.header(h);
      if (!v) return undefined;
      try { return decodeURIComponent(v).slice(0, 500); } catch { return v.slice(0, 500); }
    };
    const opts = {
      sessionId: c.req.header("x-airlock-session") ?? undefined,
      agent: c.req.header("x-airlock-agent") ?? undefined,
      user: text("x-airlock-user"),
      justification: text("x-airlock-justification"),
      extra,
    };
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
      const method = d.verifier.mode === "mock" ? ("mock" as const) : ("idkit" as const);
      if (!v.ok) decision = { status: "proof_invalid", method, reason: `World ID proof rejected: ${v.error}`, worldIdVerified: false };
      else {
        const commitment = commitmentOf(v.nullifier!);
        const roleCheck = await d.roles.isValidApprover(commitment, req.requiredRole, body.approverName);
        decision =
          roleCheck === "valid"
            ? { status: "approved", method, approverCommitment: commitment, approverName: body.approverName, roleCheck, worldIdVerified: true }
            : { status: "role_invalid", method, reason: `verified human, but ENS role check failed: ${roleCheck} for ${req.requiredRole}`, approverCommitment: commitment, approverName: body.approverName, roleCheck, worldIdVerified: true };
      }
    }
    d.approvals.resolve(req.id, decision);
    return c.json(decision, decision.status === "approved" ? 200 : 403);
  });

  // The requester changes their mind before anyone approved: nothing is sent.
  app.post("/approvals/:id/withdraw", async (c) => {
    const ok = d.approvals.resolve(c.req.param("id"), { status: "denied", reason: "withdrawn by requester", worldIdVerified: false });
    return ok ? c.json({ ok }) : c.json({ error: "not pending" }, 409);
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
  app.get("/ens", async (c) => (d.ens ? c.json(await d.ens.status(d.audit.merkleRoot())) : c.json({ error: "ENS not configured (static JSON mode)" }, 404)));
  app.get("/ens/approver", async (c) => (d.ens ? c.json(await d.ens.approver(c.req.query("name") ?? "", c.req.query("role"))) : c.json({ error: "ENS not configured" }, 404)));

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

  // ---------- World ID for Agents (Human Continuity OIDC) ----------
  // Opened as a popup by the Console (so the agent's stream keeps running): tell the opener and close.
  // Opened directly: go back to the Console after a moment.
  const page = (title: string, body: string, next?: string) =>
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>` +
    `<body style="font:15px/1.6 system-ui;max-width:560px;margin:12vh auto;padding:0 16px;color:#141414"><p style="font:500 11px ui-monospace,monospace;letter-spacing:.1em;text-transform:uppercase;color:#6f6f6f">Airlock · World ID for Agents</p><h2 style="margin:.2em 0">${title}</h2><p>${body}</p>${next ? `<p><a href="${next}">Back to the console →</a></p>` : ""}` +
    `<script>if (window.opener) { try { window.opener.postMessage({ airlock: "worldid-done" }, location.origin); } catch (e) {} setTimeout(() => window.close(), 600); }${next ? ` else setTimeout(() => (location.href = ${JSON.stringify(next)}), 2500);` : ""}</script></body>`;
  const esc = (s: string) => s.replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[ch]!);

  app.get("/approvals/:id/oidc", async (c) => {
    if (!d.oidc) return c.json({ error: "World ID for Agents (OIDC) not configured" }, 501);
    const req = d.approvals.get(c.req.param("id"));
    if (!req) return c.json({ error: "not found" }, 404);
    if (req.status !== "pending") return c.redirect(`/console#${req.id}`);
    // The OIDC nonce commits to this approval + payloadHash; see approval/src/oidc.ts.
    return c.redirect(await d.oidc.start("approve", req.id, c.req.query("approverName") ?? "", req.payloadHash));
  });

  app.get("/enroll/oidc", async (c) => {
    if (!d.oidc) return c.json({ error: "World ID for Agents (OIDC) not configured" }, 501);
    const name = c.req.query("approverName") ?? "";
    if (!name) return c.json({ error: "approverName required" }, 400);
    return c.redirect(await d.oidc.start("enroll", name, name, enrollSignal(name)));
  });

  app.get("/oidc/callback", async (c) => {
    if (!d.oidc) return c.html(page("Not configured", "World ID for Agents is not configured on this gateway."), 501);
    const { state = "", code = "", error, error_description } = c.req.query();
    if (error) {
      // Cancelled / refused at World: the protected action must not happen.
      const p = d.oidc.cancel(state);
      if (p?.kind === "approve") d.approvals.resolve(p.ref, { status: "denied", method: "oidc", reason: `approver cancelled World ID (${error})`, worldIdVerified: false });
      return c.html(page("Not approved", `World ID returned <b>${esc(error)}</b>${error_description ? ` — ${esc(error_description)}` : ""}. Nothing was sent.`, p?.kind === "approve" ? `/console#${p.ref}` : "/console#enroll"));
    }
    const r = await d.oidc.finish(state, code);
    if (!r.ok) {
      if (r.pending?.kind === "approve") d.approvals.resolve(r.pending.ref, { status: "proof_invalid", method: "oidc", reason: `World ID for Agents: ${r.error}`, worldIdVerified: false });
      return c.html(page("Verification failed", esc(r.error), r.pending?.kind === "approve" ? `/console#${r.pending.ref}` : "/console#enroll"), 403);
    }
    const commitment = commitmentOf(r.nullifier);
    if (r.pending.kind === "enroll") {
      if (!d.roles.enroll) return c.html(page("Read-only registry", "This gateway can't write approver records."), 501);
      await d.roles.enroll(r.pending.approverName, commitment);
      return c.html(page("Enrolled", `<b>${esc(r.pending.approverName)}</b> is now bound to this World ID.<br><code style="font-size:12px">commitment ${commitment}</code>`, "/console#enroll"));
    }
    const req = d.approvals.get(r.pending.ref);
    if (!req || req.status !== "pending") return c.html(page("Too late", "This request is no longer waiting for approval."), 409);
    const binding = d.oidcBinding === "name" && d.roles.isLiveApprover ? ("name" as const) : ("commitment" as const);
    const roleCheck =
      binding === "name"
        ? await d.roles.isLiveApprover!(req.requiredRole, r.pending.approverName)
        : await d.roles.isValidApprover(commitment, req.requiredRole, r.pending.approverName);
    const who = { method: "oidc" as const, identityBinding: binding, approverCommitment: commitment, approverName: r.pending.approverName, roleCheck, worldIdVerified: true };
    d.approvals.resolve(
      req.id,
      roleCheck === "valid"
        ? { status: "approved", ...who }
        : { status: "role_invalid", reason: `verified human, but ENS role check failed: ${roleCheck} for ${req.requiredRole}`, ...who },
    );
    return c.html(
      roleCheck === "valid"
        ? page("Approved", `Verified human · <b>${esc(r.pending.approverName)}</b> holds a live ${esc(req.requiredRole)} role. The outer door opens.`, `/console#${req.id}`)
        : page("Role check failed", `Verified human, but <b>${esc(r.pending.approverName)}</b> is ${esc(roleCheck)} for ${esc(req.requiredRole)}. Nothing was sent.`, `/console#${req.id}`),
    );
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
