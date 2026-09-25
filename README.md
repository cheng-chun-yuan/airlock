# Airlock

> **Local AI by default. Frontier AI by human consent. Accountability on-chain.**

Airlock is an OpenAI-compatible gateway that sits between your chat clients (LibreChat, agents, curl) and the models they use.

- **Local by default.** Requests go to a local model (vLLM on a GB10).
- **Frontier only with consent.** A request reaches a frontier model (Claude) only after:
  - **redaction**: sensitive entities are swapped for stable placeholders;
  - a **policy decision**, read from ENS;
  - for confidential data, a **human approval**: a World ID proof whose signal is bound to the exact redacted payload, plus an ENS role check for the approver.
- **Real names restored locally.** Answers are rehydrated on the gateway, so the mapping table never leaves it.
- **Everything is audited.** Every decision lands in a hash-chained log, and the log's Merkle root is anchored to ENS.

Architecture (中文): [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). How Airlock relates to AI token gateways like [ATP](https://atptoken.ai/zh-tw/), and how to chain them: [docs/TOKEN-GATEWAYS.md](docs/TOKEN-GATEWAYS.md). Verified integration details for World ID 4.0 and ENSv2 on Sepolia: [docs/INTEGRATION-NOTES.md](docs/INTEGRATION-NOTES.md).

```
client ──▶ Router ─▶ Redactor ─▶ RiskScorer ─▶ PolicyResolver(ENS) ─▶ Approver(World ID + ENS role)
                                                                          │
           ◀── Rehydrator ◀── Egress(Claude, redacted only) ◀─────────────┘
                     └────────▶ AuditSink (hash chain → Merkle root → ENS)
```

## Quick start

```bash
npm install
cp .env.example .env        # optional: works with zero config in mock mode
npm start                   # gateway + console on :8787
open http://localhost:8787/console
npm test                    # unit tests
npm run smoke               # e2e: approve / deny / non-approver / revoked, against a running gateway
```

With no config you get:
- a local model at `http://localhost:8000/v1`;
- a **mock** World ID verifier, with "Verify as alice/mallory" buttons in the Console;
- policies and approvers from JSON: `demo/policies.json` and `data/approvers.json`, seeded from `demo/`.

To turn on the real integrations, set these in `.env`:

| Feature | Env |
|---|---|
| Claude egress | `ANTHROPIC_API_KEY`, `CLAUDE_MODEL` |
| Egress via a token gateway (ATP, OpenRouter, LiteLLM; one key, many providers) | `EGRESS_PROVIDER=openai`, `EGRESS_BASE_URL`, `EGRESS_API_KEY` |
| Real World ID (staging works with simulator.worldcoin.org) | `WORLD_APP_ID`, `WORLD_RP_ID`, `WORLD_RP_SIGNING_KEY`, `WORLD_ENV` |
| ENS policies and roles (read) | `SEPOLIA_RPC_URL` |
| ENS enroll, revoke and audit anchoring (write) | `ENS_RESOLVER`, `ENS_PRIVATE_KEY`, `ENS_AUDIT_NAME` |
| Presidio NER | `PRESIDIO_URL` (`docker compose up` starts the analyzer) |

## Models (`model` field)

| Model | Behavior |
|---|---|
| `local/<name>` | Straight to the local model. Nothing leaves the box. |
| `airlock/<claude-model>` | Full pipeline: redact → policy → (approve) → Claude → rehydrate. |
| `auto` | Local first. Escalates through the Airlock pipeline only when the local answer is unsure. |

Optional headers:
- `x-airlock-session`: keeps placeholders stable across turns.
- `x-airlock-agent`: the ENS name of the agent policy, default `contract-agent.agents.acme.eth`.

Any failure path (blocked, denied, expired, role invalid, egress error) falls back to the local model's answer, prefixed with the reason. Responses carry an `airlock` metadata object and `x-airlock-route` / `x-airlock-decision` headers.

## API

- `POST /v1/chat/completions`, `GET /v1/models`: OpenAI-compatible. With `stream: true`, the whole answer arrives as a single SSE chunk.
- `GET /approvals?status=pending`, `GET /approvals/:id`
- `GET /approvals/:id/worldid`: IDKit request context (signed `rp_context`, `signal = payloadHash`).
- `POST /approvals/:id/verify`: IDKit result, plus `approverName` (ENS subname).
- `POST /approvals/:id/deny`
- `GET /events`: SSE for the Console.
- `GET /audit`, `POST /audit/anchor`
- `GET /enroll/worldid?approverName=…`, `POST /enroll`: World ID → commitment → `airlock.approver` text record.
- `POST /admin/revoke`: clears an approver's record. On ENS you can also `unregister` the subname.

## Repo layout

```
gateway/        Hono server: router, pipeline, egress, rehydrate, console serving
packages/core/  types, interfaces, policy decision table
redactor/       rules + company dictionary + Presidio recognizers; rule-based risk scorer
approval/       approval queue / SSE bus; World ID 4.0 verifier (+ mock)
registry/       ENSv2 policy/role resolvers + setText writer (viem); JSON fallback
audit/          JSONL hash chain, Merkle root, anchoring
console/        single-page Console (queue, side-by-side redaction, World ID QR, audit)
demo/           fake contract, dictionary, policies, LibreChat snippet, smoke test
```

## Status

**Done (P0/P1 core):**
- Routing and redaction/rehydration, with session-stable placeholders.
- The policy decision table.
- The approval flow: approve, deny, timeout, role-invalid and revoked.
- World ID 4.0 verification: RP signing, signal binding, replay guard.
- ENS reads, verified live on Sepolia; ENS writes.
- Hash-chain audit and a Merkle root, with per-request attribution (agent + egress token usage).
- Pluggable egress: Anthropic directly, or any Anthropic/OpenAI-compatible token gateway (e.g. ATP). The ENS model allow-list is still enforced.
- The Console.
- Docker image.

**Not yet:**
- An end-to-end run with a real World ID staging app.
- On-chain ENS writes. The code follows the ENSv2 `PermissionedResolver` ABI but hasn't been run against the chain yet.
- Local-model indirect-identifier tagging and a local attack test (P2).
- Approval scope reuse (P2).
- Real token streaming.
- A Next.js Console. The current Console is a single HTML page.

See [docs/INTEGRATION-NOTES.md](docs/INTEGRATION-NOTES.md) for the ENS setup checklist.
