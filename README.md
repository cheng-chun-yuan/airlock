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

Architecture (中文): [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Design references (e.g. ideas borrowed from AI token gateways such as [ATP](https://atptoken.ai/zh-tw/); reference only, no service used): [docs/REFERENCES.md](docs/REFERENCES.md). Verified integration details for World ID 4.0 and ENSv2 on Sepolia: [docs/INTEGRATION-NOTES.md](docs/INTEGRATION-NOTES.md).

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
npm run smoke               # e2e: approve / scope reuse / deny / non-approver / revoked, against a running gateway
npm run ens -- check contract-agent.agents.acme.eth   # read ENS policy + approver + audit records
```

With no config you get:
- a local model at `http://localhost:8000/v1`;
- a **mock** World ID verifier, with "Verify as alice/mallory" buttons in the Console;
- policies and approvers from JSON: `demo/policies.json` and `data/approvers.json`, seeded from `demo/`.

To turn on the real integrations, set these in `.env`:

| Feature | Env |
|---|---|
| Claude egress | `ANTHROPIC_API_KEY`, `CLAUDE_MODEL` |
| Self-configured OpenAI-compatible egress (e.g. your own LiteLLM) | `EGRESS_PROVIDER=openai`, `EGRESS_BASE_URL`, `EGRESS_API_KEY` |
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

- `POST /v1/chat/completions`, `GET /v1/models`: OpenAI-compatible, streaming included. The first stream chunk carries the `airlock` metadata.
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

**Done:**
- Routing (`local/*`, `airlock/*`, `auto`) with **real token streaming**. Checks and approval finish before the first byte. A client that hangs up cancels the upstream, and the egress is still audited.
- Redaction and rehydration with session-stable placeholders, including placeholders split across stream chunks. Recognizers run in this order: rules → company dictionary → Presidio → local-model tagging of indirect identifiers (`REDACT_LLM=1`).
- **Local attack test** (`ATTACK_TEST`, on by default): before anything leaves, the local model tries to guess what's behind each placeholder. It's graded against the real mapping, so a hit is a measured leak and forces high risk.
- The policy decision table, including owner escalation for high risk.
- The approval flow: approve, deny, timeout, role-invalid and revoked.
- **Approval scope reuse** (`APPROVAL_SCOPE_MS`): follow-ups in the same session with no new entities and no higher risk ride on an earlier approval. The approver's ENS role is re-checked on every reuse, so a revocation also ends the scope.
- World ID 4.0 verification: RP signing, signal binding, replay guard.
- ENS: `npm run ens:setup` builds the whole name tree on ENSv2 Sepolia; `npm run ens` does check / set-policy / enroll / revoke / anchor.
- Hash-chain audit and a Merkle root, with per-request attribution (agent, token usage, `scopeOf`).
- Pluggable egress: Anthropic directly, or a self-configured OpenAI-compatible upstream. The ENS model allow-list is still enforced.
- The Console: airlock chamber, hold-to-approve, linked redaction view, hash-chain ledger, and a streamed "Try it" conversation.
- An agent skill ([skills/airlock/SKILL.md](skills/airlock/SKILL.md)) and a Docker image.

**Live and verified end to end (2026-09-26):**
- **World ID 4.0** (staging, via the World ID simulator): real proofs for enrollment and approval, with the same nullifier on both, so the role check holds.
- **ENSv2 on Sepolia:** `airlock.eth` with its policy, approver and audit records. Revoking by unregistering the subname → the next approval is `revoked`. Re-enrollment re-creates the subname. The audit root is anchored to `audit.airlock.eth`. See [docs/SETUP.md](docs/SETUP.md).

- **Egress via codex-lb** (OpenAI-compatible, local, `gpt-5.6-sol`): confidential text is redacted → approved with World ID + ENS role → sent to codex-lb → rehydrated locally, with 0 placeholders left and token usage audited. `ANTHROPIC_API_KEY` is optional.

**Deliberately not done:**
- **Next.js Console:** the single HTML page is served by the gateway with no build step. That keeps the trust boundary to one process.
- **Streaming tool-call deltas:** requests with `tools` use the buffered path.

See [docs/INTEGRATION-NOTES.md](docs/INTEGRATION-NOTES.md) for the ENS setup checklist.
