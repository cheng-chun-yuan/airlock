---
name: airlock
description: Route LLM calls through the Airlock gateway so confidential text is redacted, policy-checked and human-approved before it reaches a frontier model. Use when an agent needs a model for work that may contain client names, contracts, personal data or secrets.
---

# Using Airlock

Airlock is an OpenAI-compatible gateway (default `http://localhost:8787/v1`). Point any OpenAI client at it; no API key is needed on the client side.

## Pick the model

| `model` | Use it for |
|---|---|
| `auto` | Default. The local model answers; the request escalates through Airlock only if the local answer is unsure. |
| `local/<name>` | Anything that must never leave the machine. |
| `airlock/<frontier-model>` | You specifically need the frontier model. Confidential text is redacted and may wait for a human. |

List what's available with `GET /v1/models`.

## Headers

- `x-airlock-session: <stable id per conversation>`: always send it. Placeholders (`<ORG_1>`) stay stable across turns, and an approval covers follow-ups that introduce no new sensitive entities.
- `x-airlock-agent: <agent>.agents.<org>.eth`: the ENS policy you're acting under.

## What to expect

- **Waiting is normal.** A confidential request is held until an approver clears it with World ID. That can take minutes (up to `APPROVAL_TIMEOUT_MS`), so use a long client timeout and don't retry while waiting; a retry creates a second approval request.
- **Not sent ≠ error.** If Airlock blocks or a human denies, you still get an answer from the local model. It starts with `> ⚠️ Airlock: not sent to … — <reason>`. Don't re-send the same content to get around it.
- **Real names come back.** Placeholders are replaced with real values locally before you see the answer, including tool-call arguments.
- **Metadata.** Non-streamed responses include an `airlock` object (`route`, `decision`, `entities`, `risk`, `scopeOf`). Streamed responses carry it on the first chunk. Headers `x-airlock-route` and `x-airlock-decision` are always set.

## Don'ts

- Don't paste secrets (API keys, card numbers, national IDs). They are classified restricted and never leave; the local model handles the request.
- Don't split a confidential document across several requests to dodge review. Each new entity triggers a new approval anyway.
