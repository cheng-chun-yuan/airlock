---
name: airlock
description: Route LLM calls through the Airlock gateway so confidential text is redacted, policy-checked and human-approved before it reaches a frontier model. Use when an agent needs a model for work that may contain client names, contracts, personal data or secrets.
---

# Using Airlock

Airlock is an OpenAI-compatible gateway. Point any OpenAI client at `<airlock>/v1` (e.g. `https://airlock.polyoctant.com/v1`, or `http://localhost:8787/v1` self-hosted) with an Airlock API key as the bearer token: `Authorization: Bearer alk_…`.

- A member creates the key on their gateway's **Connect** page (it's shown once). The key alone picks the gateway and the person you act for; there is no other login.
- Each key runs under an agent's ENS policy: the agent an admin assigned to the member (or the gateway default policy), or, for an admin-made service key, the agent it was made for.
- The shared demo gateway has no API keys (Playground only); connect agents to your own gateway.

## Pick the model

| `model` | Use it for |
|---|---|
| `auto` | Default. The local model answers; the request escalates through Airlock only if the local answer is unsure. |
| `local/<name>` | Anything that must never leave the machine. |
| `airlock/<frontier-model>` | You specifically need the frontier model. Confidential text is redacted and may wait for a human. |

List what's available with `GET /v1/models`.

## Headers

- `x-airlock-session: <stable id per conversation>`: always send it. Placeholders (`<ORG_1>`) stay stable across turns, and an approval covers follow-ups that introduce no new sensitive entities.
- Identity and policy come from the key. `x-airlock-user` and `x-airlock-agent` sent by a client are ignored (replaced by the server); you can't pick a laxer agent.

## What to expect

- **Waiting is normal.** A confidential request is held until an approver clears it with World ID. That can take minutes (up to `APPROVAL_TIMEOUT_MS`), so use a long client timeout and don't retry while waiting; a retry creates a second approval request.
- **Not sent ≠ error.** If Airlock blocks or a human denies, you still get an answer from the local model. It starts with `> ⚠️ Airlock: not sent to … — <reason>`. Don't re-send the same content to get around it.
- **401 / 429.** A missing or deleted key gets 401 (removing a member deletes their keys). Chat requests are rate-limited per member per hour; a 429 says how many minutes to wait.
- **Real names come back.** Placeholders are replaced with real values locally before you see the answer, including tool-call arguments.
- **Metadata.** Non-streamed responses include an `airlock` object (`route`, `decision`, `entities`, `risk`, `scopeOf`). Streamed responses carry it on the first chunk. Headers `x-airlock-route` and `x-airlock-decision` are always set.

## Don'ts

- Don't paste secrets (API keys, card numbers, national IDs). They are classified restricted and never leave; the local model handles the request.
- Don't split a confidential document across several requests to dodge review. Each new entity triggers a new approval anyway.
