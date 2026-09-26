# ETHGlobal Tokyo 2026: submission pack

## Form fields

**Project name:** Airlock

**Short description** (under 100 characters):
> Local AI by default. Frontier AI only when a verified human with an ENS role approves the exact payload.

**Description:**
> AI agents leak confidential data the moment they call a frontier model. Airlock is an OpenAI-compatible gateway that any agent (LibreChat, Hermes, Claude Code) can point at instead of a model provider. It works in six steps:
>
> 1. **Local by default.** Requests are answered by a local model.
> 2. **Redact.** When an agent needs a frontier model, Airlock replaces names, companies, amounts and IDs with placeholders.
> 3. **Attack-test.** The local model tries to re-identify the placeholders; a correct guess forces high risk.
> 4. **Read the policy from ENS.** The agent's egress policy comes from ENSv2 records.
> 5. **Human approval.** For confidential data, Airlock pauses the agent until a human approves through World ID for Agents. The approval is bound to the payload's hash, and the approver must hold a live ENS subname under the approver role. Revoke the subname and the approval fails.
> 6. **Send, restore and audit.** Only the redacted text leaves, streamed. Real names are restored locally. Every decision is appended to a hash-chained audit log whose Merkle root is anchored to ENS.

**How it's made:**
> - **Gateway:** TypeScript monorepo with a Hono server that speaks the OpenAI API, including streaming. It uses a local Qwen 3.5 on vLLM (NVIDIA GB10) and a local codex-lb (`gpt-5.6-sol`) as the frontier upstream.
> - **Redaction:** rules + company dictionary + optional Presidio + local-LLM tagging. A streaming rehydrator handles placeholders split across tokens.
> - **World ID for Agents:** Human Continuity OIDC on the event sandbox, using the authorization code flow with PKCE. The OIDC nonce is a hash of the approval id and payloadHash. The ID token is verified in the backend against JWKS (iss, aud, nonce, auth_time), and `state` is single use.
> - **IDKit:** World ID 4.0 Proof of Human is also supported, with the signal bound to payloadHash. It was verified with real staging proofs.
> - **ENSv2 on Sepolia:** a script builds the whole name tree with viem: a UserRegistry per level, a PermissionedResolver, MockUSDC commit-reveal registration, and subnames with expiry. The Enhanced Access Control split lets only a security account change policy records, while the gateway may write only `airlock.approver` and `airlock.auditRoot`.
> - **Design finding:** only leaf names get a resolver. Otherwise the wildcard lookup of the name-keyed resolver lets unregistered approvers keep resolving.
> - **Console:** a single HTML page with the chamber view, hold-to-approve, linked redaction view, ledger and a live ENS panel.
> - **Tests:** 17 unit tests, including OIDC against a mock IdP, plus end-to-end runs against the real World sandbox and Sepolia.

**Links:**
- GitHub: https://github.com/cheng-chun-yuan/airlock
- Live: https://airlock.polyoctant.com/?token=<AIRLOCK_ACCESS_TOKEN>. Put the real token in the form, not in git. Rotate it after judging.
- ENS: https://app.ens.dev/airlock.eth

## Tracks

### World: Best Use of World ID for Agents
| Requirement | Where |
|---|---|
| Official World ID for Agents on the event dev environment | `sandbox.auth.world.org` OIDC ([approval/src/oidc.ts](../approval/src/oidc.ts)) |
| Full journey: request → user completes → validated → protected action | Approvals → *World ID for Agents* → hold → World → `/oidc/callback` → egress. Verified against the real sandbox |
| Denied / cancelled / expired path where the action doesn't happen | cancel (`access_denied`), timeout, no role, revoked role, replayed callback; all audited, nothing sent |
| Secure backend validation, no client secrets | token exchange + JWKS verification in the gateway; the secret lives only in `.env` |
| Integration debrief | README → *Integration debrief* |

### ENS: Best Use of ENSv2
| Requirement | Where |
|---|---|
| Built on ENSv2 (Sepolia) | `airlock.eth`; contracts and txs in the README |
| ENSv2 central, not cosmetic | policy engine (agent records), role registry (subname under role, expiry, unregister = revoke), EAC write split, audit anchor |
| Functional, not hardcoded | every request reads ENS live; the Console's Agents page reads it live; changing `airlock.models` on-chain changes behaviour |
| Live link | https://airlock.polyoctant.com |
| Open source | GitHub |
| Bonus: AI agents | each agent *is* an ENS name whose records are its egress policy |

## Demo video (≈3 min): walk the product

Two browser windows side by side: the **requester** on Playground, the **approver** on Approvals (each with its own profile). World ID opens in a popup, so the agent's stream keeps running.

| Time | Page | Do | Say |
|---|---|---|---|
| 0:00 | Overview | Show status and today's decisions | "Agents leak data the moment they call a frontier model. Airlock is the airlock between them: local AI by default, frontier AI only with human consent." |
| 0:15 | Playground | Example *Public question* → Send | "Nothing sensitive, so it's sent automatically, and still audited." |
| 0:30 | Playground → Approvals | Example *Contract review* → Send; approver: flip **Readable / As the model sees it** → **hold** → World ID for Agents | "Names, money and email become labels. The approver reads them; the model only gets `ORG·1`. The policy comes from the agent's ENS name: legal must approve. Hold, verify with World ID." → CLEARED, answer streams back with real names. |
| 1:10 | Approvals | Same request again → **Seal** with a note | "Sealed: the frontier model never sees it; the local model answers and the requester sees why." |
| 1:25 | Approvers | **Revoke** an approver → try to approve as them | "Revocation is one ENS transaction; MultiBaas pushes it to the gateway at once. World ID still passes, the role check fails, nothing is sent." |
| 1:50 | Playground → Approvals | Example *Client pricing* → approve as `bob` (1 of 2) → same World ID as `alice` → refused, still 1 of 2 | "The re-identification test catches TSMC, so risk is high and ENS requires two different humans. The same World ID under another name is refused: World ID knows it's the same person without knowing who. Only a second, different human can release it." |
| 2:25 | Playground | Agent `intern-bot` → *Contract review* | "An agent nobody registered gets the org default through ENSv2 wildcard resolution: confidential data blocked, zero setup." |
| 2:40 | Agents → Audit | Linked policy + access matrix → **Verify chain** → **Anchor to ENS** | "Only the security key can change policy. Every decision is hash-chained and anchored to ENS." |
| 2:50 | | | "Local AI by default. Frontier AI by human consent. Accountability on-chain." |

## Pre-demo checklist
- [ ] `docker ps` shows `airlock-named-tunnel` and `codex-lb` up; `curl localhost:8000/v1/models` (vLLM) answers.
- [ ] Gateway up: `npm start` (the Console header says `world id worldid + agents · ens sepolia (read/write)`).
- [ ] The World OIDC client lists `https://airlock.polyoctant.com/oidc/callback` as a redirect URI (matches `WORLD_OIDC_REDIRECT_URI` in `.env`).
- [ ] At least two approvers are **live** (Approvers page), each enrolled with World ID. A revoked approver comes back only by enrolling again with World ID.
- [ ] Allow popups for the demo URL (World ID for Agents opens in a popup).
- [ ] The two-person segment needs two live approvers (`bob`, `alice`). The "same human" moment needs nothing extra: in one browser the World ID for Agents sandbox returns the same identity, so the second name is refused. Releasing the request needs a second human on their own device (not shown in the video).
- [ ] `carol` is live again before recording (the Revoke segment unregisters her): Approvers → `carol.legal.approvers.airlock.eth` → Enroll with World ID. Always type the full ENS name.
- [ ] For IDKit only: the staging window is open. It expires 24h after opening; reopen it via the Portal MCP `set_world_id_staging_verification`.
- [ ] Fresh ledger for recording: stop the gateway, `rm data/audit.jsonl`, start it, then *Anchor now* at the end.
- [ ] After judging: rotate `AIRLOCK_ACCESS_TOKEN`, the World OIDC client secret, the RP signing key and the Portal team API key.
