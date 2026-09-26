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
- Live demo: https://soil-foods-jam-conflicts.trycloudflare.com/console?token=<AIRLOCK_ACCESS_TOKEN>. Put the real token in the form, not in git. Rotate it after judging.
- ENS: https://app.ens.dev/airlock.eth

## Tracks

### World: Best Use of World ID for Agents
| Requirement | Where |
|---|---|
| Official World ID for Agents on the event dev environment | `sandbox.auth.world.org` OIDC ([approval/src/oidc.ts](../approval/src/oidc.ts)) |
| Full journey: request → user completes → validated → protected action | Queue → *World ID for Agents* → hold → World → `/oidc/callback` → egress. Verified against the real sandbox |
| Denied / cancelled / expired path where the action doesn't happen | cancel (`access_denied`), timeout, no role, revoked role, replayed callback; all audited, nothing sent |
| Secure backend validation, no client secrets | token exchange + JWKS verification in the gateway; the secret lives only in `.env` |
| Integration debrief | README → *Integration debrief* |

### ENS: Best Use of ENSv2
| Requirement | Where |
|---|---|
| Built on ENSv2 (Sepolia) | `airlock.eth`; contracts and txs in the README |
| ENSv2 central, not cosmetic | policy engine (agent records), role registry (subname under role, expiry, unregister = revoke), EAC write split, audit anchor |
| Functional, not hardcoded | every request reads ENS live; the Console's ENS tab reads it live; changing `airlock.models` on-chain changes behaviour |
| Live demo link | tunnel URL above |
| Open source | GitHub |
| Bonus: AI agents | each agent *is* an ENS name whose records are its egress policy |

## Demo video (≈3 min): follow the **Demo** tab

Open the live demo. The Console lands on **Demo**: a 6-scene stepper on top, the **Agent** conversation on the left and the **Airlock** (chamber + approval) on the right. For each scene, press **Run scene ▸**, then **Next →**. Everything is one screen, and World ID opens in a popup so the agent's stream keeps running.

| Time | Scene | Do | Say |
|---|---|---|---|
| 0:00 | (title) | Show the Demo tab | "Agents leak data the moment they call a frontier model. Airlock is the airlock between them, and it's also an ENS-governed, human-approved gateway." |
| 0:15 | **01 Public** | Run | "Nothing sensitive, so it's sent automatically. Every decision is still audited." (Airlock: *Sent automatically*) |
| 0:30 | **02 Confidential** | Run → point at the **De-identified** box → flip to **As the model sees it** → *World ID for Agents* → **hold** the button | "First we de-identify: names, money and email become labels. I can read them here; the model only ever gets `ORG·1`, `PERSON·1`, and the mapping never leaves the box. The local model already tried to re-identify them and failed, so risk is low. Policy comes from ENS: approval by someone holding `legal.approvers.airlock.eth`. A tap does nothing; I hold to open the outer door." → popup → **CLEARED**, the door opens, the answer streams with real names. |
| 1:10 | **03 Seal** | Run → **Seal** | "Same request, but I seal it. The frontier model never sees it; the local model answers instead." |
| 1:25 | **04 Revoked** | **Revoke carol on ENS** (Sepolia tx) → Run → hold | "Carol is a real human. I just unregistered her ENS approver subname. World ID passes, the ENS role check fails, and nothing is sent. Revocation is one on-chain call." |
| 1:55 | **05 Re-identification test** | Run → **Seal** | "De-identification alone isn't enough. TSMC became `ORG·1`, but the context still describes it. Before anything leaves, our local model plays attacker, re-identifies it, and risk goes high: now only the data owner's role could approve." |
| 2:20 | **06 Proof** | **Open ENS** → back → **Walk the chain** → **Anchor to ENS** | "The agent's policy *is* its ENS records. Only the security key can change them; the gateway may only write approvers and the audit root. That's ENSv2 Enhanced Access Control per record key. Every decision is hash-chained, and the root is anchored to `audit.airlock.eth`." |
| 2:50 | (end) | | "Local AI by default. Frontier AI by human consent. Accountability on-chain." |

## Pre-demo checklist
- [ ] `docker ps` shows `airlock-tunnel` and `codex-lb` up; `curl localhost:8000/v1/models` (vLLM) answers.
- [ ] Gateway up: `npm start` (the Console header says `world id worldid + agents · ens sepolia (read/write)`).
- [ ] The tunnel URL is unchanged. If it changed, update the OIDC redirect URI in the World portal and `PUBLIC_URL` / `WORLD_OIDC_REDIRECT_URI` in `.env`.
- [ ] `carol.legal.approvers.airlock.eth` is **live** before scene 04: ENS tab → Approvers → enroll `carol.legal.approvers.airlock.eth` with World ID for Agents (or `npm run ens -- enroll carol.legal.approvers.airlock.eth 0x01`). Scene 04 revokes her, so re-enroll between takes.
- [ ] Allow popups for the demo URL (World ID for Agents opens in a popup).
- [ ] For IDKit only: the staging window is open. It expires 24h after opening; reopen it via the Portal MCP `set_world_id_staging_verification`.
- [ ] Fresh ledger for recording: stop the gateway, `rm data/audit.jsonl`, start it, then *Anchor now* at the end.
- [ ] After judging: rotate `AIRLOCK_ACCESS_TOKEN`, the World OIDC client secret, the RP signing key and the Portal team API key.
