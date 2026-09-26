# Airlock

> **Local AI by default. Frontier AI by human consent. Accountability on-chain.**

**Airlock is an OpenAI-compatible gateway that stops AI agents from sending confidential data to frontier models unless a verified human with the right on-chain role approves that exact payload.**

- **Live demo:** <https://soil-foods-jam-conflicts.trycloudflare.com/console>. The access token is in the ETHGlobal submission.
- **ENS name:** [`airlock.eth`](https://app.ens.dev/airlock.eth) on ENSv2 Sepolia.
- **Built at:** ETHGlobal Tokyo 2026.

Agents (LibreChat, Hermes, Claude Code, anything that speaks the OpenAI API) point at Airlock instead of a model provider. Every request goes through the same airlock:

```
                    ┌──────────── ENSv2 (Sepolia) · airlock.eth ────────────┐
                    │ contract-agent.agents   → policy records               │
                    │ legal.approvers → alice → approver commitment          │
                    │ audit                   → Merkle root of the audit log │
                    └───────────▲───────────────────────▲────────────────────┘
                                │ policy / role          │ anchor
agent ──OpenAI API──▶  Router → Redactor → Risk (local attack test) → Policy → Approver → Egress → Rehydrator → Audit
  ▲                      │                                               │         │
  └── real names ◀───────┘ local model (GB10 vLLM)           World ID for Agents   frontier model
       restored locally      never leaves the box            (human approval)      (sees placeholders only)
```

1. **De-identify.** Names, companies, amounts, emails and IDs become stable labels (`<ORG_1>`) within a session. The mapping never leaves the gateway.
2. **Re-identification test.** The local model plays attacker and tries to work out who each label is. A correct guess is a measured leak and forces high risk.
3. **Decide.** The agent's policy is read live from ENS: `public/internal` → send; `confidential` → human approval; `restricted` → never leaves.
4. **Approve.** A verified human (World ID) whose ENS approver subname is live signs off on **this payload's hash**. Revoke the subname and they can't approve.
5. **Egress + rehydrate.** Only the redacted text goes out, streamed. Real names are put back locally, including in tool-call arguments.
6. **Audit.** Every decision is appended to a hash chain, and its Merkle root is anchored to `audit.airlock.eth`.

---

## 🧑‍⚖️ For judges: the 3-minute tour

Open the live demo. It lands on **Demo**: a 7-scene stepper, with the **agent** on the left and the **airlock** on the right. Press **Run scene ▸**, then **Next →**:

| # | Scene | What happens |
|---|---|---|
| 01 | Public | Nothing sensitive → sent automatically, still audited. |
| 02 | Confidential | **De-identified**: names become labels like `ORG·1` (shown readable for you; flip to *As the model sees it*) → **held** → *World ID for Agents* → **hold** to approve → the answer streams back with the real names. |
| 03 | Seal | Same request, sealed → the frontier model never sees it; the local model answers. |
| 04 | Revoked | **Revoke carol on ENS** (Sepolia tx) → carol is a verified human but her role is gone → **role check failed**, nothing sent. |
| 05 | Two humans | TSMC is de-identified, but the context gives it away → **high risk** → the ENS policy needs **two different humans**: alice ✓, the same person under another name ✗ (World ID), bob ✓ → released. |
| 06 | New agent | `intern-bot` was never registered → ENSv2 wildcard → org default policy → confidential data **blocked**, with zero setup. |
| 07 | Proof | **ENS** tab (agents linked to one shared policy, who may write which record key, audit anchor) · **Verify chain** · **Anchor to ENS**. |

Other tabs: **Queue** (every held request with the full airlock chamber), **Ledger** (hash chain), **ENS** (live ENSv2 state, plus approver enroll and lookup).

---|---|
| **Try it** | *Public question* is sent straight out. *Confidential contract* is held at the door. *Re-identifiable* is caught by the local attack test. *Restricted data* never leaves. The answers stream in with real names restored. |
| **Queue** | The request sits in the **airlock chamber**: Local → Redact → Policy → Human → Egress. Hover a `ORG·1` chip to see the real value, which stays local. Pick **World ID for Agents**, type `alice.legal.approvers.airlock.eth`, and **hold** the button (a tap does nothing). |
| **Ledger** | Every decision is a hash-chained block. **Walk the chain** re-verifies it. **Anchor root to ENS** writes the Merkle root to `audit.airlock.eth`. |
| **ENS** | Everything read **live** from Sepolia: the agent's policy records and who may write each one, whether the on-chain audit root matches the local ledger (**Anchor now**), the access-control matrix per record key, an approver lookup, and the name tree. |
| **Enroll** | Bind a World ID to an ENS approver name. The subname is created on-chain if it doesn't exist. |

### Built for the people who use it
| Who | What they get |
|---|---|
| **Employee** (talks to the agent) | Sends as themselves (`x-airlock-user`) with a **business reason** (`x-airlock-justification`). A **"Held for approval" card** in the chat says why, with a **Withdraw** button. The answer streams back with real names, or they see why it wasn't sent. |
| **Approver** (holds the ENS role) | Sees **who asks and why**, the de-identified text (readable, or *as the model sees it*), and the risk. Then **holds to approve** (World ID) or **Seals** with an optional **note** to the requester. **Browser notifications** arrive when a request is waiting. |
| **Security / compliance** | Live **ENS policy** and who may change it, a hash-chained **ledger** with stats (sent / cleared / sealed / fields kept private / tokens), **CSV/JSON export**, and one-click **anchoring** to ENS. Approvers can be **enrolled and revoked** from the ENS tab. |

Patterns borrowed from products teams already know: DLP policy tips with business justification (Microsoft Purview), review with a comment (GitHub pull requests), approval notifications (Slack/Teams approvals), and audit export (Okta / Google Workspace).

---

## 🌍 World: Best Use of World ID for Agents

**The trust moment:** an AI agent is about to send confidential text (client names, contract terms, money) to a third-party frontier model. It's the one point where "the agent decided" isn't enough, and the action can't be undone once the bytes leave. Airlock pauses the agent there and needs a **verified human, holding a live approver role, to approve this exact payload**.

**The two-person rule, which only World ID can enforce without KYC.** When the re-identification test finds high risk, the agent's ENS policy (`airlock.highRiskQuorum = 2`) requires **two different humans**.
- An account system can prove "two accounts" but not "two people", so one person with two logins could approve twice.
- World ID's nullifier is fixed per person and action, so Airlock refuses **the same human under a second approver name**. Verified with real proofs: alice ✓ → "bob" on the same World ID ✗ *"same person"* → bob as a different human ✓ → released, and the audit records both approvers.
- Airlock never learns who they are, only that they're two distinct verified humans who each hold the ENS role.

**Why World ID for Agents (Human Continuity):**
- Airlock needs to know that a **real human** consented to a specific agent action, not who that human is. Proof of personhood (`acr = …/orb-v3`) is the minimum sufficient assurance.
- Authority comes from ENS, not from World: *which* humans may approve is an on-chain role that can be revoked.

### Integration (the event's dev environment: `sandbox.auth.world.org`)
| Step | Implementation |
|---|---|
| Request | Authorization code + **PKCE S256**. The OIDC `nonce` = `H(approvalId, payloadHash, salt)`, so World's signed ID token commits to this one operation. Source: [`approval/src/oidc.ts`](approval/src/oidc.ts). |
| User completion | World's hosted ceremony, then back to `/oidc/callback`. |
| Validated result (**backend only**) | Token exchange with `client_secret_basic` (the secret never reaches the browser). ID token verified against the issuer's **JWKS**: RS256, `iss`, `aud`, **`nonce` matches this operation**, `auth_time` ≤ 5 min. `state` is single use. |
| Protected action | Only then does the payload leave. Approval is also re-checked for **payload hash equality** and **expiry** right before egress. Source: [`gateway/src/pipeline.ts`](gateway/src/pipeline.ts). |
| Unsuccessful paths | Cancel at World (`access_denied`) → **denied, nothing sent**. Replayed callback → 403. Timeout → expired. Verified human **without a live ENS role**, or **revoked** → denied, nothing sent. Every one of these falls back to the local model and is audited. |

All of the above was tested against the **real** `sandbox.auth.world.org`, with egress to a real frontier model; details in [docs/SETUP.md](docs/SETUP.md). Airlock also supports **IDKit (World ID 4.0 Proof of Human)** as a second approval method, with the signal bound to `payloadHash`. It was verified with real staging proofs through the World ID simulator.

### Integration debrief
- **Time to first success:**
  - IDKit v4: about 30 minutes from app credentials to the first verified proof, most of it spent on the four issues below.
  - World ID for Agents: about 15 minutes from client credentials to the first verified end-to-end approval, because we had built the flow against a mock IdP first.
- **Friction we hit:**
  1. `/api/v4/verify` answered **`app_not_migrated`** for an app whose RP was already registered. The fallback v2 endpoint then answered **"Action not found"**: v2 doesn't auto-create actions, while v4 does. We only found the fix (`create_world_id_action` via the Portal MCP) by probing both endpoints.
  2. Staging proofs need a **24-hour staging verification window token** (`x-staging-verification-token`). This is only discoverable through the Portal MCP's instructions.
  3. The **IDKit CDN build fails WASM init**. We now serve `idkit.global.js` and the `.wasm` from `node_modules`.
  4. The docs say v4 **nullifiers are "one-time-use"**, yet the portal reports "nullifier reuse", and our tests show they're deterministic per (RP, action, human). We depend on that for role binding, so the docs should say so clearly.
  5. The **Human Continuity sandbox issues a new `sub` on every sign-in** (a fresh test human, auto-completed ceremony). Apps therefore can't test *binding an identity to an account* in the sandbox. We added an explicit, audited **name-binding** mode for the sandbox: World proves a human approved this payload, and ENS proves the claimed approver is live. On production the mode is **commitment binding** (the enrolled identity must match).
- **Missing capabilities:**
  - a sandbox test user with a **stable `sub`**;
  - a documented way to put **operation context** into the ceremony UI (what the human is approving);
  - a verify-side check of the nonce/action binding, like `signal_hash` for IDKit.
- **Priority improvements:**
  1. a stable sandbox identity;
  2. one page listing the v4 prerequisites (RP registration, action, staging token);
  3. a CDN build that initializes WASM.

---

## 🔷 ENS: Best Use of ENSv2

ENS isn't a label here; it is Airlock's **policy engine, role registry and audit anchor**. Every decision reads live records, and nothing is hardcoded.

```
airlock.eth                                   UserRegistry (own subregistry), no resolver
├─ agents.airlock.eth                         UserRegistry, no resolver
│   └─ contract-agent.agents.airlock.eth      PermissionedResolver
│        airlock.maxClass     = confidential      ← highest data class this agent may send out
│        airlock.egress       = approval          ← auto | approval | block
│        airlock.models       = gpt-*,claude-*    ← frontier models it may use
│        airlock.approverRole = legal.approvers.airlock.eth
├─ approvers.airlock.eth                      UserRegistry, no resolver
│   └─ legal.approvers.airlock.eth            UserRegistry, no resolver   ← the approver ROLE
│       └─ alice.legal.approvers.airlock.eth  PermissionedResolver, 180-day expiry
│            airlock.approver = commitment(World ID identity)   ← never the raw identifier
└─ audit.airlock.eth                          PermissionedResolver
     airlock.auditRoot = Merkle root of the gateway's hash-chained audit log
```

| ENSv2 feature | What it does in Airlock |
|---|---|
| **Hierarchical subname registries** (a `UserRegistry` per level) | Roles are namespaces: *being an approver* means holding a live subname under `legal.approvers.airlock.eth`. |
| **Expiry + `unregister`** | Approvals expire with the subname. Revoking = unregistering → the next approval by that human is **denied**, and any session approval scope they opened ends too. |
| **PermissionedResolver** (records keyed by name, `setText(bytes name, …)`) | One resolver serves every leaf. Policy, approver commitments and the audit root live there. |
| **Enhanced Access Control** (per-record-key roles) | **Write access is split by record key.** A **security account** is the resolver's sole admin and the only key that can change policy records (`maxClass`, `egress`, `models`, `approverRole`, `ownerRole`). The **gateway** holds `ROLE_SET_TEXT` only on `airlock.approver` and `airlock.auditRoot` (granted with `grantSetterRoles`; its root roles are revoked), so a stolen gateway key can't loosen any agent's policy. Verified on-chain: gateway `setText(airlock.models)` reverts. Source: [`npm run ens:eac`](registry/scripts/ens-eac.ts). Subname tokens carry their own roles (unregister, renew, set resolver). |
| **Record aliasing** (`linkToNode`) | `contract-agent` and `nda-agent` **link** to one shared record, `legal.policies.airlock.eth` (same record id #8). The security account edits the policy **once** and every linked agent follows; there's no per-agent drift. |
| **Wildcard resolution + resolver default record** | `agents.airlock.eth` points at the resolver, and the resolver's default record (node 0) holds the **org default policy** (`maxClass = internal`). An agent that was **never registered** (e.g. `intern-bot`) resolves to it automatically, so confidential data can't leave with zero setup. Approver names stay revocable because their parents have no resolver. |
| **Policy as records** | `airlock.highRiskQuorum = 2`: how many different humans must approve high-risk egress, set on-chain by the security account. |
| **Universal Resolver v2** | The gateway reads everything through it, so any ENS client sees the same policy. |

**Design finding:** the PermissionedResolver answers wildcard (ENSIP-10) lookups by full name. If a *parent* like `legal.approvers.airlock.eth` pointed at it, an **unregistered** `alice` would fall back to the parent's resolver and still resolve her commitment, so revocation would silently fail. **Only leaves get a resolver.** We verified on-chain that unregistering alone makes the approver resolve to nothing.

**On-chain evidence** (Sepolia):
- **Name:** `airlock.eth` registered in tx [`0x6452cf5e…`](https://sepolia.etherscan.io/tx/0x6452cf5e91c6c1437b237a6275f31f13d8c8b7f435b3d9efa21087e65656b377).
- **Records:** multicall [`0x65292570…`](https://sepolia.etherscan.io/tx/0x65292570b9d3c029392dba4f00af8b22cadb61d01288a56cfbbd05cf4a89dbaa).
- **Audit anchor:** [`0xf5c095b7…`](https://sepolia.etherscan.io/tx/0xf5c095b781713c5dc4291c038af79d51289cc11e1a461b78dbbe14a0fd49f758).
- **Contracts:**
  - PermissionedResolver [`0x0c47Bc81…`](https://sepolia.etherscan.io/address/0x0c47Bc813361aEB3d0aD84f8F642bCce0e34B7F4)
  - registries: root [`0xcfAC3D22…`](https://sepolia.etherscan.io/address/0xcfAC3D225b371fe4dD1a939bb8bcd0B9697C61aa), agents [`0x3A6759DD…`](https://sepolia.etherscan.io/address/0x3A6759DDb877aD4f370C9D5638FE886a6b0912D1), approvers [`0xFA9DA14A…`](https://sepolia.etherscan.io/address/0xFA9DA14AF7038A24B17Eb98d65b0BED278925733), legal [`0x12F22d6a…`](https://sepolia.etherscan.io/address/0x12F22d6a77F14815D8ac374715cad5d56ae41a2E)
- **EAC split** (Sepolia):
  - security admin grant [`0x07e6f01b…`](https://sepolia.etherscan.io/tx/0x07e6f01be423afa5acaeb25ea3f3a9b801c39c229fb87baa917da74ca42e05eb)
  - gateway per-key grants [`0x84f0d540…`](https://sepolia.etherscan.io/tx/0x84f0d54084bdc6808d8798881c7c1dc4a2936263fb676b6f345d6a4266f6f319) (approver) and [`0x7922fe04…`](https://sepolia.etherscan.io/tx/0x7922fe04130492363fa7c3a66aeee95bc52e230e719b28848a3575c822a8ce0a) (auditRoot)
  - gateway root roles revoked [`0x11d0c69d…`](https://sepolia.etherscan.io/tx/0x11d0c69dac2b0f20617731c7c07907ce3decbbd9dba1fb9e50292ab463a449fd)
- **Shared policy + wildcard default** (Sepolia):
  - legal policy written by security [`0xd36b3fbb…`](https://sepolia.etherscan.io/tx/0xd36b3fbb8582a95139bf7e839a78ed4de541445121d5655dbc2bd68705c371a5)
  - links: contract-agent [`0x559d8ef1…`](https://sepolia.etherscan.io/tx/0x559d8ef13308a9d2eb62d2949a8024119b12d10305ddbbb267bb49884fd54512), nda-agent [`0x1893fe12…`](https://sepolia.etherscan.io/tx/0x1893fe128340ac36639b02028aee9b0c570702f290dfb121aeee8a8ac8291a94)
  - org default record [`0x33709462…`](https://sepolia.etherscan.io/tx/0x33709462ee7a056aca907c280c767958ca4c80d7928f8bdb2107246eaaf9a4c4)
  - `agents.airlock.eth` wildcard resolver [`0xb176e942…`](https://sepolia.etherscan.io/tx/0xb176e94254ea7520fdcca6a9b3712047389ffce153e0f12db7c355d95cf1ea4b)
- **Reproduce the whole tree:** `npm run ens:setup -- <name> <approver>`, then `npm run ens:eac` and `npm run ens:policies`. **Inspect it:** `npm run ens -- check contract-agent.agents.airlock.eth alice.legal.approvers.airlock.eth`.

**AI agents:** each agent is an ENS name whose records *are* its egress policy. Changing `airlock.models` or `airlock.egress` on-chain changes what the agent is allowed to do on the next request, with no redeploy.

---

## Run it

```bash
npm install
npm start                                   # gateway + Console on :8787
npm test                                    # 17 unit tests (redaction, policy, World ID, OIDC vs mock IdP, …)
npm run ens -- check contract-agent.agents.airlock.eth
```

- **Zero config:** runs with a mock World ID and JSON policies.
- **Real World ID, ENS, OIDC and egress:** see [docs/SETUP.md](docs/SETUP.md).
- **Upstreams:** anything OpenAI-compatible (we use a local **codex-lb** with `gpt-5.6-sol`) or Anthropic directly. The ENS `airlock.models` record decides which models are allowed.
- **Before exposing publicly:** set `AIRLOCK_ACCESS_TOKEN`. Clients send `Authorization: Bearer`; browsers open `/console?token=…` once.

### Models
| `model` | Behaviour |
|---|---|
| `local/<name>` | Local model only. Nothing leaves. |
| `airlock/<model>` | Full airlock: redact → attack test → ENS policy → (human approval) → egress → rehydrate. |
| `auto` | Local first; escalates through the airlock only if the local answer is unsure. |

Headers:
- `x-airlock-session`: keeps placeholders stable, and lets follow-ups reuse an approval when no new sensitive entity appears (the approver's ENS role is re-checked on every reuse).
- `x-airlock-agent`: the ENS name of the agent's policy.

## Repo layout
```
gateway/        Hono server: router, pipeline (plan/execute, streaming), egress clients, access gate
packages/core/  types, interfaces, policy decision table
redactor/       rules + dictionary + Presidio + local-LLM recognizers, stream rehydrator, local attack test
approval/       approval queue/SSE, World ID 4.0 (IDKit) verifier, World ID for Agents (OIDC)
registry/       ENSv2 resolvers/writer (viem), ens:setup (whole name tree), ens CLI
audit/          hash-chained JSONL, Merkle root, ENS anchoring
console/        single-page Console (chamber, hold-to-approve, linked redaction view, ledger, live ENS panel, enroll, try it)
skills/airlock/ agent skill: how an agent should use Airlock
docs/           ARCHITECTURE (中文), SETUP, INTEGRATION-NOTES, REFERENCES, SUBMISSION (form text, video script, checklist)
```

## Honest limitations
- The World ID for Agents sandbox issues a new `sub` per sign-in, so the demo uses **name binding**, which is audited. Commitment binding is the production mode.
- The live demo runs on a Cloudflare quick tunnel to the machine we hacked on (GB10). The URL changes if the tunnel restarts.
- Requests with `tools` use the buffered (non-streaming) path.
- Redaction is rules + dictionary + optional Presidio/local LLM. It reduces what leaves; it doesn't prove nothing sensitive leaves, which is why the attack test and the human exist.
