# Setup: World ID and ENS on Sepolia

Everything below is optional. With no config, Airlock runs with a mock World ID and demo JSON policies.

## 0. Keys

The gateway's Sepolia key lives in `.env` (gitignored) as `ENS_PRIVATE_KEY`, with its address in `ENS_ADDRESS`. Fund it with Sepolia ETH (~0.05 is plenty) from any Sepolia faucet. Check the balance:

```bash
node --input-type=module -e 'import {createPublicClient,http,formatEther} from "viem";import {sepolia} from "viem/chains";const c=createPublicClient({chain:sepolia,transport:http("https://ethereum-sepolia-rpc.publicnode.com")});console.log(formatEther(await c.getBalance({address:process.argv[1]})),"ETH")' $(grep ENS_ADDRESS .env | cut -d= -f2)
```

## 1. World ID 4.0

**Verified end to end (2026-09-26)** against World's staging network, with the World ID simulator acting as the phone:
1. Enroll → real proof → commitment stored.
2. Approve with a second real proof → same nullifier → role `valid` → approved.
3. The same human claiming another approver's name → `role_invalid`.

### With the Developer Portal MCP (what we used)

```bash
claude mcp add worldcoin-developer-portal https://developer.world.org/api/mcp --transport http --header "Authorization: Bearer <team API key>"
```

1. **Check the app.** `get_app_config {app_id}` should show a managed RP with `status: registered`, whose `signer_address` matches your RP signing key. If there's no RP, run `configure_world_id {app_id}` and save the returned private key once.
2. **Create the action.** `create_world_id_action {app_id, action: "airlock-approve", environment: "staging"}`, plus `"production"`. Enrollment and approval **share this one action**: nullifiers are deterministic per (RP, action, person), so the enrolled commitment matches at approval. Each approval is bound to its payload by the signal (`payloadHash`).
3. **Open the staging window.** `set_world_id_staging_verification {app_id, enabled: true}` opens a **24-hour window**. Put the token it returns (shown once) in `.env` as `WORLD_STAGING_TOKEN`. The gateway sends it as `x-staging-verification-token`. When the window expires, run the call again.
4. **Configure `.env`:**
   ```
   WORLD_APP_ID=app_...
   WORLD_RP_ID=rp_...
   WORLD_RP_SIGNING_KEY=0x...
   WORLD_ENV=staging
   WORLD_STAGING_TOKEN=...
   # WORLD_PROOF=legacy   # v3 Orb proofs instead of native v4 Proof of Human
   ```
5. **Restart.** The Console header shows `world id worldid`.
6. **Enroll.** Console → **Enroll** → type an ENS name → scan the QR code. Without a phone, use the **World ID simulator**: paste the link at <https://simulator.worldcoin.org>, or have an agent call `complete_test_request {connect_url}` on the simulator MCP (`https://simulator.worldcoin.org/api/mcp`, no key).
7. **Approve.** Queue → type the same ENS name → hold **open outer door** → scan.

### Notes
- **Proof type:** the default is native **World ID 4.0 Proof of Human** (`proofOfHuman`, `min_protocol_version: "4.0"`), which is what the simulator supports. `WORLD_PROOF=legacy` switches to v3 Orb proofs. For apps not migrated to 4.0, those fall back to `/api/v2/verify`, where the action must already exist in the portal.
- **IDKit is served locally.** The gateway serves the browser bundle and its WASM from `node_modules` at `/vendor/idkit/`, because the CDN build fails WASM initialization.
- **Replays:** v4 accepts nullifier reuse (with a message), so the gateway rejects replays itself.

### World ID for Agents (Human Continuity OIDC) — the event's dev environment

1. **Register a client.** Go to <https://sandbox.auth.world.org/portal>. The redirect URI must be **public HTTPS**, e.g. `https://<tunnel>/oidc/callback`; localhost isn't accepted. Use auth method `client_secret_basic`.
2. **Configure `.env`:**
   ```
   WORLD_OIDC_CLIENT_ID=...
   WORLD_OIDC_CLIENT_SECRET=...
   WORLD_OIDC_REDIRECT_URI=https://<tunnel>/oidc/callback
   # WORLD_OIDC_ISSUER=https://sandbox.auth.world.org
   # WORLD_OIDC_BINDING=name|commitment   # default: name on the sandbox, commitment elsewhere
   ```
3. **Use it.** In the Console, choose **World ID for Agents** when approving or enrolling.

**Verified against the real sandbox (2026-09-26):**
- An agent request is held → World sign-in → ID token verified (RS256 via JWKS, `aud`, `iss`, **nonce = H(approval, payloadHash)**, `auth_time`) → ENS role → egress to codex-lb → rehydrated. ✅
- Cancel (`access_denied`) → denied, nothing sent. ✅
- A replayed `state` → rejected. ✅
- A revoked (unregistered) approver → `revoked`, nothing sent. ✅

**Sandbox behaviour worth knowing (also debrief feedback):**
- The sandbox runs its own test ceremony automatically (`ceremony → approve → complete`), with no human step and no phone.
- It returns a **new `sub` on every sign-in** (a fresh test human each time), with `acr = …/orb-v3`. So binding one World identity to one approver can't be tested there. In the sandbox the gateway therefore uses **name binding**: World proves *a* verified human approved *this exact payload*, and ENS proves the claimed approver name is a live, unrevoked subname under the role. On a production issuer, set `WORLD_OIDC_BINDING=commitment` to require the enrolled identity. The binding used is written to every audit record (`identityBinding`).

## 2. ENS v2 on Sepolia

**Live:** `airlock.eth` was set up on 2026-09-26 with the script below, and verified end to end. World ID proofs (simulator) + ENS role reads, on-chain revocation (unregister) → `revoked`, re-enrollment, and the audit root anchored to `audit.airlock.eth` (it matches the gateway's Merkle root).

```bash
npm run ens:setup -- airlock alice      # <name> <first approver label> [commitment]
```

The script is resumable; progress is kept in `data/ens-deploy.json`. It does the following:
1. **Deploys** a PermissionedResolver and four UserRegistry proxies through ENS's VerifiableFactory.
2. **Registers** `airlock.eth`: mints MockUSDC for the ~8 USDC/year fee, then commit → wait 60s → register.
3. **Creates the subnames:**
   ```
   airlock.eth                               registry, no resolver
   ├─ agents.airlock.eth                     registry, no resolver
   │   └─ contract-agent.agents.airlock.eth  resolver: airlock.maxClass / egress / models / approverRole / ownerRole
   ├─ approvers.airlock.eth                  registry, no resolver
   │   └─ legal.approvers.airlock.eth        registry, no resolver   ← approver role
   │       └─ alice.legal.approvers…         resolver: airlock.approver = commitment (180-day expiry)
   └─ audit.airlock.eth                      resolver: airlock.auditRoot
   ```
4. **Writes** the policy records and alice's commitment (from `data/approvers.json`, or the third argument).
5. **Prints** the `.env` lines: `SEPOLIA_RPC_URL`, `ENS_RESOLVER`, `ENS_APPROVER_REGISTRY`, `ENS_AUDIT_NAME`, `DEFAULT_AGENT`.

**Why only leaves have resolvers:** the PermissionedResolver stores records by full name and answers wildcard (ENSIP-10) lookups. If a parent such as `legal.approvers.airlock.eth` had it as its resolver, an **unregistered** `alice` would fall back to the parent's resolver and still resolve her old commitment, so revocation would silently fail. With no resolvers on parents, an unregistered approver resolves to nothing. Tested on-chain: unregister alone → text `null` → role `revoked`.

**Day to day:**
```bash
npm run ens -- check contract-agent.agents.airlock.eth alice.legal.approvers.airlock.eth
npm run ens -- enroll bob.legal.approvers.airlock.eth <commitment>   # creates the subname if needed
npm run ens -- revoke alice.legal.approvers.airlock.eth               # unregister + clear record
```
In the Console, **Enroll** creates the subname and writes the commitment, and **Ledger → Anchor root to ENS** writes `airlock.auditRoot`.

**Contract addresses** (ENSv2 Sepolia deployment of 2026-09-15; override with env if ENS redeploys): ETHRegistrar `0xabe7…94ca`, VerifiableFactory `0x9e72…841c`, UserRegistryImpl `0xa803…0263`, PermissionedResolverImpl `0x14f0…f243`, MockUSDC `0x16f9…aa8e`. The universal resolver is viem's default `0xeeee…eeee`.
