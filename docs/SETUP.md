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

## 2. ENS v2 on Sepolia

1. **Register a name.** Register your name at <https://app.ens.dev> (Sepolia, ENSv2). v2 registration pays in test ERC-20 (mint MockUSDC in the app); gas is Sepolia ETH.
2. **Create subnames.** Create `agents.<you>.eth`, `contract-agent.agents.<you>.eth`, `legal.approvers.<you>.eth`, `alice.legal.approvers.<you>.eth` and `audit.<you>.eth`.
3. **Set the resolver.** Point these names at a **PermissionedResolver** you control. Grant `ROLE_SET_TEXT` to the gateway address (`ENS_ADDRESS`) for the keys it writes (`airlock.approver` and `airlock.auditRoot`). Grants are per exact key, with no wildcards. Details are in [INTEGRATION-NOTES.md](INTEGRATION-NOTES.md).
4. **Configure `.env`:**
   ```
   SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
   ENS_RESOLVER=0x...          # your PermissionedResolver
   ENS_AUDIT_NAME=audit.<you>.eth
   DEFAULT_AGENT=contract-agent.agents.<you>.eth
   ```
5. **Write the policy records.** Rename the key in `demo/policies.json` to your agent name, then run:
   ```bash
   npm run ens -- set-policy contract-agent.agents.<you>.eth
   npm run ens -- check contract-agent.agents.<you>.eth alice.legal.approvers.<you>.eth
   ```
6. **Restart.** Policies and roles now come from ENS. Enrollment writes `airlock.approver` on-chain, and **Ledger → Anchor root to ENS** writes `airlock.auditRoot`.
7. **Revocation demo.** Unregister alice's subname in the ENS app, or run `npm run ens -- revoke alice.legal.approvers.<you>.eth`. Her next World ID approval passes the human check but fails the role check.
