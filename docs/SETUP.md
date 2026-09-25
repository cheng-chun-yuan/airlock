# Setup: World ID and ENS on Sepolia

Everything below is optional. With no config, Airlock runs with a mock World ID and demo JSON policies.

## 0. Keys

The gateway's Sepolia key lives in `.env` (gitignored) as `ENS_PRIVATE_KEY`, with its address in `ENS_ADDRESS`. Fund it with Sepolia ETH (~0.05 is plenty) from any Sepolia faucet. Check the balance:

```bash
node --input-type=module -e 'import {createPublicClient,http,formatEther} from "viem";import {sepolia} from "viem/chains";const c=createPublicClient({chain:sepolia,transport:http("https://ethereum-sepolia-rpc.publicnode.com")});console.log(formatEther(await c.getBalance({address:process.argv[1]})),"ETH")' $(grep ENS_ADDRESS .env | cut -d= -f2)
```

## 1. World ID (staging)

1. **Create an app.** Sign in at <https://developer.world.org>, create an app, and pick **Staging**. Copy the **App ID** (`app_…`).
2. **Enable World ID 4.0 / Relying Party.** In the app's World ID settings, register it as a Relying Party. Copy the **RP ID** (`rp_…`) and generate an **RP signing key** (hex). The gateway uses the key to sign each request (`rp_context`). Keep it secret.
3. **Set up the action.** Create an action called `airlock-approve` with **unlimited verifications per user**; v4 can also create it on first use.
   - Enrollment and approval **share this one action**. That keeps a person's nullifier stable, so the commitment stored at enrollment matches at approval time. Each approval is bound to its payload through the *signal* (`payloadHash`), not through the action.
   - **Tested against the live API:** an app that hasn't been migrated to World ID 4.0 gets `app_not_migrated` from `/api/v4/verify`. The gateway then retries on `/api/v2/verify` automatically. v2 does **not** auto-create actions and answers `invalid_action: Action not found` until you create `airlock-approve` in the portal.
4. **Configure `.env`:**
   ```
   WORLD_APP_ID=app_...
   WORLD_RP_ID=rp_...
   WORLD_RP_SIGNING_KEY=0x...
   WORLD_ENV=staging
   ```
5. **Restart** with `npm start`. The Console header should now show `world id worldid`.
6. **Enroll an approver.** In the Console, open **Enroll**, type the ENS name (e.g. `alice.legal.approvers.<you>.eth`) and click **Enroll with World ID**. Scan the QR with World App. In staging you can instead paste the link into <https://simulator.worldcoin.org>.
7. **Approve.** Send a confidential request (**Try it → Confidential contract**). In **Queue**, enter the same ENS name and hold **open outer door**, then scan again.

The Console asks for an **Orb** legacy credential (`orbLegacy`), which the simulator provides. On a real phone the approver needs an Orb-verified World ID. For device-level only, switch the preset to `deviceLegacy` in `console/index.html`.

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
