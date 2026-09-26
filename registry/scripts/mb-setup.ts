/**
 * Point Curvegrid MultiBaas at Airlock's ENSv2 contracts (Sepolia) and subscribe the gateway to their events.
 *
 *   npm run mb:setup        (MULTIBAAS_URL, MULTIBAAS_API_KEY; PUBLIC_URL for the webhook; idempotent)
 *
 * - uploads two event ABIs: airlockresolver (PermissionedResolver) and airlockregistry (PermissionedRegistry)
 * - aliases + links the resolver and the four registries from data/ens-deploy.json (free plan: from 100 blocks back)
 * - creates the webhook → <PUBLIC_URL>/multibaas/webhook and saves its secret to .env (MULTIBAAS_WEBHOOK_SECRET)
 */
import { appendFileSync, readFileSync } from "node:fs";
import { parseAbi } from "viem";
import { MultiBaas } from "../src/multibaas";

const env = process.env;
if (!env.MULTIBAAS_URL || !env.MULTIBAAS_API_KEY) throw new Error("set MULTIBAAS_URL and MULTIBAAS_API_KEY in .env");
const mb = new MultiBaas(env.MULTIBAAS_URL, env.MULTIBAAS_API_KEY);
const deploy = JSON.parse(readFileSync("data/ens-deploy.json", "utf8"));
// Free plan: past_logs_max_depth = 100 blocks, so index from ~20 min back; everything newer is indexed and pushed.
const START = env.MULTIBAAS_START_BLOCK ?? "-100";

const RESOLVER_ABI = parseAbi([
  "event TextUpdated(uint256 indexed recordId, string indexed keyHash, string key, string value)",
  "event Linked(uint256 indexed recordId, bytes32 indexed node, bytes name)",
  "event NameUpdated(uint256 indexed recordId, string primaryName)",
  "event EACRolesChanged(uint256 indexed resource, address indexed account, uint256 oldRoleBitmap, uint256 newRoleBitmap)",
  "function text(bytes32 node, string key) view returns (string)",
]);
const REGISTRY_ABI = parseAbi([
  "event LabelRegistered(uint256 indexed tokenId, bytes32 indexed labelHash, string label, address owner, uint64 expiry, address indexed sender)",
  "event LabelUnregistered(uint256 indexed tokenId, address indexed sender)",
  "event ExpiryUpdated(uint256 indexed tokenId, uint64 indexed newExpiry, address indexed sender)",
  "event ResolverUpdated(uint256 indexed tokenId, address indexed resolver, address indexed sender)",
  "event EACRolesChanged(uint256 indexed resource, address indexed account, uint256 oldRoleBitmap, uint256 newRoleBitmap)",
  "function getResolver(string label) view returns (address)",
]);

/** 409 / "already exists" means a previous run did it. */
async function once(label: string, fn: () => Promise<unknown>) {
  try {
    await fn();
    console.log(`  ✓ ${label}`);
  } catch (e: any) {
    if (e.status === 409 || /exist|duplicate|already/i.test(e.message)) console.log(`  · ${label} (already)`);
    else throw e;
  }
}

async function main() {
  console.log(`MultiBaas ${env.MULTIBAAS_URL}\n1) contract ABIs`);
  await once("upload airlockresolver", () => mb.uploadContract("airlockresolver", RESOLVER_ABI as unknown as unknown[]));
  await once("upload airlockregistry", () => mb.uploadContract("airlockregistry", REGISTRY_ABI as unknown as unknown[]));

  console.log(`\n2) addresses (index from ${START})`);
  const targets: [string, string | undefined, string][] = [
    ["airlock-resolver", env.ENS_RESOLVER, "airlockresolver"],
    ["airlock-root", deploy["registry:root"], "airlockregistry"],
    ["airlock-agents", deploy["registry:agents"], "airlockregistry"],
    ["airlock-policies", deploy["registry:policies"], "airlockregistry"],
    ["airlock-legal-approvers", deploy["registry:legal"], "airlockregistry"],
  ];
  for (const [alias, address, label] of targets) {
    if (!address) { console.log(`  - ${alias}: no address, skipped`); continue; }
    await once(`alias ${alias} → ${address}`, () => mb.setAlias(alias, address));
    await once(`link ${alias} ↔ ${label}`, () => mb.link(alias, label, START));
  }

  console.log("\n3) webhook");
  if (!env.PUBLIC_URL) console.log("  - PUBLIC_URL not set: skipped (events still visible via /ens/changes)");
  else {
    const url = `${env.PUBLIC_URL.replace(/\/$/, "")}/multibaas/webhook`;
    const existing = (await mb.webhooks()).find((w) => w.url === url);
    if (existing && env.MULTIBAAS_WEBHOOK_SECRET) console.log(`  · webhook ${existing.id} → ${url} (already)`);
    else {
      const w = await mb.createWebhook(url, "airlock-gateway");
      appendFileSync(".env", `\n# MultiBaas webhook ${w.id} → ${url}\nMULTIBAAS_WEBHOOK_SECRET=${w.secret}\n`);
      console.log(`  ✓ webhook ${w.id} → ${url} (secret saved to .env)`);
    }
  }

  console.log("\n4) indexing status");
  for (const [alias, address, label] of targets) {
    if (!address) continue;
    const s = await mb.status(alias, label).catch((e) => ({ error: e.message }));
    console.log(`  ${alias.padEnd(24)} ${JSON.stringify(s)}`);
  }
  const recent = await mb.events({ contract_label: "airlockresolver", limit: 3 }).catch((e) => `error: ${e.message}`);
  console.log(`\n  latest resolver events: ${Array.isArray(recent) ? recent.length : recent}`);
}
main().catch((e) => { console.error(`\n✗ ${e.message}`); process.exit(1); });
