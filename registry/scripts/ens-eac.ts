/**
 * Split write access on the Airlock PermissionedResolver with ENSv2 Enhanced Access Control:
 *
 *   security account  → all root roles (admin): the only key that can change policy records
 *   gateway account   → ROLE_SET_TEXT on exactly two record keys: airlock.approver, airlock.auditRoot
 *
 *   npm run ens:eac            (reads ENS_PRIVATE_KEY / ENS_RESOLVER; creates ENS_SECURITY_PRIVATE_KEY if missing)
 *
 * Resumable and idempotent: each step checks on-chain state first.
 */
import { appendFileSync, readFileSync } from "node:fs";
import { createPublicClient, createWalletClient, encodeFunctionData, formatEther, http, keccak256, parseAbi, parseEther, toBytes, toHex, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import { packetToBytes } from "viem/ens";

const env = process.env;
const rpc = env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com";
const resolver = env.ENS_RESOLVER as Hex;
if (!env.ENS_PRIVATE_KEY || !resolver) throw new Error("ENS_PRIVATE_KEY and ENS_RESOLVER required");

const gateway = privateKeyToAccount(env.ENS_PRIVATE_KEY as Hex);
let securityKey = env.ENS_SECURITY_PRIVATE_KEY as Hex | undefined;
if (!securityKey) {
  securityKey = generatePrivateKey();
  appendFileSync(".env", `\n# ENS security account: sole admin of the resolver; the only key that may change airlock.* policy records\nENS_SECURITY_PRIVATE_KEY=${securityKey}\nENS_SECURITY_ADDRESS=${privateKeyToAccount(securityKey).address}\n`);
  console.log("created security account → .env");
}
const security = privateKeyToAccount(securityKey);

const pub = createPublicClient({ chain: sepolia, transport: http(rpc) });
const as = (account: typeof gateway) => createWalletClient({ account, chain: sepolia, transport: http(rpc) });
const abi = parseAbi([
  "function grantRootRoles(uint256 roleBitmap, address account) returns (bool)",
  "function revokeRootRoles(uint256 roleBitmap, address account) returns (bool)",
  "function grantSetterRoles(bytes setter, address account) returns (bool)",
  "function roles(uint256 resource, address account) view returns (uint256)",
  "function hasRootRoles(uint256 roleBitmap, address account) view returns (bool)",
  "function setText(bytes name, string key, string value)",
]);

const ROLE_SET_TEXT = 1n << 4n;
const ALL = [0n, 4n, 8n, 12n, 16n, 20n, 24n, 28n].reduce((a, b) => a | (1n << b) | (1n << (b + 128n)), 0n);
const GATEWAY_KEYS = ["airlock.approver", "airlock.auditRoot"];
const POLICY_KEYS = ["airlock.maxClass", "airlock.egress", "airlock.models", "airlock.approverRole", "airlock.ownerRole"];
const res = (key: string) => BigInt(keccak256(toBytes(key)));
const dns = (name: string) => toHex(packetToBytes(name));
const root = (env.DEFAULT_AGENT ?? "contract-agent.agents.airlock.eth").split(".").slice(-2).join(".");
const agent = env.DEFAULT_AGENT ?? `contract-agent.agents.${root}`;

async function send(label: string, account: typeof gateway, fn: string, args: unknown[]) {
  const { request } = await pub.simulateContract({ account, address: resolver, abi, functionName: fn as any, args: args as any });
  const hash = await as(account).writeContract(request as any);
  const r = await pub.waitForTransactionReceipt({ hash });
  if (r.status !== "success") throw new Error(`${label} reverted`);
  console.log(`  ✓ ${label}  tx ${hash}`);
}
const can = async (account: typeof gateway, name: string, key: string) =>
  pub
    .simulateContract({ account, address: resolver, abi, functionName: "setText", args: [dns(name), key, "probe"] })
    .then(() => "ALLOWED")
    .catch((e) => `denied (${(e.shortMessage ?? e.message).split("\n")[0].replace(/^The contract function "setText" reverted with the following reason:\s*/, "").slice(0, 60)})`);

async function main() {
  console.log(`resolver ${resolver}\ngateway  ${gateway.address}\nsecurity ${security.address}\n`);

  console.log("1) fund security account");
  const bal = await pub.getBalance({ address: security.address });
  if (bal < parseEther("0.01")) {
    const hash = await as(gateway).sendTransaction({ to: security.address, value: parseEther("0.05") });
    await pub.waitForTransactionReceipt({ hash });
    console.log(`  ✓ sent 0.05 ETH  tx ${hash}`);
  } else console.log(`  · has ${formatEther(bal)} ETH`);

  console.log("2) security becomes resolver admin (all root roles)");
  if (!(await pub.readContract({ address: resolver, abi, functionName: "hasRootRoles", args: [ALL, security.address] })))
    await send("grantRootRoles(ALL, security)", gateway, "grantRootRoles", [ALL, security.address]);
  else console.log("  · already");

  console.log("3) gateway gets ROLE_SET_TEXT on its two record keys only");
  for (const key of GATEWAY_KEYS) {
    if ((await pub.readContract({ address: resolver, abi, functionName: "roles", args: [res(key), gateway.address] })) & ROLE_SET_TEXT) console.log(`  · ${key} already`);
    else {
      const setter = encodeFunctionData({ abi, functionName: "setText", args: [dns(root), key, ""] });
      await send(`grantSetterRoles(setText ${key}, gateway)`, security, "grantSetterRoles", [setter, gateway.address]);
    }
  }

  console.log("4) security revokes the gateway's root roles");
  const gwRoot = await pub.readContract({ address: resolver, abi, functionName: "roles", args: [0n, gateway.address] });
  if (gwRoot !== 0n) await send("revokeRootRoles(ALL, gateway)", security, "revokeRootRoles", [gwRoot, gateway.address]);
  else console.log("  · already revoked");

  console.log("\n5) who can write what (eth_call against the live resolver)");
  const approver = `alice.legal.approvers.${root}`;
  const rows: [string, typeof gateway, string, string][] = [
    ["gateway ", gateway, agent, "airlock.models"],
    ["gateway ", gateway, agent, "airlock.egress"],
    ["gateway ", gateway, approver, "airlock.approver"],
    ["gateway ", gateway, `audit.${root}`, "airlock.auditRoot"],
    ["security", security, agent, "airlock.models"],
    ["security", security, agent, "airlock.egress"],
  ];
  for (const [who, acct, name, key] of rows) console.log(`  ${who} setText(${key.padEnd(18)}) → ${await can(acct, name, key)}`);
  console.log(`\n  policy keys owned by security: ${POLICY_KEYS.join(", ")}`);
}

main().catch((e) => {
  console.error(`\n✗ ${e.shortMessage ?? e.message}`);
  process.exit(1);
});
