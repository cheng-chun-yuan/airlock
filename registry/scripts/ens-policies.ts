/**
 * Shared policies with ENSv2 record aliasing + a wildcard org default.
 *
 *   legal.policies.<root>.eth           ← one policy record (security account writes it)
 *   contract-agent.agents.<root>.eth    ─┐ linkToNode → legal.policies: edit the policy once,
 *   nda-agent.agents.<root>.eth         ─┘              every linked agent changes
 *   <anything>.agents.<root>.eth        ← unregistered agent: the resolver sits on agents.<root>.eth
 *                                          (ENSIP-10 wildcard) and answers from its DEFAULT record
 *                                          (node 0) = the org default policy (confidential stays inside)
 *
 * Approver names are unaffected: their parents have no resolver, so a revoked approver still resolves to nothing.
 *
 *   npm run ens:policies            (needs ENS_PRIVATE_KEY, ENS_SECURITY_PRIVATE_KEY, ENS_RESOLVER; resumable)
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createPublicClient, createWalletClient, encodeFunctionData, http, keccak256, namehash, parseAbi, parseEventLogs, stringToBytes, toBytes, toHex, zeroAddress, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import { packetToBytes } from "viem/ens";

const env = process.env;
const rpc = env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com";
const resolver = env.ENS_RESOLVER as Address;
const gateway = privateKeyToAccount(env.ENS_PRIVATE_KEY as Hex);
const security = privateKeyToAccount(env.ENS_SECURITY_PRIVATE_KEY as Hex);
const FACTORY = (env.ENS_VERIFIABLE_FACTORY ?? "0x9e726eb570beb6bceb495ab8cda7df517d4e841c") as Address;
const USER_REGISTRY_IMPL = (env.ENS_USER_REGISTRY_IMPL ?? "0xa80338aaa8d23831cea25e858d1774534abb0263") as Address;
const STATE_FILE = "data/ens-deploy.json";
const state: Record<string, string> = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2) + "\n");
const root = (env.DEFAULT_AGENT ?? "contract-agent.agents.airlock.eth").split(".").slice(-2).join(".");
const R_ROOT = state["registry:root"] as Address, R_AGENTS = state["registry:agents"] as Address;

const pub = createPublicClient({ chain: sepolia, transport: http(rpc) });
const as = (a: typeof gateway) => createWalletClient({ account: a, chain: sepolia, transport: http(rpc) });
const abi = parseAbi([
  "struct Grant { address account; uint256 roleBitmap; }",
  "function initialize(Grant[] grants)",
  "function deployProxy(address implementation, uint256 salt, bytes data) returns (address)",
  "event ProxyDeployed(address indexed sender, address indexed proxyAddress, uint256 salt, address implementation)",
  "function register(string label, address owner, address registry, address resolver, uint256 roleBitmap, uint64 expiry) returns (uint256)",
  "function getResolver(string label) view returns (address)",
  "function getSubregistry(string label) view returns (address)",
  "function setResolver(uint256 anyId, address resolver)",
  "function setText(bytes name, string key, string value)",
  "function multicall(bytes[] calls) returns (bytes[])",
  "function linkToNode(bytes sourceName, bytes32 targetNode)",
  "function getRecordId(bytes32 node) view returns (uint256)",
]);
const withAdmin = (...bits: bigint[]) => bits.reduce((a, b) => a | (1n << b) | (1n << (b + 128n)), 0n);
const REGISTRY_ROOT_ROLES = withAdmin(0n, 8n, 12n, 16n, 20n, 24n, 36n);
const TOKEN_ROLES = withAdmin(12n, 16n, 20n, 24n);
const dns = (name: string) => toHex(packetToBytes(name));

async function send(label: string, who: typeof gateway, address: Address, fn: string, args: unknown[]) {
  const { request } = await pub.simulateContract({ account: who, address, abi, functionName: fn as any, args: args as any });
  const hash = await as(who).writeContract(request as any);
  const r = await pub.waitForTransactionReceipt({ hash });
  if (r.status !== "success") throw new Error(`${label} reverted`);
  console.log(`  ✓ ${label}  tx ${hash}`);
  return r;
}
/** Register a subname unless it's already live (a previous run may have died before saving its progress). */
async function registerOnce(key: string, registry: Address, label: string, sub: Address, res: Address, exp: bigint) {
  return step(key, async () => {
    const [r0, s0] = await Promise.all([
      pub.readContract({ address: registry, abi, functionName: "getResolver", args: [label] }),
      pub.readContract({ address: registry, abi, functionName: "getSubregistry", args: [label] }),
    ]);
    if (r0 !== zeroAddress || s0 !== zeroAddress) return console.log(`  · ${key} already on-chain`), "existing";
    return (await send(`register ${key}`, gateway, registry, "register", [label, gateway.address, sub, res, TOKEN_ROLES, exp])).transactionHash;
  });
}
async function step(key: string, fn: () => Promise<string>) {
  if (state[key]) return console.log(`  · ${key} (done)`), state[key];
  state[key] = await fn();
  save();
  return state[key];
}
const expiry = () => BigInt(Math.floor(Date.now() / 1000) + 300 * 86400);

const LEGAL = `legal.policies.${root}`;
const LEGAL_POLICY: Record<string, string> = {
  "airlock.maxClass": "confidential",
  "airlock.egress": "approval",
  "airlock.models": "gpt-*,claude-*",
  "airlock.approverRole": `legal.approvers.${root}`,
  "airlock.highRiskQuorum": "2", // high risk: two *different* verified humans (World ID) must approve
};
const ORG_DEFAULT: Record<string, string> = {
  "airlock.maxClass": "internal", // an unconfigured agent may not send confidential data at all
  "airlock.egress": "approval",
  "airlock.models": "gpt-*,claude-*",
  "airlock.approverRole": `legal.approvers.${root}`,
  "airlock.highRiskQuorum": "2",
};

async function main() {
  if (!R_ROOT || !R_AGENTS) throw new Error("run npm run ens:setup first");
  console.log(`root ${root} · resolver ${resolver}\n`);

  console.log("1) legal.policies — the shared policy record");
  const R_POLICIES = (await step("registry:policies", async () => {
    const salt = BigInt(keccak256(stringToBytes(`airlock:${root}:registry:policies:${gateway.address}`)));
    const data = encodeFunctionData({ abi, functionName: "initialize", args: [[{ account: gateway.address, roleBitmap: REGISTRY_ROOT_ROLES }]] });
    const rcpt = await send("deploy registry:policies", gateway, FACTORY, "deployProxy", [USER_REGISTRY_IMPL, salt, data]);
    return parseEventLogs({ abi, logs: rcpt.logs, eventName: "ProxyDeployed" })[0].args.proxyAddress;
  })) as Address;
  await registerOnce(`policies.${root}`, R_ROOT, "policies", R_POLICIES, zeroAddress, expiry());
  await registerOnce(LEGAL, R_POLICIES, "legal", zeroAddress, resolver, expiry() - 86400n);
  await step("records:legal-policy", async () => {
    const calls = Object.entries(LEGAL_POLICY).map(([k, v]) => encodeFunctionData({ abi, functionName: "setText", args: [dns(LEGAL), k, v] }));
    return (await send(`security writes ${LEGAL} (×${calls.length})`, security, resolver, "multicall", [calls])).transactionHash;
  });

  console.log("\n2) aliasing — agents link to the shared policy");
  const target = namehash(LEGAL);
  await registerOnce(`nda-agent.agents.${root}`, R_AGENTS, "nda-agent", zeroAddress, resolver, expiry() - 2n * 86400n);
  for (const agent of [`contract-agent.agents.${root}`, `nda-agent.agents.${root}`])
    await step(`link:${agent}`, async () => (await send(`linkToNode(${agent} → ${LEGAL})`, security, resolver, "linkToNode", [dns(agent), target])).transactionHash);

  console.log("\n3) wildcard org default for unregistered agents");
  await step("records:org-default", async () => {
    const calls = Object.entries(ORG_DEFAULT).map(([k, v]) => encodeFunctionData({ abi, functionName: "setText", args: ["0x00", k, v] })); // "" → node 0 = default record
    return (await send(`security writes the default record (×${calls.length})`, security, resolver, "multicall", [calls])).transactionHash;
  });
  await step(`resolver:agents.${root}`, async () => (await send(`agents.${root} → resolver (wildcard)`, gateway, R_ROOT, "setResolver", [BigInt(keccak256(toBytes("agents"))), resolver])).transactionHash);

  console.log("\n4) read back through the universal resolver");
  for (const name of [`contract-agent.agents.${root}`, `nda-agent.agents.${root}`, `intern-bot.agents.${root}`]) {
    const t = async (k: string) => (await pub.getEnsText({ name, key: k }).catch(() => null)) ?? "—";
    console.log(`  ${name.padEnd(38)} maxClass=${await t("airlock.maxClass")}  egress=${await t("airlock.egress")}  highRiskQuorum=${await t("airlock.highRiskQuorum")}`);
  }
  const ids = await Promise.all([`contract-agent.agents.${root}`, `nda-agent.agents.${root}`, LEGAL].map((n) => pub.readContract({ address: resolver, abi, functionName: "getRecordId", args: [namehash(n)] })));
  console.log(`  record ids: contract-agent=${ids[0]} nda-agent=${ids[1]} legal.policies=${ids[2]}  → ${ids[0] === ids[2] && ids[1] === ids[2] ? "shared ✓" : "NOT shared"}`);
  const alice = `alice.legal.approvers.${root}`;
  console.log(`  revocation still safe: unknown.legal.approvers.${root} approver = ${(await pub.getEnsText({ name: `nobody.legal.approvers.${root}`, key: "airlock.approver" }).catch(() => null)) ?? "— (no resolver)"}`);
  void alice;
}
main().catch((e) => { console.error(`\n✗ ${e.shortMessage ?? e.message}`); process.exit(1); });
