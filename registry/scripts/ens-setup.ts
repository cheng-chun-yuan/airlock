/**
 * One-shot ENSv2 (Sepolia) setup for Airlock:
 *
 *   <root>.eth                          subregistry R_root, no resolver
 *   ├─ agents.<root>.eth                subregistry R_agents, no resolver
 *   │   └─ contract-agent.agents…       resolver → airlock.maxClass / egress / models / approverRole / ownerRole
 *   ├─ approvers.<root>.eth             subregistry R_approvers, no resolver
 *   │   └─ legal.approvers…             subregistry R_legal, no resolver       ← the approver role
 *   │       └─ <approver>.legal…        resolver → airlock.approver = commitment   (expiring, revocable)
 *   └─ audit.<root>.eth                 resolver → airlock.auditRoot
 *
 * Only leaves get a resolver. Our PermissionedResolver keys records by full
 * name and supports wildcard (ENSIP-10) lookup, so a resolver on a parent would
 * keep answering for an unregistered child — i.e. revocation would silently
 * fail. With no parent resolvers, an unregistered approver resolves to nothing.
 *
 *   npm run ens:setup -- airlock [approverLabel] [commitment]
 *
 * Resumable: progress is kept in data/ens-deploy.json. Addresses come from
 * contracts-v2 deployments/sepolia (2026-09-15); override with env if ENS redeploys.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  formatUnits,
  http,
  keccak256,
  parseAbi,
  parseEventLogs,
  stringToBytes,
  toHex,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import { packetToBytes } from "viem/ens";

const env = process.env;
const A = {
  registrar: (env.ENS_ETH_REGISTRAR ?? "0xabe76f6c8dfced81aa5a2bb8034202a7136b94ca") as Address,
  factory: (env.ENS_VERIFIABLE_FACTORY ?? "0x9e726eb570beb6bceb495ab8cda7df517d4e841c") as Address,
  userRegistryImpl: (env.ENS_USER_REGISTRY_IMPL ?? "0xa80338aaa8d23831cea25e858d1774534abb0263") as Address,
  resolverImpl: (env.ENS_PERMISSIONED_RESOLVER_IMPL ?? "0x14f09fd05d4585759e54844dc9b00147131cf243") as Address,
  usdc: (env.ENS_PAYMENT_TOKEN ?? "0x16f95d91dba7da3aca778ec053df0ff6c6a8aa8e") as Address,
};
const STATE_FILE = "data/ens-deploy.json";
const YEAR = 365n * 24n * 3600n;

// Role bits (contracts-v2 RegistryRolesLib / PermissionedResolverLib); admin role = role << 128.
const withAdmin = (...bits: bigint[]) => bits.reduce((acc, b) => acc | b | (b << 128n), 0n);
const REG = { REGISTRAR: 1n << 0n, SET_PARENT: 1n << 8n, UNREGISTER: 1n << 12n, RENEW: 1n << 16n, SET_SUBREGISTRY: 1n << 20n, SET_RESOLVER: 1n << 24n, SET_URI: 1n << 36n };
const REGISTRY_ROOT_ROLES = withAdmin(REG.REGISTRAR, REG.SET_PARENT, REG.UNREGISTER, REG.RENEW, REG.SET_SUBREGISTRY, REG.SET_RESOLVER, REG.SET_URI);
const TOKEN_ROLES = withAdmin(REG.UNREGISTER, REG.RENEW, REG.SET_SUBREGISTRY, REG.SET_RESOLVER);
const RESOLVER_ROLES = withAdmin(...[0n, 4n, 8n, 12n, 16n, 20n, 24n, 28n].map((b) => 1n << b));

const abi = {
  registrar: parseAbi([
    "function isAvailable(string label) view returns (bool)",
    "function getRegisterPrice(string label, uint64 duration, address paymentToken) view returns (uint256 base, uint256 premium)",
    "function makeCommitment(string label, address owner, bytes32 secret, address subregistry, address resolver, uint64 duration, bytes32 referrer) pure returns (bytes32)",
    "function commit(bytes32 commitment)",
    "function register(string label, address owner, bytes32 secret, address subregistry, address resolver, uint64 duration, address paymentToken, bytes32 referrer) returns (uint256)",
  ]),
  erc20: parseAbi(["function mint(address to, uint256 amount)", "function approve(address spender, uint256 amount) returns (bool)", "function balanceOf(address) view returns (uint256)", "function allowance(address,address) view returns (uint256)"]),
  factory: parseAbi(["function deployProxy(address implementation, uint256 salt, bytes data) returns (address)", "event ProxyDeployed(address indexed sender, address indexed proxyAddress, uint256 salt, address implementation)"]),
  userRegistry: parseAbi([
    "struct Grant { address account; uint256 roleBitmap; }",
    "function initialize(Grant[] grants)",
    "function register(string label, address owner, address registry, address resolver, uint256 roleBitmap, uint64 expiry) returns (uint256)",
    "function getResolver(string label) view returns (address)",
    "function getSubregistry(string label) view returns (address)",
  ]),
  resolver: parseAbi(["struct Grant { address account; uint256 roleBitmap; }", "function initialize(Grant[] grants, bytes[] calls)", "function setText(bytes name, string key, string value)", "function multicall(bytes[] calls) returns (bytes[])"]),
};

const [root = "airlock", approverLabel = "alice", commitmentArg] = process.argv.slice(2);
if (!env.ENS_PRIVATE_KEY) throw new Error("ENS_PRIVATE_KEY missing (.env)");
const account = privateKeyToAccount(env.ENS_PRIVATE_KEY as Hex);
const rpc = env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com";
const pub = createPublicClient({ chain: sepolia, transport: http(rpc) });
const wallet = createWalletClient({ account, chain: sepolia, transport: http(rpc) });

type State = Record<string, string>;
const state: State = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2) + "\n");
const log = (s: string) => console.log(s);

async function send(label: string, req: Parameters<typeof wallet.writeContract>[0]) {
  const { request } = await pub.simulateContract({ ...(req as any), account });
  const hash = await wallet.writeContract(request as any);
  const rcpt = await pub.waitForTransactionReceipt({ hash });
  if (rcpt.status !== "success") throw new Error(`${label} reverted (${hash})`);
  log(`  ✓ ${label}  tx ${hash}`);
  return rcpt;
}

async function step(key: string, fn: () => Promise<string>) {
  if (state[key]) return log(`  · ${key} (done: ${state[key]})`), state[key];
  state[key] = await fn();
  save();
  return state[key];
}

async function deployProxy(key: string, impl: Address, data: Hex) {
  return step(key, async () => {
    const salt = BigInt(keccak256(stringToBytes(`airlock:${root}:${key}:${account.address}`)));
    const rcpt = await send(`deploy ${key}`, { address: A.factory, abi: abi.factory, functionName: "deployProxy", args: [impl, salt, data] } as any);
    const [ev] = parseEventLogs({ abi: abi.factory, logs: rcpt.logs, eventName: "ProxyDeployed" });
    return ev.args.proxyAddress;
  });
}

const dns = (name: string) => toHex(packetToBytes(name));

async function main() {
  const eth = await pub.getBalance({ address: account.address });
  log(`account ${account.address}  ${Number(eth) / 1e18} Sepolia ETH\nname    ${root}.eth\n`);

  // 1. contracts we own: one resolver, one registry per non-leaf level
  log("1) proxies");
  const resolver = (await deployProxy("resolver", A.resolverImpl, encodeFunctionData({ abi: abi.resolver, functionName: "initialize", args: [[{ account: account.address, roleBitmap: RESOLVER_ROLES }], []] }))) as Address;
  const regInit = encodeFunctionData({ abi: abi.userRegistry, functionName: "initialize", args: [[{ account: account.address, roleBitmap: REGISTRY_ROOT_ROLES }]] });
  const R = {
    root: (await deployProxy("registry:root", A.userRegistryImpl, regInit)) as Address,
    agents: (await deployProxy("registry:agents", A.userRegistryImpl, regInit)) as Address,
    legal: (await deployProxy("registry:legal", A.userRegistryImpl, regInit)) as Address,
    approvers: (await deployProxy("registry:approvers", A.userRegistryImpl, regInit)) as Address,
  };

  // 2. <root>.eth: pay in MockUSDC, commit, wait, register
  log(`\n2) register ${root}.eth`);
  await step(`eth:${root}`, async () => {
    if (!(await pub.readContract({ address: A.registrar, abi: abi.registrar, functionName: "isAvailable", args: [root] }))) throw new Error(`${root}.eth is not available`);
    const [base, premium] = await pub.readContract({ address: A.registrar, abi: abi.registrar, functionName: "getRegisterPrice", args: [root, YEAR, A.usdc] });
    const price = base + premium;
    log(`  price ${formatUnits(price, 6)} MockUSDC`);
    if ((await pub.readContract({ address: A.usdc, abi: abi.erc20, functionName: "balanceOf", args: [account.address] })) < price)
      await send("mint MockUSDC", { address: A.usdc, abi: abi.erc20, functionName: "mint", args: [account.address, price * 2n] } as any);
    if ((await pub.readContract({ address: A.usdc, abi: abi.erc20, functionName: "allowance", args: [account.address, A.registrar] })) < price)
      await send("approve registrar", { address: A.usdc, abi: abi.erc20, functionName: "approve", args: [A.registrar, price * 2n] } as any);
    const secret = (state[`secret:${root}`] ??= keccak256(stringToBytes(`${Date.now()}:${Math.random()}`))) as Hex;
    save();
    const commitment = await pub.readContract({ address: A.registrar, abi: abi.registrar, functionName: "makeCommitment", args: [root, account.address, secret, R.root, zeroAddress, YEAR, `0x${"0".repeat(64)}`] });
    if (!state[`committed:${root}`]) {
      await send("commit", { address: A.registrar, abi: abi.registrar, functionName: "commit", args: [commitment] } as any);
      state[`committed:${root}`] = String(Date.now());
      save();
    }
    const wait = Number(state[`committed:${root}`]) + 75_000 - Date.now();
    if (wait > 0) log(`  waiting ${Math.ceil(wait / 1000)}s (commit-reveal)…`), await new Promise((r) => setTimeout(r, wait));
    const rcpt = await send(`register ${root}.eth`, { address: A.registrar, abi: abi.registrar, functionName: "register", args: [root, account.address, secret, R.root, zeroAddress, YEAR, A.usdc, `0x${"0".repeat(64)}`] } as any);
    return rcpt.transactionHash;
  });

  // 3. subnames — only leaves get the resolver
  log("\n3) subnames");
  const now = BigInt(Math.floor(Date.now() / 1000));
  const sub = (key: string, registry: Address, label: string, subregistry: Address, res: Address, expiry: bigint) =>
    step(key, async () => (await send(`register ${key}`, { address: registry, abi: abi.userRegistry, functionName: "register", args: [label, account.address, subregistry, res, TOKEN_ROLES, expiry] } as any)).transactionHash);
  const exp = now + YEAR - 7n * 86400n;
  await sub(`agents.${root}.eth`, R.root, "agents", R.agents, zeroAddress, exp);
  await sub(`approvers.${root}.eth`, R.root, "approvers", R.approvers, zeroAddress, exp);
  await sub(`audit.${root}.eth`, R.root, "audit", zeroAddress, resolver, exp);
  await sub(`contract-agent.agents.${root}.eth`, R.agents, "contract-agent", zeroAddress, resolver, exp - 86400n);
  await sub(`legal.approvers.${root}.eth`, R.approvers, "legal", R.legal, zeroAddress, exp - 86400n);
  const approverName = `${approverLabel}.legal.approvers.${root}.eth`;
  await sub(approverName, R.legal, approverLabel, zeroAddress, resolver, now + 180n * 86400n);

  // 4. records
  log("\n4) text records");
  const agent = `contract-agent.agents.${root}.eth`;
  const policy: Record<string, string> = {
    maxClass: "confidential",
    egress: "approval",
    models: "claude-*",
    approverRole: `legal.approvers.${root}.eth`,
    ownerRole: `owners.${root}.eth`,
  };
  const commitment = commitmentArg ?? (JSON.parse(readFileSync("data/approvers.json", "utf8")) as { name: string; commitment: string }[]).find((a) => a.name.startsWith(`${approverLabel}.`))?.commitment;
  const calls = [
    ...Object.entries(policy).map(([k, v]) => encodeFunctionData({ abi: abi.resolver, functionName: "setText", args: [dns(agent), `airlock.${k}`, v] })),
    ...(commitment ? [encodeFunctionData({ abi: abi.resolver, functionName: "setText", args: [dns(approverName), "airlock.approver", commitment] })] : []),
  ];
  await step("records:v1", async () => (await send(`multicall setText ×${calls.length}`, { address: resolver, abi: abi.resolver, functionName: "multicall", args: [calls] } as any)).transactionHash);
  if (!commitment) log(`  (no commitment for ${approverLabel} yet — enroll in the Console, then: npm run ens -- enroll ${approverName} <commitment>)`);

  // 5. read back through the universal resolver
  log("\n5) read back via universal resolver");
  for (const [name, key] of [[agent, "airlock.egress"], [agent, "airlock.approverRole"], [approverName, "airlock.approver"]])
    log(`  ${name}  ${key} = ${(await pub.getEnsText({ name, key }).catch((e) => `error: ${e.shortMessage ?? e.message}`)) ?? "—"}`);

  log(`\nAdd to .env:\n  SEPOLIA_RPC_URL=${rpc}\n  ENS_RESOLVER=${resolver}\n  ENS_AUDIT_NAME=audit.${root}.eth\n  DEFAULT_AGENT=${agent}\n  ENS_APPROVER_REGISTRY=${R.legal}   # registry holding <approver>.legal.approvers — used by \`npm run ens -- revoke\``);
}

main().catch((e) => {
  console.error(`\n✗ ${e.shortMessage ?? e.message}`);
  process.exit(1);
});
