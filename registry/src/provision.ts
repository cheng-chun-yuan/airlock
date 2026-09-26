import { createWalletClient, encodeFunctionData, keccak256, namehash, parseAbi, parseEventLogs, stringToBytes, toBytes, toHex, zeroAddress, type Address, type Hex, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import { normalize, packetToBytes } from "viem/ens";
import { GATEWAY_KEYS, sepoliaTransport, txLock } from "./ens";

/**
 * Gives a new gateway its own corner of ENS, under the platform root (airlock.eth):
 *
 *   <slug>.airlock.eth                 owner = the creator's wallet · subregistry R_gw · no resolver
 *   ├─ policy.<slug>.airlock.eth       resolver → airlock.maxClass / egress / models / approverRole / highRiskQuorum
 *   ├─ approvers.<slug>.airlock.eth    subregistry R_approvers · no resolver     ← the approver role
 *   │   └─ <name>.approvers.<slug>…    resolver → airlock.approver = commitment  (created on enrollment)
 *   └─ audit.<slug>.airlock.eth        resolver → airlock.auditRoot
 *
 * The gateway gets its own PermissionedResolver and registries. The creator's wallet holds every role on them
 * (admin included). The platform key holds them only while it builds the gateway; its last transactions hand
 * the gateway over (ENSv2 Enhanced Access Control, as in registry/scripts/ens-eac.ts):
 *
 *   resolver      platform keeps ROLE_SET_TEXT on airlock.approver and airlock.auditRoot only, so it can enroll
 *                 approvers and anchor the audit log but can't write a policy key (the owner's wallet signs those)
 *   R_gw          platform keeps nothing, so it can't re-point policy.<slug> at a resolver it controls
 *   R_approvers   platform keeps its roles: enrollment registers and revokes approver names
 *
 * EAC scopes a key grant to the whole resolver, not to one name (contracts-v2 PermissionedResolver: the resource
 * is keccak256(key)), which is why every gateway needs a resolver of its own. Only leaves get a resolver, so an
 * unregistered approver resolves to nothing (see registry/scripts/ens-setup.ts).
 *
 * Resumable: every finished step is recorded in `state` (persisted by the caller) and skipped on the next run.
 */

// contracts-v2 deployments/sepolia (2026-09-15); override with env if ENS redeploys.
const env = process.env;
export const ENS_V2 = {
  factory: (env.ENS_VERIFIABLE_FACTORY ?? "0x9e726eb570beb6bceb495ab8cda7df517d4e841c") as Address,
  userRegistryImpl: (env.ENS_USER_REGISTRY_IMPL ?? "0xa80338aaa8d23831cea25e858d1774534abb0263") as Address,
  resolverImpl: (env.ENS_PERMISSIONED_RESOLVER_IMPL ?? "0x14f09fd05d4585759e54844dc9b00147131cf243") as Address,
};

// Role bits (contracts-v2 RegistryRolesLib / PermissionedResolverLib); admin role = role << 128.
const withAdmin = (...bits: bigint[]) => bits.reduce((acc, b) => acc | (1n << b) | (1n << (b + 128n)), 0n);
const REGISTRY_ROOT_ROLES = withAdmin(0n, 8n, 12n, 16n, 20n, 24n, 36n);
const TOKEN_ROLES = withAdmin(12n, 16n, 20n, 24n);
const RESOLVER_ROLES = withAdmin(0n, 4n, 8n, 12n, 16n, 20n, 24n, 28n);

const abi = parseAbi([
  "struct Grant { address account; uint256 roleBitmap; }",
  "function initialize(Grant[] grants)",
  "function deployProxy(address implementation, uint256 salt, bytes data) returns (address)",
  "event ProxyDeployed(address indexed sender, address indexed proxyAddress, uint256 salt, address implementation)",
  "function register(string label, address owner, address registry, address resolver, uint256 roleBitmap, uint64 expiry) returns (uint256)",
  "function getResolver(string label) view returns (address)",
  "function getSubregistry(string label) view returns (address)",
  "function setText(bytes name, string key, string value)",
  "function multicall(bytes[] calls) returns (bytes[])",
  "function grantSetterRoles(bytes setter, address account) returns (bool)",
  "function revokeRootRoles(uint256 roleBitmap, address account) returns (bool)",
  "function roles(uint256 resource, address account) view returns (uint256)",
  "function getRecordId(bytes32 node) view returns (uint256)",
  "event TextUpdated(uint256 indexed recordId, string indexed keyHash, string key, string value)",
]);
const ROLE_SET_TEXT = 1n << 4n;
const resolverInit = parseAbi(["struct Grant { address account; uint256 roleBitmap; }", "function initialize(Grant[] grants, bytes[] calls)"]);

/** Labels a gateway can't take: they'd shadow the platform's own names. */
const RESERVED = new Set(["agents", "approvers", "audit", "policies", "policy", "legal", "security", "www", "app", "api", "demo", "admin", "root", "gateway"]);

/** A DNS-safe ENS label: 3–32 of a-z, 0-9 and inner hyphens. */
export function checkSlug(slug: string): string | undefined {
  if (!/^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$/.test(slug)) return "3–32 characters: lowercase letters, digits and inner hyphens";
  if (slug.includes("--")) return "no double hyphens";
  if (RESERVED.has(slug)) return `"${slug}" is reserved`;
  if (normalize(slug) !== slug) return "not a normalized ENS label";
}

export type PolicyRecords = Record<"maxClass" | "egress" | "models" | "approverRole" | "ownerRole" | "highRiskQuorum", string>;

/** Names under a gateway, in one place so the gateway and the Console agree. */
export function gatewayNames(slug: string, root: string) {
  const base = `${slug}.${root}`;
  return { base, policy: `policy.${base}`, approverRole: `approvers.${base}`, audit: `audit.${base}`, approver: (label: string) => `${label}.approvers.${base}` };
}

export interface ProvisionState {
  resolver?: Address;
  registry?: Address;
  approverRegistry?: Address;
  /** step → tx hash ("existing" when a retry found the step already on-chain) */
  done: Record<string, Hex | "existing">;
  /** Block before the first transaction: where a retry starts looking for a deploy whose receipt was lost. */
  fromBlock?: string;
}

export const PROVISION_STEPS = ["deploy resolver", "deploy registry", "deploy approver registry", "register name", "register policy", "register approvers", "register audit", "write policy", "hand over policy", "hand over registry"] as const;

export interface ProvisionOpts {
  client: PublicClient;
  rpcUrl: string;
  privateKey: Hex;
  /** UserRegistry that holds <label>.<root> (airlock.eth's subregistry). */
  rootRegistry: Address;
  root: string;
  slug: string;
  owner: Address;
  /** Read when the records are written, so a policy edited during provisioning is the one that lands. */
  policy: () => PolicyRecords;
  state: ProvisionState;
  save(state: ProvisionState): void;
  progress?(step: string, i: number, n: number): void;
}

export class EnsProvisioner {
  private account;
  private wallet;
  constructor(private client: PublicClient, rpcUrl: string, privateKey: Hex, private rootRegistry: Address) {
    this.account = privateKeyToAccount(privateKey);
    this.wallet = createWalletClient({ account: this.account, chain: sepolia, transport: sepoliaTransport(rpcUrl) });
  }

  get address() {
    return this.account.address;
  }

  /** Is `<slug>.<root>` free on-chain? (Our own store is checked separately.) */
  async available(slug: string): Promise<boolean> {
    // Public RPCs drop the odd request: retry once, and let a real failure surface instead of reading as "taken".
    const read = (fn: "getSubregistry" | "getResolver") => {
      const once = () => this.client.readContract({ address: this.rootRegistry, abi, functionName: fn, args: [slug] });
      return once().catch(once);
    };
    const [sub, res] = await Promise.all([read("getSubregistry"), read("getResolver")]);
    return sub === zeroAddress && res === zeroAddress;
  }

  private async send(label: string, req: { address: Address; functionName: string; args: readonly unknown[] }) {
    return txLock(this.account.address, async () => {
      const { request } = await this.client.simulateContract({ account: this.account, abi, ...req } as any);
      const hash = await this.wallet.writeContract(request as any);
      const rcpt = await this.client.waitForTransactionReceipt({ hash });
      if (rcpt.status !== "success") throw new Error(`${label} reverted (${hash})`);
      return rcpt;
    });
  }

  async provision(o: Omit<ProvisionOpts, "client" | "rpcUrl" | "privateKey" | "rootRegistry">): Promise<ProvisionState> {
    const s = o.state;
    const me = this.account.address;
    const names = gatewayNames(o.slug, o.root);
    // Expiries: structural names for ~11 months (the platform root renews yearly), approvers 180 days (EnsWriter).
    const expiry = BigInt(Math.floor(Date.now() / 1000) + 330 * 86400);
    let i = 0;
    if (!s.fromBlock) {
      s.fromBlock = String(await this.client.getBlockNumber());
      o.save(s);
    }
    const step = async (name: (typeof PROVISION_STEPS)[number], fn: () => Promise<{ hash: Hex | "existing"; set?: Partial<ProvisionState> }>) => {
      o.progress?.(name, i++, PROVISION_STEPS.length);
      if (s.done[name]) return;
      const r = await fn();
      Object.assign(s, r.set);
      s.done[name] = r.hash;
      o.save(s);
    };
    const deploy = async (key: string, impl: Address, data: Hex) => {
      const salt = BigInt(keccak256(stringToBytes(`airlock:${names.base}:${key}:${o.owner}`)));
      // A retry after a lost receipt: the proxy may already exist (same salt would revert), so look for it first.
      const [prior] = await this.client
        .getContractEvents({ address: ENS_V2.factory, abi, eventName: "ProxyDeployed", args: { sender: me }, fromBlock: BigInt(s.fromBlock!) })
        .then((logs) => logs.filter((l) => l.args.salt === salt))
        .catch(() => []);
      if (prior) return { hash: prior.transactionHash as Hex, proxy: prior.args.proxyAddress! };
      const rcpt = await this.send(`deploy ${key}`, { address: ENS_V2.factory, functionName: "deployProxy", args: [impl, salt, data] });
      const [ev] = parseEventLogs({ abi, logs: rcpt.logs, eventName: "ProxyDeployed" });
      return { hash: rcpt.transactionHash, proxy: ev.args.proxyAddress };
    };
    const grants = (roles: bigint) => [{ account: me, roleBitmap: roles }, ...(o.owner.toLowerCase() !== me.toLowerCase() ? [{ account: o.owner, roleBitmap: roles }] : [])];
    const regInit = encodeFunctionData({ abi, functionName: "initialize", args: [grants(REGISTRY_ROOT_ROLES)] });

    await step("deploy resolver", async () => {
      const d = await deploy("resolver", ENS_V2.resolverImpl, encodeFunctionData({ abi: resolverInit, functionName: "initialize", args: [grants(RESOLVER_ROLES), []] }));
      return { hash: d.hash, set: { resolver: d.proxy } };
    });
    await step("deploy registry", async () => {
      const d = await deploy("registry", ENS_V2.userRegistryImpl, regInit);
      return { hash: d.hash, set: { registry: d.proxy } };
    });
    await step("deploy approver registry", async () => {
      const d = await deploy("approvers", ENS_V2.userRegistryImpl, regInit);
      return { hash: d.hash, set: { approverRegistry: d.proxy } };
    });
    const reg = (registry: Address, label: string, subregistry: Address, resolver: Address) => async () => {
      // Already registered (a retry after the receipt was lost): registering again would revert.
      if (await this.registered(registry, label)) return { hash: "existing" as const };
      return { hash: (await this.send(`register ${label}`, { address: registry, functionName: "register", args: [label, o.owner, subregistry, resolver, TOKEN_ROLES, expiry] })).transactionHash };
    };
    await step("register name", reg(this.rootRegistry, o.slug, s.registry!, zeroAddress));
    await step("register policy", reg(s.registry!, "policy", zeroAddress, s.resolver!));
    await step("register approvers", reg(s.registry!, "approvers", s.approverRegistry!, zeroAddress));
    await step("register audit", reg(s.registry!, "audit", zeroAddress, s.resolver!));
    // Owner and platform are the same account only on a dev setup; there's nobody to hand over to.
    const handOver = o.owner.toLowerCase() !== me.toLowerCase();
    await step("write policy", async () => {
      // Already handed over (a retry after the receipt was lost): the policy landed in that same transaction.
      if (handOver && !(await this.rootRoles(s.resolver!))) return { hash: "existing" as const };
      const calls = [...this.policyCalls(names.policy, o.policy()), ...(handOver ? await this.handOverCalls(s.resolver!, names.policy) : [])];
      return { hash: (await this.send("write policy", { address: s.resolver!, functionName: "multicall", args: [calls] })).transactionHash };
    });
    // A no-op for new gateways ("write policy" did it); gateways provisioned before the hand-over existed get it here.
    await step("hand over policy", async () => {
      if (!handOver || !(await this.rootRoles(s.resolver!))) return { hash: "existing" as const };
      const calls = await this.handOverCalls(s.resolver!, names.policy);
      return { hash: (await this.send("hand over policy", { address: s.resolver!, functionName: "multicall", args: [calls] })).transactionHash };
    });
    await step("hand over registry", async () => {
      const held = handOver ? await this.rootRoles(s.registry!) : 0n;
      if (!held) return { hash: "existing" as const };
      return { hash: (await this.send("hand over registry", { address: s.registry!, functionName: "revokeRootRoles", args: [held, me] })).transactionHash };
    });
    o.progress?.("live", PROVISION_STEPS.length, PROVISION_STEPS.length);
    return s;
  }

  private async registered(registry: Address, label: string) {
    const [sub, res] = await Promise.all(
      (["getSubregistry", "getResolver"] as const).map((fn) => this.client.readContract({ address: registry, abi, functionName: fn, args: [label] })),
    );
    return sub !== zeroAddress || res !== zeroAddress;
  }

  /** The platform's root roles on a resolver or registry (0 once it has handed the gateway over). */
  private rootRoles(contract: Address) {
    return this.client.readContract({ address: contract, abi, functionName: "roles", args: [0n, this.account.address] });
  }

  private policyCalls(policyName: string, records: Partial<PolicyRecords>) {
    const dns = toHex(packetToBytes(normalize(policyName)));
    return Object.entries(records).map(([k, v]) => encodeFunctionData({ abi, functionName: "setText", args: [dns, `airlock.${k}`, v ?? ""] }));
  }

  /** Keep ROLE_SET_TEXT on the gateway's own keys, then give up every root role (runs inside a resolver multicall). */
  private async handOverCalls(resolver: Address, anyName: string) {
    const dns = toHex(packetToBytes(normalize(anyName)));
    const me = this.account.address;
    // The grant is per key (the name in the setter is ignored), and granting a role already held is harmless.
    const grants = GATEWAY_KEYS.map((key) =>
      encodeFunctionData({ abi, functionName: "grantSetterRoles", args: [encodeFunctionData({ abi, functionName: "setText", args: [dns, key, ""] }), me] }),
    );
    return [...grants, encodeFunctionData({ abi, functionName: "revokeRootRoles", args: [await this.rootRoles(resolver), me] })];
  }

  /** One multicall: every policy record for the gateway, so a policy change lands atomically. Only before hand-over. */
  async writePolicy(resolver: Address, policyName: string, records: Partial<PolicyRecords>): Promise<Hex> {
    return (await this.send("write policy", { address: resolver, functionName: "multicall", args: [this.policyCalls(policyName, records)] })).transactionHash;
  }

  /** The transaction the owner's wallet signs to change the policy (the platform can't send it for them). */
  policyTx(resolver: Address, policyName: string, records: Partial<PolicyRecords>) {
    return { to: resolver, data: encodeFunctionData({ abi, functionName: "multicall", args: [this.policyCalls(policyName, records)] }), chainId: sepolia.id };
  }

  /** May `account` write every policy key on this resolver? Asked of the chain, since the owner can grant others. */
  async canWritePolicy(resolver: Address, account: Address, records: Partial<PolicyRecords>): Promise<boolean> {
    const read = (resource: bigint) => this.client.readContract({ address: resolver, abi, functionName: "roles", args: [resource, account] });
    const root = await read(0n);
    if (root & ROLE_SET_TEXT) return true;
    const perKey = await Promise.all(Object.keys(records).map((k) => read(BigInt(keccak256(toBytes(`airlock.${k}`))))));
    return perKey.every((r) => (r & ROLE_SET_TEXT) !== 0n);
  }

  /**
   * Did transaction `hash` write exactly `records` to the gateway's policy name? Read from its own TextUpdated
   * events rather than the records, so a lagging RPC can't make a good write look missing. Returns why not, or undefined.
   */
  async checkPolicyTx(resolver: Address, policyName: string, records: Partial<PolicyRecords>, hash: Hex): Promise<string | undefined> {
    const rcpt = await this.client.waitForTransactionReceipt({ hash, timeout: 120_000 });
    if (rcpt.status !== "success") return "the transaction reverted";
    const recordId = await this.client.readContract({ address: resolver, abi, functionName: "getRecordId", args: [namehash(normalize(policyName))] });
    const written = new Map<string, string>();
    for (const ev of parseEventLogs({ abi, logs: rcpt.logs, eventName: "TextUpdated" }))
      if (ev.address.toLowerCase() === resolver.toLowerCase() && ev.args.recordId === recordId) written.set(ev.args.key, ev.args.value);
    const wrong = Object.entries(records).filter(([k, v]) => written.get(`airlock.${k}`) !== (v ?? ""));
    if (wrong.length) return `the transaction didn't write ${wrong.map(([k]) => k).join(", ")} as asked`;
  }
}
