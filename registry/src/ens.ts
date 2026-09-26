import { createPublicClient, createWalletClient, http, keccak256, parseAbi, toBytes, toHex, zeroAddress, type Hex, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import { normalize, packetToBytes } from "viem/ens";
import type { DataClass, Policy, PolicyResolver, RoleCheck, RoleRegistry } from "@airlock/core";

/**
 * ENSv2 on Sepolia (docs.ens.domains/learn/deployments). viem's built-in
 * `sepolia.contracts.ensUniversalResolver` (0xeeee…eeee) is the permanent
 * entry proxy that forwards to UniversalResolverV2, so plain getEnsText works.
 * Other v2 addresses move on each testnet redeploy — keep them in env, not code.
 */
export function ensClient(rpcUrl: string, universalResolverAddress?: Hex): PublicClient {
  return createPublicClient({
    chain: universalResolverAddress ? { ...sepolia, contracts: { ...sepolia.contracts, ensUniversalResolver: { address: universalResolverAddress } } } : sepolia,
    transport: http(rpcUrl),
  }) as PublicClient;
}

const text = (client: PublicClient, name: string, key: string) =>
  client.getEnsText({ name: normalize(name), key }).then((v) => v || null).catch(() => null);

export class EnsPolicyResolver implements PolicyResolver {
  constructor(private client: PublicClient, private cacheMs = 10_000) {}
  private cache = new Map<string, { at: number; p: Policy }>();

  async resolve(agent: string): Promise<Policy> {
    const hit = this.cache.get(agent);
    if (hit && Date.now() - hit.at < this.cacheMs) return hit.p;
    const [maxClass, egress, models, approverRole, ownerRole] = await Promise.all(
      ["maxClass", "egress", "models", "approverRole", "ownerRole"].map((k) => text(this.client, agent, `airlock.${k}`)),
    );
    // Fail closed: a missing record means nothing leaves.
    const p: Policy = {
      agent,
      maxClass: (maxClass as DataClass) ?? "internal",
      egress: (egress as Policy["egress"]) ?? "block",
      models: models ?? "",
      approverRole: approverRole ?? "",
      ownerRole: ownerRole ?? undefined,
    };
    this.cache.set(agent, { at: Date.now(), p });
    return p;
  }
}

/**
 * Approver = subname under the role, e.g. alice.legal.approvers.acme.eth, with
 * text `airlock.approver` = commitment(nullifier). Revoking = `unregister` the
 * subname (or clear the record); ENSv2 subname expiry also makes it stop
 * resolving. Either way the record reads back empty → not valid.
 * Optional `airlock.expires` (unix seconds) gives a soft expiry distinct from revocation.
 */
export class EnsRoleRegistry implements RoleRegistry {
  constructor(private client: PublicClient, private writer?: EnsWriter) {}

  async isValidApprover(commitment: string, role: string, approverName?: string): Promise<RoleCheck> {
    if (!approverName || !normalize(approverName).endsWith("." + normalize(role))) return "unknown";
    const [onChain, expires] = await Promise.all([text(this.client, approverName, "airlock.approver"), text(this.client, approverName, "airlock.expires")]);
    if (!onChain) return "revoked";
    if (onChain.toLowerCase() !== commitment.toLowerCase()) return "unknown";
    if (expires && Number(expires) * 1000 < Date.now()) return "expired";
    return "valid";
  }

  async isLiveApprover(role: string, approverName: string): Promise<RoleCheck> {
    if (!approverName || !normalize(approverName).endsWith("." + normalize(role))) return "unknown";
    return (await text(this.client, approverName, "airlock.approver")) ? "valid" : "revoked";
  }

  /** Creates the approver's subname if needed (ENS_APPROVER_REGISTRY), then stores the commitment. */
  async enroll(name: string, commitment: string) {
    if (!this.writer) throw new Error("ENS writer not configured (ENS_PRIVATE_KEY / ENS_RESOLVER)");
    await this.writer.ensureSubname(normalize(name).split(".")[0]);
    await this.writer.setText(name, "airlock.approver", commitment);
  }

  /** Unregisters the subname (ENS_APPROVER_REGISTRY) and clears the record, so nothing resolves any more. */
  async revoke(name: string) {
    if (!this.writer) throw new Error("ENS writer not configured (ENS_PRIVATE_KEY / ENS_RESOLVER)");
    await this.writer.unregister(normalize(name).split(".")[0]);
    await this.writer.setText(name, "airlock.approver", "");
  }
}

const resolverAbi = parseAbi(["function setText(bytes name, string key, string value)"]);
const registryAbi = parseAbi([
  "function register(string label, address owner, address registry, address resolver, uint256 roleBitmap, uint64 expiry) returns (uint256)",
  "function unregister(uint256 anyId)",
  "function getResolver(string label) view returns (address)",
]);
// Token roles for approver subnames: unregister, renew, set subregistry, set resolver (+ their admin roles).
const APPROVER_TOKEN_ROLES = [12n, 16n, 20n, 24n].reduce((acc, b) => acc | (1n << b) | (1n << (b + 128n)), 0n);

/**
 * Writes to an ENSv2 PermissionedResolver. Setters take the DNS-encoded name
 * (not a namehash). EAC grants ROLE_SET_TEXT per exact record key, so the
 * gateway account should hold it only for airlock.auditRoot / airlock.approver
 * — policy keys stay with security.acme.eth. See docs/ENS.md.
 */
export class EnsWriter {
  private wallet;
  constructor(
    rpcUrl: string,
    privateKey: Hex,
    private resolver: Hex,
    private client: PublicClient,
    /** UserRegistry that holds <approver>.legal.approvers.<org>.eth (from `npm run ens:setup`). */
    private approverRegistry?: Hex,
  ) {
    this.wallet = createWalletClient({ account: privateKeyToAccount(privateKey), chain: sepolia, transport: http(rpcUrl) });
  }

  async setText(name: string, key: string, value: string): Promise<Hex> {
    const hash = await this.wallet.writeContract({
      address: this.resolver,
      abi: resolverAbi,
      functionName: "setText",
      args: [toHex(packetToBytes(normalize(name))), key, value],
    });
    await this.client.waitForTransactionReceipt({ hash });
    return hash;
  }

  private async write(fn: "register" | "unregister", args: readonly unknown[]): Promise<Hex> {
    if (!this.approverRegistry) throw new Error("ENS_APPROVER_REGISTRY not set");
    const { request } = await this.client.simulateContract({ account: this.wallet.account, address: this.approverRegistry, abi: registryAbi, functionName: fn, args } as any);
    const hash = await this.wallet.writeContract(request as any);
    const rcpt = await this.client.waitForTransactionReceipt({ hash });
    if (rcpt.status !== "success") throw new Error(`${fn} reverted (${hash})`);
    return hash;
  }

  /** Register `label` in the approver registry with our resolver, unless it's already live. */
  async ensureSubname(label: string, days = 180): Promise<Hex | undefined> {
    if (!this.approverRegistry) return;
    const current = await this.client.readContract({ address: this.approverRegistry, abi: registryAbi, functionName: "getResolver", args: [label] });
    if (current !== zeroAddress) return;
    const expiry = BigInt(Math.floor(Date.now() / 1000) + days * 86400);
    return this.write("register", [label, this.wallet.account.address, zeroAddress, this.resolver, APPROVER_TOKEN_ROLES, expiry]);
  }

  async unregister(label: string): Promise<Hex | undefined> {
    if (!this.approverRegistry) return;
    return this.write("unregister", [BigInt(keccak256(toBytes(label)))]);
  }
}

const inspectAbi = parseAbi([
  "function roles(uint256 resource, address account) view returns (uint256)",
]);
const ROLE_SET_TEXT = 1n << 4n;
export const POLICY_KEYS = ["airlock.maxClass", "airlock.egress", "airlock.models", "airlock.approverRole", "airlock.ownerRole"];
export const GATEWAY_KEYS = ["airlock.approver", "airlock.auditRoot"];

/** Read-only view of Airlock's ENS state for the Console: records, anchor, and who may write which key. */
export class EnsInspector {
  constructor(
    private client: PublicClient,
    private cfg: { resolver?: Hex; agent: string; auditName: string; accounts: { label: string; address: Hex }[]; approverRegistry?: Hex },
  ) {}

  async status(localRoot: string) {
    const { agent, auditName, resolver } = this.cfg;
    const policy = Object.fromEntries(await Promise.all(POLICY_KEYS.map(async (k) => [k, await text(this.client, agent, k)] as const)));
    const auditRoot = await text(this.client, auditName, "airlock.auditRoot");
    const keys = [...POLICY_KEYS, ...GATEWAY_KEYS];
    const access = resolver
      ? await Promise.all(
          this.cfg.accounts.map(async ({ label, address }) => {
            const read = (resource: bigint) => this.client.readContract({ address: resolver, abi: inspectAbi, functionName: "roles", args: [resource, address] }).catch(() => 0n);
            const root = await read(0n);
            const perKey = await Promise.all(keys.map(async (k) => [k, !!((root | (await read(BigInt(keccak256(toBytes(k)))))) & ROLE_SET_TEXT)] as const));
            return { label, address, admin: (root & (ROLE_SET_TEXT << 128n)) !== 0n, canWrite: Object.fromEntries(perKey) };
          }),
        )
      : [];
    return {
      agent,
      policy,
      approverRole: policy["airlock.approverRole"],
      audit: { name: auditName, onChain: auditRoot, local: localRoot, anchored: !!auditRoot && auditRoot.toLowerCase() === localRoot.toLowerCase() },
      resolver,
      approverRegistry: this.cfg.approverRegistry,
      access,
    };
  }

  async approver(name: string, role?: string) {
    const record = await text(this.client, name, "airlock.approver");
    const under = role ? normalize(name).endsWith("." + normalize(role)) : true;
    return { name, record, underRole: under, status: !under ? "not under role" : record ? "live" : "not registered / revoked" };
  }
}
