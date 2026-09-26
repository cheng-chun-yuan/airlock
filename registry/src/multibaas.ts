import { createHmac, timingSafeEqual } from "node:crypto";
import { hexToBytes, keccak256, toBytes, type Hex } from "viem";

/**
 * Curvegrid MultiBaas: indexes the ENSv2 contracts Airlock depends on and pushes their events to the gateway.
 * Airlock uses it so on-chain changes (a revoked approver, an edited policy, an access-control change) take
 * effect immediately and leave a readable change history, instead of waiting for caches to expire.
 * REST reference: https://docs.curvegrid.com/multibaas/
 */
export class MultiBaas {
  constructor(
    private base: string, // https://<id>.multibaas.com
    private apiKey: string,
  ) {}

  private async req<T = any>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.base.replace(/\/$/, "")}/api/v0${path}`, {
      method,
      headers: { authorization: `Bearer ${this.apiKey}`, "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const j = (await res.json().catch(() => ({}))) as { status?: number; message?: string; result?: T };
    if (!res.ok) throw Object.assign(new Error(`MultiBaas ${method} ${path}: ${res.status} ${j.message ?? ""}`.trim()), { status: res.status });
    return j.result as T;
  }

  uploadContract(label: string, abi: unknown[], version = "1.0") {
    return this.req("POST", `/contracts/${label}`, { label, contractName: label, version, rawAbi: JSON.stringify(abi) });
  }
  setAlias(alias: string, address: string) {
    return this.req("POST", `/chains/ethereum/addresses`, { alias, address });
  }
  /** Without `startingBlock` MultiBaas doesn't index events. "-N" = N blocks back, "latest", or an absolute number. */
  link(addressOrAlias: string, label: string, startingBlock: string) {
    return this.req("POST", `/chains/ethereum/addresses/${addressOrAlias}/contracts`, { label, startingBlock });
  }
  status(addressOrAlias: string, label: string) {
    return this.req<{ isProcessingPastLogs: boolean; latestBlockNumber: number; startBlockNumber: number }>("GET", `/chains/ethereum/addresses/${addressOrAlias}/contracts/${label}/status`);
  }
  events(params: Record<string, string | number>) {
    const q = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)]));
    return this.req<unknown[]>("GET", `/events?${q}`);
  }
  webhooks() {
    return this.req<{ id: number; url: string; label: string }[]>("GET", `/webhooks`);
  }
  createWebhook(url: string, label: string) {
    return this.req<{ id: number; secret: string }>("POST", `/webhooks`, { url, label, subscriptions: ["event.emitted"] });
  }
}

/** X-MultiBaas-Signature = hex(HMAC-SHA256(secret, rawBody + X-MultiBaas-Timestamp)). */
export function verifyWebhook(secret: string, rawBody: string, signature?: string, timestamp?: string, maxSkewS = 300): boolean {
  if (!signature || !timestamp) return false;
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > maxSkewS) return false; // stale or replayed delivery
  const want = createHmac("sha256", secret).update(rawBody + timestamp).digest("hex");
  const a = Buffer.from(want), b = Buffer.from(signature.replace(/^0x/, "").toLowerCase());
  return a.length === b.length && timingSafeEqual(a, b);
}

export interface ChainEvent {
  name: string;
  args: Record<string, string>;
  contract: string; // address (lowercase)
  label?: string;
  tx?: string;
  block?: number;
  at?: string;
}

/** Normalise a MultiBaas event (webhook `data` or `/events` item) into name + args. */
export function toChainEvent(e: any): ChainEvent | undefined {
  const ev = e?.event ?? e;
  if (!ev?.name) return undefined;
  const args: Record<string, string> = {};
  for (const i of ev.inputs ?? []) args[i.name] = typeof i.value === "string" ? i.value : JSON.stringify(i.value);
  return {
    name: ev.name,
    args,
    contract: String(ev.contract?.address ?? "").toLowerCase(),
    label: ev.contract?.label,
    tx: e?.transaction?.txHash ?? e?.transaction?.hash,
    block: e?.transaction?.blockNumber,
    at: e?.triggeredAt ?? e?.transaction?.blockTime,
  };
}

export function parseWebhook(body: unknown): ChainEvent[] {
  return (Array.isArray(body) ? body : [body])
    .filter((d: any) => d?.event === "event.emitted")
    .map((d: any) => toChainEvent(d.data))
    .filter((x): x is ChainEvent => !!x);
}

/** Decode a DNS-encoded name (as emitted by Linked). */
export function dnsDecode(hex: string): string {
  const b = hexToBytes(hex as Hex);
  const labels: string[] = [];
  for (let i = 0; i < b.length && b[i] !== 0; i += b[i] + 1) labels.push(new TextDecoder().decode(b.slice(i + 1, i + 1 + b[i])));
  return labels.join(".");
}

/**
 * What Airlock knows about names, so events carrying ids and hashes can be read by humans:
 * resolver record ids → names, registry address → parent name, label hashes → labels, EAC resources → record keys.
 */
export interface NameBook {
  records: Record<string, string>; // recordId → name
  registries: Record<string, string>; // registry address (lowercase) → parent name
  labels: string[]; // candidate labels (alice, bob, …)
  keys: string[]; // airlock.* record keys
  accounts: Record<string, string>; // address (lowercase) → label
}

export type Described = { kind: "policy" | "approver" | "audit" | "access" | "alias" | "name"; text: string; invalidates: boolean };

export function describe(e: ChainEvent, book: NameBook): Described {
  const rec = (id: string) => book.records[id] ?? `record #${id}`;
  const labelOf = (tokenId: string) => {
    const hi = BigInt(tokenId) >> 32n; // token id = labelhash with the low 32 bits used as a version
    return book.labels.find((l) => BigInt(keccak256(toBytes(l))) >> 32n === hi) ?? `label ${tokenId.slice(0, 10)}…`;
  };
  const parent = book.registries[e.contract] ?? "";
  switch (e.name) {
    case "TextUpdated": {
      const name = rec(e.args.recordId), key = e.args.key, v = e.args.value;
      const kind = key === "airlock.approver" ? "approver" : key === "airlock.auditRoot" ? "audit" : "policy";
      return { kind, text: `${name}: ${key} ${v ? `= ${v.length > 42 ? v.slice(0, 18) + "…" + v.slice(-6) : v}` : "cleared"}`, invalidates: true };
    }
    case "Linked":
      return { kind: "alias", text: `${dnsDecode(e.args.name)} linked → ${rec(e.args.recordId)} (shared record)`, invalidates: true };
    case "LabelUnregistered":
      return { kind: "approver", text: `${labelOf(e.args.tokenId)}${parent && "." + parent} unregistered (revoked)`, invalidates: true };
    case "LabelRegistered":
      return { kind: "name", text: `${e.args.label}${parent && "." + parent} registered`, invalidates: true };
    case "ExpiryUpdated":
      return { kind: "name", text: `${labelOf(e.args.tokenId)}${parent && "." + parent} expiry → ${new Date(Number(e.args.newExpiry) * 1000).toISOString().slice(0, 10)}`, invalidates: true };
    case "EACRolesChanged": {
      const res = BigInt(e.args.resource);
      const key = res === 0n ? "all records (root)" : book.keys.find((k) => BigInt(keccak256(toBytes(k))) === res) ?? `resource ${e.args.resource.slice(0, 10)}…`;
      const who = book.accounts[String(e.args.account).toLowerCase()] ?? String(e.args.account).slice(0, 10) + "…";
      const was = BigInt(e.args.oldRoleBitmap || "0"), now = BigInt(e.args.newRoleBitmap || "0");
      return { kind: "access", text: `${who} ${now > was ? "granted" : now < was ? "lost" : "kept"} write access on ${key}`, invalidates: true };
    }
    default:
      return { kind: "name", text: `${e.name}`, invalidates: false };
  }
}
