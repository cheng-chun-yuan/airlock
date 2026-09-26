import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { DataClass } from "@airlock/core";
import type { ProvisionState } from "@airlock/registry";

/**
 * Who may do what in one gateway. admin: settings, members, invites, revoking approvers, anchoring (and may
 * approve once enrolled). approver: reviews held requests, after enrolling with World ID. member: sends
 * requests through the gateway with their own API keys.
 */
export type Role = "admin" | "approver" | "member";
export const ROLES: Role[] = ["admin", "approver", "member"];
export const canApprove = (r: Role) => r === "admin" || r === "approver";

export interface Member {
  /** Lowercased wallet address (SIWE). */
  address: string;
  /** ENS label inside the gateway: the approver name is <label>.approvers.<slug>.<root>. */
  label: string;
  role: Role;
  joinedAt: number;
  /**
   * The agent this member runs as (a label in Gateway.agents; unset = the gateway default policy). Set by admins
   * only: every request the member makes, from any of their keys or the Console, uses its ENS policy.
   */
  agent?: string;
}

export interface Invite {
  id: string;
  /** sha256 of the invite code; the code itself is only in the link. */
  codeHash: string;
  role: Role;
  /** Suggested label for the invitee (they can change it when joining). */
  label?: string;
  createdBy: string;
  createdAt: number;
  expiresAt: number;
  usedBy?: string;
  usedAt?: number;
}

export interface ApiKey {
  id: string;
  /** sha256 of the key; the key is shown once, at creation. */
  hash: string;
  /** First characters, so people can tell their keys apart. */
  prefix: string;
  name: string;
  member: string;
  /** Service keys only (made by an admin): the agent this key runs as. Unset = the member's assigned agent. */
  agent?: string;
  createdAt: number;
  lastUsedAt?: number;
}

/** <label>.policy.<slug>: a policy agents can be linked to, besides the gateway default. */
export interface NamedPolicy {
  label: string;
  policy: PolicyConfig;
  createdAt: number;
}

/** <label>.agents.<slug>: its policy is a named one (linked on ENS), or the gateway default when unset. */
export interface Agent {
  label: string;
  policy?: string;
  createdAt: number;
}

/** Encrypted at rest (AES-256-GCM); never sent back to the browser. */
export type Sealed = { sealed: string; last4: string };

export interface LocalConfig {
  /** shared: the platform's own local model. custom: an OpenAI-compatible endpoint the owner runs. */
  mode: "shared" | "custom";
  baseUrl?: string;
  model?: string;
  apiKey?: Sealed;
}

export interface FrontierConfig {
  /** hosted: the platform's own frontier upstream, shared and rate-limited; no URL or key of the gateway's own. */
  provider: "anthropic" | "openai" | "hosted";
  /** Anthropic default when unset; required for "openai" (any OpenAI-compatible upstream). */
  baseUrl?: string;
  apiKey?: Sealed;
  /** Models members may ask for; also written to ENS as airlock.models. */
  models: string[];
  defaultModel: string;
}

export interface PolicyConfig {
  maxClass: DataClass;
  egress: "auto" | "approval" | "block";
  highRiskQuorum: number;
}

export interface Gateway {
  id: string;
  slug: string;
  name: string;
  /** demo: the platform's preconfigured showcase (config from env, every signed-in user may use it). */
  kind: "user" | "demo";
  owner: string;
  createdAt: number;
  local: LocalConfig;
  frontier: FrontierConfig;
  /** Last policy written to ENS. ENS stays the source of truth; this is what the settings form starts from. */
  policy: PolicyConfig;
  ens: { status: "provisioning" | "live" | "failed"; step?: string; error?: string; state: ProvisionState };
  members: Member[];
  invites: Invite[];
  keys: ApiKey[];
  agents?: Agent[];
  policies?: NamedPolicy[];
}

interface Data {
  gateways: Gateway[];
}

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/** A short, readable ENS label: 1–32 of a-z, 0-9 and inner hyphens. */
export const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;

export class Vault {
  private key: Buffer;
  constructor(secret: string) {
    this.key = createHash("sha256").update(`airlock/vault/v1|${secret}`).digest();
  }
  seal(plain: string): Sealed {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.key, iv);
    const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
    return { sealed: Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64"), last4: plain.slice(-4) };
  }
  open(s?: Sealed): string | undefined {
    if (!s) return undefined;
    const b = Buffer.from(s.sealed, "base64");
    const d = createDecipheriv("aes-256-gcm", this.key, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8");
  }
}

/** JSON file store. Small data, one process: every change rewrites the file (tmp + rename, so never half-written). */
export class PlatformStore {
  private data: Data;
  constructor(private file: string) {
    mkdirSync(dirname(file), { recursive: true });
    this.data = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : { gateways: [] };
  }

  save() {
    const tmp = `${this.file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, this.file);
  }

  all() {
    return this.data.gateways;
  }
  bySlug(slug: string) {
    return this.data.gateways.find((g) => g.slug === slug);
  }
  add(g: Omit<Gateway, "id" | "createdAt" | "members" | "invites" | "keys"> & { members?: Member[] }): Gateway {
    const gw: Gateway = { id: randomUUID(), createdAt: Date.now(), invites: [], keys: [], members: [], ...g };
    this.data.gateways.push(gw);
    this.save();
    return gw;
  }
  remove(id: string) {
    this.data.gateways = this.data.gateways.filter((g) => g.id !== id);
    this.save();
  }

  /** A member's role, or for the demo gateway an implicit membership for anyone signed in. */
  memberOf(g: Gateway, address: string): Member | undefined {
    const a = address.toLowerCase();
    const m = g.members.find((x) => x.address === a);
    if (m || g.kind !== "demo") return m;
    return { address: a, label: `guest-${a.slice(2, 8)}`, role: "admin", joinedAt: 0 };
  }

  forUser(address: string) {
    const a = address.toLowerCase();
    return this.data.gateways.filter((g) => g.kind === "demo" || g.members.some((m) => m.address === a));
  }

  // ---------- invites ----------
  createInvite(g: Gateway, by: string, role: Role, label?: string, days = 7): { invite: Invite; code: string } {
    const code = randomBytes(18).toString("base64url");
    const invite: Invite = { id: randomUUID(), codeHash: sha256(code), role, label, createdBy: by, createdAt: Date.now(), expiresAt: Date.now() + days * 86400_000 };
    g.invites.push(invite);
    this.save();
    return { invite, code };
  }
  findInvite(code: string): { g: Gateway; invite: Invite } | undefined {
    const h = sha256(code);
    for (const g of this.data.gateways) {
      const invite = g.invites.find((i) => i.codeHash === h);
      if (invite) return { g, invite };
    }
  }

  // ---------- API keys ----------
  createKey(g: Gateway, member: string, name: string, agent?: string): { key: ApiKey; secret: string } {
    const secret = `alk_${randomBytes(24).toString("base64url")}`;
    const key: ApiKey = { id: randomUUID(), hash: sha256(secret), prefix: secret.slice(0, 10), name, member: member.toLowerCase(), ...(agent && { agent }), createdAt: Date.now() };
    g.keys.push(key);
    this.save();
    return { key, secret };
  }
  /** Resolve a bearer key to its gateway and still-current member. Keys die with the membership. */
  byKey(secret: string): { g: Gateway; key: ApiKey; member: Member } | undefined {
    if (!secret.startsWith("alk_")) return;
    const h = sha256(secret);
    for (const g of this.data.gateways) {
      const key = g.keys.find((k) => k.hash === h);
      if (!key) continue;
      const member = this.memberOf(g, key.member);
      if (!member) return;
      // Written at most once a minute: a busy agent shouldn't rewrite the store on every request.
      if (!key.lastUsedAt || Date.now() - key.lastUsedAt > 60_000) {
        key.lastUsedAt = Date.now();
        this.save();
      }
      return { g, key, member };
    }
  }
}
