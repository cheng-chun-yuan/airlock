import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { Policy, PolicyResolver, RoleCheck, RoleRegistry } from "@airlock/core";

/** Local JSON stand-in for ENS text records (same keys, minus the `airlock.` prefix). */
export class StaticPolicyResolver implements PolicyResolver {
  constructor(private file: string) {}
  async resolve(agent: string): Promise<Policy> {
    const all = JSON.parse(readFileSync(this.file, "utf8")) as Record<string, Omit<Policy, "agent">>;
    const p = all[agent];
    if (!p) throw new Error(`no policy for ${agent}`);
    return { agent, ...p };
  }
}

interface ApproverEntry {
  name: string; // alice.legal.approvers.acme.eth
  commitment: string;
  expires?: number; // unix seconds
  revoked?: boolean;
}

/** Local JSON stand-in for approver subnames. */
export class StaticRoleRegistry implements RoleRegistry {
  constructor(private file: string) {}

  private load(): ApproverEntry[] {
    return existsSync(this.file) ? JSON.parse(readFileSync(this.file, "utf8")) : [];
  }
  private save(list: ApproverEntry[]) {
    writeFileSync(this.file, JSON.stringify(list, null, 2) + "\n");
  }

  async isValidApprover(commitment: string, role: string, approverName?: string): Promise<RoleCheck> {
    const hits = this.load().filter(
      (a) => a.commitment.toLowerCase() === commitment.toLowerCase() && a.name.endsWith("." + role) && (!approverName || a.name === approverName),
    );
    if (!hits.length) return "unknown";
    const live = hits.find((a) => !a.revoked && !(a.expires && a.expires * 1000 < Date.now()));
    if (live) return "valid";
    return hits.some((a) => a.revoked) ? "revoked" : "expired";
  }

  async isLiveApprover(role: string, approverName: string): Promise<RoleCheck> {
    const a = this.load().find((x) => x.name === approverName && x.name.endsWith("." + role));
    if (!a) return "unknown";
    if (a.revoked) return "revoked";
    return a.expires && a.expires * 1000 < Date.now() ? "expired" : "valid";
  }

  async enroll(name: string, commitment: string) {
    this.save([...this.load().filter((a) => a.name !== name), { name, commitment }]);
  }

  async revoke(name: string) {
    this.save(this.load().map((a) => (a.name === name ? { ...a, revoked: true } : a)));
  }
}
