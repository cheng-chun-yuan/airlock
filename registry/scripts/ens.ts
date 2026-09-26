/**
 * ENS setup / inspection for Airlock (ENSv2 on Sepolia). See docs/INTEGRATION-NOTES.md.
 *
 *   npm run ens -- check <agent> [approverName]    read policy, approver and audit records
 *   npm run ens -- set-policy <agent> [file]       write airlock.* policy records (default demo/policies.json)
 *   npm run ens -- enroll <approverName> <commitment>
 *   npm run ens -- revoke <approverName>           unregister the subname (ENS_APPROVER_REGISTRY) and clear airlock.approver
 *   npm run ens -- anchor <root>                   write airlock.auditRoot on ENS_AUDIT_NAME
 *   npm run ens -- set <name> <key> <value>        write any text record (e.g. airlock.models)
 *   npm run ens -- commitment <nullifier>          what enrollment would store for a nullifier
 *
 * Env: SEPOLIA_RPC_URL, ENS_RESOLVER + ENS_PRIVATE_KEY (writes), ENS_APPROVER_REGISTRY, ENS_AUDIT_NAME, COMMITMENT_SALT, ENS_UNIVERSAL_RESOLVER.
 */
import { readFileSync } from "node:fs";
import type { Hex } from "viem";
import { commitmentOf, ensClient, EnsPolicyResolver, EnsRoleRegistry, EnsWriter } from "../src/index";

const env = process.env;
const [cmd, ...args] = process.argv.slice(2);
const rpc = env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com";
const client = ensClient(rpc, env.ENS_UNIVERSAL_RESOLVER as Hex | undefined);
const auditName = env.ENS_AUDIT_NAME ?? "audit.acme.eth";
const POLICY_KEYS = ["maxClass", "egress", "models", "approverRole", "ownerRole"] as const;

/** Gateway key: approver + audit records. Policy keys need the security key (see `npm run ens:eac`). */
const GATEWAY_KEYS = new Set(["airlock.approver", "airlock.auditRoot"]);
function writer(forKey?: string): EnsWriter {
  const policy = forKey && !GATEWAY_KEYS.has(forKey) && env.ENS_SECURITY_PRIVATE_KEY;
  const key = policy ? env.ENS_SECURITY_PRIVATE_KEY : env.ENS_PRIVATE_KEY;
  if (!key || !env.ENS_RESOLVER) throw new Error("set ENS_PRIVATE_KEY and ENS_RESOLVER (your PermissionedResolver) to write");
  if (forKey) console.log(`  signing ${forKey} as ${policy ? "security" : "gateway"} account`);
  return new EnsWriter(rpc, key as Hex, env.ENS_RESOLVER as Hex, client, env.ENS_APPROVER_REGISTRY as Hex | undefined);
}
const need = (v: string | undefined, name: string) => v ?? (console.error(`missing <${name}>`), process.exit(2));
const text = (name: string, key: string) => client.getEnsText({ name, key }).catch((e) => `error: ${(e as Error).message.split("\n")[0]}`);

async function main() {
  switch (cmd) {
    case "check": {
      const agent = need(args[0], "agent");
      console.log(`rpc ${rpc}\n\n${agent}`);
      for (const k of POLICY_KEYS) console.log(`  airlock.${k.padEnd(13)} ${(await text(agent, `airlock.${k}`)) ?? "—"}`);
      const p = await new EnsPolicyResolver(client, 0).resolve(agent);
      console.log(`  effective policy     ${JSON.stringify(p)}${p.egress === "block" ? "   ← fail-closed (records missing?)" : ""}`);
      if (args[1]) {
        console.log(`\n${args[1]}\n  airlock.approver     ${(await text(args[1], "airlock.approver")) ?? "—"}\n  airlock.expires      ${(await text(args[1], "airlock.expires")) ?? "—"}`);
        const onchain = await text(args[1], "airlock.approver");
        if (onchain && !onchain.startsWith("error")) console.log(`  role check           ${await new EnsRoleRegistry(client).isValidApprover(onchain, p.approverRole, args[1])} (for role ${p.approverRole})`);
      }
      console.log(`\n${auditName}\n  airlock.auditRoot    ${(await text(auditName, "airlock.auditRoot")) ?? "—"}`);
      return;
    }
    case "set-policy": {
      const agent = need(args[0], "agent");
      const all = JSON.parse(readFileSync(args[1] ?? "demo/policies.json", "utf8"));
      const p = all[agent] ?? Object.values(all)[0];
      const w = writer("airlock.maxClass");
      for (const k of POLICY_KEYS)
        if (p[k] !== undefined) console.log(`airlock.${k} = ${p[k]}  tx ${await w.setText(agent, `airlock.${k}`, String(p[k]))}`);
      return;
    }
    case "enroll":
      await new EnsRoleRegistry(client, writer()).enroll(need(args[0], "approverName"), need(args[1], "commitment"));
      console.log(`enrolled ${args[0]}`);
      return;
    case "revoke":
      await new EnsRoleRegistry(client, writer()).revoke(need(args[0], "approverName"));
      console.log(`revoked ${args[0]} (subname unregistered, record cleared)`);
      return;
    case "anchor":
      console.log(`tx ${await writer().setText(auditName, "airlock.auditRoot", need(args[0], "root"))}`);
      return;
    case "set":
      console.log(`tx ${await writer(need(args[1], "key")).setText(need(args[0], "name"), args[1], need(args[2], "value"))}`);
      return;
    case "commitment":
      console.log(commitmentOf(need(args[0], "nullifier")));
      return;
    default:
      console.log(readFileSync(new URL(import.meta.url), "utf8").split("*/")[0].replace(/^\/\*\*?|^ \* ?/gm, "").trim());
  }
}
main().catch((e) => {
  console.error(`error: ${(e as Error).message}`);
  process.exit(1);
});
