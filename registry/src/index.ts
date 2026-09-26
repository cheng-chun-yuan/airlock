import { concat, keccak256, pad, toHex, type Hex } from "viem";

export * from "./static";
export * from "./ens";
export * from "./multibaas";

/**
 * On-chain we store commitment(nullifier), never the nullifier itself, so the
 * public record can't be linked to other apps' World ID usage without the salt.
 */
export function commitmentOf(nullifier: string, salt = process.env.COMMITMENT_SALT ?? "airlock-dev-salt"): Hex {
  return keccak256(concat([pad(nullifier as Hex, { size: 32 }), toHex(salt)]));
}
