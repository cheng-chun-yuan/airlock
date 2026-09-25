import { createHash } from "node:crypto";

export * from "./types";
export * from "./policy";

/** JSON with sorted keys, so hashes are stable. */
export function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const o = v as Record<string, unknown>;
  return (
    "{" +
    Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + canonical(o[k]))
      .join(",") +
    "}"
  );
}

export const sha256 = (s: string) => "0x" + createHash("sha256").update(s).digest("hex");
export const hashOf = (v: unknown) => sha256(canonical(v));
