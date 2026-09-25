import { createHmac } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonical, sha256, type AuditRecord, type AuditSink } from "@airlock/core";

const GENESIS = "0x" + "0".repeat(64);

type Draft = Omit<AuditRecord, "seq" | "prevHash" | "timestamp" | "hash" | "gatewaySig">;

/** Append-only JSONL hash chain. Each record commits to the previous record's hash. */
export class JsonlAuditLog implements AuditSink {
  private records: AuditRecord[] = [];

  constructor(
    private file: string,
    private secret: string,
    private anchorFn?: (root: string) => Promise<string | undefined>,
  ) {
    mkdirSync(dirname(file), { recursive: true });
    if (existsSync(file))
      this.records = readFileSync(file, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l));
  }

  private digest(r: Omit<AuditRecord, "hash" | "gatewaySig">) {
    return sha256(canonical(r));
  }

  append(draft: Draft): AuditRecord {
    const prev = this.records.at(-1);
    const body = { ...draft, seq: (prev?.seq ?? -1) + 1, prevHash: prev?.hash ?? GENESIS, timestamp: Date.now() };
    const hash = this.digest(body);
    const rec: AuditRecord = { ...body, hash, gatewaySig: createHmac("sha256", this.secret).update(hash).digest("hex") };
    appendFileSync(this.file, JSON.stringify(rec) + "\n");
    this.records.push(rec);
    return rec;
  }

  list(): AuditRecord[] {
    return this.records;
  }

  /** Recompute every hash and link. Returns the first broken seq, if any. */
  verify(): { ok: boolean; brokenAt?: number } {
    let prevHash = GENESIS;
    for (const r of this.records) {
      const { hash, gatewaySig, ...body } = r;
      const sig = createHmac("sha256", this.secret).update(hash).digest("hex");
      if (r.prevHash !== prevHash || this.digest(body) !== hash || sig !== gatewaySig) return { ok: false, brokenAt: r.seq };
      prevHash = hash;
    }
    return { ok: true };
  }

  merkleRoot(): string {
    let level = this.records.map((r) => r.hash);
    if (!level.length) return GENESIS;
    while (level.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < level.length; i += 2) next.push(sha256(level[i] + (level[i + 1] ?? level[i]).slice(2)));
      level = next;
    }
    return level[0];
  }

  async anchor(): Promise<{ root: string; tx?: string }> {
    const root = this.merkleRoot();
    return { root, tx: await this.anchorFn?.(root) };
  }
}
