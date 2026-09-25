import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dictionaryRecognizer, newSession, PipelineRedactor, rehydrateText, ruleRecognizer } from "./index";

const dict = JSON.parse(readFileSync(new URL("../../demo/dictionary.json", import.meta.url), "utf8"));
const redactor = new PipelineRedactor([ruleRecognizer, dictionaryRecognizer(dict)]);

test("contract is confidential, redacted, and keeps punctuation", async () => {
  const s = newSession("t1");
  const out = await redactor.redact([{ role: "user", content: readFileSync(new URL("../../demo/contract.md", import.meta.url), "utf8") }], s);
  const text = out.payload[0].content!;
  assert.equal(out.sourceClass, "confidential");
  for (const leak of ["Globex", "Hank Scorpio", "hank@globex.example", "2,400,000", "Initech"]) assert(!text.includes(leak), leak);
  assert.match(text, /capped at <MONEY_\d+>, excluding/);
  assert.deepEqual(out.entities, { ORG: 3, PERSON: 1, EMAIL: 1, PHONE: 1, MONEY: 2 });
});

test("placeholders are stable across turns and overlapping hits don't mint extra ids", async () => {
  const s = newSession("t2");
  const a = await redactor.redact([{ role: "user", content: "Globex Corporation signed." }], s);
  const b = await redactor.redact([{ role: "user", content: "Did globex corporation pay?" }], s);
  assert.equal(a.payload[0].content, "<ORG_1> signed.");
  assert.equal(b.payload[0].content, "Did <ORG_1> pay?");
  assert.equal(s.counters.ORG, 1);
});

test("restricted identifiers force local-only", async () => {
  const out = await redactor.redact([{ role: "user", content: "Card 4111 1111 1111 1111" }], newSession("t3"));
  assert.equal(out.sourceClass, "restricted");
});

test("rehydrate restores values, tolerating escaped brackets", () => {
  const s = newSession("t4");
  s.reverse.set("<ORG_1>", "Globex Corporation");
  assert.equal(rehydrateText("Ask \\<ORG_1\\> and < ORG_1 >; keep <MONEY_9>.", s), "Ask Globex Corporation and Globex Corporation; keep <MONEY_9>.");
});
