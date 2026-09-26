import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dictionaryRecognizer, LocalAttackScorer, llmRecognizer, newSession, PipelineRedactor, rehydrateText, ruleRecognizer, StreamRehydrator } from "./index";

const dict = JSON.parse(readFileSync(new URL("../../demo/dictionary.json", import.meta.url), "utf8"));
const redactor = new PipelineRedactor([ruleRecognizer, dictionaryRecognizer(dict)]);

test("contract is confidential, redacted, and keeps punctuation", async () => {
  const s = newSession("t1");
  const out = await redactor.redact([{ role: "user", content: readFileSync(new URL("../../demo/contract.md", import.meta.url), "utf8") }], s);
  const text = out.payload[0].content!;
  assert.equal(out.sourceClass, "confidential");
  for (const leak of ["Morrow Vale", "Daniel Okafor", "d.okafor@morrowvale.example", "2,400,000", "Halden & Brook", "Kestrelwood"]) assert(!text.includes(leak), leak);
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

test("stream rehydration survives placeholders split across chunks", () => {
  const s = newSession("t5");
  s.reverse.set("<ORG_1>", "Globex Corporation");
  s.reverse.set("<PERSON_12>", "Hank Scorpio");
  const pieces = ["Ask ", "\\", "<PER", "SON_", "12\\", "> at <", "ORG_1", ">", " if 3 < 5 and a<b.", " Done <"];
  const r = new StreamRehydrator(s);
  const out = pieces.map((p) => r.push(p)).join("") + r.flush();
  assert.equal(out, "Ask Hank Scorpio at Globex Corporation if 3 < 5 and a<b. Done <");
});

test("local attack test: a correct guess of a placeholder is a measured leak → high", async () => {
  const mapping = { "<ORG_1>": "Apple Inc.", "<PERSON_1>": "Hank Scorpio" };
  const payload = [{ role: "user" as const, content: "The Cupertino iPhone maker <ORG_1> hired <PERSON_1>." }];
  const leaky = new LocalAttackScorer(async () => '```json\n{"<ORG_1>": "Apple", "<PERSON_1>": null}\n```');
  const r = await leaky.score(payload, mapping);
  assert.equal(r.level, "high");
  assert.match(r.findings.join(), /re-identified <ORG_1>/);
  const blind = new LocalAttackScorer(async () => '{"<ORG_1>": "Samsung", "<PERSON_1>": "John Smith"}');
  assert.equal((await blind.score(payload, mapping)).level, "low");
  const broken = new LocalAttackScorer(async () => { throw new Error("down"); });
  assert.match((await broken.score(payload, mapping)).findings.join(), /unavailable/);
});

test("llm recognizer accepts only verbatim substrings", async () => {
  const text = "Our client, the largest chip foundry in Hsinchu, wants Project Bluebird kept quiet until Q3.";
  const rec = llmRecognizer(async () => '[{"text":"the largest chip foundry in Hsinchu","type":"ORG"},{"text":"Project Bluebird","type":"PROJECT"},{"text":"invented stuff","type":"ORG"},{"text":"Q3","type":"ID"}]');
  const spans = await rec.find(text);
  assert.deepEqual(spans.map((s) => text.slice(s.start, s.end)), ["the largest chip foundry in Hsinchu", "Project Bluebird"]);
});

test("dictionary aliases share the canonical placeholder, so short forms can't leak", async () => {
  const s = newSession("t6");
  const r = new PipelineRedactor([dictionaryRecognizer({ ORG: [["Kestrelwood Analytics", "Kestrelwood"]] })]);
  const out = await r.redact([{ role: "user", content: "Kestrelwood Analytics signed; Kestrelwood's liability is capped." }], s);
  assert.equal(out.payload[0].content, "<ORG_1> signed; <ORG_1>'s liability is capped.");
  assert.equal(rehydrateText("<ORG_1>'s risk", s), "Kestrelwood Analytics's risk");
});
