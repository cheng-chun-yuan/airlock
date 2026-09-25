import type { ChatMessage, DataClass, RedactResult, Redactor, RiskResult, RiskScorer, Session } from "@airlock/core";

export interface Span {
  start: number;
  end: number;
  type: string;
}

export interface Recognizer {
  name: string;
  find(text: string): Span[] | Promise<Span[]>;
}

/** Entity types whose presence makes the whole request `restricted` (local-only). */
export const RESTRICTED_TYPES = new Set(["TW_ID", "CREDIT_CARD", "US_SSN", "API_KEY", "IBAN_CODE"]);

const RULES: [string, RegExp][] = [
  ["API_KEY", /\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})\b/g],
  ["TW_ID", /\b[A-Z][12]\d{8}\b/g],
  ["CREDIT_CARD", /\b(?:\d{4}[ -]?){3}\d{4}\b/g],
  ["US_SSN", /\b\d{3}-\d{2}-\d{4}\b/g],
  ["EMAIL", /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g],
  ["PHONE", /\+\d{1,3}[\s-]?\d[\d\s-]{6,}\d|\b09\d{2}-?\d{3}-?\d{3}\b|\(\d{3}\)\s?\d{3}-\d{4}/g],
  ["MONEY", /(?:US\$|NT\$|\$|€|£)\s?\d(?:[\d,]*\d)?(?:\.\d+)?(?:\s?(?:million|billion|[MBk]\b))?/gi],
  ["MONEY", /\b\d(?:[\d,]*\d)?(?:\.\d+)?\s?(?:USD|TWD|NTD|EUR|萬元|億元|元)/g],
];

export const ruleRecognizer: Recognizer = {
  name: "rules",
  find(text) {
    const out: Span[] = [];
    for (const [type, re] of RULES) for (const m of text.matchAll(re)) out.push({ start: m.index!, end: m.index! + m[0].length, type });
    return out;
  },
};

/** Company dictionary: { "ORG": ["Globex"], "PERSON": ["Hank Scorpio"], ... } — case-insensitive literal match. */
export function dictionaryRecognizer(dict: Record<string, string[]>): Recognizer {
  const entries = Object.entries(dict).flatMap(([type, words]) => words.map((w) => ({ type, w })));
  return {
    name: "dictionary",
    find(text) {
      const out: Span[] = [];
      const lower = text.toLowerCase();
      for (const { type, w } of entries) {
        const needle = w.toLowerCase();
        for (let i = lower.indexOf(needle); i !== -1; i = lower.indexOf(needle, i + needle.length))
          out.push({ start: i, end: i + needle.length, type });
      }
      return out;
    },
  };
}

const PRESIDIO_TYPES: Record<string, string> = {
  PERSON: "PERSON",
  LOCATION: "LOCATION",
  EMAIL_ADDRESS: "EMAIL",
  PHONE_NUMBER: "PHONE",
  CREDIT_CARD: "CREDIT_CARD",
  US_SSN: "US_SSN",
  IBAN_CODE: "IBAN_CODE",
  IP_ADDRESS: "IP_ADDRESS",
  NRP: "NRP",
};

/** Presidio analyzer sidecar. Offsets come back as code points; convert to UTF-16 indices. */
export function presidioRecognizer(url: string, language = "en", threshold = 0.5): Recognizer {
  return {
    name: "presidio",
    async find(text) {
      const res = await fetch(`${url}/analyze`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text, language, score_threshold: threshold }),
      });
      if (!res.ok) throw new Error(`presidio ${res.status}`);
      const hits = (await res.json()) as { entity_type: string; start: number; end: number }[];
      const cp = Array.from(text);
      const toUtf16 = (i: number) => cp.slice(0, i).join("").length;
      return hits
        .filter((h) => PRESIDIO_TYPES[h.entity_type])
        .map((h) => ({ start: toUtf16(h.start), end: toUtf16(h.end), type: PRESIDIO_TYPES[h.entity_type] }));
    },
  };
}

const CLASS_MARKERS: [DataClass, RegExp][] = [
  ["restricted", /\bRESTRICTED\b|極機密/],
  ["confidential", /\bCONFIDENTIAL\b|機密/i],
  ["internal", /\bINTERNAL\b|內部/],
];

export function newSession(id: string): Session {
  return { id, forward: new Map(), reverse: new Map(), counters: {} };
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export class PipelineRedactor implements Redactor {
  constructor(private recognizers: Recognizer[], private onError: (r: string, e: unknown) => void = () => {}) {}

  private placeholder(session: Session, type: string, value: string): string {
    const key = value.trim().toLowerCase(); // forward keys are case-folded; reverse keeps the first spelling seen
    let ph = session.forward.get(key);
    if (!ph) {
      session.counters[type] = (session.counters[type] ?? 0) + 1;
      ph = `<${type}_${session.counters[type]}>`;
      session.forward.set(key, ph);
      session.reverse.set(ph, value.trim());
    }
    return ph;
  }

  async redact(msgs: ChatMessage[], session: Session): Promise<RedactResult> {
    const texts = msgs.flatMap((m) => [m.content ?? "", ...(m.tool_calls ?? []).map((t) => t.function.arguments)]);
    const types = new Set<string>();
    let sourceClass: DataClass = "public";
    const raise = (c: DataClass) => {
      const order: DataClass[] = ["public", "internal", "confidential", "restricted"];
      if (order.indexOf(c) > order.indexOf(sourceClass)) sourceClass = c;
    };

    for (const text of texts) {
      if (!text) continue;
      for (const [cls, re] of CLASS_MARKERS) if (re.test(text)) raise(cls);
      const spans: Span[] = [];
      for (const r of this.recognizers) {
        try {
          spans.push(...(await r.find(text)));
        } catch (e) {
          this.onError(r.name, e);
        }
      }
      // Earliest, then longest span wins; drop anything overlapping a kept span.
      spans.sort((a, b) => a.start - b.start || b.end - a.end);
      let lastEnd = -1;
      for (const s of spans) {
        if (s.start < lastEnd) continue;
        lastEnd = s.end;
        this.placeholder(session, s.type, text.slice(s.start, s.end));
        types.add(s.type);
      }
    }
    for (const t of types) raise(RESTRICTED_TYPES.has(t) ? "restricted" : "confidential");

    // Replace every known value of this session (longest first) so placeholders stay stable across turns.
    const known = [...session.forward.keys()].sort((a, b) => b.length - a.length);
    const re = known.length ? new RegExp(known.map(escapeRe).join("|"), "gi") : null;
    const used = new Map<string, string>();
    const sub = (s: string) =>
      re
        ? s.replace(re, (m) => {
            const ph = session.forward.get(m.toLowerCase())!;
            used.set(ph, session.reverse.get(ph)!);
            return ph;
          })
        : s;

    const payload = msgs.map((m) => ({
      ...m,
      content: m.content == null ? m.content : sub(m.content),
      ...(m.tool_calls && {
        tool_calls: m.tool_calls.map((t) => ({ ...t, function: { ...t.function, arguments: sub(t.function.arguments) } })),
      }),
    }));

    const entities: Record<string, number> = {};
    for (const ph of used.keys()) {
      const type = ph.slice(1, ph.lastIndexOf("_"));
      entities[type] = (entities[type] ?? 0) + 1;
    }
    return { payload, mapping: Object.fromEntries(used), entities, sourceClass };
  }
}

/** Put real values back into text. Tolerates markdown-escaped brackets. */
export function rehydrateText(text: string, session: Session): string {
  return text.replace(/\\?<\s*([A-Z_]+_\d+)\s*\\?>/g, (m, id) => session.reverse.get(`<${id}>`) ?? m);
}

export function rehydrateMessage(m: ChatMessage, session: Session): ChatMessage {
  return {
    ...m,
    content: m.content == null ? m.content : rehydrateText(m.content, session),
    ...(m.tool_calls && {
      tool_calls: m.tool_calls.map((t) => ({
        ...t,
        function: { ...t.function, arguments: rehydrateText(t.function.arguments, session) },
      })),
    }),
  };
}

/**
 * Rule-based residual risk (P2 replaces this with a local-model attack test).
 * Looks for quasi-identifiers that survive redaction.
 */
export class RuleRiskScorer implements RiskScorer {
  private checks: [string, RegExp][] = [
    ["job title (indirect identifier)", /\b(?:CEO|CFO|CTO|COO|founder|general counsel|chairman)\b|董事長|總經理|執行長|財務長/i],
    ["exact date", /\b\d{4}-\d{2}-\d{2}\b|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{1,2},? \d{4}\b/],
    ["long number (account / case id?)", /(?<![<_\w])\d{6,}(?![>\w])/],
    ["street address", /\b\d+\s+\w+\s+(?:Street|St|Avenue|Ave|Road|Rd|Blvd)\b|路\d+號|街\d+號/i],
    ["unique descriptor", /\b(?:the only|sole|largest|first-ever)\b|唯一/i],
  ];

  score(payload: ChatMessage[]): RiskResult {
    const text = payload.map((m) => m.content ?? "").join("\n");
    const findings = this.checks.filter(([, re]) => re.test(text)).map(([f]) => f);
    return { level: findings.length >= 2 ? "high" : "low", findings };
  }
}
