import type { ChatMessage, ToolCall } from "@airlock/core";

export interface Usage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface Completion {
  message: ChatMessage;
  finishReason: string;
  model: string;
  usage?: Usage;
}

/** One streamed piece: text, and/or (at the end) finish reason and usage. */
export interface Chunk {
  text?: string;
  finishReason?: string;
  usage?: Usage;
}

/** Minimal SSE reader over a fetch Response. */
async function* sse(res: Response): AsyncGenerator<{ event?: string; data: string }> {
  const reader = res.body!.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  try {
    yield* frames();
  } finally {
    // Consumer stopped early (e.g. client hung up): cancel the upstream so it stops generating.
    await reader.cancel().catch(() => {});
  }
  async function* frames(): AsyncGenerator<{ event?: string; data: string }> {
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += value.replace(/\r\n/g, "\n");
    for (let i = buf.indexOf("\n\n"); i >= 0; i = buf.indexOf("\n\n")) {
      const raw = buf.slice(0, i);
      buf = buf.slice(i + 2);
      let event: string | undefined;
      const data: string[] = [];
      for (const line of raw.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
      }
      if (data.length) yield { event, data: data.join("\n") };
    }
  }
  }
}

async function* openaiStream(url: string, headers: Record<string, string>, body: Record<string, unknown>, signal?: AbortSignal): AsyncGenerator<Chunk> {
  const res = await fetch(url, {
    signal,
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ ...body, stream: true, stream_options: { include_usage: true } }),
  });
  if (!res.ok) throw new Error(`upstream ${res.status}: ${await res.text()}`);
  for await (const { data } of sse(res)) {
    if (data === "[DONE]") break;
    const j = JSON.parse(data);
    const c = j.choices?.[0];
    if (c?.delta?.content) yield { text: c.delta.content };
    if (c?.finish_reason) yield { finishReason: c.finish_reason };
    if (j.usage) yield { usage: j.usage };
  }
}

/** OpenAI-compatible local model (vLLM on the GB10). */
export class LocalModel {
  constructor(
    private baseUrl: string,
    public model: string,
    private disableThinking = true,
  ) {}

  private body(messages: ChatMessage[], extra: Record<string, unknown>) {
    return {
      max_tokens: 2048,
      ...extra,
      model: this.model,
      messages,
      ...(this.disableThinking && { chat_template_kwargs: { enable_thinking: false } }),
    };
  }

  async complete(messages: ChatMessage[], extra: Record<string, unknown> = {}): Promise<Completion> {
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...this.body(messages, extra), stream: false }),
    });
    if (!res.ok) throw new Error(`local model ${res.status}: ${await res.text()}`);
    const j = (await res.json()) as any;
    const c = j.choices[0];
    return {
      message: { role: "assistant", content: c.message.content ?? "", tool_calls: c.message.tool_calls },
      finishReason: c.finish_reason,
      model: `local/${this.model}`,
      usage: j.usage,
    };
  }

  stream(messages: ChatMessage[], extra: Record<string, unknown> = {}, signal?: AbortSignal): AsyncGenerator<Chunk> {
    return openaiStream(`${this.baseUrl}/chat/completions`, {}, this.body(messages, extra), signal);
  }

  /** Plain question → text, for the local helpers (attack test, identifier tagging). */
  async ask(system: string, user: string, maxTokens = 1024): Promise<string> {
    const r = await this.complete(
      [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
      { temperature: 0, max_tokens: maxTokens },
    );
    return r.message.content ?? "";
  }
}

/** Frontier model. Only the Egress step calls this, and only with redacted payloads. */
export interface FrontierModel {
  readonly name: string;
  readonly configured: boolean;
  complete(model: string, messages: ChatMessage[]): Promise<Completion>;
  /** `signal` aborts the upstream request (client hung up). */
  stream(model: string, messages: ChatMessage[], signal?: AbortSignal): AsyncGenerator<Chunk>;
}

const ANTHROPIC = "https://api.anthropic.com";

/**
 * Anthropic Messages API. `baseUrl` can point at a self-hosted
 * Anthropic-compatible proxy; those usually take the key as a Bearer token,
 * so we send both headers when not talking to Anthropic directly.
 */
export class ClaudeModel implements FrontierModel {
  readonly name: string;
  constructor(
    private apiKey: string | undefined,
    private baseUrl = ANTHROPIC,
    private maxTokens = 4096,
  ) {
    this.name = baseUrl === ANTHROPIC ? "anthropic" : `anthropic-compatible (${new URL(baseUrl).host})`;
  }

  get configured() {
    return !!this.apiKey;
  }

  private request(model: string, messages: ChatMessage[], stream: boolean, signal?: AbortSignal) {
    if (!this.apiKey) throw new Error("egress API key not set");
    const system = messages
      .filter((m) => m.role === "system")
      .map((m) => m.content)
      .join("\n\n");
    const turns = messages
      .filter((m) => m.role !== "system")
      .map((m) => ({
        role: m.role === "assistant" ? "assistant" : "user",
        content:
          m.role === "tool"
            ? `[tool result ${m.tool_call_id ?? ""}]\n${m.content ?? ""}`
            : [m.content ?? "", ...(m.tool_calls ?? []).map((t: ToolCall) => `[tool call ${t.function.name}(${t.function.arguments})]`)]
                .filter(Boolean)
                .join("\n") || "(empty)",
      }));
    return fetch(`${this.baseUrl}/v1/messages`, {
      signal,
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": this.apiKey,
        "anthropic-version": "2023-06-01",
        ...(this.baseUrl !== ANTHROPIC && { authorization: `Bearer ${this.apiKey}` }),
      },
      body: JSON.stringify({ model, max_tokens: this.maxTokens, ...(system && { system }), messages: turns, stream }),
    });
  }

  async complete(model: string, messages: ChatMessage[]): Promise<Completion> {
    const res = await this.request(model, messages, false);
    if (!res.ok) throw new Error(`claude ${res.status}: ${await res.text()}`);
    const j = (await res.json()) as any;
    const text = j.content
      .filter((b: any) => b.type === "text")
      .map((b: any) => b.text)
      .join("");
    return {
      message: { role: "assistant", content: text },
      finishReason: j.stop_reason === "max_tokens" ? "length" : "stop",
      model: `airlock/${model}`,
      usage: usageOf(j.usage?.input_tokens, j.usage?.output_tokens),
    };
  }

  async *stream(model: string, messages: ChatMessage[], signal?: AbortSignal): AsyncGenerator<Chunk> {
    const res = await this.request(model, messages, true, signal);
    if (!res.ok) throw new Error(`claude ${res.status}: ${await res.text()}`);
    let input = 0;
    for await (const { event, data } of sse(res)) {
      const j = JSON.parse(data);
      if (event === "error" || j.type === "error") throw new Error(`claude stream: ${j.error?.message ?? data}`);
      if (j.type === "message_start") input = j.message?.usage?.input_tokens ?? 0;
      else if (j.type === "content_block_delta" && j.delta?.type === "text_delta") yield { text: j.delta.text };
      else if (j.type === "message_delta")
        yield { finishReason: j.delta?.stop_reason === "max_tokens" ? "length" : "stop", usage: usageOf(input, j.usage?.output_tokens) };
    }
  }
}

const usageOf = (i = 0, o = 0): Usage => ({ prompt_tokens: i, completion_tokens: o, total_tokens: i + o });

/**
 * Any OpenAI-compatible upstream you configure (e.g. a self-hosted LiteLLM
 * or vLLM). Which models may be used is still decided by the ENS policy
 * (`airlock.models`), not by the upstream.
 */
export class OpenAICompatModel implements FrontierModel {
  readonly name: string;
  constructor(
    private apiKey: string | undefined,
    private baseUrl: string,
  ) {
    this.name = `openai-compatible (${new URL(baseUrl).host})`;
  }

  get configured() {
    return !!this.apiKey;
  }

  async complete(model: string, messages: ChatMessage[]): Promise<Completion> {
    if (!this.apiKey) throw new Error("egress API key not set");
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${this.apiKey}` },
      body: JSON.stringify({ model, messages, stream: false }),
    });
    if (!res.ok) throw new Error(`egress ${res.status}: ${await res.text()}`);
    const j = (await res.json()) as any;
    const c = j.choices[0];
    return {
      message: { role: "assistant", content: c.message.content ?? "", tool_calls: c.message.tool_calls },
      finishReason: c.finish_reason,
      model: `airlock/${model}`,
      usage: j.usage,
    };
  }

  stream(model: string, messages: ChatMessage[], signal?: AbortSignal): AsyncGenerator<Chunk> {
    if (!this.apiKey) throw new Error("egress API key not set");
    return openaiStream(`${this.baseUrl}/chat/completions`, { authorization: `Bearer ${this.apiKey}` }, { model, messages }, signal);
  }
}
