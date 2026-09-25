import type { ChatMessage, ToolCall } from "@airlock/core";

export interface Completion {
  message: ChatMessage;
  finishReason: string;
  model: string;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

/** OpenAI-compatible local model (vLLM on the GB10). */
export class LocalModel {
  constructor(
    private baseUrl: string,
    public model: string,
    private disableThinking = true,
  ) {}

  async complete(messages: ChatMessage[], extra: Record<string, unknown> = {}): Promise<Completion> {
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        max_tokens: 2048,
        ...extra,
        model: this.model,
        messages,
        stream: false,
        ...(this.disableThinking && { chat_template_kwargs: { enable_thinking: false } }),
      }),
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
}

/** Frontier model. Only the Egress step calls this, and only with redacted payloads. */
export interface FrontierModel {
  readonly name: string;
  readonly configured: boolean;
  complete(model: string, messages: ChatMessage[]): Promise<Completion>;
}

const ANTHROPIC = "https://api.anthropic.com";

/**
 * Anthropic Messages API. `baseUrl` can point at an Anthropic-compatible
 * token gateway (e.g. ATP: https://api.atptoken.ai) — those take the key as a
 * Bearer token, so we send both headers when not talking to Anthropic directly.
 */
export class ClaudeModel implements FrontierModel {
  readonly name: string;
  constructor(
    private apiKey: string | undefined,
    private baseUrl = ANTHROPIC,
  ) {
    this.name = baseUrl === ANTHROPIC ? "anthropic" : `anthropic-compatible (${new URL(baseUrl).host})`;
  }

  get configured() {
    return !!this.apiKey;
  }

  async complete(model: string, messages: ChatMessage[], maxTokens = 4096): Promise<Completion> {
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
    const res = await fetch(`${this.baseUrl}/v1/messages`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": this.apiKey,
        "anthropic-version": "2023-06-01",
        ...(this.baseUrl !== ANTHROPIC && { authorization: `Bearer ${this.apiKey}` }),
      },
      body: JSON.stringify({ model, max_tokens: maxTokens, ...(system && { system }), messages: turns }),
    });
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
      usage: {
        prompt_tokens: j.usage?.input_tokens ?? 0,
        completion_tokens: j.usage?.output_tokens ?? 0,
        total_tokens: (j.usage?.input_tokens ?? 0) + (j.usage?.output_tokens ?? 0),
      },
    };
  }
}

/**
 * Any OpenAI-compatible upstream: a multi-provider token gateway such as ATP
 * (https://api.atptoken.ai/v1, one `atp-` key for Claude / GPT / Gemini / …),
 * OpenRouter, or LiteLLM. Which models may be used is still decided by the
 * ENS policy (`airlock.models`), not by the upstream.
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
}
