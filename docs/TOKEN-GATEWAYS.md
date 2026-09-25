# Airlock 與 AI token gateway（以 ATP 為參考）

參考對象：[ATP Token](https://atptoken.ai/zh-tw/)。它是多供應商的 AI token gateway，一把 `atp-` key 可以用 OpenAI、Anthropic、Gemini、DeepSeek、Qwen 等 70 多個模型。

## 定位：兩者管的東西不同

| | Token gateway（ATP、OpenRouter、LiteLLM…） | Airlock |
|---|---|---|
| 主要問題 | **誰能用哪個模型、花多少錢** | **哪些內容可以離開本機、誰同意的** |
| 控制單位 | Organization → Workspace → Project、per-project key、模型白名單、額度 | ENS agent 政策（資料等級、egress 模式、模型 glob）、核可者角色 |
| 請求內容 | 原封不動轉送給供應商 | 先去敏；機密資料要經過真人核可（World ID），答案回到本機再還原 |
| 紀錄 | 每筆請求都有歸屬：model、key、tokens、credits | 每筆請求都有**決策**：hash chain、核可者 commitment、角色檢查結果、Merkle root 錨定到 ENS |
| 預設 | 雲端模型 | 本地模型；雲端模型要有政策加上同意才能用 |

兩者**可以串在一起**：

```
client ─▶ Airlock（去敏 / 政策 / 核可 / 還原 / 稽核）─▶ ATP（統一 key / 路由 / 計費）─▶ Claude / GPT / Gemini …
```

Airlock 負責「內容能不能出去」，token gateway 負責「出去以後怎麼路由、怎麼計費」。token gateway 只會看到去敏後的 payload。

## 設定方式

**OpenAI 相容**（一把 key 用多家模型）：
```bash
EGRESS_PROVIDER=openai
EGRESS_BASE_URL=https://api.atptoken.ai/v1
EGRESS_API_KEY=atp-...
CLAUDE_MODEL=claude-sonnet-5          # 預設的 egress 模型（名稱以上游 /v1/models 回傳的為準）
CLAUDE_MODELS=claude-sonnet-5,gpt-5.5,gemini-3-5-flash
```

**Anthropic 相容**（保留 Messages API 格式）：
```bash
EGRESS_BASE_URL=https://api.atptoken.ai
EGRESS_API_KEY=atp-...
```

- **模型白名單仍然在 ENS。** 上游能用哪些模型不代表 agent 能用：`airlock.models` 的 glob 沒涵蓋的模型（例如 `claude-*` 政策下的 `gpt-5.5`）會被阻擋，退回本地模型。
- **實測**（用本機 vLLM 模擬 OpenAI 相容上游）：
  - 公開問題自動放行。
  - 機密請求核可後，上游只收到 `<PERSON_1> of <ORG_1>`，答案在本機還原成真實名稱。
  - 不在 glob 內的模型被阻擋。
- **ATP 的 key 格式**是 `Authorization: Bearer atp-...`。Anthropic 相容模式下，Airlock 會同時送出 `x-api-key` 和 `Authorization: Bearer`；直連 Anthropic 時只送 `x-api-key`。⚠️ 尚未用真的 ATP key 實測。

## 從 ATP 借來的想法

- **已實作：請求歸屬。** AuditRecord 加上 `agent` 和 egress 的 `usage`（prompt / completion tokens），每筆決策都能歸到某個 agent 政策和成本。
- **之後可做：**
  - **額度 / 預算當成政策。** 在 ENS 加 `airlock.budget`，超過就改走本地模型，而不是直接拒絕。
  - **Project 層級的 key。** 目前用 `x-airlock-agent` header 選政策；產品版可以讓每個 project key 綁定一個 agent 政策，client 就不能自己選。
  - **Agent Skills。** ATP 用 Markdown skill 讓 agent 自己接上 gateway。Airlock 也可以提供一份 skill，讓 Claude Code 或 Hermes 預設走 `auto`，並知道核可流程會暫停請求。
