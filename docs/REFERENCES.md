# 設計參考

> 這裡只記錄我們借鏡的**設計想法**。Airlock 不串接、也不依賴下列任何服務。

## ATP Token（https://atptoken.ai/zh-tw/）

ATP 是一個多供應商的 AI token gateway：一個 OpenAI 相容的 API 背後接很多家模型，並提供組織層級的權限、額度和計費。

### 定位差異

| | Token gateway（如 ATP） | Airlock |
|---|---|---|
| 主要問題 | **誰能用哪個模型、花多少錢** | **哪些內容可以離開本機、誰同意的** |
| 控制單位 | Organization → Workspace → Project、per-project key、模型白名單、額度 | ENS agent 政策（資料等級、egress 模式、模型 glob）、核可者角色 |
| 請求內容 | 原封不動轉送 | 先去敏；機密資料要經過真人核可（World ID），答案回到本機再還原 |
| 紀錄 | 每筆請求都有歸屬：model、key、tokens、credits | 每筆請求都有**決策**：hash chain、核可者 commitment、角色檢查、Merkle root 錨定到 ENS |
| 預設 | 雲端模型 | 本地模型；雲端模型要有政策加上同意才能用 |

### 借鏡的想法

- **已實作：**
  - **請求歸屬。** AuditRecord 加上 `agent` 和 egress 的 `usage`（prompt / completion tokens），每筆決策都能歸到某個 agent 政策和成本。
  - **一個介面接多個上游。** Egress 抽象成 `FrontierModel`，可以直連 Anthropic，也可以接自己架設的 OpenAI 相容上游（例如 LiteLLM）。但模型白名單一律以 ENS 的 `airlock.models` 為準。
- **之後可以考慮：**
  - **權限跟著結構走。** ATP 的權限綁在 Organization → Workspace → Project 結構上，不是綁在個人身上。這和我們用 ENS 階層（`acme.eth → agents / approvers`）表達政策與角色是同一個思路。
  - **額度 / 預算當成政策。** 在 ENS 加 `airlock.budget`，超過就改走本地模型，而不是直接拒絕。
  - **Project 層級的 key。** 目前用 `x-airlock-agent` header 選政策；產品版可以讓每個 project key 綁定一個 agent 政策，client 就不能自己選。
  - **依角色區分的檢視。** Console 可以分開開發者、財務、管理者的檢視，例如財務只看 usage 歸屬，核可者只看待核可佇列。
  - **Agent Skills。** 提供一份 Markdown skill，讓 Claude Code 或 Hermes 知道預設走 `auto`，也知道核可流程會暫停請求。

### 視覺設計（Console）

Console 的視覺語言參考 ATP 網站（只參考風格，沒有使用他們的素材或程式碼）：
- **配色：** 白底（canvas）、淺灰面板（haze `#f5f5f5`）、細線邊框（hairline `#e6e6e6`）、墨色文字（ink）、灰階輔助字（umber `#6f6f6f`），全頁只用一個強調色 ember `#f04d3b`。
- **字體：** 標題用 Lexend，內文用 Figtree，標籤和資料用 IBM Plex Mono（皆為 Google Fonts）。
- **元件：**
  - 小型大寫 mono 標籤，字距 0.1em。
  - 膠囊形（rounded-full）導覽和按鈕：主要動作用 ink，送出和 World ID 用 ember。
  - 卡片圓角 16px、內層 10px。
- **深色模式：** 同一套 token 各自定義深色版本，並另外處理手機版版面。
