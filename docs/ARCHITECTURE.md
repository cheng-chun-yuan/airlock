# Airlock：架構大綱

> **Local AI by default. Frontier AI by human consent. Accountability on-chain.**

> 實作與整合查證結果見 [INTEGRATION-NOTES.md](./INTEGRATION-NOTES.md)（§12 待確認事項的答案也在那裡）。

## 1. 系統全貌

```
                         ┌──────────────── ENS v2 (Sepolia) ────────────────┐
                         │ acme.eth                                          │
                         │  ├─ agents.acme.eth → contract-agent (政策 records)│
                         │  ├─ legal.approvers.acme.eth → 核可者 subnames    │
                         │  └─ audit.acme.eth → Merkle root                  │
                         └───────────▲───────────────────────▲──────────────┘
                                     │ 讀政策 / 角色          │ 錨定
┌──────────────┐  OpenAI API  ┌──────┴─────────────────────────┴─────────┐
│ LibreChat    │─────────────▶│             Airlock Gateway              │
│ Hermes / curl│◀─────────────│  Router → Redactor → RiskScorer →        │
└──────────────┘  還原後答案   │  PolicyResolver → Approver → Egress →    │
                              │  Rehydrator → AuditSink                  │
                              └──┬──────────┬───────────┬──────────┬─────┘
                                 │          │           │          │
                       ┌─────────▼──┐ ┌─────▼──────┐ ┌──▼───────┐ ┌▼────────────┐
                       │ Local model │ │ Presidio   │ │ World ID │ │ Claude API  │
                       │ (GB10 vLLM) │ │ (sidecar)  │ │ verify   │ │ (frontier)  │
                       └─────────────┘ └────────────┘ └────▲─────┘ └─────────────┘
                                                           │ proof
                              ┌─────────────┐        ┌─────┴──────┐
                              │ Console     │◀─SSE──▶│ World App  │
                              │ (Next.js)   │        │ (核可者手機) │
                              └─────────────┘        └────────────┘
```

**信任邊界**：只有 Egress 模組能連到外部。對照表、原文和日誌都不會離開本地。

## 2. 請求流程

1. **Router**：依照 `model` 欄位分流
   - `local/*` → 直接交給本地模型
   - `airlock/*` → 進入 Airlock 流程
   - `auto` → 本地模型先試，信心不足才升級
2. **Redactor**：去敏整段對話歷史，依 session 使用固定代號
   - 規則（Presidio）→ 公司字典 → 本地模型標記間接識別資訊
3. **RiskScorer**：計算殘餘風險（本地攻擊測試，P2；先用規則計分）
4. **PolicyResolver**：從 ENS 讀取 agent 政策，決定走哪一條路：
   - 自動放行
   - 需要核可（以及由哪個角色核可）
   - 阻擋
5. **Approver**（需要核可時）：
   - 建立 ApprovalRequest，推送到 Console
   - 核可者掃 World ID，signal 綁定 `payloadHash`
   - 後端驗證 proof，並檢查核可者的 ENS 角色是否仍然有效
6. **Egress**：在核可效期內，把去敏後的 payload 送給 Claude
7. **Rehydrator**：用本地對照表把代號換回真實內容，tool call 參數也要還原
8. **AuditSink**：寫入 hash chain 日誌，定期把 Merkle root 錨定到 ENS

**失敗路徑**：拒絕、逾時、角色無效或 payload hash 不符 → 不送出，退回本地模型的答案，並附上原因。

## 3. 政策決策表

| 原始資料等級 | 殘餘風險 | 結果 |
|---|---|---|
| public / internal | — | 自動放行，只記錄審計 |
| confidential | 低 | World ID（Proof of Human）+ 角色檢查 |
| confidential | 高 | 資料擁有者核可，或阻擋 |
| restricted | — | 永遠阻擋，只能用本地模型 |

**核可範圍（P2）**：同一個 session 內，沒有出現新的敏感實體、風險也沒超過已核可的等級 → 沿用既有核可。

## 4. ENS 結構

```
acme.eth
├─ security.acme.eth              ← 唯一可以修改 airlock.* records 的角色（EAC）
├─ agents.acme.eth
│   └─ contract-agent.agents.acme.eth
│        text: airlock.maxClass     = confidential
│        text: airlock.egress       = approval
│        text: airlock.models       = claude-*
│        text: airlock.approverRole = legal.approvers.acme.eth
├─ legal.approvers.acme.eth
│   └─ alice.legal.approvers.acme.eth   (可設到期、可撤銷)
│        text: airlock.approver     = commitment(nullifier)
└─ audit.acme.eth
     text: airlock.auditRoot      = <最新 Merkle root>
```

**角色檢查**：World ID proof 的 nullifier 算出 commitment 後，必須對應到 `approverRole` 底下一個尚未到期、未被撤銷的 subname。

**隱私**：鏈上只放 commitment，不放 nullifier，也不放任何內容。

## 5. 資料模型

**ApprovalRequest**
```ts
{
  id, sessionId,
  agent: "contract-agent.agents.acme.eth",
  requiredRole: "legal.approvers.acme.eth",
  payloadHash,        // 去敏後實際送出的內容
  viewHash,           // 核可者看到的畫面
  redactedPreview,    // 給核可者看的去敏內容
  entities: { ORG: 3, PERSON: 2, MONEY: 2 },
  riskLevel, findings[],  // 例如間接識別資訊
  targetModel, expiresAt
}
```

**AuditRecord**（append-only，hash chain）
```ts
{
  seq, prevHash,
  requestId, decision: "approved" | "denied" | "expired" | "auto" | "blocked",
  sourceHash, payloadHash, viewHash,
  approverCommitment?, roleCheck: "valid" | "revoked" | "expired",
  worldIdVerified: boolean,
  timestamp, gatewaySig
}
```

## 6. 介面（之後合併的接口）

```ts
interface Redactor       { redact(msgs, session): { payload, mapping, entities } }
interface RiskScorer     { score(payload): { level, findings } }
interface PolicyResolver { resolve(agentId): Policy }
interface RoleRegistry   { isValidApprover(commitment, role): RoleCheck }
interface Approver       { request(req: ApprovalRequest): Promise<Decision> }
interface AuditSink      { append(rec: AuditRecord); anchor(): Promise<string> }
```

| 介面 | 黑客松實作 | 產品實作 |
|---|---|---|
| PolicyResolver / RoleRegistry | ENS | Keycloak + Console |
| Approver | World ID | World ID 或 Keycloak step-up |
| AuditSink | JSONL + ENS 錨定 | JSONL + 可選的鏈上錨定 |

## 7. API

**Gateway（對客戶端）**
- `POST /v1/chat/completions`：OpenAI 相容，可選 `x-airlock-session` header
- `GET /v1/models`：列出 `local/*`、`airlock/*`、`auto`

**Approval（對 Console 和核可者）**
- `GET /approvals?status=pending`
- `GET /approvals/:id`
- `POST /approvals/:id/verify`：送出 World ID proof
- `POST /approvals/:id/deny`
- `GET /events`：SSE，推送即時狀態給 Console

**Enrollment（demo 前先建好）**
- `POST /enroll`：World ID proof → commitment → 寫入 ENS subname

## 8. Console 畫面

1. **Queue**：待核可的請求、自動放行和阻擋的紀錄
2. **Request detail**：原文和去敏版本並排、遮蔽的實體、風險發現、ENS 政策、World ID QR code
3. **Audit**：日誌列表、hash chain 驗證狀態、最新 Merkle root 和 ENS 連結

## 9. Repo 結構和部署

```
airlock/
├─ gateway/        TS (Hono)：router, redact 調度, egress, rehydrate
├─ packages/core/  介面、型別、政策引擎
├─ redactor/       Presidio 設定、公司字典 recognizer
├─ approval/       World ID 驗證、SSE
├─ registry/       ENS 讀寫（viem）、Sepolia 部署腳本
├─ audit/          hash chain、Merkle、錨定
├─ console/        Next.js
├─ demo/           假合約、客戶名單、LibreChat 設定、demo 腳本
└─ docker-compose.yml   gateway, presidio-analyzer, console, librechat(+mongo)
```

外部依賴：本地模型端點（GB10，準備一個備案）、Claude API、World ID sandbox、Sepolia RPC。

## 10. 時程（截止時間是週日 09:00）

| 時段 | 目標 | 對應優先級 |
|---|---|---|
| 週五 22:30–02:00 | World ID sandbox 跑通；repo 骨架；proxy + 本地和 Claude 路由 | P0 |
| 週六 02:00–10:00 | 去敏 + 還原；核可流程（批准和拒絕）；Console 最簡版 | P0 |
| 週六 10:00–18:00 | ENS 政策 + 角色檢查 + 撤銷；咎責日誌 + 錨定 | P1 |
| 週六 18:00–24:00 | 接上 LibreChat；本地攻擊測試；整合測試 | P1/P2 |
| 週日 00:00–06:00 | 部署 live demo；README、整合回饋；錄 demo 影片 | 投稿 |
| 週日 06:00–09:00 | 緩衝時間，投稿 | — |

**砍功能的順序**（時間不夠時從上往下砍）：Hermes → 串流 → 核可範圍 → 本地攻擊測試 → LibreChat（改用 Console 內建的測試聊天）

## 11. Demo 腳本（3 分鐘）

1. **自動放行**：問一個公開資料的問題 → 直接送出，不需要 World ID
2. **核可**：審閱機密合約 → 去敏 → Console 顯示前後比較 → 手機 World ID → Claude 回答 → 還原成真實名稱
3. **拒絕**：同樣的請求，按拒絕 → 退回本地模型的答案
4. **角色撤銷**：撤銷 alice 的 ENS subname → 她完成 World ID 驗證（確實是真人）→ 角色檢查失敗 → 不送出
5. **稽核**：打開日誌 → 驗證 hash chain → 點 ENS 錨點

## 12. 待確認

1. World ID：同一個 action 能不能重複驗證？World ID for Agents 有沒有「重新驗證」的語意？
2. ENSv2 Sepolia：EAC 能不能限制只有特定角色能改 `airlock.*` 這類 text record？
3. GB10 能不能從會場連線？
4. LibreChat 的請求 timeout 能拉到多長？

---

## 實作狀態（2026-09-26）

| 項目 | 狀態 |
|---|---|
| Router（local / airlock / auto）＋ 串流 | ✅ 真正的 token 串流；client 斷線會取消上游，並仍寫入稽核 |
| Redactor：規則 → 字典 → Presidio → 本地模型標記 | ✅（本地模型標記：`REDACT_LLM=1`） |
| RiskScorer：規則 ＋ 本地攻擊測試（P2） | ✅ 本地模型嘗試還原代號，猜中即為高風險 |
| PolicyResolver / RoleRegistry（ENS） | ✅ `airlock.eth` 已上 Sepolia；依 record key 分權（EAC）：security 帳號改政策，gateway 只能寫 approver 和 auditRoot |
| Approver | ✅ World ID for Agents（sandbox OIDC）＋ IDKit v4，都已用真實環境實測 |
| 核可範圍（P2） | ✅ 每次沿用都重新檢查核可者的 ENS 角色，撤銷即失效 |
| AuditSink：hash chain ＋ Merkle ＋ 錨定 | ✅ 已錨定到 `audit.airlock.eth`，Console 的 ENS 分頁可以比對鏈上和本地的 root |
| Console | ✅ 單一 HTML（由 gateway 提供），未改用 Next.js |
| LibreChat | 提供設定片段 `demo/librechat.yaml`，未改動本機運行中的 LibreChat |
| Hermes | 依砍功能順序未做；可用 `skills/airlock/SKILL.md` 接入 |

