# 整合查證紀錄：World ID 與 ENS v2（2026-09-25）

以下根據官方文件、`worldcoin/idkit`、`worldcoin/developer-portal`、`ensdomains/contracts-v2`（`post-audit-2` 分支）原始碼，以及實際打 API 與 Sepolia 鏈上讀取的結果整理。標 ⚠️ 的是尚未實測確認的部分。

---

## World ID

### 已確認（有實測）
- **驗證 API（v4）**：`POST https://developer.world.org/api/v4/verify/{rp_id}`（staging：`https://staging-developer.worldcoin.org`）。兩個 host 都實際回應了，錯誤格式是 `{code, detail, attribute}`。
- **Request body** 直接轉送 IDKit 的結果：`{protocol_version, nonce, action, responses:[{identifier, nullifier, proof, signal_hash, merkle_root?}], environment}`。
- **RP 簽章是必要的**。後端要用 `signRequest({signingKeyHex, action, ttl})`（`@worldcoin/idkit-core/signing`）產生 `rp_context = {rp_id, nonce, created_at, expires_at, signature}`，再交給前端。實作：`GET /approvals/:id/worldid`。
- **`@worldcoin/idkit-standalone` 已經停用**，改用 `@worldcoin/idkit-core@4.3.0`。瀏覽器 bundle `dist/idkit.global.js` 會暴露 `globalThis.IDKit`，提供 `request`、`orbLegacy`、`proofOfHuman` 等函式（已從 bundle 原始碼確認）。
- **Signal hash** = `keccak256(bytes) >> 8`。合法的 `0x…` 十六進位字串會當成原始 bytes 雜湊，其他字串當 UTF-8。後端用 `hashSignal()` 自己比對 `signal_hash`，因為 portal 只驗證你傳給它的 signal_hash，不管它是否等於 payloadHash。
- **v4 遇到重複使用的 nullifier 還是會回 `success:true`**（訊息是 "nullifier reuse"），所以 gateway 要自己擋重放。

### 設計上的影響（已實作）
- **角色檢查需要「穩定」的個人識別。**
  - v3（legacy）的 nullifier 對同一組 (app, action, person) 是固定的。
  - v4 的 uniqueness nullifier 是一次性的。
  - 因此：
    1. enroll 和 approve **共用同一個 action**（`WORLD_ACTION=airlock-approve`）；若用不同 action，nullifier 不同，commitment 永遠對不上。
    2. 前端用 `orbLegacy({signal: payloadHash})` 搭配 `allow_legacy_proofs: true`。
    3. 每次核可跟 payload 的綁定靠 **signal**，而不是靠 action。
- **Developer Portal 要設定**：這個 action 的 max verifications 設為**無限**。
- **§12-1 的答案**：同一個 action 可以重複驗證（legacy 流程依 max verifications 設定）。沒有叫「重新驗證」的功能。World 另外有 **Human-in-the-loop** 產品（`@worldcoin/human-in-the-loop`），做的事和 Approver 很像，可以當成產品版的替代方案。

### 未確認 ⚠️
- **v4-only 的使用者**：World App 使用者全面改用 v4 後，legacy proof 可能被拒。
  - 那時需要改用 v4 session（`IDKit.createSession` / `proveSession` → `getSessionCommitment(session_id)`）作為穩定識別。
  - 但 session proof 能不能帶 signal，目前沒查到。
- **模擬器**：simulator.worldcoin.org 是否支援 v4 `proofOfHuman` 未確認；legacy preset 可以用。
- **真實手機流程**：這個 repo 還沒用真的 staging app 跑過；要先在 developer.world.org 建 app 並設定 RP。

---

## ENS v2（Sepolia）

### 已確認（有實測）
- **ENSv2 已部署在 Sepolia**（2026-09-15 重新部署）。viem 內建的 `sepolia.contracts.ensUniversalResolver` = `0xeeee…eeee` 是固定不變的入口 proxy，會轉到 UniversalResolverV2。
- **讀取不需要特別設定。** `getEnsAddress("nick.eth")` 從這個 repo 的 `ensClient()` 實測成功。
- **Fail-closed**：讀不到政策 record 時，`EnsPolicyResolver` 會回傳 `egress=block`（已實測）。

### 寫入與權限（來自原始碼，⚠️ 尚未上鏈實測）
- **Text record** 寫在 **PermissionedResolver**：`setText(bytes dnsEncodedName, string key, string value)`。注意是 DNS 編碼的名稱，不是 namehash。實作在 `registry/src/ens.ts` 的 `EnsWriter`，用 viem 的 `packetToBytes`。
- **§12-2 的答案：EAC 可以依 record key 授權**，但**沒有前綴萬用字元**。
  - `setText` 檢查的是 `ROLE_SET_TEXT`（1<<4），resource 是 `keccak256(key)`。
  - 授權要用 `grantSetterRoles(bytes setterCalldata, address account)`。
  - 做法：
    1. 每個 key 各自授權。
    2. gateway 帳號只拿 `airlock.auditRoot`、`airlock.approver`。
    3. policy key（`maxClass/egress/models/approverRole/ownerRole`）只給 security.acme.eth 的帳號。
  - key 的授權對同一個 resolver 服務的**所有名稱**都有效。要做到名稱層級的隔離，就用不同的 resolver，例如 audit 一個、approvers 一個。
- **Subname**：
  - 在每一層的 UserRegistry 上呼叫 `register(label, owner, registry, resolver, roleBitmap, uint64 expiry)`。
  - **有原生的到期時間**；`renew` 只能延長。
  - **撤銷**用 `unregister(id)`（需要 `ROLE_UNREGISTER` 1<<12）：燒掉 token，到期時間設為現在。
  - 撤銷或到期後名稱不再解析，`airlock.approver` 讀回空值，角色檢查就回傳 `revoked`（實作也支援清空 record：`POST /admin/revoke`）。
- **註冊 .eth**：
  1. 用 ERC20（MockUSDC）付款：`mint` → `approve`。
  2. `commit`。
  3. 等 ≥60 秒。
  4. `register(label, owner, secret, subregistry, resolver, duration, paymentToken, referrer)`。
  - 也可以直接用網頁：<https://app.ens.dev>。
- **ENSv1 在 Sepolia 已不能註冊新的 .eth**（controller 已停用），不能當作備案。
- **地址每次重新部署都會變**（`0xeeee…` 例外），所以只放在 env（`ENS_RESOLVER`），不寫死在程式裡。
- 另外有一組 09-03 的「hackathon clean testnet」部署（ensjs PR #377）。要跟主辦方確認用哪一組。

### Demo 前的 ENS 設定清單
1. 在 app.ens.dev（Sepolia）註冊 `acme.eth`，並建立 subname：`agents`、`contract-agent.agents`、`legal.approvers`、`audit`。
2. 部署 PermissionedResolver proxy，對 gateway 帳號授權 `airlock.auditRoot` 和 `airlock.approver` 的 `setText`。
3. 由 security 帳號寫入 contract-agent 的 policy text records。
4. `.env` 設定 `SEPOLIA_RPC_URL`、`ENS_RESOLVER`、`ENS_PRIVATE_KEY`、`ENS_AUDIT_NAME`。
5. 建立 `alice.legal.approvers.acme.eth` subname → alice 用 World ID 完成 `POST /enroll` → commitment 寫入 ENS。
6. Demo 撤銷：`unregister` alice 的 subname（或 `POST /admin/revoke`）。

---

## 其他 §12 項目
- **GB10**：vLLM（Qwen3.5-35B-A3B-FP8）在本機 `:8000` 正常運作。能不能從會場連線，要看網路和 tunnel 設定，repo 管不到。
- **LibreChat timeout**：核可期間 HTTP 請求會一直掛著，最長 `APPROVAL_TIMEOUT_MS`（預設 180 秒），LibreChat 的 timeout 要調得比這個長。已提供 `demo/librechat.yaml` 片段；header 裡的 session placeholder 要確認 LibreChat 版本是否支援。
