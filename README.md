# BearWarden

BearWarden 是一個以「快速找到、安心使用」為核心的桌面密碼管理器。介面採三欄式工作流程，支援搜尋、收藏、最近使用排序，以及把登入項目拖放到資料夾中整理。

> 目前是本機優先的開發版本，尚未接受獨立密碼學或安全稽核。請勿在正式安全稽核與復原流程完成前，用它作為真實密碼的唯一備份。

## 已實作範圍

- 以主密碼建立、解鎖與鎖定本機密碼庫
- 登入項目的新增、檢視、編輯與刪除
- 每個登入項目可保存有順序的多個 URI，並設定 Bitwarden 相容的 URI match 規則
- 保存最近 5 筆密碼／隱藏欄位歷史；詳情只顯示安全計數，確認明文警告與必要的主密碼重新提示後才讀取
- 垃圾桶、項目還原、永久刪除與清空垃圾桶，並支援所選項目的批次移入、還原與永久刪除
- 項目複製、封存、取消封存與封存篩選，並支援批次移動、封存與取消封存
- 資料夾的新增、重新命名、排序與刪除
- 拖放登入項目到資料夾，以及鍵盤可操作的移動選單
- 全域搜尋、收藏、最近使用與最近修改排序
- 密碼預設遮蔽、明確揭露、複製及開啟網站
- 產生 Bitwarden 相容的一次性驗證碼，支援 Base32、`otpauth://` 自訂演算法／位數／週期與 Steam Guard；無效或未來格式仍可原樣同步
- 新增 SSH Key 項目時由主程序安全產生 Ed25519 金鑰，或從剪貼簿匯入 OpenSSH／PKCS#8 的 Ed25519、RSA 與 ECDSA 私鑰（含密碼保護），並正規化為相符的 OpenSSH 私鑰、公鑰與 `SHA256:` 指紋
- 本機安全產生密碼、EFF 長單字密語、隨機使用者名稱、Plus Address 與 Catch-all Email；最近 200 筆結果保存在加密歷史中
- 匯入 Bitwarden JSON，並匯出可攜、受獨立密碼保護的 Bitwarden JSON 備份
- 支援主密碼重新提示；短效授權只存在主程序，並綁定視窗、項目集合與保管庫世代
- Electron renderer sandbox、context isolation、具名 IPC 與外部網址驗證
- 系統鎖定或休眠時自動鎖定密碼庫
- 直接與 Bitwarden Cloud 或 Vaultwarden 雙向同步，不依賴 `bw` CLI
- 同步個人保管庫項目、資料夾、多 URI／match、密碼歷史、重新提示、封存與垃圾桶狀態，並以衝突副本避免覆蓋資料
- 同步附件的解密檔名、大小與 legacy 狀態，並可安全上傳、下載、刪除及修復 legacy 附件；操作提供進度與主動取消，金鑰、短效網址、檔案路徑與內容只存在主程序

## 資料安全模型

- 主密碼不寫入磁碟。
- 密碼庫使用密碼型 KDF 衍生的金鑰與 authenticated encryption 加密後才寫入 app data。
- 每次寫入先建立權限為 `0600` 的暫存檔，再以原子替換更新密碼庫。
- renderer 不具 Node.js、任意 IPC 或檔案系統能力；登入清單不包含密碼。
- 匯入／匯出的路徑與檔案內容只由主程序處理；備份以 `0600` 暫存檔、fsync 與原子替換寫入。
- SSH 私鑰匯入只在主程序讀取一次剪貼簿；renderer 僅取得綁定視窗與保管庫世代的短效單次 token、公鑰及指紋，鎖定、取消、逾期或程式結束都會清除未完成 session。
- 附件上傳會在主程序建立獨立金鑰與 authenticated type-2 加密 envelope，再依伺服器指定的 Direct 或 Azure 流程傳送；下載會重新取得短效網址、先驗證 metadata，再於主程序驗證 HMAC／解密，並以 `0600` 暫存檔與原子替換寫入。上傳、下載、刪除與 legacy Fix 支援進度、主動取消及鎖定中止，明文 Buffer 用畢後會清除。
- 附件目前採記憶體內加解密，加密後的 envelope 上限為 128 MiB；超過此上限的大檔串流、可讀的剩餘儲存額度，以及附件 ZIP 匯入／匯出仍未實作。
- 受重新提示保護的項目清單不包含使用者名稱、URI 或 TOTP 中繼資料；主密碼驗證後取得的 capability 會在 60 秒後失效。
- 鎖定時會清除主程序內的金鑰與已解密資料。

Bitwarden 的 Password Manager SDK 目前不是公開穩定 API，因此本專案沒有把 `@bitwarden/sdk-napi`（Secrets Manager SDK）誤用為個人密碼庫資料層。

## 匯入與加密備份

在「設定 → 資料可攜性」可匯入未加密或受密碼保護的 Bitwarden JSON，也可建立受獨立密碼保護的可攜 JSON 備份。兩個流程都會先在主程序重新驗證目前的主密碼；備份密碼不會成為 BearWarden 主密碼。

匯入遵循 Bitwarden 的不去重語意：每個資料夾與項目都會取得新的本機 ID，撞名資料夾會加上 `Imported` 後綴。匯出不包含垃圾桶、附件或 Sends；匯入會略過 JSON 中的垃圾桶項目。帳號限制型加密 JSON 綁定原帳號金鑰，無法跨帳號攜帶，因此目前只支援[官方所述的 password-protected encrypted export](https://bitwarden.com/help/encrypted-export/)；格式與匯入限制以 [Bitwarden Import Data](https://bitwarden.com/help/import-data/) 為準。

## Bitwarden／Vaultwarden 同步

BearWarden 直接實作 Bitwarden 桌面客戶端使用的登入、KDF、端對端加密與同步流程，
不需要另外安裝 `bw`。這是相容性協定而非穩定的公開 API，因此升級時必須以 Bitwarden
Cloud 與支援中的 Vaultwarden 版本執行相容測試。

在 BearWarden 左側欄開啟「Bitwarden 同步」後：

- Bitwarden Cloud 的伺服器網址填 `https://bitwarden.com`。
- Vaultwarden 填部署站台的 HTTPS 根網址；開發測試僅後端允許 loopback HTTP。
- 支援 Authenticator、Email、YubiKey OTP，以及新裝置電子郵件驗證碼。

主密碼不會寫入 BearWarden 密碼庫或設定；只在登入或解鎖時於主程序記憶體使用，
衍生金鑰在鎖定時清除。登入 token、同步設定與 ID 對應只存放在已加密的本機密碼庫內。

目前同步範圍限個人保管庫的 items、folders、封存、垃圾桶與附件。附件 metadata 以 server 為準，支援安全上傳、下載、刪除及 legacy Fix；組織項目、Sends、Passkey 寫入與
SSO 尚不由 BearWarden 編輯。同步的自訂欄位可在項目詳情安全地顯示與編輯。附件主要流程已有自動化 fixture 覆蓋，但 Direct／Azure live server 相容驗證仍是後續工作。完整差距與
實作順序記錄於 [`docs/vaultwarden-feature-gap.md`](docs/vaultwarden-feature-gap.md)。
更新既有 login 時，direct connector 會保留 BearWarden 未支援的遠端欄位。若兩端同時修改，
遠端版本會保留為主要項目，本機修改會另建 `(BearWarden conflict)` 副本。

目前支援 V1 AES-CBC-HMAC 與 Account Encryption V2 個人保管庫。V2 會嚴格驗證
COSE/XChaCha20-Poly1305、Ed25519 或 ML-DSA-44 security state、簽署的公開金鑰，以及包裝的
帳號私鑰；新版個人項目的 `Cipher.data` SealedCipherBlob 也支援舊版 XChaCha envelope 與目前的
AES-256-GCM data envelope。驗證失敗時不會暴露資料或執行遠端寫入。Key Connector、
SSO／Trusted Device Encryption 仍會保持同步鎖定，且不會降級使用 legacy key。

## 開發

需求：Node.js 24.13.1 以上、pnpm 11.12.0。

```bash
pnpm install --frozen-lockfile
pnpm dev
```

Electron 43 之後會在第一次使用時下載平台 binary。`pnpm dev` 與 `pnpm start`
會先執行官方的 `install-electron`，避免 electron-vite 在 binary 尚未就緒時誤判為
`Electron uninstall`。

## 驗證

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm build:unpack
pnpm audit --prod
```

## 封裝

```bash
pnpm build:mac
pnpm build:win
pnpm build:linux
```

正式發佈前仍需在對應作業系統完成簽章、公證、安裝與升級路徑測試。
