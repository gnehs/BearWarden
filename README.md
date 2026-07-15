# BearWarden

BearWarden 是一個以「快速找到、安心使用」為核心的桌面密碼管理器。介面採三欄式工作流程，支援搜尋、收藏、最近使用排序，以及把登入項目拖放到資料夾中整理。

> 目前是本機優先的開發版本，尚未接受獨立密碼學或安全稽核。請勿在正式安全稽核與復原流程完成前，用它作為真實密碼的唯一備份。

## 已實作範圍

- 以主密碼建立、解鎖與鎖定本機密碼庫
- 登入項目的新增、檢視、編輯與刪除
- 資料夾的新增、重新命名、排序與刪除
- 拖放登入項目到資料夾，以及鍵盤可操作的移動選單
- 全域搜尋、收藏、最近使用與最近修改排序
- 密碼預設遮蔽、明確揭露、複製及開啟網站
- Electron renderer sandbox、context isolation、具名 IPC 與外部網址驗證
- 系統鎖定或休眠時自動鎖定密碼庫
- 直接與 Bitwarden Cloud 或 Vaultwarden 雙向同步，不依賴 `bw` CLI
- 同步個人登入項目、資料夾、修改與刪除，並以衝突副本避免覆蓋資料

## 資料安全模型

- 主密碼不寫入磁碟。
- 密碼庫使用密碼型 KDF 衍生的金鑰與 authenticated encryption 加密後才寫入 app data。
- 每次寫入先建立權限為 `0600` 的暫存檔，再以原子替換更新密碼庫。
- renderer 不具 Node.js、任意 IPC 或檔案系統能力；登入清單不包含密碼。
- 鎖定時會清除主程序內的金鑰與已解密資料。

Bitwarden 的 Password Manager SDK 目前不是公開穩定 API，因此本專案沒有把 `@bitwarden/sdk-napi`（Secrets Manager SDK）誤用為個人密碼庫資料層。

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

目前同步範圍限個人保管庫的 login items 與 folders。組織項目、附件、Sends、Passkeys、
SSO 與自訂欄位尚不由 BearWarden 編輯；更新既有 login 時，direct connector 會保留 BearWarden
未支援的遠端欄位。若兩端同時修改，遠端版本會保留為主要項目，本機修改會另建
`(BearWarden conflict)` 副本。

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
