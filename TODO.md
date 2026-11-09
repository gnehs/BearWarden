# BearWarden 後續工作

本清單接續 [`docs/vaultwarden-feature-gap.md`](docs/vaultwarden-feature-gap.md) 的 Vaultwarden／Bitwarden 功能差距稽核。每個階段必須先核對固定版本的官方文件與原始碼，完成後獨立以英文 Conventional Commit 提交。

## 明確排除

- [x] 不擴充 Send。
- [x] 不實作 Emergency Access。
- [x] 不實作 Organizations／Collections 寫入、分享或管理功能；既有只讀相容流程保留。
- [x] 不實作 Email forwarder 或保存第三方 forwarder API 憑證。

## 已完成：組織、Emergency Access 與 Send 顯示／相容性

- [x] 組織唯讀頁補上組織／Collection／共享項目權限與狀態顯示。
- [x] 組織隱藏密碼權限的摘要遮罩、快速切換競態、載入錯誤與鍵盤操作。
- [x] Emergency Access 相容 Vaultwarden 缺省／nullable metadata 與官方狀態 enum。
- [x] Emergency Access 載入錯誤、重試、名稱 fallback 與唯讀狀態顯示。
- [x] Send 補上生命週期、存取限制、隱私條件、日期與備註的表單及列表顯示。
- [x] Send 補上已停用、已過期、達存取上限、待刪除、密碼、Email 驗證等狀態標籤。
- [x] Email OTP Send 可安全辨識並保留既有驗證條件；不支援的 OTP 編輯／下載流程維持唯讀。
- [x] 輔助頁面支援 `/vault/*` 深連結、重新整理與上一頁／下一頁。
- [x] 完成 focused tests、完整測試與 Node／Web typecheck 驗證。

## 已完成：取消所有工作階段授權

- [x] 重新核對 Vaultwarden 與 Bitwarden Server 的 `security-stamp` 契約、主密碼 proof、回應格式及目前工作階段失效語意。
- [x] 在帳號安全設定加入「取消所有工作階段授權」，與單純列出裝置或移除本機帳號明確區隔。
- [x] 每次操作都要求新的主密碼驗證及明確破壞性確認。
- [x] Mutation 禁止自動重送；網路中斷、取消、逾時或 malformed response 後，不可把未知結果顯示為成功。
- [x] 遠端撤銷後清除目前遠端 session／notification capability，但保留本機加密 vault，不把它誤作刪除帳號或安全 logout。
- [x] 鎖定、切換帳號、renderer reload 與 app 關閉時中止舊操作，防止 stale response 套用到新帳號。
- [x] 使用 exact IPC schema；主密碼、hash、token、security stamp 與帳號識別資料不得進 renderer state、log 或錯誤訊息。
- [x] 補齊 HTTP、direct client、service、IPC、preload、UI、鎖定競態、通知 token rotation 及 response-loss 測試。
- [x] Commit：`feat(security): deauthorize all sessions`

## 下一階段

優先順序如下；每一項都應獨立評估、驗證並 commit，不綁成單一大型變更。

1. Passkey 外部 provider transport 的 caller authenticity 威脅模型與可行性閘門。
2. Vaultwarden／Bitwarden Cloud 雙裝置與長時間離線 live fixtures。
3. `.bwbackup` 定期復原演練與官方明文附件 ZIP 跨客戶端 fixture。
4. 多帳號切換、移除中斷、重啟續作與 stale operation 壓力測試。
5. Windows OpenSSH named pipe、實體 FIDO2 security key 與附件 transport 真機驗證。

## 資料核心重構

目標是讓 wire、domain、IPC、renderer 四個邊界各有一份型別定義，資料只在邊界驗證一次。每步獨立 commit，且 `pnpm run typecheck`、`pnpm run lint`、`pnpm test` 全綠。

1. [x] 合併重複的 `isRecord`、UUID、prototype guard 與 sync 診斷 enum（`src/main/validation-primitives.ts`）。
2. [x] renderer 不再自行投影 login summary（`src/shared/login-summary.ts`），reprompt 與無 `viewPassword` 權限的共享項目在存檔後也維持遮蔽。
3. [x] Bitwarden／Vaultwarden 欄位大小寫統一由 `src/main/bitwarden-fields.ts` 讀取。原計畫的 zod `/sync` schema 不採用：cipher row 必須保留未知欄位做 round-trip，診斷 stage 也依讀取順序決定。
4. [x] `/sync` 解析與解密抽成純函式 `decodeSyncPayload`（`src/main/bitwarden-sync-decoder.ts`），row codec 在 `src/main/bitwarden-cipher-codec.ts`。
5. [x] 所有 vault 寫入走 `VaultCore.commit`；寫入落地後先裝回記憶體再回報 `LOCKED`，修正鎖定競爭時後續修改覆蓋已寫入資料的問題。
6. [ ] 一次同步只下載一次 `/sync`。只拉取的同步已是一次；有推送時仍會在結尾重抓一次做附件對帳與遠端漂移偵測，要改用 CRUD 回應前需先確認官方伺服器與 Vaultwarden 的回應都帶附件與 revision。
7. [x] 所有鎖定路徑（逾時、選單、系統、視窗關閉、renderer 手動、帳號切換）共用同一個 fail-closed barrier，關機與鎖定共用互動操作取消清單。原計畫的事件 emitter 不採用：`beforeVaultLock` 是需要依序 await 的清單。
8. [x] `VaultServiceBase` 五層繼承鏈改為 `VaultCore` 加上各 domain 模組（`src/main/vault/`），`VaultService` 保留為 facade。
9. [x] `src/shared/ipc-api.ts` 一張表推導 preload API、`BearWardenAPI` 與主程序 handler 型別。
10. [ ] renderer：`VaultShell` 已拆成 hooks 與 stores（約 1,470 行、無直接 IPC）。尚未做的是讓 `vault:changed` 帶版本或差異，目前每次背景同步後仍以 7 個 IPC 重新載入清單；`OrganizationsPage` 仍直接呼叫 list IPC。

後續可考慮：

- [ ] `src/main/vault/account-security.ts`（約 1,860 行）依 2FA、WebAuthn、login approvals 再拆。
- [ ] `src/main/bitwarden-cipher-codec.ts`（約 1,500 行）拆成 decode 與 encode。
- [ ] 共享項目只有在舊密碼非空時才設定 `passwordRevisionDate`，個人項目則只要密碼改變就設定，確認是否為刻意差異。

約束：

- v23 磁碟格式與 `PersistedSyncData` 不變，`parseVaultData` 原樣沿用。
- 保留 copy-on-write `VaultData`、原子加密寫入、三方 fingerprint 合併與 journal、原始列 round-trip、損壞個人 cipher 隔離、trusted sender 檢查、每帳號一個 process、鎖定即 reload。
- 錯誤碼、remote mutation 次數與 persist 時機若改變，必須有對應測試說明新行為。

## 已完成：垃圾桶密碼歷史窄化唯讀入口

- [x] 沿用既有密碼歷史窄 IPC，不載入垃圾桶項目的完整 `LoginView`。
- [x] 主程序在同一個 exclusive boundary 重新檢查 deleted／reprompt 狀態與 sender／item／vault generation-bound authorization。
- [x] 垃圾桶 detail cache 無論是否有 token 都會失效，不能繞過 main 的完整 detail 拒絕。
- [x] 垃圾桶對話框只允許明文警告後查看，不提供「套用為目前密碼」。
- [x] 還原歷史 mutation、目前內容、附件與編輯入口仍必須先還原項目。
- [x] Commit：`feat(vault): show password history for trashed items`

## Passkey 外部 provider transport

此階段先做安全可行性閘門。現有 authenticator、create/get ceremony、操作級 UV、項目選擇與 provider-neutral ingress 已完成，但尚無可信的外部網站 transport。

- [x] 比較簽署瀏覽器擴充套件＋Native Messaging 與作業系統 credential provider；macOS 選定 AuthenticationServices Credential Provider appex，威脅模型與分階段方案見 `docs/macos-credential-provider.md`。
- [ ] 完成獨立威脅模型：偽造 caller、origin／RP ID 混淆、replay、renderer compromise、跨帳號／跨 vault generation、provider crash 與鎖庫競態。
- [ ] transport 必須重用現有 URI matcher、等效網域、exact origin／RP ID、request digest、單次 capability 與 UV／reprompt gate。
- [ ] challenge、credential ID、user handle、私鑰、assertion 與 capability 不得進一般 renderer。
- [ ] 若無法可靠驗證 transport caller，維持不實作，不以一般 IPC 或 localhost listener 降低安全邊界。
- [ ] 加入真實瀏覽器／OS、Bitwarden／Vaultwarden 與多帳號 lock/unlock fixture。
- [ ] 建議分拆 commits：transport trust boundary、lifecycle integration、provider packaging、live fixtures。

## 相容性與可靠性驗證

- [ ] 使用無敏感資料 fixture 驗證 Vaultwarden 與 Bitwarden Cloud 的個人項目、資料夾、垃圾桶、附件、Passkey、SSH Key、2FA 與帳號設定雙向 round trip。
- [ ] 建立雙裝置通知、長時間離線後重連、跨裝置衝突、批次操作與 response-loss 測試。
- [ ] 執行 `.bwbackup` 定期復原演練，以及 Bitwarden 明文附件 ZIP 跨官方客戶端 fixture。
- [ ] 補多帳號長時間切換、移除中斷、重啟續作與跨帳號 stale operation 壓力測試。
- [ ] 補 Windows OpenSSH named pipe、實體 FIDO2 security key、Azure／Direct 附件 transport 真機測試。
- [ ] 更新功能差距矩陣，讓近期完成的 timeout、個人 Profile、所有個人 2FA provider 停用與 fallback notification sync 狀態反映在文件中。

## 需先證明安全性，暫不直接實作

- [ ] Timeout logout：必須先證明沒有未同步資料、pending mutation/import/purge/attachment restore 或未知遠端結果，並具備 crash-safe account cleanup；證明不足時只能鎖定。
- [ ] SSO／trusted device：先完成金鑰交換、裝置信任、撤銷、跨帳號隔離與 recovery threat model。
- [ ] HIBP breached-domain：必須有已驗證網域及可安全使用的 server proxy；不可用帳號 breach endpoint 偽裝。
- [ ] 附件剩餘額度：只有伺服器提供個人使用者可讀、可驗證的 authoritative quota 時才顯示。

## 每階段完成門檻

- [ ] 對照固定 commit 的官方 Bitwarden／Vaultwarden 文件與原始碼。
- [ ] 驗證輸入與回應大小上限、exact schema、prototype/accessor、秘密清除與不寫 log。
- [ ] 驗證 migration、鎖定後重開、雙向同步、遠端刪除、衝突、取消與 app 重啟。
- [ ] 對破壞性 mutation 測試「最多送一次」及 response-loss reconciliation；無法證明結果時必須回 unknown。
- [ ] 執行 focused tests、完整 `pnpm test`、`pnpm run typecheck`、`pnpm run lint`、Prettier 與 production build。
- [ ] 完成對抗式審查，列出最可能失敗的 3–5 點並修正 blocker。
- [ ] 確認工作區沒有混入其他人的變更，再建立單一目的的英文 Conventional Commit。
