# Vaultwarden／Bitwarden 功能差距

本文件追蹤 BearWarden 與 Vaultwarden、Bitwarden 官方桌面客戶端之間的功能差距。
比較基準為 2026-07-15 的上游版本：

- [Vaultwarden `169aa5e`](https://github.com/dani-garcia/vaultwarden/commit/169aa5efcc8d94684ff3bc813a00e6bcc0cc537a)
- [Bitwarden Server `c2d97d5`](https://github.com/bitwarden/server/commit/c2d97d5ff2019c524405c36f7f3afc992ec0ef03)
- [Bitwarden Clients `505cf25`](https://github.com/bitwarden/clients/commit/505cf25c2555d0297b1b660513454e8c069b73b9)

## 比較原則

BearWarden 是本機優先的桌面密碼管理器，不是 Vaultwarden 伺服器替代品。因此比較範圍是使用者可在桌面客戶端操作的功能；伺服器管理、SMTP、資料庫維護、管理員後台等能力不會直接複製到桌面程式。

狀態定義：

- **完成**：具備本機流程、同步語意與主要測試。
- **部分**：已有資料或讀取能力，但缺少完整編輯、同步或 UI。
- **未實作**：尚無可用流程。

## 功能矩陣

| 領域                            | 狀態   | BearWarden 現況                                                                                                                                                    | 後續工作                                           |
| ------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------- |
| 本機保管庫建立、鎖定、解鎖      | 完成   | 主密碼、Touch ID、自動鎖定、休眠／系統鎖定                                                                                                                         | 安全稽核與復原演練                                 |
| 個人項目 CRUD                   | 完成   | Login、Card、Identity、Secure Note、SSH Key                                                                                                                        | 補齊批次操作                                       |
| 資料夾、常用、排序、搜尋        | 部分   | 資料夾 CRUD／拖放、常用，並搜尋名稱、摘要與所有 URI                                                                                                                | 進階搜尋語法與更多可搜尋欄位                       |
| 垃圾桶                          | 完成   | 軟刪除、垃圾桶清單、還原、永久刪除、清空；同步 `deletedDate`                                                                                                       | 批次還原／刪除與伺服器保留期限提示                 |
| Bitwarden／Vaultwarden 直接同步 | 部分   | 個人項目、資料夾、衝突副本、封存、垃圾桶與中斷續傳                                                                                                                 | 遠端 push 通知、更多帳號與組織狀態                 |
| TOTP                            | 部分   | 匯入、顯示與複製既有 TOTP                                                                                                                                          | QR 掃描、產生器與更多參數編輯                      |
| Passkey                         | 部分   | 安全同步並唯讀顯示中繼資料                                                                                                                                         | 建立、使用、編輯與刪除                             |
| 自訂欄位                        | 完成   | 文字、隱藏、布林、連結欄位                                                                                                                                         | 與未來項目歷史整合                                 |
| 多網址與 URI match 規則         | 完成   | 有順序的多 URI 編輯、搜尋、複製、HTTP(S) 開啟與 0–5 match type；V1 legacy 與 V2 blob 均無損同步 checksum／未知欄位                                                 | 帳號層級等效網域仍另列追蹤                         |
| 複製／Clone 項目                | 完成   | 本機複製所有支援欄位並同步；不複製 Passkey，保留封存狀態                                                                                                           | 未來附件仍必須排除                                 |
| 封存／Archive                   | 完成   | 封存、取消封存、獨立篩選與 `archivedDate` 雙向同步                                                                                                                 | 批次操作與 entitlement 提示                        |
| 主密碼重新提示／Reprompt        | 完成   | V10 資料模型與 Direct 雙向同步；主程序發出 60 秒、sender／item-set／vault-generation bound capability，敏感讀寫在 service atomic gate 內重驗；批次只需一次 proof   | 安全稽核與跨視窗壓力測試                           |
| 密碼歷史／項目版本              | 完成   | V12 儲存最近 5 筆密碼與變更／刪除的隱藏欄位；歷史不進入一般 detail IPC，僅顯示安全計數，經明文警告與 reprompt atomic gate 後由窄 IPC 讀取；legacy/V2 blob 雙向同步 | 完整項目快照比較與一鍵還原仍另列追蹤               |
| 密碼／使用者名稱產生器          | 部分   | 已有密碼與可注入 EFF 字表的 passphrase 安全核心                                                                                                                    | UI、完整 EFF 字表、使用者名稱產生與本機歷史        |
| 附件                            | 未實作 | 無                                                                                                                                                                 | v2 上傳、下載、續期、刪除、額度與加密檔案處理      |
| 匯入／匯出                      | 未實作 | 無                                                                                                                                                                 | 加密備份優先；垃圾桶不納入匯出                     |
| 組織、Collections、分享         | 未實作 | 遠端組織項目目前不編輯                                                                                                                                             | 權限模型、collection 篩選、分享與衝突處理          |
| Sends                           | 未實作 | 無                                                                                                                                                                 | 文字／檔案 Send、期限、密碼與刪除排程              |
| Emergency Access                | 未實作 | 無                                                                                                                                                                 | 邀請、確認、等待期與接管流程                       |
| Breach report／HIBP             | 未實作 | 無                                                                                                                                                                 | 隱私保護查詢與弱密碼／重複密碼報告                 |
| 等效網域                        | 未實作 | 無                                                                                                                                                                 | 讀取、編輯與網站匹配整合                           |
| 即時通知                        | 未實作 | 只有本機 mutation 後自動同步                                                                                                                                       | WebSocket／push 後觸發增量或完整同步               |
| 帳號與安全設定                  | 部分   | 登入、KDF、部分 2FA 與新裝置 OTP                                                                                                                                   | Email 驗證、API key、更多 2FA、SSO／trusted device |

## 實作順序

1. **資料安全與可復原性**：加密匯出／匯入、完整項目版本與備份驗證。
2. **個人保管庫完整度**：Clone、Archive、Reprompt、多 URI、產生器、附件。
3. **同步一致性**：批次操作、遠端通知、離線／重試與跨裝置衝突測試。
4. **組織協作**：Organizations、Collections、分享、權限與稽核事件。
5. **延伸產品能力**：Sends、Emergency Access、風險報告與進階帳號流程。

每一批完成前都必須驗證：本機資料 migration、鎖定後重開、同步雙向轉換、遠端刪除、衝突情境、renderer 不暴露秘密，以及失敗時不留下半完成狀態。
