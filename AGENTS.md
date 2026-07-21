# 專案開發規範

## 前端樣式

- 單次使用且能由 Tailwind CSS utilities 清楚表達的樣式，應直接寫在元件的 `className`，不要為它建立自訂 CSS class。
- 樣式或 UI 結構需要在多處重用時，應抽成 component，並由 component 封裝 Tailwind CSS utilities，不要寫到 main.css。
- 頁面標題上方不要放置 eyebrow、headline 或其他裝飾性前導文字；直接顯示語意化的主要標題。

## 國際化與翻譯

- 本專案使用 Lingui，套件管理器為 pnpm；修改翻譯後使用 `pnpm run i18n:extract` 更新 catalog，再使用 `pnpm run i18n:compile` 驗證。
- 依照 [Lingui 官方 macro 文件](https://lingui.dev/ref/macro#comment)，翻譯者需要額外資訊時，在 source macro 加上 `comment`。comment 應以英文撰寫，清楚說明 UI 位置、資料類型與實際語意；不要只重述英文原文。
- 同一個英文詞在不同畫面代表不同意思時，必須使用 `context` 拆成不同 message ID，並為每個 context 加上獨立的 `comment` 與翻譯。不要只在 `.po` 中修改 `msgstr`，也不要用一個泛用翻譯掩蓋不同語境。
- 同一詞在不同畫面若語意相同，則不要無謂拆分 context；先確認 source refs 與元件用途，再決定共用或切開。
- `comment` 與 `context` 應放在 source macro，`.po` 是抽取結果；修改後需確認所有 locale 都有對應 entry，且不可因抽取而遺失既有翻譯。

### 已建立的多重語境

- `Type`：`credential-generator-type` 是密碼／使用者名稱產生方式；`item-type` 是保管庫項目類型；`custom-field-type` 是自訂欄位資料類型。
- `Created`：`backup-created` 是備份檔案建立時間；`device-created` 是帳戶裝置註冊時間；`item-created` 是保管庫項目建立時間。
- `Recently used`：`recent-items-filter` 是快速存取或排序用的最近使用篩選；`item-last-used` 是項目詳情中的最後使用時間欄位。

### 翻譯語意基準

- Login editor 的 `Organization` 是本機項目整理區，翻成「整理／整理／整理」，不是公司或 Bitwarden 組織；`Organization and activity` 應表達整理與項目使用狀態。
- Passkey 核准對話框的 `Action` 是網站要求執行的 passkey 操作；付款卡欄位的 `Brand` 是卡片品牌；`Card` 是付款卡項目類型；`Company` 是身分項目的公司名稱。
- 產生器分頁的 `History` 是產生紀錄，不是一般物件歷史；時間欄位如 `Last edited`、`Password last updated` 應明確表達「時間／日時」，避免被翻成動作或狀態。
