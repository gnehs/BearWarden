# 專案開發規範

## 架構與狀態管理

- 複雜 TSX 應優先把狀態同步、副作用、IPC 流程、競態防護、計時器與清理邏輯抽到語意明確的 hook 或 store；元件本身保留畫面結構、互動綁定與必要的展示邏輯。
- 不要為了縮短行數建立泛用或含糊的 `useAsync` 類抽象；hook 應表達具體領域用途，並封裝可測試的行為邊界。
- 跨元件或 IPC-backed runtime state 使用 Zustand；URL 只保存真正需要可分享或可返回的路由狀態；表單草稿、密碼、PIN、解鎖 token、揭露中的秘密、短生命週期 dialog state 留在元件或 session-scoped store。
- 保管庫相關 Zustand store 必須避免 `persist` 與 devtools；鎖定、卸載或切換 session 後，未完成的非同步操作不可再把 vault、sync 或秘密資料寫回已失效的 store。
- 大型主程序服務應依領域能力拆分，保留穩定 facade 與既有 public API；拆分時要檢查公開方法、型別 export、mutex/generation、dispose/cleanup 與資料安全流程沒有被縮限或改變。
- 大型重構應先建立測試基線，分批抽出低風險的純函式、leaf component、hook、service module，再處理高風險安全狀態機；不要只追求行數下降。

## 前端樣式

- 單次使用且能由 Tailwind CSS utilities 清楚表達的樣式，應直接寫在元件的 `className`，不要為它建立自訂 CSS class。
- 樣式或 UI 結構需要在多處重用時，應抽成 component，並由 component 封裝 Tailwind CSS utilities，不要寫到 main.css。
- Tailwind 有官方 utility 時優先使用官方 utility，例如 backdrop blur/saturate 不要改寫成 arbitrary CSS property；只有官方 utility 無法清楚表達或需要平台特殊值時才使用 arbitrary value。
- 多平台 titlebar、window controls overlay、backdrop、圓角階梯等樣式要集中在語意化的 class 組合或 component variant，避免同一元素同時保留互相覆蓋的 `rounded-*`、filter 或 backdrop class。
- shadcn/ui 的共用視覺調整應修改 component variant 或共用元件，讓檢視、新增、編輯等介面一致套用；不要在各頁散落互相衝突的 one-off class。
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

## 驗證與提交

- 本專案使用 `pnpm@11.12.0`；新增套件或執行 script 前先確認 `package.json` 與 lockfile，不要混用 npm、yarn 或 bun。
- 一般程式碼變更至少執行 `pnpm run typecheck`、`pnpm run lint` 與相關測試；涉及 i18n 時額外執行 `pnpm run i18n:extract` 與 `pnpm run i18n:compile`；涉及跨層或使用者流程時執行 `pnpm build`。
- 測試失敗時要區分本次回歸、既有失敗與 sandbox 限制；若與 socket/listen 權限有關，必要時用受控權限重跑相關測試，不要直接略過。
- 提交前用 `git status` 與 diff 確認只納入本次任務相關檔案；若工作樹有使用者或其他 agent 的變更，不要一起 stage，也不要復原。
- Commit message 使用英文 Conventional Commits，scope 儘量反映實際層級，例如 `renderer`、`vault`、`state`、`i18n`、`ui`。
