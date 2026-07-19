# 專案開發規範

## 前端樣式

- 單次使用且能由 Tailwind CSS utilities 清楚表達的樣式，應直接寫在元件的 `className`，不要為它建立自訂 CSS class。
- 樣式或 UI 結構需要在多處重用時，應抽成 component，並由 component 封裝 Tailwind CSS utilities，不要寫到 main.css。
