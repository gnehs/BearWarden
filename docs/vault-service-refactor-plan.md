# `vault-service.ts` 拆分規劃

> 基準：`src/main/vault-service.ts` @ 11,267 行（2026-07-20）。
> 文中行號皆以此版本為準，實際執行時請重新對照。

## 目標

- 將單一 11k 行檔案依功能拆成多個小檔案，降低維護成本。
- **不改變任何行為與公開 API**：外部 importer（8 個檔案）與測試（`vault-service.test.ts` 10,566 行）零改動。
- 每一步都可獨立驗證（`pnpm typecheck` + `pnpm test`），可隨時中斷、分段合併。

## 現況結構

| 區段 | 行號 | 內容 | 約略行數 |
|---|---|---|---|
| import | 1–216 | — | 216 |
| 常數 | 218–287 | `DATA_VERSION` 系列、`MAX_*` 限制、regex pattern | 70 |
| 型別 | 289–630 | `StoredLogin`、`VaultData`、`PersistedSyncData`、Passkey/SSH/WebAuthn 介面 | 340 |
| 模組層純函式 | 631–3399 | parse / normalize / clone / assert / view mapper，全部無狀態 | 2,770 |
| `VaultService` class | 3400–11267 | 所有業務邏輯與內部狀態 | 7,870 |

### 外部相依（importer 清單）

| 檔案 | 使用內容 |
|---|---|
| `src/main/index.ts` | `VaultService`（class） |
| `src/main/vault-ipc.ts` | `VaultService`（type only） |
| `src/main/vault-portability.ts` | `VaultService`（type only） |
| `src/main/ssh-agent-coordinator.ts` | `SshAgentVault*` 型別 |
| `src/main/passkey-ceremony-service.ts` | `PasskeyVault*` 型別 |
| 測試 ×3 | `VaultService` 與上述型別 |

→ 只要 `vault-service.ts` 持續 re-export 這些符號，所有 importer 都不必修改。

---

## Phase 1：抽出模組層純函式（低風險，純搬移）

建立 `src/main/vault/` 目錄。以下每個檔案對應原始行號範圍，內容為**原樣搬移**，僅補上 import/export，不重寫邏輯。

| 新檔案 | 內容（原行號） | 主要符號 |
|---|---|---|
| `vault/limits.ts` | 218–287 | `DATA_VERSION` 系列、`MAX_*`、`MIN_MASTER_PASSWORD_LENGTH`、`UUID_PATTERN` 等 |
| `vault/types.ts` | 289–630、2513、3226–3398 的 interface/type | `StoredLogin`、`StoredSend`、`StoredSharedLogin`、`VaultData`、`PersistedSyncData`、`SyncEntityMapping`、`Pending*`、`MasterPasswordChangeJournal`、以及所有 `export` 的 `Vault*` / `SshAgentVault*` / `PasskeyVault*` 型別 |
| `vault/parse-primitives.ts` | 631–634、719–768、2482–2512 | `isRecord`、`assertIsoDate`、`assertUuid`、`parseNullableString`、`normalizeRequiredString`、`normalizeString`、`normalizeSyncPassword`、`normalizeNullableString`、`normalizeMasterPassword`（2857） |
| `vault/item-fields.ts` | 915–1064、2594–2624 | `ITEM_FIELD_NAMES`、`ITEM_FIELDS_BY_TYPE`、`SECRET_FIELDS_BY_TYPE`、`EDITOR_SECRET_FIELDS_BY_TYPE`、`COPY_FIELDS_BY_TYPE`、`emptyItemFields`、`normalizeItemFieldsForStorage`、`maxLengthForItemField`、`isVaultItemType`、`normalizeItemType`、`normalizeReprompt`、`applyItemFields`、`assertSecretField`、`assertCopyField`（2768–2775） |
| `vault/login-uris.ts` | 769–811、911–913、2625–2685、2846–2856 | `isVaultUriMatch`、`parseStoredLoginUris`、`normalizeLoginUris`、`cloneLoginUris`、`uriAlias`、`createRequestUris`、`updateRequestUris`、`remoteLoginUris`、`loginUriAt` |
| `vault/password-history.ts` | 812–840 | `parsePasswordHistory`、`clonePasswordHistory` |
| `vault/generator-history.ts` | 841–910 | `generatorCategoryForAlgorithm`、`isGeneratorCategory`、`isGeneratorAlgorithm`、`parseGeneratorHistory`、`cloneGeneratorHistory` |
| `vault/ssh-helpers.ts` | 1065–1084 | `parseSupportedSshAgentPublicKeyBlob`、`sshAgentFingerprint` |
| `vault/passkey-parsing.ts` | 635–718、1085–1140、3250–3300 | `normalizePasskeyRpId`、`normalizePasskeyCredentialId(s)`、`decodeStoredPasskeyCredentialId`、`credentialIdIsAllowed`、`assertPasskeyApproval`、`parseStoredPasskey`、`validateRemotePasskeys`、`findPasskeyVaultMatches`、`assertUnambiguousPasskeyMatches`、`activeVaultContainsCredentialId` |
| `vault/custom-fields.ts` | 1141–1168、2686–2845 | `parseCustomField`、`cloneCustomFields`、`normalizeCustomFields`、`customFieldFromSource`、`linkedCustomFieldValue`、`customFieldValue` |
| `vault/attachments-parsing.ts` | 1169–1218 | `parseStoredAttachment(s)`、`cloneAttachments`、`validateRemoteAttachments` |
| `vault/login-parsing.ts` | 735–760、1219–1390、1562–1617 | `parseFolder`、`cloneItemName`、`parseStoredLogin`、`parseStoredSharedLogin` |
| `vault/send-parsing.ts` | 1391–1494、1770–1791、2513–2593 | `parseStoredSend`、`sendViewFromRemote`、`NormalizedSendOptions`、`normalizeSendOptions`、`normalizeSendDraft`、`normalizeFileSendDraft` |
| `vault/org-collection-parsing.ts` | 1495–1561、1792–1795 | `parseStoredOrganization`、`parseStoredCollection`、`emergencyAccessViewFromRemote` |
| `vault/equivalent-domains.ts` | 1696–1769、1796–1890 | `parseStoredEquivalentDomain*`、`cloneEquivalentDomainSettings`、`validateRemoteEquivalentDomainSettings`、`equivalentDomainRevision`、`equivalentDomainSettingsView`、`normalizeEquivalentDomain(Update)` |
| `vault/sync-data-parsing.ts` | 1618–1695、1891–2129、2941–2973 | `parseSyncMappings`、`parseDirectState`、`parseSyncData`、`recordSyncDeletion`、`assertNoPendingLoginImport`、`assertNoPendingPersonalVaultPurge` |
| `vault/vault-data-parsing.ts` | 2130–2481、2871–2940 | `parseMasterPasswordChangeJournal`、`taggedVaultSection`、`taggedVaultItem`、`parseVaultData(Tagged)`、`cloneData` |
| `vault/views.ts` | 2974–3225、3243–3249 | `toSummary`、`toSharedSummary`、`toVaultSearchItem`、`summarizeSecureNote`、`toView`、`toSharedView`、`compareText`、`validRemoteDate` 系列、`isCompositeRemoteLoginUpdate`、`sameLoginContentExceptFolder` |

保留在 `vault-service.ts` 的模組層小工具（與 class 狀態耦合的 3302–3398 區段）：
`AttachmentAuthorizationValidator`、`ExposedPasswordSnapshot`、`ActiveExposedPasswordOperation`、setup session 相關 interface、`clearAccountWebAuthnRegistrationSetup`、`clearAccountWebAuthnAttestation`、`scrubAccountSessionDeauthorizationRequest` — 可放入 `vault/runtime-types.ts` 或暫留原檔，Phase 2 再歸位。

### 相容層（關鍵）

`vault-service.ts` 檔頭改為：

```ts
export type {
  PersistedSyncData,
  VaultMasterPasswordChangeStatus,
  VaultMasterPasswordChangeRequest,
  // …所有原本 export 的型別
  SshAgentVaultIdentity,
  SshAgentVaultSignRequest,
  SshAgentVaultSignResult,
  SshAgentVaultAuthorizationValidator,
  PasskeyVaultAuthorizationValidator,
  PasskeyVaultCredentialCandidate,
  PasskeyVaultDiscoveryRequest,
  PasskeyVaultDiscoveryResult,
  PasskeyVaultCreationTarget,
  PasskeyVaultCreationTargetDiscoveryRequest,
  PasskeyVaultCreationTargetDiscoveryResult,
  PasskeyVaultCreateRequest,
  PasskeyVaultCreateResult,
  PasskeyVaultAssertionRequest,
  PasskeyVaultAssertionResult
  // …
} from './vault/types'
```

### 執行順序與驗證

依賴方向大致為：`limits` → `types` → `parse-primitives` → 其餘各檔 → `views`。建議每完成 2–3 個檔案就跑一次：

```sh
pnpm typecheck && pnpm test -- vault-service
```

全部完成後跑完整 `pnpm lint && pnpm typecheck && pnpm test`。

**Phase 1 完成後：`vault-service.ts` 約剩 8,000 行（import + 相容 re-export + class）。**

---

## Phase 2：拆分 `VaultService` class（設計變更，中高風險）

### class 內部方法叢集（現況行號）

| 叢集 | 行號 | 約略行數 |
|---|---|---|
| 生命週期：setup/unlock/lock/PIN/主密碼變更 | 3464–3921、9226–9278、11210–11235 | 550 |
| 帳號安全：profile、devices、驗證信、API key、2FA（TOTP/Email/WebAuthn）、session 撤銷 | 3922–5410、9279–9378 | 1,600 |
| Sync 連線管理：connect/unlock/disconnect/remoteLogout/pending import/purge | 5382–5817、9531–9649 | 650 |
| Sync 引擎：performSync、snapshot、login import batch、bulk mutation、executeSyncAction | 9650–10711、8855–9010（status/error helpers）、9379–9464 | 1,500 |
| Equivalent domains | 5740–5817 | 80 |
| Sends | 5818–6075 | 260 |
| Folders | 6076–6157、10618–10656、11124–11209 | 250 |
| 健康報表：health/inactive 2FA/exposed/breach | 6158–6533 | 375 |
| 讀取與清單：list/get/prefetch/password history | 6534–6839 | 300 |
| Attachments：上傳/下載/刪除/fix legacy/cancel | 6840–7160、9129–9162、9439–9530 | 500 |
| Portability + 原生附件備份/還原 | 7161–7799、10712–10881 | 810 |
| 產生器：credential/SSH key/history | 7800–7929 | 130 |
| SSH agent + 授權 | 7930–8097 | 170 |
| 項目 CRUD + passkey 操作 | 8098–8675、10882–11060 | 760 |
| Reveal/Copy/TOTP/開啟 URI/網站圖示 | 8676–8854 | 180 |
| 內部原語：exclusive/mutate/persist/requireData/id/now | 9117–9128、11061–11123、11236–11267 | 100 |

### 拆分策略：協作類別 + 薄委派

1. 定義內部 core 介面（`vault/core.ts`），封裝共享狀態與原語：

   ```ts
   interface VaultCore {
     requireData(): VaultData
     mutate<T>(mutation: (data: VaultData, now: string) => T): Promise<T>
     persist(data: VaultData): Promise<void>
     exclusive<T>(op: () => Promise<T>): Promise<T>
     requireSyncData(): PersistedSyncData
     getOrCreateSyncClient(sync: PersistedSyncData): BitwardenSyncClient
     nowIso(): string
     validatedNewId(): string
     // …依實際需要漸進擴充
   }
   ```

2. 依叢集抽出協作類別，建議順序（由獨立到耦合）：

   | 順序 | 新檔案 | 叢集 | 理由 |
   |---|---|---|---|
   | 1 | `vault/generator.ts` | 產生器 | 幾乎不碰 vault 資料，只用 clipboard/history |
   | 2 | `vault/sends.ts` | Sends | 自成一格，只依賴 sync client |
   | 3 | `vault/health-reports.ts` | 健康報表 | 唯讀，只需 `requireData` |
   | 4 | `vault/folders.ts` | Folders | 小而完整 |
   | 5 | `vault/account-security.ts` | 帳號安全 | 量最大、與 vault 資料耦合低，效益最高 |
   | 6 | `vault/attachments.ts` | Attachments | 需要 operation lease 狀態一併搬移 |
   | 7 | `vault/portability.ts` | Portability + 原生附件還原 | 依賴 attachments 與 sync client |
   | 8 | `vault/sync-engine.ts` | Sync 引擎 + 連線管理 | 最深的耦合，最後處理 |
   | — | 留在 `VaultService` | 生命週期、CRUD、reveal/copy、內部原語 | 這是 class 的核心身分 |

3. `VaultService` 公開方法保留為一行委派（`listSends() { return this.sends.listSends() }`），確保 `vault-ipc.ts` 與所有測試不需改動。

4. 每抽一個叢集即獨立 commit 並完整跑 `pnpm typecheck && pnpm test`。

**Phase 2 完成後：`vault-service.ts` 預估 2,500–3,000 行（核心狀態 + CRUD + 委派）。**

---

## 風險與注意事項

- **純搬移原則**：Phase 1 禁止順手重構、改名、調整邏輯；diff 應可逐段對照。
- **`VaultError` 語意**：parse 函式丟 `CORRUPT_VAULT`、normalize 函式丟 `INVALID_INPUT`，搬移時勿混淆。
- **循環依賴**：`vault/types.ts` 只放型別（`import type`），避免與 parsing 檔互相引用實值。
- **`private` 存取**：Phase 2 中協作類別無法存取 `VaultService` 的 private 成員，必須透過 `VaultCore` 介面；抽每個叢集前先盤點它觸碰哪些欄位。
- **Abort/lease 狀態**：`accountSecurityAborts`、`activeAttachmentOperation`、setup sessions 等 Map/Set 需隨叢集一起搬到協作類別，`clearUnlockedRuntimeState()`（3896）要改為呼叫各協作類別的 `dispose()`。
- **測試即安全網**：`vault-service.test.ts` 全走公開 API，是本次重構的驗收標準；不應為了拆分而修改測試。

## 驗收清單

- [ ] `pnpm lint`、`pnpm typecheck`、`pnpm test` 全數通過
- [ ] 外部 8 個 importer 檔案 diff 為零
- [ ] `vault-service.ts` 不再包含模組層 parse/normalize 函式（Phase 1）
- [ ] 每個新檔案 < 1,000 行
- [ ] 無循環依賴（可用 `npx madge --circular src/main` 檢查）
