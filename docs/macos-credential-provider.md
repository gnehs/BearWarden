# macOS Password／Passkey Provider 方案

## 決策

BearWarden 在 macOS 14+ 應以 AuthenticationServices 的 **AutoFill Credential Provider
Extension** 提供系統密碼與 Passkey；`Ctrl+\\` Accessibility 自動填入則保留給 Chrome／Firefox
等未保證採用系統密碼 AutoFill 的場景。Passkey 不得透過 Accessibility 模擬，必須維持
WebAuthn 的 RP ID、origin、challenge 與 user verification 安全邊界。

Vaultwarden 不需要新增 provider API。網站 Passkey 仍是 Bitwarden cipher 內的端對端加密資料，
伺服器只負責同步；Vaultwarden 的 WebAuthn two-factor 是另一個功能。

## 平台能力與最低版本

- Host app 與 extension 都需要
  `com.apple.developer.authentication-services.autofill-credential-provider` entitlement。
- Extension point 是 `com.apple.authentication-services-credential-provider-ui`，controller 繼承
  `ASCredentialProviderViewController`。
- `Info.plist` 的 `ASCredentialProviderExtensionCapabilities` 啟用 `ProvidesPasswords` 與
  `ProvidesPasskeys`。
- 密碼 provider 可從 macOS 11 起使用；第三方 Passkey identity、registration 與 assertion API
  需要 macOS 14，因此 BearWarden Passkey Provider 的 deployment target 設為 macOS 14。
- 使用者必須在系統設定主動啟用 BearWarden；app 不得自行靜默設為 provider。

官方參考：

- [AutoFill Credential Provider entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.authentication-services.autofill-credential-provider)
- [ASCredentialProviderViewController](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)
- [ASPasskeyCredentialIdentity](https://developer.apple.com/documentation/authenticationservices/aspasskeycredentialidentity)
- [ASPasskeyRegistrationCredential](https://developer.apple.com/documentation/authenticationservices/aspasskeyregistrationcredential)
- [ASPasskeyAssertionCredential](https://developer.apple.com/documentation/authenticationservices/aspasskeyassertioncredential)
- [WWDC24：What’s new in Authentication Services](https://developer.apple.com/videos/play/wwdc2024/10125/)

## 建議架構

```mermaid
flowchart LR
  Website["網站 WebAuthn"] --> OS["macOS AuthenticationServices"]
  OS --> Appext["BearWarden Credential Provider appex"]
  Appext --> IPC["已簽署、request-bound IPC"]
  IPC --> Ingress["AuthenticationServices 專用可信 ingress"]
  Ingress --> Ceremony["共用選擇／UV／vault operation core"]
  Ceremony --> Vault["既有 VaultService／加密 cipher"]
  Vault --> Identity["ASCredentialIdentityStore metadata index"]
```

Extension 只做平台 adapter：

1. 接收 `ASPasskeyCredentialRequest` 或 password request。
2. 將系統提供的 RP ID、`clientDataHash`、credential descriptor、user verification requirement
   與 request lifetime 封裝成 bounded binary message。AuthenticationServices 不提供可由 hash
   還原的 `clientDataJSON`，extension 也不得自行捏造 origin／challenge JSON。
3. 經 authenticated IPC 送到 Electron main；main 將 peer identity、connection epoch 與 abort
   signal 以 out-of-band transport context 綁到 AuthenticationServices 專用可信 ingress。
4. 不直接呼叫目前以 browser WebAuthn `clientDataJSON` 為輸入的 `PasskeyCeremonyService.create/get`。
   應抽出並重用其中的 choice、UV、reprompt、generation 與 vault create/assert operation，新增
   接受系統 `clientDataHash` 的 adapter；assertion 直接簽署 `authenticatorData || clientDataHash`。
5. 私鑰、密碼、challenge 與 credential ID 不得進入一般 renderer。Renderer 只保留既有的安全
   選擇／核准 metadata UI。
6. 成功後 extension 以 `ASPasskeyAssertionCredential` 或
   `ASPasskeyRegistrationCredential` 完成系統 request。

`ASCredentialIdentityStore` 只寫入系統匹配需要的 metadata：password service identifier，或
Passkey 的 RP ID、username、credential ID、user handle 與 opaque record identifier。密碼與私鑰
永遠留在 BearWarden 加密 vault。每次 unlock、sync、item/passkey mutation、account switch 後重建
目前帳號的 index；lock 時不必刪除 identity metadata，但 extension 必須拒絕取用秘密並引導解鎖。

可參考 Bitwarden 官方 clients：

- [`apps/desktop/macos/autofill-extension/Info.plist`](https://github.com/bitwarden/clients/blob/main/apps/desktop/macos/autofill-extension/Info.plist)
- [`CredentialProviderViewController.swift`](https://github.com/bitwarden/clients/blob/main/apps/desktop/macos/autofill-extension/CredentialProviderViewController.swift)
- [`desktop_native/autofill_provider/README.md`](https://github.com/bitwarden/clients/blob/main/apps/desktop/desktop_native/autofill_provider/README.md)
- [`objc/.../autofill/commands/sync.m`](https://github.com/bitwarden/clients/blob/main/apps/desktop/desktop_native/objc/src/native/autofill/commands/sync.m)

## IPC 與 caller authenticity 威脅模型

不能使用 localhost HTTP/WebSocket，也不能信任 payload 自稱的 provider、origin 或 PID。建議採
Unix domain socket，放在目前使用者專屬、`0700` 的 app container／group container；每次 app
啟動建立新的 socket 與隨機 session nonce，並要求以下條件全部成立：

- socket peer 必須是同一 UID；連線後再以 macOS audit token／code-signing requirement 驗證
  Team ID、bundle ID 與 designated requirement，確認是 BearWarden appex。
- request ID、connection epoch、nonce、request digest 與 system request lifetime 一起綁定；
  replay、跨連線 response、重複完成與過期 request 全部拒絕。
- origin、RP ID、challenge 與 `clientDataJSON` 由系統 request 加上 extension 本身產生，不接受
  renderer 或任意 payload 宣告的 trusted identity。
- lock、account switch、sync mutation、appex disconnect、renderer crash、app quit 都 abort
  pending request 並提升 generation；late response 必須無法簽章或寫入。
- binary protocol 設定 frame、array、string、credential descriptor 與 timeout 上限；錯誤只回穩定
  code，不回秘密或原生 exception detail。
- app 若未執行，可由 appex 啟動，但在完成 code-signing 驗證、vault unlock 與 request rebind 前
  不得提供 credential。

正式散布時 host app、helper 與 appex 必須使用同一開發團隊的一致簽章，完成 hardened runtime、
notarization／Mac App Store provisioning；開發期 ad-hoc 簽章不可進 release artifact。

## 實作階段

1. 建立 Xcode host companion project 與 Credential Provider appex，先完成 password identity store
   sync 與無秘密 fixture。
2. 實作 Unix socket transport、audit token／code-signing 驗證、bounded codec 與 request abort。
3. 將 transport adapter 接到既有 Passkey ingress／ceremony，完成 assertion（讀取）與
   registration（寫入）。
4. electron-builder `afterPack`／`afterSign` 嵌入並簽署 appex，為主 app 與 appex 配置 entitlement
   與 provisioning profile。
5. 真機測試 Safari、Chrome stable、Firefox stable：建立、discoverable login、allowCredentials、
   conditional UI、拒絕、取消、lock/unlock、account switch、sync race、appex crash 與 app cold start。

Chrome 已透過 macOS AuthenticationServices 取得第三方 provider passkeys；Firefox 也使用 macOS
platform WebAuthn service，但仍要把每個 stable browser 版本納入 release regression matrix。一般
HTML 密碼欄不應假設 Chrome／Firefox 必定採用系統 password provider，因此 `Ctrl+\\` fallback
仍有存在價值。
