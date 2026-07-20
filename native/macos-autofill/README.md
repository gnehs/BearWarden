# BearWarden macOS autofill helper

This executable is a narrow bridge to macOS Accessibility. It supports:

- Safari and Safari Technology Preview.
- Google Chrome Stable, Beta, Dev, and Canary, and Microsoft Edge channels. Locally built or
  third-party-signed Chromium is excluded because it has no single vendor signing identity.
- Arc, Brave channels, Vivaldi/Snapshot, and Opera/Opera GX channels through an exact
  bundle-identifier allowlist. Chromium-based Electron apps are intentionally excluded.
- Firefox, Firefox Developer Edition, and Firefox Nightly.

- `context`: returns the frontmost supported browser's PID, bundle identifier,
  HTTP(S) URL, and non-secret focused-element metadata. URL user info, query,
  and fragment components are removed before output.
- `fill`: reads the captured PID, bundle identifier, sanitized URL, username, and password JSON
  from standard input, revalidates that the same browser and URL are still active,
  reactivates that supported browser, sets the focused field through `AXValue`,
  tabs to the next field, and sets its value. If focus is already in a secure
  field, only the password is filled.
- `permission [--prompt]`: checks Accessibility trust and optionally asks macOS
  to show its permission prompt.
- `self-test`: runs deterministic tests that do not require Accessibility trust.

Errors are JSON on standard error and use stable uppercase `error.code` values.
Credential values are never accepted as command-line arguments and are never
written to standard output, standard error, or the clipboard.

Build from the repository root:

```sh
./scripts/build-macos-autofill-helper.sh
'./resources/bin/BearWarden Autofill Helper.app/Contents/MacOS/bearwarden-macos-autofill' self-test
```

An optional first build-script argument overrides the output app-bundle path. The helper is built
as `BearWarden Autofill Helper.app` with the stable bundle identifier
`com.bearwarden.app.autofill-helper`. Packaged builds place it at
`BearWarden.app/Contents/Helpers/` so macOS can attribute Accessibility consent to proper nested
code instead of an anonymous executable in `Contents/Resources`.
The legacy raw-helper Accessibility grant does not transfer to the new bundle, so the first bundle
release requires granting Accessibility once to the newly identified helper.
Set `BEARWARDEN_REQUIRE_SIGNED_AUTOFILL=1` in a signed release pipeline so the build fails
closed unless `CODESIGN_IDENTITY` names a real distribution identity.
The default binary is universal (`arm64` and `x86_64`). Set
`MACOS_AUTOFILL_ARCHITECTURE` to `native`, `arm64`, or `x86_64` when building a
thin binary. Set `CODESIGN_IDENTITY` to a distribution identity when required.

## Security and platform limits

- The helper must be signed consistently with the parent app for a stable macOS
  Accessibility consent identity. The build script only applies an ad-hoc
  signature for local development; distribution signing should replace it.
- Before using Accessibility, packaged helpers verify that their direct parent is the declared
  executable of the containing `com.bearwarden.app`; development helpers accept only the Electron
  runtime inside the same project. Direct invocation by unrelated local processes fails closed.
- Accessibility is a powerful user-granted permission. The helper restricts
  reads and writes to explicitly allowlisted browser bundle IDs with their expected vendor
  code-signing identity, but cannot provide
  the same origin isolation as a browser extension.
- URL discovery is best effort because browser accessibility trees change. It
  only accepts HTTP(S) URLs, prefers the focused element's ancestor chain, bounds tree traversal,
  and rejects focused windows that expose more than one ambiguous document URL.
- Fill requires the login field to have retained accessibility focus. It never
  searches the whole page for arbitrary writable fields.
- Filling can be partial if the username succeeds but the next field cannot be
  focused or rejects `AXValue`; the helper does not read the previous field
  value to attempt rollback.
- Username/password strings necessarily exist briefly in process memory. Swift
  does not guarantee deterministic zeroization of immutable strings.
- The Tab event contains no credential data. Credential text is set with
  `AXValue`; it is not synthesized as keyboard text.
