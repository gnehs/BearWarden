// electron-vite 5's isolated-entry reporter assumes stdout is an interactive TTY.
// GitHub Actions uses a pipe, so provide the no-op cursor methods that the reporter calls.
if (!process.stdout.isTTY) {
  process.stdout.clearLine ??= () => false
  process.stdout.cursorTo ??= () => false
  process.stdout.moveCursor ??= () => false
}
