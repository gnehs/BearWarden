import { chmodSync, lstatSync, mkdirSync } from 'node:fs'

/** Creates a private development-only userData root without following a pre-existing symlink. */
export function prepareDevelopmentUserData(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 })
  const metadata = lstatSync(path)
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error('UNSAFE_DEVELOPMENT_USER_DATA')
  }
  if (
    process.platform !== 'win32' &&
    typeof process.getuid === 'function' &&
    metadata.uid !== process.getuid()
  ) {
    throw new Error('UNSAFE_DEVELOPMENT_USER_DATA_OWNER')
  }
  if (process.platform !== 'win32') chmodSync(path, 0o700)
}
