import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'

const isElectronChild = process.argv.includes('--electron-child')

if (isElectronChild) {
  assert.ok(process.versions.electron, 'verification must run inside Electron')
  const { argon2idAsync } = await import('@noble/hashes/argon2.js')
  const salt = createHash('sha256').update('test_key').digest()
  const derived = await argon2idAsync(Buffer.from('67t9b5g67$%Dh89n'), salt, {
    t: 4,
    m: 32 * 1024,
    p: 2,
    dkLen: 32
  })
  assert.equal(
    Buffer.from(derived).toString('hex'),
    'cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2'
  )
  derived.fill(0)
  salt.fill(0)
} else {
  const electronPath = (await import('electron')).default
  const result = spawnSync(electronPath, [fileURLToPath(import.meta.url), '--electron-child'], {
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
    encoding: 'utf8'
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    if (result.stderr) process.stderr.write(result.stderr)
    if (result.stdout) process.stdout.write(result.stdout)
    process.exit(result.status ?? 1)
  }
  console.log('Electron portable Argon2id verification passed.')
}
