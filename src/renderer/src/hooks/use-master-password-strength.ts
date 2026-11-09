import { useEffect, useState } from 'react'
import {
  scoreMasterPassword,
  type MasterPasswordStrengthLevel
} from '@renderer/lib/master-password-strength'

export function useMasterPasswordStrength(password: string): MasterPasswordStrengthLevel | null {
  const [level, setLevel] = useState<MasterPasswordStrengthLevel | null>(null)

  useEffect(() => {
    if (!password) return
    let current = true
    void scoreMasterPassword(password).then(
      (next) => {
        if (current) setLevel(next)
      },
      () => {
        if (current) setLevel(null)
      }
    )
    return () => {
      current = false
    }
  }, [password])

  return password ? level : null
}
