export type MasterPasswordStrengthScore = 0 | 1 | 2 | 3 | 4

export interface MasterPasswordStrengthLevel {
  score: MasterPasswordStrengthScore
  /** 1-4 filled segments out of 4 */
  segments: 1 | 2 | 3 | 4
  tone: 'destructive' | 'warning' | 'success'
}

export const MASTER_PASSWORD_STRENGTH_LEVELS: Record<
  MasterPasswordStrengthScore,
  MasterPasswordStrengthLevel
> = {
  0: { score: 0, segments: 1, tone: 'destructive' },
  1: { score: 1, segments: 1, tone: 'destructive' },
  2: { score: 2, segments: 2, tone: 'warning' },
  3: { score: 3, segments: 3, tone: 'success' },
  4: { score: 4, segments: 4, tone: 'success' }
}

// Matches the main-process vault health scorer: zxcvbn latency grows with input length.
const MAX_ZXCVBN_PASSWORD_LENGTH = 100
const BRAND_USER_INPUTS = ['bearwarden', 'bear', 'warden']

type ZxcvbnScorer = typeof import('zxcvbn')

let zxcvbnLoad: Promise<ZxcvbnScorer> | null = null

function loadZxcvbn(): Promise<ZxcvbnScorer> {
  if (!zxcvbnLoad) {
    zxcvbnLoad = import('zxcvbn').then(
      (module) => module.default,
      (error: unknown) => {
        zxcvbnLoad = null
        throw error
      }
    )
  }
  return zxcvbnLoad
}

export async function scoreMasterPassword(
  password: string
): Promise<MasterPasswordStrengthLevel | null> {
  if (!password) return null
  const zxcvbn = await loadZxcvbn()
  const { score } = zxcvbn(password.slice(0, MAX_ZXCVBN_PASSWORD_LENGTH), BRAND_USER_INPUTS)
  return MASTER_PASSWORD_STRENGTH_LEVELS[score]
}
