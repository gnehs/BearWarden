import { useLingui } from '@lingui/react/macro'
import { useMemo } from 'react'
import type { BankAccountType } from '../lib/document-item-fields'

/** Translated names for Bitwarden's bank account kinds. */
export function useBankAccountTypeLabels(): Record<BankAccountType, string> {
  const { t } = useLingui()
  return useMemo(
    () => ({
      checking: t({
        message: 'Checking',
        context: 'bank-account-type',
        comment: 'Bank account kind: a checking or current account used for everyday payments.'
      }),
      savings: t({ message: 'Savings', comment: 'Bank account kind: a savings account.' }),
      certificateOfDeposit: t({
        message: 'Certificate of deposit',
        comment: 'Bank account kind: a fixed-term certificate of deposit or time deposit.'
      }),
      lineOfCredit: t({
        message: 'Line of credit',
        comment: 'Bank account kind: a revolving line of credit.'
      }),
      investmentBrokerage: t({
        message: 'Investment / brokerage',
        comment: 'Bank account kind: an investment or brokerage account.'
      }),
      moneyMarket: t({
        message: 'Money market',
        comment: 'Bank account kind: a money market account.'
      }),
      other: t({
        message: 'Other',
        context: 'bank-account-type',
        comment: 'Bank account kind for accounts that fit none of the listed kinds.'
      })
    }),
    [t]
  )
}
