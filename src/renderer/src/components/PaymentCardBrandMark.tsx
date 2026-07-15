import { CreditCard } from 'lucide-react'
import type { PaymentCardBrand } from '../lib/payment-card'

interface PaymentCardBrandMarkProps {
  brand: PaymentCardBrand
  compact?: boolean
}

function PaymentCardBrandMark({
  brand,
  compact = false
}: PaymentCardBrandMarkProps): React.JSX.Element {
  if (brand === 'unknown') {
    return (
      <span className="payment-brand-mark unknown" aria-label="其他發卡組織">
        <CreditCard size={compact ? 17 : 20} aria-hidden="true" />
      </span>
    )
  }
  if (brand === 'mastercard') {
    return (
      <span
        className={`payment-brand-mark mastercard ${compact ? 'compact' : ''}`}
        aria-label="Mastercard"
      >
        <i aria-hidden="true" />
        <i aria-hidden="true" />
        {!compact && <b>mastercard</b>}
      </span>
    )
  }
  if (brand === 'jcb') {
    return (
      <span className={`payment-brand-mark jcb ${compact ? 'compact' : ''}`} aria-label="JCB">
        <i>J</i>
        <i>C</i>
        <i>B</i>
      </span>
    )
  }
  if (brand === 'american-express') {
    return (
      <span
        className={`payment-brand-mark amex ${compact ? 'compact' : ''}`}
        aria-label="American Express"
      >
        {compact ? 'AX' : 'AMEX'}
      </span>
    )
  }
  return (
    <span className={`payment-brand-mark visa ${compact ? 'compact' : ''}`} aria-label="Visa">
      VISA
    </span>
  )
}

export default PaymentCardBrandMark
