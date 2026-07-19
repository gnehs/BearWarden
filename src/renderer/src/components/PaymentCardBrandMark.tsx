import { CreditCard } from 'lucide-react'
import AmexLogo from '~icons/logos/amex'
import JcbLogo from '~icons/logos/jcb'
import MastercardLogo from '~icons/logos/mastercard'
import VisaLogo from '~icons/logos/visa'
import type { PaymentCardBrand } from '../lib/payment-card'
import { cn } from '../lib/utils'

interface PaymentCardBrandMarkProps {
  brand: PaymentCardBrand
  compact?: boolean
}

const paymentCardBrandLogos = {
  visa: { label: 'Visa', Logo: VisaLogo },
  mastercard: { label: 'Mastercard', Logo: MastercardLogo },
  jcb: { label: 'JCB', Logo: JcbLogo },
  'american-express': { label: 'American Express', Logo: AmexLogo }
} satisfies Record<Exclude<PaymentCardBrand, 'unknown'>, { label: string; Logo: typeof VisaLogo }>

function PaymentCardBrandMark({
  brand,
  compact = false
}: PaymentCardBrandMarkProps): React.JSX.Element {
  if (brand === 'unknown') {
    return (
      <span
        className="relative inline-flex min-h-5 min-w-7 items-center justify-center leading-none"
        role="img"
        aria-label="其他發卡組織"
      >
        <CreditCard size={compact ? 17 : 20} aria-hidden="true" />
      </span>
    )
  }
  const { label, Logo } = paymentCardBrandLogos[brand]

  return (
    <span
      className={cn(
        'relative inline-flex h-7 w-[58px] min-w-[58px] items-center justify-center leading-none [&>svg]:block [&>svg]:size-full [[data-detail-icon]_>_&]:max-w-[calc(100%-8px)] [[data-detail-icon]_>_&]:min-w-[0px]',
        compact && 'h-[18px] w-[29px] min-w-[29px]'
      )}
      role="img"
      aria-label={label}
    >
      <Logo aria-hidden="true" focusable="false" />
    </span>
  )
}

export default PaymentCardBrandMark
