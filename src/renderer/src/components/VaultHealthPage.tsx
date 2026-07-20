import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  ExternalLink,
  KeyRound,
  MailSearch,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldQuestion,
  WifiOff,
  X
} from 'lucide-react'
import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'
import { Plural, Trans, useLingui } from '@lingui/react/macro'
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import type {
  InactiveTwoFactorFinding,
  InactiveTwoFactorReport,
  VaultHealthAccountBreachFinding,
  VaultHealthReport,
  VaultHealthExposedFinding,
  VaultHealthExposedReport,
  VaultHealthReusedFinding,
  VaultHealthUnsecuredWebsiteFinding,
  VaultHealthWeakFinding
} from '../../../shared/vault-contract'
import { Alert, AlertAction, AlertDescription, AlertTitle } from './ui/alert'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from './ui/empty'
import { Spinner } from './ui/spinner'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs'
import { Input } from './ui/input'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from './ui/field'
import {
  beginAccountBreachCheck,
  beginExposedPasswordCheck,
  cancelAccountBreachCheck,
  cancelExposedPasswordCheck,
  createAccountBreachIdleState,
  createExposedPasswordIdleState,
  failAccountBreachCheck,
  failExposedPasswordCheck,
  invalidateAccountBreachCheck,
  resolveAccountBreachCheck,
  resolveExposedPasswordCheck,
  type AccountBreachCheckState,
  type ExposedPasswordCheckState
} from '../lib/vault-health-ui'

type HealthTab = 'reused' | 'weak' | 'unsecured' | 'inactive-two-factor' | 'exposed' | 'account'

export type InactiveTwoFactorCheckState =
  | { status: 'idle'; revision: string }
  | { status: 'loading'; revision: string; requestId: number }
  | { status: 'failed'; revision: string }
  | { status: 'success'; revision: string; report: InactiveTwoFactorReport }

// Exported for security-state regression tests; this file otherwise remains the page boundary.
// eslint-disable-next-line react-refresh/only-export-components
export function createInactiveTwoFactorIdleState(revision: string): InactiveTwoFactorCheckState {
  return { status: 'idle', revision }
}

// eslint-disable-next-line react-refresh/only-export-components
export function resolveInactiveTwoFactorCheck(
  current: InactiveTwoFactorCheckState,
  revision: string,
  requestId: number,
  report: InactiveTwoFactorReport
): InactiveTwoFactorCheckState {
  if (
    current.status !== 'loading' ||
    current.revision !== revision ||
    current.requestId !== requestId
  ) {
    return current
  }
  return { status: 'success', revision, report }
}

// eslint-disable-next-line react-refresh/only-export-components
export function failInactiveTwoFactorCheck(
  current: InactiveTwoFactorCheckState,
  revision: string,
  requestId: number
): InactiveTwoFactorCheckState {
  if (
    current.status !== 'loading' ||
    current.revision !== revision ||
    current.requestId !== requestId
  ) {
    return current
  }
  return { status: 'failed', revision }
}

// eslint-disable-next-line react-refresh/only-export-components
export async function openInactiveTwoFactorDocumentation(
  finding: Pick<InactiveTwoFactorFinding, 'matchedDomain' | 'documentationUrl'>
): Promise<void> {
  if (finding.documentationUrl === null) return
  try {
    await window.bearwarden.health.openTwoFactorDocumentation({
      matchedDomain: finding.matchedDomain
    })
  } catch {
    toast.error(i18n._(msg`Unable to open the two-factor authentication setup instructions`))
  }
}

interface VaultHealthPageProps {
  revision: string
  onOpenItem: (id: string) => void
}

function HealthLoading(): React.JSX.Element {
  return (
    <Empty className="min-h-72" aria-live="polite">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Spinner />
        </EmptyMedia>
        <EmptyTitle>
          <Trans>Analyzing the vault locally</Trans>
        </EmptyTitle>
        <EmptyDescription>
          <Trans>
            Passwords remain in the main process and are never sent to the renderer process or an
            external service.
          </Trans>
        </EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

function HealthEmpty({
  kind
}: {
  kind: Exclude<HealthTab, 'exposed' | 'account'>
}): React.JSX.Element {
  const { t } = useLingui()
  const copy =
    kind === 'reused'
      ? [t`No reused passwords`, t`None of the analyzed login items share the same password.`]
      : kind === 'weak'
        ? [t`No weak passwords`, t`All analyzed login items are above the weak-password threshold.`]
        : [t`No unsecured websites`, t`None of the valid personal login items use an http:// URI.`]
  return (
    <Empty className="min-h-56 xl:col-span-2">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <CheckCircle2 />
        </EmptyMedia>
        <EmptyTitle>{copy[0]}</EmptyTitle>
        <EmptyDescription>{copy[1]}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

function HealthFindingCard({
  title,
  description,
  status,
  onOpen
}: {
  title: string
  description: string
  status: ReactNode
  onOpen: () => void
}): React.JSX.Element {
  const { t } = useLingui()
  return (
    <Card size="sm">
      <CardHeader className="gap-2 has-data-[slot=card-action]:grid-cols-1 sm:has-data-[slot=card-action]:grid-cols-[1fr_auto]">
        <CardTitle className="truncate">{title}</CardTitle>
        <CardDescription className="truncate">{description}</CardDescription>
        <CardAction className="col-start-1 row-start-3 flex items-center gap-1 justify-self-start sm:col-start-2 sm:row-span-2 sm:row-start-1 sm:justify-self-end">
          {status}
          <Button
            variant="ghost"
            size="sm"
            type="button"
            aria-label={t`View ${title}`}
            onClick={onOpen}
          >
            <Trans>View</Trans>
            <ChevronRight data-icon="inline-end" />
          </Button>
        </CardAction>
      </CardHeader>
    </Card>
  )
}

function HealthResultsHeader({
  title,
  description,
  count
}: {
  title: string
  description: string
  count: number
}): React.JSX.Element {
  return (
    <div className="flex items-start justify-between gap-4 py-2 xl:col-span-2">
      <div>
        <h2 className="text-base font-medium">{title}</h2>
        <p className="text-muted-foreground mt-1 text-sm">{description}</p>
      </div>
      <Badge variant={count ? 'destructive' : 'secondary'}>
        <Plural value={count} one="# item" other="# items" />
      </Badge>
    </div>
  )
}

function ReusedFindingCard({
  finding,
  onOpenItem
}: {
  finding: VaultHealthReusedFinding
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  const { t } = useLingui()
  const reuseCount = finding.reuseCount
  return (
    <HealthFindingCard
      title={finding.name}
      description={finding.subtitle || t`Login item`}
      status={
        <Badge variant="destructive">
          <Plural value={reuseCount} one="Reused # time" other="Reused # times" />
        </Badge>
      }
      onOpen={() => onOpenItem(finding.id)}
    />
  )
}

function WeakFindingCard({
  finding,
  onOpenItem
}: {
  finding: VaultHealthWeakFinding
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  const { t } = useLingui()
  return (
    <HealthFindingCard
      title={finding.name}
      description={finding.subtitle || t`Login item`}
      status={
        <Badge variant={finding.score <= 1 ? 'destructive' : 'outline'}>
          {finding.score <= 1 ? t`Very weak` : t`Weak`}
        </Badge>
      }
      onOpen={() => onOpenItem(finding.id)}
    />
  )
}

function UnsecuredWebsiteFindingCard({
  finding,
  onOpenItem
}: {
  finding: VaultHealthUnsecuredWebsiteFinding
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  const { t } = useLingui()
  return (
    <HealthFindingCard
      title={finding.name}
      description={t`At least one URI explicitly uses http://`}
      status={
        <Badge variant="destructive">
          <Trans>Unencrypted connection</Trans>
        </Badge>
      }
      onOpen={() => onOpenItem(finding.id)}
    />
  )
}

function InactiveTwoFactorFindingCard({
  finding,
  onOpenItem
}: {
  finding: InactiveTwoFactorFinding
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  const { t } = useLingui()
  const findingName = finding.name
  const matchedDomain = finding.matchedDomain
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{findingName}</CardTitle>
        <CardDescription>
          <Trans>2fa.directory service: {matchedDomain}</Trans>
        </CardDescription>
        <CardAction className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            type="button"
            aria-label={t`View ${findingName}`}
            onClick={() => onOpenItem(finding.id)}
          >
            <Trans>View item</Trans>
          </Button>
          {finding.documentationUrl !== null && (
            <Button
              variant="outline"
              size="sm"
              type="button"
              aria-label={t`Open two-factor authentication setup instructions for ${findingName}`}
              onClick={() => {
                void openInactiveTwoFactorDocumentation(finding)
              }}
            >
              <ExternalLink data-icon="inline-start" />
              <Trans>Setup instructions</Trans>
            </Button>
          )}
        </CardAction>
      </CardHeader>
    </Card>
  )
}

function InactiveTwoFactorPrivacyNotice(): React.JSX.Element {
  return (
    <Alert>
      <ShieldCheck />
      <AlertTitle>
        <Trans>Download the service list only when requested</Trans>
      </AlertTitle>
      <AlertDescription>
        <Trans>
          After you start the check, the main process downloads only the static TOTP service list
          from 2fa.directory and compares it locally. Vault domains, URIs, passwords, and TOTP
          secrets are never uploaded.
        </Trans>
      </AlertDescription>
    </Alert>
  )
}

function InactiveTwoFactorIdle({ onStart }: { onStart: () => void }): React.JSX.Element {
  return (
    <Empty className="min-h-56">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <KeyRound />
        </EmptyMedia>
        <EmptyTitle>
          <Trans>Login items without two-factor authentication have not been checked yet</Trans>
        </EmptyTitle>
        <EmptyDescription>
          <Trans>
            The service list is loaded only after you press the button. Items in the trash, archived
            items, and items that already have TOTP are skipped.
          </Trans>
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button type="button" onClick={onStart}>
          <Search data-icon="inline-start" />
          <Trans>Check two-factor authentication</Trans>
        </Button>
      </EmptyContent>
    </Empty>
  )
}

function InactiveTwoFactorLoading(): React.JSX.Element {
  return (
    <Empty className="min-h-56" aria-live="polite" aria-busy="true">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Spinner />
        </EmptyMedia>
        <EmptyTitle>
          <Trans>Loading the 2fa.directory service list</Trans>
        </EmptyTitle>
        <EmptyDescription>
          <Trans>
            The main process is comparing service domains locally without uploading any vault data.
          </Trans>
        </EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

function InactiveTwoFactorFailed({ onRetry }: { onRetry: () => void }): React.JSX.Element {
  return (
    <Alert variant="destructive">
      <WifiOff />
      <AlertTitle>
        <Trans>Unable to complete the two-factor authentication check</Trans>
      </AlertTitle>
      <AlertDescription>
        <Trans>
          The 2fa.directory network request, service list, or response validation failed, so this
          result is unknown. Try again later.
        </Trans>
      </AlertDescription>
      <AlertAction>
        <Button variant="outline" size="sm" type="button" onClick={onRetry}>
          <Trans>Retry</Trans>
        </Button>
      </AlertAction>
    </Alert>
  )
}

function InactiveTwoFactorSuccess({
  report,
  onOpenItem
}: {
  report: InactiveTwoFactorReport
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  const analyzedCount = report.analyzedCount
  const findingCount = report.findings.length
  const excludedTotpCount = report.excludedTotpCount
  const excludedDeletedCount = report.excludedDeletedCount
  const excludedArchivedCount = report.excludedArchivedCount
  return (
    <div className="flex flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>
              <Trans>Analyzed this time</Trans>
            </CardTitle>
            <CardDescription>
              <Trans>Valid personal login items included in this check</Trans>
            </CardDescription>
            <CardAction>
              <Badge variant="secondary">{analyzedCount}</Badge>
            </CardAction>
          </CardHeader>
          <CardContent>
            <Trans>Service domains are compared with the static list only on this device.</Trans>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>
              <Trans>TOTP available</Trans>
            </CardTitle>
            <CardDescription>
              <Trans>The service supports TOTP, but the login item is not configured</Trans>
            </CardDescription>
            <CardAction>
              <Badge variant={findingCount ? 'destructive' : 'secondary'}>{findingCount}</Badge>
            </CardAction>
          </CardHeader>
          <CardContent>
            <Trans>
              Open an item to edit it, or view the setup instructions provided by the service.
            </Trans>
          </CardContent>
        </Card>
      </div>

      <Alert>
        <ShieldCheck />
        <AlertTitle>
          <Trans>Items that do not apply were skipped</Trans>
        </AlertTitle>
        <AlertDescription className="flex flex-wrap gap-2">
          <Badge variant="outline">
            <Plural
              value={excludedTotpCount}
              one="# already has TOTP"
              other="# already have TOTP"
            />
          </Badge>
          <Badge variant="outline">
            <Plural value={excludedDeletedCount} one="# item in trash" other="# items in trash" />
          </Badge>
          <Badge variant="outline">
            <Plural value={excludedArchivedCount} one="# archived item" other="# archived items" />
          </Badge>
        </AlertDescription>
      </Alert>

      {report.findings.length ? (
        report.findings.map((finding) => (
          <InactiveTwoFactorFindingCard
            key={finding.id}
            finding={finding}
            onOpenItem={onOpenItem}
          />
        ))
      ) : (
        <Empty className="min-h-56">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <CheckCircle2 />
            </EmptyMedia>
            <EmptyTitle>
              <Trans>No supported services without TOTP were found</Trans>
            </EmptyTitle>
            <EmptyDescription>
              <Trans>
                None of the analyzed login items matched a service in the 2fa.directory TOTP list
                that does not yet have TOTP configured.
              </Trans>
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      )}
    </div>
  )
}

export function InactiveTwoFactorPanel({
  state,
  onStart,
  onOpenItem
}: {
  state: InactiveTwoFactorCheckState
  onStart: () => void
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <div className="flex flex-col gap-3">
      <InactiveTwoFactorPrivacyNotice />
      {state.status === 'idle' ? (
        <InactiveTwoFactorIdle onStart={onStart} />
      ) : state.status === 'loading' ? (
        <InactiveTwoFactorLoading />
      ) : state.status === 'failed' ? (
        <InactiveTwoFactorFailed onRetry={onStart} />
      ) : (
        <InactiveTwoFactorSuccess report={state.report} onOpenItem={onOpenItem} />
      )}
    </div>
  )
}

function ExposedFindingCard({
  finding,
  onOpenItem
}: {
  finding: VaultHealthExposedFinding
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  const { t } = useLingui()
  const exposedCount = finding.exposedCount
  return (
    <HealthFindingCard
      title={finding.name}
      description={finding.subtitle || t`Login item`}
      status={
        <Badge variant="destructive">
          <Plural value={exposedCount} one="# known breach record" other="# known breach records" />
        </Badge>
      }
      onOpen={() => onOpenItem(finding.id)}
    />
  )
}

function ExposedPrivacyNotice(): React.JSX.Element {
  return (
    <Alert>
      <ShieldCheck />
      <AlertTitle>
        <Trans>Protect queries with k-anonymity</Trans>
      </AlertTitle>
      <AlertDescription>
        <Trans>
          BearWarden sends only the first 5 characters of the password SHA-1 hash, downloads the
          padded range response from HIBP Pwned Passwords, and compares the complete SHA-1 locally
          in the main process. Neither the password nor the complete hash is sent to HIBP or the
          renderer process.
        </Trans>
      </AlertDescription>
    </Alert>
  )
}

function ExposedIdle({ onStart }: { onStart: () => void }): React.JSX.Element {
  return (
    <Empty className="min-h-56">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <ShieldQuestion />
        </EmptyMedia>
        <EmptyTitle>
          <Trans>Known breaches have not been checked yet</Trans>
        </EmptyTitle>
        <EmptyDescription>
          <Trans>
            This check connects to HIBP only after you press the button. Opening this page does not
            start a query automatically.
          </Trans>
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button type="button" onClick={onStart}>
          <Search data-icon="inline-start" />
          <Trans>Check exposed passwords</Trans>
        </Button>
      </EmptyContent>
    </Empty>
  )
}

function ExposedLoading({ onCancel }: { onCancel: () => void }): React.JSX.Element {
  return (
    <Empty className="min-h-56" aria-live="polite" aria-busy="true">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Spinner />
        </EmptyMedia>
        <EmptyTitle>
          <Trans>Querying HIBP padded ranges</Trans>
        </EmptyTitle>
        <EmptyDescription>
          <Trans>
            The main process is comparing each complete SHA-1. Passwords and complete hashes never
            leave this device.
          </Trans>
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button variant="outline" type="button" onClick={onCancel}>
          <X data-icon="inline-start" />
          <Trans>Cancel check</Trans>
        </Button>
      </EmptyContent>
    </Empty>
  )
}

function ExposedFailed({ onRetry }: { onRetry: () => void }): React.JSX.Element {
  return (
    <Alert variant="destructive">
      <WifiOff />
      <AlertTitle>
        <Trans>Unable to determine whether any passwords were exposed</Trans>
      </AlertTitle>
      <AlertDescription>
        <Trans>
          The HIBP network request or response validation failed, so this result is unknown.
          BearWarden will not mark any login item as safe because of this failure.
        </Trans>
      </AlertDescription>
      <AlertAction>
        <Button variant="outline" size="sm" type="button" onClick={onRetry}>
          <Trans>Retry</Trans>
        </Button>
      </AlertAction>
    </Alert>
  )
}

function ExposedSuccess({
  report,
  onOpenItem
}: {
  report: VaultHealthExposedReport
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  const protectedSkippedCount = report.totals.protectedSkippedCount
  return (
    <div className="flex flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>
              <Trans>Checked this time</Trans>
            </CardTitle>
            <CardDescription>
              <Trans>Valid login passwords not protected by master password reprompt</Trans>
            </CardDescription>
            <CardAction>
              <Badge variant="secondary">{report.totals.analyzedCount}</Badge>
            </CardAction>
          </CardHeader>
          <CardContent>
            <Trans>The complete SHA-1 is compared only in main-process memory.</Trans>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>
              <Trans>Known breaches found</Trans>
            </CardTitle>
            <CardDescription>
              <Trans>Login items whose complete hash matched an HIBP padded range</Trans>
            </CardDescription>
            <CardAction>
              <Badge variant={report.totals.exposedPasswordCount ? 'destructive' : 'secondary'}>
                {report.totals.exposedPasswordCount}
              </Badge>
            </CardAction>
          </CardHeader>
          <CardContent>
            <Trans>
              Breach counts come from HIBP and do not mean the password is still circulating on a
              specific website.
            </Trans>
          </CardContent>
        </Card>
      </div>

      {protectedSkippedCount > 0 && (
        <Alert>
          <ShieldCheck />
          <AlertTitle>
            <Trans>Protected items were not queried</Trans>
          </AlertTitle>
          <AlertDescription>
            <Plural
              value={protectedSkippedCount}
              one="# login item with master password reprompt enabled was skipped without creating a SHA-1 or sending an HIBP range query."
              other="# login items with master password reprompt enabled were skipped without creating a SHA-1 or sending an HIBP range query."
            />
          </AlertDescription>
        </Alert>
      )}

      {report.exposedPasswords.length ? (
        report.exposedPasswords.map((finding) => (
          <ExposedFindingCard key={finding.id} finding={finding} onOpenItem={onOpenItem} />
        ))
      ) : (
        <Empty className="min-h-56">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <CheckCircle2 />
            </EmptyMedia>
            <EmptyTitle>
              <Trans>No known breaches were found this time</Trans>
            </EmptyTitle>
            <EmptyDescription>
              <Trans>
                The checked complete SHA-1 hashes did not appear in the HIBP response. This is only
                the result of the current query and does not mean the passwords will always be safe.
              </Trans>
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      )}
    </div>
  )
}

function ExposedPasswordPanel({
  state,
  onStart,
  onCancel,
  onOpenItem
}: {
  state: ExposedPasswordCheckState
  onStart: () => void
  onCancel: () => void
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <div className="flex flex-col gap-3">
      <ExposedPrivacyNotice />
      {state.status === 'idle' ? (
        <ExposedIdle onStart={onStart} />
      ) : state.status === 'loading' ? (
        <ExposedLoading onCancel={onCancel} />
      ) : state.status === 'failed' ? (
        <ExposedFailed onRetry={onStart} />
      ) : (
        <ExposedSuccess report={state.report} onOpenItem={onOpenItem} />
      )}
    </div>
  )
}

function HibpWebsiteLink(): React.JSX.Element {
  return (
    <a
      href="https://haveibeenpwned.com/"
      onClick={(event) => {
        event.preventDefault()
        void window.bearwarden.health.openHibpWebsite().catch(() => {
          // Attribution remains visible even if the system browser cannot be opened.
        })
      }}
    >
      <Trans>Have I Been Pwned (HIBP)</Trans>
    </a>
  )
}

function AccountBreachPrivacyNotice(): React.JSX.Element {
  return (
    <Alert>
      <MailSearch />
      <AlertTitle>
        <Trans>Your complete email address will leave this device</Trans>
      </AlertTitle>
      <AlertDescription>
        <Trans>
          BearWarden sends your complete email address to the configured Vaultwarden server only
          after you submit a query. That server then sends it to <HibpWebsiteLink />. This is not a
          k-anonymity password check. Query only accounts you are authorized to check.
        </Trans>
      </AlertDescription>
    </Alert>
  )
}

function isValidAccountBreachEmail(email: string): boolean {
  return email.length > 0 && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
}

function AccountBreachForm({
  email,
  invalid,
  loading,
  onEmailChange,
  onSubmit,
  onCancel
}: {
  email: string
  invalid: boolean
  loading: boolean
  onEmailChange: (value: string) => void
  onSubmit: () => void
  onCancel: () => void
}): React.JSX.Element {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Trans>Search account breaches</Trans>
        </CardTitle>
        <CardDescription>
          <Trans>Enter the email address to query through Vaultwarden and HIBP.</Trans>
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          noValidate
          onSubmit={(event) => {
            event.preventDefault()
            onSubmit()
          }}
        >
          <FieldGroup>
            <Field data-invalid={invalid || undefined} data-disabled={loading || undefined}>
              <FieldLabel htmlFor="account-breach-email">
                <Trans>Email address</Trans>
              </FieldLabel>
              <Input
                id="account-breach-email"
                type="email"
                autoComplete="email"
                maxLength={254}
                value={email}
                aria-invalid={invalid || undefined}
                aria-describedby={invalid ? 'account-breach-email-error' : undefined}
                disabled={loading}
                onChange={(event) => onEmailChange(event.target.value)}
              />
              <FieldDescription>
                <Trans>
                  The complete address is sent only after you select “Search account breaches.”
                </Trans>
              </FieldDescription>
              {invalid && (
                <FieldError id="account-breach-email-error">
                  <Trans>Enter a valid email address with no more than 254 characters.</Trans>
                </FieldError>
              )}
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={loading}>
                {loading ? (
                  <Spinner data-icon="inline-start" />
                ) : (
                  <Search data-icon="inline-start" />
                )}
                <Trans>Search account breaches</Trans>
              </Button>
              {loading && (
                <Button variant="outline" type="button" onClick={onCancel}>
                  <X data-icon="inline-start" />
                  <Trans>Cancel query</Trans>
                </Button>
              )}
            </div>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  )
}

function AccountBreachFindingCard({
  breach
}: {
  breach: VaultHealthAccountBreachFinding
}): React.JSX.Element {
  const { i18n: activeI18n, t } = useLingui()
  const pwnCount = breach.pwnCount
  const breachDate = new Date(`${breach.breachDate}T00:00:00.000Z`).toLocaleDateString(
    activeI18n.locale,
    { timeZone: 'UTC' }
  )
  const addedDate = new Date(breach.addedDate).toLocaleDateString(activeI18n.locale)
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{breach.title}</CardTitle>
        <CardDescription>{breach.domain || breach.name}</CardDescription>
        <CardAction className="flex items-center gap-2">
          <Badge variant={breach.isVerified ? 'secondary' : 'outline'}>
            {breach.isVerified ? t`Verified` : t`Unverified`}
          </Badge>
          <Badge variant="outline">
            <Plural value={pwnCount} one="# account" other="# accounts" />
          </Badge>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <p className="text-muted-foreground text-sm">
          <Trans>
            Breach date: {breachDate}; added to HIBP: {addedDate}
          </Trans>
        </p>
        {breach.dataClasses.length > 0 && (
          <div className="flex flex-wrap gap-2" aria-label={t`Affected data classes`}>
            {breach.dataClasses.map((dataClass, index) => (
              <Badge key={`${dataClass}-${index}`} variant="outline">
                {dataClass}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function AccountBreachResults({
  state
}: {
  state: AccountBreachCheckState
}): React.JSX.Element | null {
  if (state.status === 'idle') return null

  if (state.status === 'loading') {
    return (
      <Alert aria-live="polite" aria-busy="true">
        <Spinner />
        <AlertTitle>
          <Trans>Searching account breaches</Trans>
        </AlertTitle>
        <AlertDescription>
          <Trans>
            The configured Vaultwarden server is forwarding the complete email address to HIBP.
          </Trans>
        </AlertDescription>
      </Alert>
    )
  }

  if (state.status === 'failed') {
    return (
      <Alert variant="destructive">
        <WifiOff />
        <AlertTitle>
          <Trans>Unable to determine whether the account appears in a breach</Trans>
        </AlertTitle>
        <AlertDescription>
          <Trans>
            The Vaultwarden or HIBP network request or response validation failed, so this result is
            unknown. This does not mean the account is safe.
          </Trans>
        </AlertDescription>
      </Alert>
    )
  }

  if (state.status === 'unavailable') {
    return (
      <Alert>
        <ShieldQuestion />
        <AlertTitle>
          <Trans>Vaultwarden does not have an HIBP API key configured</Trans>
        </AlertTitle>
        <AlertDescription>
          <Trans>
            The server returned a notice that its API key is not configured, not a query result. Ask
            the server administrator to configure an HIBP API key and try again.
          </Trans>
        </AlertDescription>
      </Alert>
    )
  }

  const breachCount = state.report.breaches.length

  return breachCount ? (
    <div className="flex flex-col gap-3">
      <Alert>
        <AlertTriangle />
        <AlertTitle>
          <Plural value={breachCount} one="# known breach found" other="# known breaches found" />
        </AlertTitle>
        <AlertDescription>
          <Trans>
            Data provided by <HibpWebsiteLink />. Take action based on the affected data and whether
            the password was reused.
          </Trans>
        </AlertDescription>
      </Alert>
      {state.report.breaches.map((breach) => (
        <AccountBreachFindingCard key={breach.name} breach={breach} />
      ))}
    </div>
  ) : (
    <Empty className="min-h-56">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <CheckCircle2 />
        </EmptyMedia>
        <EmptyTitle>
          <Trans>No known breaches were found this time</Trans>
        </EmptyTitle>
        <EmptyDescription>
          <Trans>
            HIBP returned no known breaches for this account. This is only the result of the current
            query and does not mean the account will always be safe.
          </Trans>
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <p className="text-muted-foreground text-sm">
          <Trans>
            Data source: <HibpWebsiteLink />
          </Trans>
        </p>
      </EmptyContent>
    </Empty>
  )
}

function AccountBreachPanel({
  email,
  invalid,
  state,
  onEmailChange,
  onStart,
  onCancel
}: {
  email: string
  invalid: boolean
  state: AccountBreachCheckState
  onEmailChange: (value: string) => void
  onStart: () => void
  onCancel: () => void
}): React.JSX.Element {
  return (
    <div className="flex flex-col gap-3">
      <AccountBreachPrivacyNotice />
      <AccountBreachForm
        email={email}
        invalid={invalid}
        loading={state.status === 'loading'}
        onEmailChange={onEmailChange}
        onSubmit={onStart}
        onCancel={onCancel}
      />
      <AccountBreachResults state={state} />
    </div>
  )
}

export default function VaultHealthPage({
  revision,
  onOpenItem
}: VaultHealthPageProps): React.JSX.Element {
  const { t } = useLingui()
  const [tab, setTab] = useState<HealthTab>('reused')
  const [report, setReport] = useState<VaultHealthReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const requestIdRef = useRef(0)
  const [exposedState, setExposedState] = useState<ExposedPasswordCheckState>(() =>
    createExposedPasswordIdleState(revision)
  )
  const exposedRequestIdRef = useRef(0)
  const exposedRevisionRef = useRef(revision)
  const exposedRequestActiveRef = useRef(false)
  const [inactiveTwoFactorState, setInactiveTwoFactorState] = useState<InactiveTwoFactorCheckState>(
    () => createInactiveTwoFactorIdleState(revision)
  )
  const inactiveTwoFactorRequestIdRef = useRef(0)
  const inactiveTwoFactorRevisionRef = useRef(revision)
  const [accountBreachEmail, setAccountBreachEmail] = useState('')
  const [accountBreachEmailInvalid, setAccountBreachEmailInvalid] = useState(false)
  const [accountBreachState, setAccountBreachState] = useState<AccountBreachCheckState>(() =>
    createAccountBreachIdleState(revision)
  )
  const accountBreachRequestIdRef = useRef(0)
  const accountBreachRevisionRef = useRef(revision)
  const accountBreachRequestActiveRef = useRef(false)

  const loadReport = useCallback(async (): Promise<void> => {
    const requestId = ++requestIdRef.current
    setLoading(true)
    setFailed(false)
    try {
      const nextReport = await window.bearwarden.health.report()
      if (requestId !== requestIdRef.current) return
      setReport(nextReport)
    } catch {
      if (requestId !== requestIdRef.current) return
      setFailed(true)
    } finally {
      if (requestId === requestIdRef.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    const timeout = window.setTimeout(() => void loadReport(), 0)
    return () => {
      window.clearTimeout(timeout)
      requestIdRef.current += 1
    }
  }, [loadReport, revision])

  const startExposedPasswordCheck = useCallback(async (): Promise<void> => {
    const requestId = ++exposedRequestIdRef.current
    const requestRevision = revision
    exposedRequestActiveRef.current = true
    setExposedState(beginExposedPasswordCheck(requestRevision, requestId))

    try {
      const nextReport = await window.bearwarden.health.exposedPasswords()
      if (requestId !== exposedRequestIdRef.current) return
      exposedRequestActiveRef.current = false
      setExposedState((current) =>
        resolveExposedPasswordCheck(current, requestRevision, requestId, nextReport)
      )
    } catch {
      if (requestId !== exposedRequestIdRef.current) return
      exposedRequestActiveRef.current = false
      setExposedState((current) => failExposedPasswordCheck(current, requestRevision, requestId))
    }
  }, [revision])

  const cancelExposedPasswordRequest = useCallback((): void => {
    const wasActive = exposedRequestActiveRef.current
    exposedRequestActiveRef.current = false
    exposedRequestIdRef.current += 1
    setExposedState(cancelExposedPasswordCheck(revision))
    if (!wasActive) return
    void window.bearwarden.health.cancelExposedPasswords().catch(() => {
      // Cancellation is best effort; stale request IDs keep late responses from reaching the UI.
    })
  }, [revision])

  const startInactiveTwoFactorCheck = useCallback(async (): Promise<void> => {
    const requestId = ++inactiveTwoFactorRequestIdRef.current
    const requestRevision = revision
    setInactiveTwoFactorState({ status: 'loading', revision: requestRevision, requestId })

    try {
      const nextReport = await window.bearwarden.health.inactiveTwoFactor()
      if (requestId !== inactiveTwoFactorRequestIdRef.current) return
      setInactiveTwoFactorState((current) =>
        resolveInactiveTwoFactorCheck(current, requestRevision, requestId, nextReport)
      )
    } catch {
      if (requestId !== inactiveTwoFactorRequestIdRef.current) return
      setInactiveTwoFactorState((current) =>
        failInactiveTwoFactorCheck(current, requestRevision, requestId)
      )
    }
  }, [revision])

  const startAccountBreachCheck = useCallback(async (): Promise<void> => {
    const email = accountBreachEmail.trim().toLowerCase()
    if (!isValidAccountBreachEmail(email)) {
      setAccountBreachEmailInvalid(true)
      return
    }

    setAccountBreachEmail(email)
    setAccountBreachEmailInvalid(false)
    const requestId = ++accountBreachRequestIdRef.current
    const requestRevision = revision
    accountBreachRequestActiveRef.current = true
    setAccountBreachState(beginAccountBreachCheck(requestRevision, requestId, email))

    try {
      const nextReport = await window.bearwarden.health.accountBreaches({ email })
      if (requestId !== accountBreachRequestIdRef.current) return
      accountBreachRequestActiveRef.current = false
      setAccountBreachState((current) =>
        resolveAccountBreachCheck(current, requestRevision, requestId, nextReport)
      )
    } catch {
      if (requestId !== accountBreachRequestIdRef.current) return
      accountBreachRequestActiveRef.current = false
      setAccountBreachState((current) =>
        failAccountBreachCheck(current, requestRevision, requestId)
      )
    }
  }, [accountBreachEmail, revision])

  const cancelAccountBreachRequest = useCallback((): void => {
    const wasActive = accountBreachRequestActiveRef.current
    accountBreachRequestActiveRef.current = false
    accountBreachRequestIdRef.current += 1
    setAccountBreachState(cancelAccountBreachCheck(revision))
    if (!wasActive) return
    void window.bearwarden.health.cancelAccountBreaches().catch(() => {
      // Cancellation is best effort; stale request IDs keep late responses from reaching the UI.
    })
  }, [revision])

  useEffect(() => {
    if (exposedRevisionRef.current === revision) return
    exposedRevisionRef.current = revision
    const wasActive = exposedRequestActiveRef.current
    exposedRequestActiveRef.current = false
    exposedRequestIdRef.current += 1
    if (!wasActive) return
    void window.bearwarden.health.cancelExposedPasswords().catch(() => {
      // A revision change invalidates the renderer state even if the main request already ended.
    })
  }, [revision])

  useEffect(() => {
    if (accountBreachRevisionRef.current === revision) return
    accountBreachRevisionRef.current = revision
    const wasActive = accountBreachRequestActiveRef.current
    accountBreachRequestActiveRef.current = false
    accountBreachRequestIdRef.current += 1
    setAccountBreachState((current) => invalidateAccountBreachCheck(current, revision))
    if (!wasActive) return
    void window.bearwarden.health.cancelAccountBreaches().catch(() => {
      // A revision change invalidates the renderer state even if the main request already ended.
    })
  }, [revision])

  useEffect(() => {
    if (inactiveTwoFactorRevisionRef.current === revision) return
    inactiveTwoFactorRevisionRef.current = revision
    inactiveTwoFactorRequestIdRef.current += 1
    setInactiveTwoFactorState(createInactiveTwoFactorIdleState(revision))
  }, [revision])

  useEffect(
    () => () => {
      if (!exposedRequestActiveRef.current) return
      exposedRequestActiveRef.current = false
      exposedRequestIdRef.current += 1
      void window.bearwarden.health.cancelExposedPasswords().catch(() => {
        // Unmount cancellation must not surface as a failed exposure report.
      })
    },
    []
  )

  useEffect(
    () => () => {
      if (!accountBreachRequestActiveRef.current) return
      accountBreachRequestActiveRef.current = false
      accountBreachRequestIdRef.current += 1
      void window.bearwarden.health.cancelAccountBreaches().catch(() => {
        // Unmount cancellation must not surface as a failed account-breach report.
      })
    },
    []
  )

  const visibleExposedState =
    exposedState.revision === revision ? exposedState : createExposedPasswordIdleState(revision)
  const visibleInactiveTwoFactorState =
    inactiveTwoFactorState.revision === revision
      ? inactiveTwoFactorState
      : createInactiveTwoFactorIdleState(revision)
  const visibleAccountBreachState =
    accountBreachState.revision === revision
      ? accountBreachState
      : createAccountBreachIdleState(revision)
  const protectedSkippedCount = report?.totals.protectedSkippedCount ?? 0

  return (
    <section className="flex min-h-0 flex-1 flex-col" aria-labelledby="health-title">
      <header className="bg-card/80 border-b px-4 py-5 backdrop-blur-sm md:px-6">
        <div className="mx-auto flex w-full max-w-6xl flex-col gap-4 sm:flex-row sm:items-center">
          <div className="flex min-w-0 flex-1 items-center gap-3">
            <span
              className="bg-primary/10 text-primary grid size-11 shrink-0 place-items-center rounded-xl"
              aria-hidden="true"
            >
              <ShieldCheck />
            </span>
            <h1 id="health-title" className="min-w-0 text-2xl font-semibold tracking-tight">
              <Trans>Vault health report</Trans>
            </h1>
          </div>
          <div className="sm:self-center">
            <Button
              variant="outline"
              type="button"
              disabled={loading}
              onClick={() => void loadReport()}
            >
              {loading ? (
                <Spinner data-icon="inline-start" />
              ) : (
                <RefreshCw data-icon="inline-start" />
              )}
              <Trans>Analyze again</Trans>
            </Button>
          </div>
        </div>
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto p-4 md:p-6">
        <div className="mx-auto flex w-full max-w-6xl flex-col gap-5">
          {failed && (
            <Alert variant="destructive">
              <AlertTriangle />
              <AlertTitle>
                <Trans>Unable to generate the health report</Trans>
              </AlertTitle>
              <AlertDescription>
                <Trans>Make sure the vault is still unlocked, then analyze it again.</Trans>
              </AlertDescription>
              <AlertAction>
                <Button variant="outline" size="sm" type="button" onClick={() => void loadReport()}>
                  <Trans>Retry</Trans>
                </Button>
              </AlertAction>
            </Alert>
          )}

          {!report && loading ? (
            <HealthLoading />
          ) : report ? (
            <Tabs
              value={tab}
              orientation="vertical"
              className="grid gap-5 lg:grid-cols-[13rem_minmax(0,1fr)] lg:items-start"
              onValueChange={(value) => setTab(value as HealthTab)}
            >
              <Card size="sm" className="lg:sticky lg:top-0">
                <CardHeader>
                  <CardTitle id="health-checks-title">
                    <Trans>Checks</Trans>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <TabsList
                    variant="line"
                    className="w-full items-stretch gap-1 p-0"
                    aria-labelledby="health-checks-title"
                  >
                    <TabsTrigger
                      value="reused"
                      className="min-h-9 px-2 group-data-vertical/tabs:justify-between"
                    >
                      <Trans>Reused passwords</Trans>
                      <Badge variant="secondary">{report.totals.reusedPasswordCount}</Badge>
                    </TabsTrigger>
                    <TabsTrigger
                      value="weak"
                      className="min-h-9 px-2 group-data-vertical/tabs:justify-between"
                    >
                      <Trans>Weak passwords</Trans>
                      <Badge variant="secondary">{report.totals.weakPasswordCount}</Badge>
                    </TabsTrigger>
                    <TabsTrigger
                      value="unsecured"
                      className="min-h-9 px-2 group-data-vertical/tabs:justify-between"
                    >
                      <Trans>Unsecured websites</Trans>
                      <Badge variant="secondary">{report.totals.unsecuredWebsiteCount}</Badge>
                    </TabsTrigger>
                    <TabsTrigger
                      value="inactive-two-factor"
                      className="min-h-9 px-2 group-data-vertical/tabs:justify-between"
                    >
                      <Trans>Two-factor authentication not enabled</Trans>
                      {visibleInactiveTwoFactorState.status === 'loading' ? (
                        <Spinner />
                      ) : visibleInactiveTwoFactorState.status === 'success' ? (
                        <Badge
                          variant={
                            visibleInactiveTwoFactorState.report.findings.length
                              ? 'destructive'
                              : 'secondary'
                          }
                        >
                          {visibleInactiveTwoFactorState.report.findings.length}
                        </Badge>
                      ) : visibleInactiveTwoFactorState.status === 'failed' ? (
                        <Badge variant="outline">
                          <Trans>Unknown</Trans>
                        </Badge>
                      ) : null}
                    </TabsTrigger>
                    <TabsTrigger
                      value="exposed"
                      className="min-h-9 px-2 group-data-vertical/tabs:justify-between"
                    >
                      <Trans>Exposed passwords</Trans>
                      {visibleExposedState.status === 'loading' ? (
                        <Spinner />
                      ) : visibleExposedState.status === 'success' ? (
                        <Badge
                          variant={
                            visibleExposedState.report.totals.exposedPasswordCount
                              ? 'destructive'
                              : 'secondary'
                          }
                        >
                          {visibleExposedState.report.totals.exposedPasswordCount}
                        </Badge>
                      ) : visibleExposedState.status === 'failed' ? (
                        <Badge variant="outline">
                          <Trans>Unknown</Trans>
                        </Badge>
                      ) : null}
                    </TabsTrigger>
                    <TabsTrigger
                      value="account"
                      className="min-h-9 px-2 group-data-vertical/tabs:justify-between"
                    >
                      <Trans>Account breaches</Trans>
                      {visibleAccountBreachState.status === 'loading' ? (
                        <Spinner />
                      ) : visibleAccountBreachState.status === 'success' ? (
                        <Badge
                          variant={
                            visibleAccountBreachState.report.breaches.length
                              ? 'destructive'
                              : 'secondary'
                          }
                        >
                          {visibleAccountBreachState.report.breaches.length}
                        </Badge>
                      ) : visibleAccountBreachState.status === 'unavailable' ? (
                        <Badge variant="outline">
                          <Trans>Not configured</Trans>
                        </Badge>
                      ) : visibleAccountBreachState.status === 'failed' ? (
                        <Badge variant="outline">
                          <Trans>Unknown</Trans>
                        </Badge>
                      ) : null}
                    </TabsTrigger>
                  </TabsList>
                </CardContent>
              </Card>

              <div className="flex min-w-0 flex-col gap-5">
                {protectedSkippedCount > 0 && (
                  <Alert>
                    <ShieldCheck />
                    <AlertTitle>
                      <Trans>Protected items were not analyzed</Trans>
                    </AlertTitle>
                    <AlertDescription>
                      <Plural
                        value={protectedSkippedCount}
                        one="# login item with master password reprompt enabled was skipped to prevent health labels from revealing characteristics of protected content."
                        other="# login items with master password reprompt enabled were skipped to prevent health labels from revealing characteristics of protected content."
                      />
                    </AlertDescription>
                  </Alert>
                )}

                <TabsContent value="reused" className="grid gap-3 xl:grid-cols-2">
                  <HealthResultsHeader
                    title={t`Login items with reused passwords`}
                    description={t`Create unique passwords for the most frequently reused items first.`}
                    count={report.totals.reusedPasswordCount}
                  />
                  {report.reusedPasswords.length ? (
                    report.reusedPasswords.map((finding) => (
                      <ReusedFindingCard
                        key={finding.id}
                        finding={finding}
                        onOpenItem={onOpenItem}
                      />
                    ))
                  ) : (
                    <HealthEmpty kind="reused" />
                  )}
                </TabsContent>
                <TabsContent value="weak" className="grid gap-3 xl:grid-cols-2">
                  <HealthResultsHeader
                    title={t`Easy-to-guess passwords`}
                    description={t`Use long passwords created by the password generator instead.`}
                    count={report.totals.weakPasswordCount}
                  />
                  {report.weakPasswords.length ? (
                    report.weakPasswords.map((finding) => (
                      <WeakFindingCard key={finding.id} finding={finding} onOpenItem={onOpenItem} />
                    ))
                  ) : (
                    <HealthEmpty kind="weak" />
                  )}
                </TabsContent>
                <TabsContent value="unsecured" className="grid gap-3 xl:grid-cols-2">
                  <HealthResultsHeader
                    title={t`Unencrypted connections`}
                    description={t`Check whether the service offers HTTPS and update the saved website address.`}
                    count={report.totals.unsecuredWebsiteCount}
                  />
                  {report.unsecuredWebsites.length ? (
                    report.unsecuredWebsites.map((finding) => (
                      <UnsecuredWebsiteFindingCard
                        key={finding.id}
                        finding={finding}
                        onOpenItem={onOpenItem}
                      />
                    ))
                  ) : (
                    <HealthEmpty kind="unsecured" />
                  )}
                </TabsContent>
                <TabsContent value="inactive-two-factor">
                  <InactiveTwoFactorPanel
                    state={visibleInactiveTwoFactorState}
                    onStart={() => void startInactiveTwoFactorCheck()}
                    onOpenItem={onOpenItem}
                  />
                </TabsContent>
                <TabsContent value="exposed">
                  <ExposedPasswordPanel
                    state={visibleExposedState}
                    onStart={() => void startExposedPasswordCheck()}
                    onCancel={cancelExposedPasswordRequest}
                    onOpenItem={onOpenItem}
                  />
                </TabsContent>
                <TabsContent value="account">
                  <AccountBreachPanel
                    email={accountBreachEmail}
                    invalid={accountBreachEmailInvalid}
                    state={visibleAccountBreachState}
                    onEmailChange={(value) => {
                      setAccountBreachEmail(value)
                      setAccountBreachEmailInvalid(false)
                    }}
                    onStart={() => void startAccountBreachCheck()}
                    onCancel={cancelAccountBreachRequest}
                  />
                </TabsContent>
              </div>
            </Tabs>
          ) : null}
        </div>
      </div>
    </section>
  )
}
