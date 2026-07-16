import { Laptop, RefreshCw } from 'lucide-react'
import { useState } from 'react'
import type { AccountDevicesResult } from '../../../shared/vault-contract'
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from '@renderer/components/ui/dialog'
import { Spinner } from '@renderer/components/ui/spinner'

const deviceTypeNames: Record<number, string> = {
  0: 'Android',
  1: 'iPhone / iPad',
  2: 'Chrome 擴充功能',
  3: 'Firefox 擴充功能',
  4: 'Opera 擴充功能',
  5: 'Edge 擴充功能',
  6: 'Windows 桌面版',
  7: 'macOS 桌面版',
  8: 'Linux 桌面版',
  9: 'Chrome 網頁版',
  10: 'Firefox 網頁版',
  11: 'Opera 網頁版',
  12: 'Edge 網頁版',
  13: 'Internet Explorer 網頁版',
  14: '未知瀏覽器',
  15: 'Android（Amazon）',
  16: 'Windows UWP',
  17: 'Safari 網頁版',
  18: 'Vivaldi 網頁版',
  19: 'Vivaldi 擴充功能',
  20: 'Safari 擴充功能',
  21: 'SDK',
  22: '伺服器',
  23: 'Windows CLI',
  24: 'macOS CLI',
  25: 'Linux CLI',
  26: 'DuckDuckGo 網頁版'
}

function formatDeviceDate(value: string | null): string {
  if (value === null) return '沒有紀錄'
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '日期不可用'
  return new Intl.DateTimeFormat('zh-TW', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date)
}

function AccountDevicesDialog(): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<AccountDevicesResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function load(): Promise<void> {
    setBusy(true)
    setError('')
    try {
      setResult(await window.bearwarden.accountSecurity.devices())
    } catch {
      setResult(null)
      setError('無法讀取帳號裝置，請稍後再試。')
    } finally {
      setBusy(false)
    }
  }

  function changeOpen(next: boolean): void {
    if (busy) return
    setOpen(next)
    setResult(null)
    setError('')
    if (next) void load()
  }

  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger render={<Button variant="outline" size="sm" type="button" />}>
        <Laptop data-icon="inline-start" aria-hidden="true" />
        帳號裝置
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>帳號裝置</DialogTitle>
          <DialogDescription>
            唯讀顯示伺服器上的裝置活動與信任狀態，不會顯示裝置識別碼或網路資訊。
          </DialogDescription>
        </DialogHeader>
        {busy && result === null ? (
          <div className="text-muted-foreground flex items-center gap-2 text-sm" role="status">
            <Spinner aria-hidden="true" />
            正在讀取裝置…
          </div>
        ) : result?.status === 'unavailable' ? (
          <Alert>
            <AlertDescription>目前的伺服器不支援帳號裝置清單。</AlertDescription>
          </Alert>
        ) : result?.status === 'available' && result.devices.length === 0 ? (
          <p className="text-muted-foreground text-sm">伺服器沒有回傳任何帳號裝置。</p>
        ) : result?.status === 'available' ? (
          <div className="grid max-h-[min(60vh,32rem)] gap-3 overflow-y-auto pr-1">
            {result.devices.map((device, index) => (
              <section
                key={`${device.name}-${device.createdAt}-${index}`}
                className="grid gap-3 rounded-lg border p-3"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <h3 className="font-medium">{device.name}</h3>
                    <p className="text-muted-foreground text-sm">
                      {deviceTypeNames[device.type] ?? `未知裝置類型（${device.type}）`}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {device.current && <Badge>此裝置</Badge>}
                    <Badge variant="outline">{device.trusted ? '已信任' : '未信任'}</Badge>
                    {device.pendingAuthRequest && <Badge variant="secondary">待確認</Badge>}
                  </div>
                </div>
                <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
                  <dt className="text-muted-foreground">建立時間</dt>
                  <dd>{formatDeviceDate(device.createdAt)}</dd>
                  <dt className="text-muted-foreground">最近活動</dt>
                  <dd>{formatDeviceDate(device.lastActivityAt)}</dd>
                  <dt className="text-muted-foreground">目前裝置</dt>
                  <dd>{device.current ? '是' : '否'}</dd>
                  <dt className="text-muted-foreground">信任狀態</dt>
                  <dd>{device.trusted ? '已信任' : '未信任'}</dd>
                  <dt className="text-muted-foreground">待處理登入要求</dt>
                  <dd>{device.pendingAuthRequest ? '有' : '無'}</dd>
                </dl>
              </section>
            ))}
          </div>
        ) : null}
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <DialogFooter>
          <Button
            variant="secondary"
            type="button"
            disabled={busy}
            onClick={() => changeOpen(false)}
          >
            關閉
          </Button>
          <Button variant="outline" type="button" disabled={busy} onClick={() => void load()}>
            {busy ? (
              <Spinner data-icon="inline-start" aria-hidden="true" />
            ) : (
              <RefreshCw data-icon="inline-start" aria-hidden="true" />
            )}
            重新整理
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default AccountDevicesDialog
