import { useCallback, useRef, useState } from 'react'
import type { LoginView } from '../../../shared/vault-contract'
import { isCardCoverAttachment } from '../components/vault-attachment-ui'

interface CardCoverPreviews {
  previews: ReadonlyMap<string, string>
  clear: () => void
  invalidate: (itemId: string) => void
  prefetch: (login: LoginView) => void
  remember: (login: LoginView, attachmentId: string, dataUrl: string) => void
}

interface CachedCardCoverPreview {
  requestKey: string
  dataUrl: string
}

export function useCardCoverPreviews(): CardCoverPreviews {
  const [previews, setPreviews] = useState<ReadonlyMap<string, string>>(() => new Map())
  const requestsRef = useRef(new Map<string, string>())
  const cacheRef = useRef(new Map<string, CachedCardCoverPreview>())
  const generationRef = useRef(0)

  const clear = useCallback((): void => {
    generationRef.current += 1
    requestsRef.current.clear()
    cacheRef.current.clear()
    setPreviews(new Map())
  }, [])

  const invalidate = useCallback((itemId: string): void => {
    requestsRef.current.delete(itemId)
    cacheRef.current.delete(itemId)
    setPreviews((current) => {
      if (!current.has(itemId)) return current
      const next = new Map(current)
      next.delete(itemId)
      return next
    })
  }, [])

  const prefetch = useCallback((login: LoginView): void => {
    if (
      login.type !== 'card' ||
      login.reprompt !== 0 ||
      login.deletedAt !== null ||
      login.archivedAt !== null
    ) {
      return
    }
    const cover = login.attachments.find((attachment) => isCardCoverAttachment(attachment.fileName))
    if (!cover) return

    const requestKey = `${login.updatedAt}:${cover.id}`
    if (requestsRef.current.get(login.id) === requestKey) return
    const cached = cacheRef.current.get(login.id)
    if (cached?.requestKey === requestKey) {
      setPreviews((current) => {
        if (current.get(login.id) === cached.dataUrl) return current
        const next = new Map(current)
        next.set(login.id, cached.dataUrl)
        return next
      })
      return
    }
    requestsRef.current.set(login.id, requestKey)
    const requestGeneration = generationRef.current

    void window.bearwarden.logins
      .previewAttachment({
        id: login.id,
        attachmentId: cover.id,
        operationId: crypto.randomUUID()
      })
      .then((result) => {
        if (
          requestGeneration !== generationRef.current ||
          requestsRef.current.get(login.id) !== requestKey ||
          !isCardCoverAttachment(result.fileName)
        ) {
          return
        }
        setPreviews((current) => {
          if (current.get(login.id) === result.dataUrl) return current
          const next = new Map(current)
          next.set(login.id, result.dataUrl)
          return next
        })
        cacheRef.current.set(login.id, { requestKey, dataUrl: result.dataUrl })
      })
      .catch(() => {
        if (requestsRef.current.get(login.id) === requestKey) {
          requestsRef.current.delete(login.id)
        }
      })
  }, [])

  const remember = useCallback((login: LoginView, attachmentId: string, dataUrl: string): void => {
    const requestKey = `${login.updatedAt}:${attachmentId}`
    requestsRef.current.set(login.id, requestKey)
    cacheRef.current.set(login.id, { requestKey, dataUrl })
    setPreviews((current) => {
      if (current.get(login.id) === dataUrl) return current
      const next = new Map(current)
      next.set(login.id, dataUrl)
      return next
    })
  }, [])

  return { previews, clear, invalidate, prefetch, remember }
}
