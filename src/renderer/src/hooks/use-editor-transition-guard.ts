import { useCallback, useRef, useState } from 'react'

interface EditorTransitionGuard {
  editorDirty: boolean
  discardEditorDialogOpen: boolean
  handleEditorDirtyChange: (dirty: boolean) => void
  clearEditorDirty: () => void
  isEditorDirty: () => boolean
  requestEditorTransition: (action: () => void) => void
  confirmEditorDiscard: () => void
  handleDiscardEditorDialogOpenChange: (open: boolean) => void
}

/**
 * Keeps the synchronous dirty-state check and deferred editor transition together.
 * The ref mirrors state because navigation and IPC callbacks must observe changes
 * before React commits the next render.
 */
export function useEditorTransitionGuard(): EditorTransitionGuard {
  const [editorDirty, setEditorDirty] = useState(false)
  const [discardEditorDialogOpen, setDiscardEditorDialogOpen] = useState(false)
  const editorDirtyRef = useRef(false)
  const editorTransitionApprovedRef = useRef(false)
  const pendingEditorActionRef = useRef<(() => void) | null>(null)

  const handleEditorDirtyChange = useCallback((dirty: boolean): void => {
    editorDirtyRef.current = dirty
    setEditorDirty(dirty)
  }, [])

  const clearEditorDirty = useCallback((): void => {
    editorDirtyRef.current = false
    setEditorDirty(false)
  }, [])

  const isEditorDirty = useCallback((): boolean => editorDirtyRef.current, [])

  const requestEditorTransition = useCallback((action: () => void): void => {
    if (editorTransitionApprovedRef.current || !editorDirtyRef.current) {
      action()
      return
    }
    pendingEditorActionRef.current = action
    setDiscardEditorDialogOpen(true)
  }, [])

  const confirmEditorDiscard = useCallback((): void => {
    const action = pendingEditorActionRef.current
    pendingEditorActionRef.current = null
    setDiscardEditorDialogOpen(false)
    if (!action) return
    editorTransitionApprovedRef.current = true
    try {
      action()
    } finally {
      editorTransitionApprovedRef.current = false
    }
  }, [])

  const handleDiscardEditorDialogOpenChange = useCallback((open: boolean): void => {
    setDiscardEditorDialogOpen(open)
    if (!open) pendingEditorActionRef.current = null
  }, [])

  return {
    editorDirty,
    discardEditorDialogOpen,
    handleEditorDirtyChange,
    clearEditorDirty,
    isEditorDirty,
    requestEditorTransition,
    confirmEditorDiscard,
    handleDiscardEditorDialogOpenChange
  }
}
