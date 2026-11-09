import { useEffect, useState } from 'react'
import { useStore } from 'zustand'
import {
  createOrganizationWorkspace,
  type OrganizationWorkspace,
  type OrganizationWorkspaceState
} from '@renderer/stores/organization-workspace'

/** Loads the organization browser on mount and stops every pending write on unmount. */
export function useOrganizationWorkspace(): OrganizationWorkspaceState &
  Omit<OrganizationWorkspace, 'store' | 'dispose'> {
  const [workspace] = useState(() => createOrganizationWorkspace(() => window.bearwarden))
  const state = useStore(workspace.store)
  useEffect(() => {
    void workspace.load()
    return () => workspace.dispose()
  }, [workspace])
  return {
    ...state,
    load: workspace.load,
    selectItem: workspace.selectItem,
    clearSelected: workspace.clearSelected,
    selectOrganization: workspace.selectOrganization,
    selectCollection: workspace.selectCollection
  }
}
