import { readFile, writeFile } from 'node:fs/promises'

async function replaceOnce(path, source, search, replacement, label) {
  const matches = source.split(search).length - 1
  if (matches !== 1) {
    throw new Error(`${path}: expected exactly one ${label} match, found ${matches}`)
  }
  return source.replace(search, replacement)
}

const vaultPath = 'src/renderer/src/components/VaultShell.tsx'
let vault = await readFile(vaultPath, 'utf8')

vault = await replaceOnce(
  vaultPath,
  vault,
  "import { sortVaultItems, type VaultSortMode } from '@renderer/lib/vault-sort'\n",
  "import { sortVaultItems, type VaultSortMode } from '@renderer/lib/vault-sort'\nimport { useVaultRouteState, type VaultScope } from '@renderer/lib/vault-route-state'\n",
  'route-state import'
)

vault = await replaceOnce(
  vaultPath,
  vault,
  `type Scope =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'recent' }
  | { kind: 'folder'; folderId: string }
  | { kind: 'unfiled' }
  | { kind: 'archive' }
  | { kind: 'trash' }
`,
  'type Scope = VaultScope\n',
  'Scope type'
)

vault = await replaceOnce(
  vaultPath,
  vault,
  `}: VaultShellProps): React.JSX.Element {
  const [folders, setFolders] = useState<FolderView[]>([])
  const [items, setItems] = useState<LoginSummary[]>([])
  const [scope, setScope] = useState<Scope>({ kind: 'all' })
  const [sortMode, setSortMode] = useState<VaultSortMode>('title')
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all')
  const [query, setQuery] = useState('')
`,
  `}: VaultShellProps): React.JSX.Element {
  const {
    scope,
    setScope,
    sortMode,
    setSortMode,
    typeFilter,
    setTypeFilter,
    query,
    setQuery,
    selectedId,
    setSelectedId,
    editorMode,
    setEditorMode,
    settingsOpen,
    setSettingsOpen,
    healthOpen,
    setHealthOpen,
    sendsOpen,
    setSendsOpen,
    organizationsOpen,
    setOrganizationsOpen,
    emergencyAccessOpen,
    setEmergencyAccessOpen
  } = useVaultRouteState()
  const [folders, setFolders] = useState<FolderView[]>([])
  const [items, setItems] = useState<LoginSummary[]>([])
`,
  'primary route state declarations'
)

vault = await replaceOnce(
  vaultPath,
  vault,
  "  const [selectedId, setSelectedId] = useState<string | null>(null)\n",
  '',
  'selectedId state'
)

vault = await replaceOnce(
  vaultPath,
  vault,
  "  const [editorMode, setEditorMode] = useState<'create' | 'edit' | null>(null)\n",
  '',
  'editorMode state'
)

for (const [name, label] of [
  ['settingsOpen', 'settings state'],
  ['healthOpen', 'health state'],
  ['sendsOpen', 'sends state'],
  ['organizationsOpen', 'organizations state'],
  ['emergencyAccessOpen', 'emergency access state']
]) {
  vault = await replaceOnce(
    vaultPath,
    vault,
    `  const [${name}, set${name[0].toUpperCase()}${name.slice(1)}] = useState(false)\n`,
    '',
    label
  )
}

await writeFile(vaultPath, vault)

const appPath = 'src/renderer/src/App.tsx'
let app = await readFile(appPath, 'utf8')
app = await replaceOnce(
  appPath,
  app,
  "    if (pathname !== target) void navigate({ to: target, replace: true })\n",
  "    if (state === 'unlocked' ? !pathname.startsWith('/vault') : pathname !== target) {\n      void navigate({ to: target, replace: true })\n    }\n",
  'nested vault route guard'
)
await writeFile(appPath, app)
