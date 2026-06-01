import { CSSProperties, FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  BadgeCheck,
  Braces,
  CircleDot,
  Copy,
  Database,
  FileText,
  Gauge,
  Globe2,
  Layers3,
  ListFilter,
  LucideIcon,
  Network,
  Plus,
  Power,
  RefreshCw,
  Route,
  Search,
  Settings,
  Shield,
  Trash2,
  Wifi,
} from 'lucide-react'
import { SandfoxService } from '../bindings/sandfox'

type IconComponent = LucideIcon

type Page = 'dashboard' | 'proxies' | 'profiles' | 'policies' | 'dns' | 'rulesets' | 'connections' | 'logs' | 'settings'

type DashboardState = {
  coreRunning: boolean
  uptime: string
  profiles: number
  nodes: number
  policies: number
  dnsRules: number
  ruleSets: number
  upload: number
  download: number
  activeNode: string
  health: { target: string; status: string; delay: number }[]
}

type ProbeItem = {
  target: string
  status: string
  delay: number
}

type Profile = {
  id: string
  name: string
  url: string
  content: string
  nodeCount: number
  selected: boolean
  updateInterval: number
  filter: string
  testUrl: string
  lastError: string
  lastUpdated: string
  nodes: ProxyNode[]
  proxyGroups: ProxyGroupConfig[]
  customGroups: CustomProxyGroup[]
  proxyProviders: ProxyProviderConfig[]
  subscriptionUserinfo: SubscriptionUserinfo | null
  policyOverrides: ProfilePolicyOverride[]
  dnsPolicyOverrides: ProfileDNSPolicyOverride[]
  dnsServerDetours: ProfileDNSServerDetour[]
}

type SubscriptionUserinfo = {
  upload: number
  download: number
  total: number
  expire: number
}

type ProfilePolicyOverride = {
  policyId: string
  outbound: string
}

type ProfileDNSPolicyOverride = {
  policyId: string
  server: string
}

type ProfileDNSServerDetour = {
  serverId: string
  detour: string
}

type ProxyNode = {
  name: string
  type: string
  server: string
  port: number
  country: string
  latency: number
  selected: boolean
  raw: Record<string, unknown>
}

type ProxyGroupConfig = {
  name: string
  type: string
  proxies: string[]
  use: string[]
  url: string
  strategy: string
  interval: number
  tolerance: number
}

type CustomProxyGroup = {
  name: string
  type: string
  outbounds: string[]
  order: number
}

type ProxyProviderConfig = {
  name: string
  type: string
  url: string
  path: string
  interval: number
  filter: string
  healthCheckEnable: boolean
  healthCheckUrl: string
  healthCheckInterval: number
  nodeCount: number
  lastUpdated: string
  lastChecked: string
  lastError: string
  health: ProbeItem[]
}

type Policy = {
  id: string
  type: string
  name: string
  match: string
  domain: string[]
  domainSuffix: string[]
  domainKeyword: string[]
  domainRegex: string[]
  ipCidr: string[]
  sourceIpCidr: string[]
  port: string[]
  portRange: string[]
  sourcePort: string[]
  sourcePortRange: string[]
  processName: string[]
  processPath: string[]
  processPathRegex: string[]
  packageName: string[]
  protocol: string[]
  queryType: string[]
  network: string[]
  networkType: string[]
  defaultInterfaceAddress: string[]
  wifiSsid: string[]
  wifiBssid: string[]
  networkIsExpensive: boolean
  networkIsConstrained: boolean
  ipIsPrivate: boolean
  ruleSet: string[]
  raw_data: Record<string, unknown>
  logical_rule: Record<string, unknown>
  outbound: string
  enabled: boolean
  priority: number
  updatedAt: string
}

type DNSPolicy = {
  id: string
  type?: string
  name?: string
  domain: string
  domainSuffix: string[]
  domainKeyword: string[]
  ruleSet: string[]
  queryType: string[]
  network: string[]
  server: string
  strategy: string
  raw_data?: Record<string, unknown>
  enabled: boolean
}

type DNSServer = {
  id: string
  name?: string
  tag: string
  type: string
  address: string
  server?: string
  server_port?: number
  path?: string
  addressResolver: string
  addressStrategy: string
  detour: string
  strategy: string
  raw_data?: Record<string, unknown>
  upstreams?: string
  use_proxy?: boolean
  bootstrap_addrs?: string
  fallback_addrs?: string
  enabled: boolean
}

type DNSServerRef = {
  source: string
  index: number
  name: string
}

type RuleSet = {
  id: string
  tag: string
  type: string
  format: string
  behavior: string
  url: string
  path: string
  localPath: string
  downloadDetour: string
  enabled: boolean
  profileId: string
  lastUpdated: string
  lastError: string
  lastWarning: string
}

type BuiltinTemplate = {
  id: string
  path?: string
  name: string
  description: string
  policies: Policy[]
  ruleSets: RuleSet[]
  dnsServers: DNSServer[]
  dnsPolicies: DNSPolicy[]
  settings: SettingsState
  settingsRecord?: Record<string, string>
}

type SettingsState = {
  apiPort: number
  apiSecret: string
  mixedPort: number
  mixedListen: string
  allowLan: boolean
  subscriptionUserAgent: string
  ipv6?: boolean | null
  overrideRules?: boolean | null
  autoStartProxy?: boolean | null
  customProxyGroups: boolean
  tunEnabled: boolean
  tunStack: string
  tunInterfaceName: string
  tunAddress: string[]
  tunMTU: number
  tunAutoRoute?: boolean | null
  tunStrictRoute?: boolean | null
  tunAutoDetectInterface?: boolean | null
  tunDNSHijack: string[]
  tunRouteAddress: string[]
  tunRouteExcludeAddress: string[]
  autoStart: boolean
  systemProxy: boolean
  sniffEnabled: boolean
  sniffOverrideDestination: boolean
  mode: string
  logLevel: string
  singBoxPath: string
  dnsListen: string
  dnsStrategy: string
  dnsIPv6?: boolean | null
  dnsFakeIPEnabled: boolean
  dnsFakeIPRange: string
  dnsFakeIPv6Range: string
  dnsFakeIPFilter: string[]
  dnsFallbackFilter: Record<string, unknown>
  finalOutbound: string
  hosts: Record<string, string[]>
  experimental: Record<string, unknown>
}

type LogEntry = {
  id: string
  level: string
  source: string
  message: string
  time: string
}

type Connection = {
  id: string
  host: string
  network: string
  outbound: string
  upload: number
  download: number
  age: string
}

type ProxyGroup = {
  name: string
  type: string
  now: string
  all: ProxyNode[]
  latency: number
}

type AvailableOutbound = {
  tag: string
  type: string
  kind: string
}

type PlatformStatus = {
  os: string
  singBoxPath: string
  singBoxVersion: string
  systemProxy: boolean
  autoStart: boolean
  coreService: boolean
  tunReady: boolean
  dataDir: string
  generatedConfig: string
  platformMessage: string
  needsPrivilege: boolean
  supportedProxyApi: boolean
}

type DatabaseStatus = {
  path: string
  backupDir: string
  schemaVersion: number
  currentVersion: number
  needsMigration: boolean
  profiles: number
  policies: number
  dnsServers: number
  dnsPolicies: number
  ruleSets: number
  preferences: number
  updatedAt: string
}

type CoreServiceStatus = {
  platform: string
  supported: boolean
  socketAvailable?: boolean
  binaryInstalled: boolean
  serviceLoaded: boolean
  running: boolean
  pid?: number
  version?: string
  needsUpgrade?: boolean
  singboxRunning?: boolean
  singboxPid?: number
  singboxStartTime?: number
  servicePath?: string
  message?: string
}

type DNSRuntimeStatus = {
  success: boolean
  data?: {
    running: boolean
    address?: string
    cert_path?: string
  }
  error?: string
}

type SingBoxRuntimeStatus = {
  success: boolean
  data?: {
    running: boolean
    pid?: number
    startTime?: number
    configPath?: string
    binaryPath?: string
  }
  error?: string
  message?: string
}

type LauncherTaskResult = {
  success: boolean
  error?: string
  needsRestart?: boolean
}

type IPInfo = {
  ip: string
  country: string
  countryCode: string
}

type BuildInfo = {
  appVersion: string
  singBoxVersion: string
  buildTime: string
  buildNumber: string
  commitSha: string
}

type ReleaseManifest = {
  version: string
  buildNumber: string
  downloadUrl: string
  releaseUrl: string
  notes: string
  sha256: string
}

type UpdateCheckResult = {
  available: boolean
  currentVersion: string
  latestVersion: string
  manifest: ReleaseManifest
  source: string
  error?: string
}

type ClashProbe = {
  available: boolean
  url: string
  version: string
  message: string
}

type CoreCheckResult = {
  ok: boolean
  path: string
  message: string
}

type ConfigPreview = {
  path: string
  content: string
  changed: boolean
  warnings?: string[]
}

type LogReadResult = {
  lines: string[]
  totalLines: number
  isSearch: boolean
}

type ConfigImportResult = {
  policies: number
  ruleSets: number
  replaced: boolean
}

type RefreshScheduleItem = {
  kind: string
  id: string
  profileId: string
  providerName: string
  name: string
  enabled: boolean
  intervalHours: number
  intervalSeconds: number
  lastUpdated: string
  nextRefresh: string
  due: boolean
  lastError: string
}

const emptyDashboard: DashboardState = {
  coreRunning: false,
  uptime: 'stopped',
  profiles: 0,
  nodes: 0,
  policies: 0,
  dnsRules: 0,
  ruleSets: 0,
  upload: 0,
  download: 0,
  activeNode: 'DIRECT',
  health: [],
}

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: Gauge },
  { id: 'proxies', label: 'Proxies', icon: Network },
  { id: 'profiles', label: 'Profiles', icon: Layers3 },
  { id: 'policies', label: 'Policies', icon: Route },
  { id: 'dns', label: 'DNS', icon: Globe2 },
  { id: 'rulesets', label: 'Rule Sets', icon: ListFilter },
  { id: 'connections', label: 'Connections', icon: Activity },
  { id: 'logs', label: 'Logs', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Settings },
] as const

function App() {
  const [page, setPage] = useState<Page>('dashboard')
  const [dashboard, setDashboard] = useState<DashboardState>(emptyDashboard)
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [proxyGroups, setProxyGroups] = useState<ProxyGroup[]>([])
  const [availableOutbounds, setAvailableOutbounds] = useState<AvailableOutbound[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [templates, setTemplates] = useState<BuiltinTemplate[]>([])
  const [dnsPolicies, setDNSPolicies] = useState<DNSPolicy[]>([])
  const [dnsServers, setDNSServers] = useState<DNSServer[]>([])
  const [ruleSets, setRuleSets] = useState<RuleSet[]>([])
  const [presetRuleSets, setPresetRuleSets] = useState<RuleSet[]>([])
  const [settings, setSettings] = useState<SettingsState | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [connections, setConnections] = useState<Connection[]>([])
  const [platform, setPlatform] = useState<PlatformStatus | null>(null)
  const [toast, setToast] = useState<{ message: string; tone: 'success' | 'error' } | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    const [dash, profileList, proxyGroupList, outboundList, policyList, templateList, dnsList, dnsServerList, ruleSetList, presetRuleSetList, settingValue, logList, connectionList, platformValue] = await Promise.all([
      SandfoxService.GetDashboard(),
      SandfoxService.GetProfiles(),
      SandfoxService.GetProxyGroups(),
      SandfoxService.GetAvailableOutbounds(),
      SandfoxService.GetPolicies(),
      SandfoxService.GetBuiltinTemplates(),
      SandfoxService.GetDNSPolicies(),
      SandfoxService.GetDNSServers(),
      SandfoxService.GetRuleSets(),
      SandfoxService.GetPresetRuleSets(),
      SandfoxService.GetSettings(),
      SandfoxService.GetLogs(),
      SandfoxService.GetConnections(),
      SandfoxService.GetPlatformStatus(),
    ])
    setDashboard(dash as DashboardState)
    setProfiles(profileList as Profile[])
    setProxyGroups(proxyGroupList as ProxyGroup[])
    setAvailableOutbounds(outboundList as AvailableOutbound[])
    setPolicies(policyList as Policy[])
    setTemplates(templateList as BuiltinTemplate[])
    setDNSPolicies(dnsList as DNSPolicy[])
    setDNSServers(dnsServerList as DNSServer[])
    setRuleSets(ruleSetList as RuleSet[])
    setPresetRuleSets(presetRuleSetList as RuleSet[])
    setSettings(settingValue as SettingsState)
    setLogs(logList as LogEntry[])
    setConnections(connectionList as Connection[])
    setPlatform(platformValue as PlatformStatus)
  }, [])

  useEffect(() => {
    refresh().catch((error) => setToast({ message: String(error), tone: 'error' }))
    const id = window.setInterval(() => refresh().catch(() => undefined), 4000)
    return () => window.clearInterval(id)
  }, [refresh])

  const runAction = async (message: string, action: () => Promise<unknown>) => {
    setBusy(true)
    try {
      await action()
      await refresh()
      setToast({ message, tone: 'success' })
    } catch (error) {
      setToast({ message: error instanceof Error ? error.message : String(error), tone: 'error' })
    } finally {
      setBusy(false)
    }
  }

  const copyToast = async () => {
    if (!toast) return
    await navigator.clipboard.writeText(toast.message)
    setToast({ message: 'Message copied', tone: 'success' })
  }

  const startCoreWithServiceCheck = async () => {
    if (settings) {
      await SandfoxService.SaveSettings(settings as never)
    }
    if (settings?.tunEnabled) {
      const status = (await SandfoxService.GetCoreServiceStatus()) as CoreServiceStatus
      if (!status.binaryInstalled) {
        await SandfoxService.InstallCoreService()
      } else if (!status.socketAvailable) {
        await SandfoxService.StartCoreService()
      }
    }
    await SandfoxService.StartCore()
  }

  const activeProfile = profiles.find((profile) => profile.selected)
  const pageTitle = navItems.find((item) => item.id === page)?.label ?? 'Dashboard'

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">S</div>
          <div>
            <strong>Sandfox</strong>
            <span>sing-box console</span>
          </div>
        </div>
        <nav>
          {navItems.map((item) => {
            const Icon = item.icon
            return (
              <button key={item.id} className={page === item.id ? 'nav-item active' : 'nav-item'} onClick={() => setPage(item.id)}>
                <Icon size={18} />
                {item.label}
              </button>
            )
          })}
        </nav>
        <div className="sidebar-card">
          <span className={dashboard.coreRunning ? 'status-dot online' : 'status-dot'} />
          <div>
            <strong>{dashboard.coreRunning ? 'Core online' : 'Core stopped'}</strong>
            <small>{dashboard.uptime}</small>
          </div>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Rover-inspired Wails v3 client</p>
            <h1>{pageTitle}</h1>
          </div>
          <div className="toolbar">
            <button className="button ghost" onClick={refresh}>
              <RefreshCw size={16} />
              Refresh
            </button>
            <button
              className={dashboard.coreRunning ? 'button danger' : 'button primary'}
              disabled={busy}
              onClick={() =>
                runAction(dashboard.coreRunning ? 'Core stopped' : 'Core started', () =>
                  dashboard.coreRunning ? SandfoxService.StopCore() : startCoreWithServiceCheck(),
                )
              }
            >
              <Power size={16} />
              {dashboard.coreRunning ? 'Stop Core' : 'Start Core'}
            </button>
          </div>
        </header>

        {page === 'dashboard' && <DashboardView dashboard={dashboard} activeProfile={activeProfile} />}
        {page === 'proxies' && <ProxiesView groups={proxyGroups} runAction={runAction} />}
        {page === 'profiles' && <ProfilesView profiles={profiles} availableOutbounds={availableOutbounds} runAction={runAction} />}
        {page === 'policies' && <PoliciesView profiles={profiles} policies={policies} templates={templates} availableOutbounds={availableOutbounds} runAction={runAction} />}
        {page === 'dns' && <DNSView profiles={profiles} dnsPolicies={dnsPolicies} dnsServers={dnsServers} availableOutbounds={availableOutbounds} runAction={runAction} />}
        {page === 'rulesets' && <RuleSetsView ruleSets={ruleSets} presetRuleSets={presetRuleSets} availableOutbounds={availableOutbounds} runAction={runAction} />}
        {page === 'connections' && <ConnectionsView connections={connections} runAction={runAction} />}
        {page === 'logs' && <LogsView logs={logs} runAction={runAction} />}
        {page === 'settings' && settings && platform && (
          <SettingsView settings={settings} platform={platform} availableOutbounds={availableOutbounds} setSettings={setSettings} runAction={runAction} />
        )}
        {page === 'settings' && (!settings || !platform) && (
          <section className="panel">
            <PanelTitle icon={Settings} title="Core settings" />
            <EmptyState title="Settings unavailable" detail="Refresh after the desktop service finishes loading." />
          </section>
        )}
      </main>

      {toast && (
        <div className={`toast ${toast.tone}`} role={toast.tone === 'error' ? 'alert' : 'status'}>
          <pre>{toast.message}</pre>
          <div className="toast-actions">
            <button className="button small ghost" onClick={copyToast}>
              <Copy size={14} />
              Copy
            </button>
            <button className="button small ghost" onClick={() => setToast(null)}>Close</button>
          </div>
        </div>
      )}
    </div>
  )
}

function DashboardView({ dashboard, activeProfile }: { dashboard: DashboardState; activeProfile?: Profile }) {
  const cards = [
    ['Profiles', dashboard.profiles, Layers3],
    ['Proxy nodes', dashboard.nodes, Network],
    ['Route rules', dashboard.policies, Route],
    ['DNS rules', dashboard.dnsRules, Globe2],
    ['Rule sets', dashboard.ruleSets, ListFilter],
  ] as const

  return (
    <section className="page-grid">
      <div className="hero-panel">
        <div>
          <p className="eyebrow">Active profile</p>
          <h2>{activeProfile?.name ?? 'No profile imported'}</h2>
          <p>{dashboard.activeNode} routes through mixed port with rule mode and Clash API compatibility.</p>
        </div>
        <div className="hero-orbit">
          <Wifi size={44} />
          <span>{formatBytes(dashboard.download)}/s</span>
        </div>
      </div>
      <div className="metric-grid">
        {cards.map(([label, value, Icon]) => (
          <div className="metric-card" key={label}>
            <Icon size={18} />
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
      <div className="panel wide">
        <PanelTitle icon={Activity} title="Network detection" />
        <div className="health-grid">
          {dashboard.health.map((item) => (
            <div className="health-item" key={item.target}>
              <BadgeCheck size={18} />
              <span>{item.target}</span>
              <strong>{item.delay} ms</strong>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

function ProxiesView({ groups, runAction }: { groups: ProxyGroup[]; runAction: (message: string, action: () => Promise<unknown>) => Promise<void> }) {
  return (
    <section className="panel">
      <PanelTitle icon={Network} title="Proxy groups" action={<SearchBox />} />
      <div className="group-grid">
        {groups.map((group) => (
          <div className="proxy-group" key={group.name}>
            <div className="proxy-group-head">
              <div>
                <strong>{group.name}</strong>
                <span>{group.type} · current {group.now || 'none'}</span>
              </div>
              <b>{group.latency ? `${group.latency} ms` : 'live'}</b>
            </div>
            <div className="node-grid compact">
              {group.all.map((node) => (
                <div className={node.selected || node.name === group.now ? 'node-card selected' : 'node-card'} key={`${group.name}-${node.name}`}>
                  <div>
                    <strong>{node.name}</strong>
                    <span>{node.type} · {node.country}</span>
                  </div>
                  <div className="node-meta">
                    <small>{node.selected || node.name === group.now ? 'Active' : 'Standby'}</small>
                    <b>{node.latency ? `${node.latency} ms` : '-'}</b>
                  </div>
                  <div className="row-actions">
                    <button className="button small ghost" onClick={() => runAction('Proxy selected', () => SandfoxService.SelectProxy(group.name, node.name))}>Use</button>
                    <button className="button small ghost" onClick={() => runAction('Delay tested', () => SandfoxService.GetProxyDelay(node.name, '', 3000))}>Delay</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
        {groups.length === 0 && <EmptyState title="No proxy groups" detail="Start sing-box or import a profile to populate this view." />}
      </div>
    </section>
  )
}

function ProfilesView({
  profiles,
  availableOutbounds,
  runAction,
}: {
  profiles: Profile[]
  availableOutbounds: AvailableOutbound[]
  runAction: (message: string, action: () => Promise<unknown>) => Promise<void>
}) {
  const [name, setName] = useState('')
  const [source, setSource] = useState('')
  const [filePath, setFilePath] = useState('')
  const [contentPreview, setContentPreview] = useState({ title: '', profileId: '', content: '' })
  const [profileDraft, setProfileDraft] = useState({ id: '', name: '', url: '', updateInterval: '24', filter: '', testUrl: '', selected: false })
  const [nodeDraft, setNodeDraft] = useState({ profileId: '', index: '-1', name: '', type: 'vless', server: '', port: '443', raw: '{}' })
  const [groupDraft, setGroupDraft] = useState({ profileId: '', index: '-1', name: '', type: 'select', proxies: '', use: '', url: '', strategy: '', interval: '300', tolerance: '50' })
  const [customGroupDraft, setCustomGroupDraft] = useState({ profileId: '', originalName: '', name: '', type: 'selector', outbounds: '' })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    runAction('Profile imported', () => SandfoxService.ImportProfile(name, source)).then(() => {
      setName('')
      setSource('')
    })
  }
  const startProfileEdit = (profile: Profile) => {
    setProfileDraft({
      id: profile.id,
      name: profile.name,
      url: profile.url,
      updateInterval: String(profile.updateInterval || 24),
      filter: profile.filter || '',
      testUrl: profile.testUrl || '',
      selected: profile.selected,
    })
    setNodeDraft((current) => ({ ...current, profileId: profile.id }))
    setGroupDraft((current) => ({ ...current, profileId: profile.id }))
    setCustomGroupDraft((current) => ({ ...current, profileId: profile.id }))
  }
  const viewProfileContent = (profile: Profile) =>
    runAction('Profile content loaded', async () => {
      const content = await SandfoxService.GetProfileContent(profile.id) as string
      setContentPreview({ title: profile.name, profileId: profile.id, content })
    })
  const viewProviderContent = (profile: Profile, provider: ProxyProviderConfig) =>
    runAction('Provider content loaded', async () => {
      const content = await SandfoxService.GetProxyProviderContent(profile.id, provider.name) as string
      setContentPreview({ title: `${profile.name} / ${provider.name}`, profileId: '', content })
    })
  const saveProfileContent = () =>
    runAction('Profile content saved', async () => {
      if (!contentPreview.profileId) throw new Error('profile content is read-only')
      await SandfoxService.UpdateProfileContent(contentPreview.profileId, contentPreview.content)
    })
  const saveProfileDraft = () => {
    const current = profiles.find((profile) => profile.id === profileDraft.id)
    if (!current) return
    runAction('Profile saved', () =>
      SandfoxService.SaveProfile({
        ...current,
        name: profileDraft.name,
        url: profileDraft.url,
        updateInterval: Number(profileDraft.updateInterval) || 24,
        filter: profileDraft.filter,
        testUrl: profileDraft.testUrl,
        selected: profileDraft.selected,
        subscriptionUserinfo: current.subscriptionUserinfo ?? null,
      }),
    ).then(() => setProfileDraft({ id: '', name: '', url: '', updateInterval: '24', filter: '', testUrl: '', selected: false }))
  }
  const addManualNode = () =>
    runAction('Node added', async () => {
      const targetProfileID = nodeDraft.profileId || profiles.find((profile) => profile.selected)?.id || profiles[0]?.id || ''
      let raw: Record<string, unknown>
      try {
        raw = nodeDraft.raw.trim() ? JSON.parse(nodeDraft.raw) as Record<string, unknown> : {}
      } catch (error) {
        throw new Error(error instanceof Error ? error.message : String(error))
      }
      const payload = {
        name: nodeDraft.name,
        type: nodeDraft.type,
        server: nodeDraft.server,
        port: Number(nodeDraft.port) || 443,
        country: '',
        latency: 0,
        selected: false,
        raw,
      }
      const index = Number(nodeDraft.index)
      if (index >= 0) {
        await SandfoxService.UpdateProfileNode(targetProfileID, index, payload)
      } else {
        await SandfoxService.AddNodeToProfile(targetProfileID, payload)
      }
    }).then(() => setNodeDraft((current) => ({ ...current, index: '-1', name: '', server: '', raw: '{}' })))
  const startNodeEdit = (profile: Profile, index: number, node: ProxyNode) => {
    setNodeDraft({
      profileId: profile.id,
      index: String(index),
      name: node.name,
      type: node.type,
      server: node.server,
      port: String(node.port || 443),
      raw: JSON.stringify(node.raw || {}, null, 2),
    })
  }
  const activeNodeProfile = profiles.find((profile) => profile.id === nodeDraft.profileId) || profiles.find((profile) => profile.selected) || profiles[0]
  const activeGroupProfile = profiles.find((profile) => profile.id === groupDraft.profileId) || profiles.find((profile) => profile.selected) || profiles[0]
  const activeCustomGroupProfile = profiles.find((profile) => profile.id === customGroupDraft.profileId) || profiles.find((profile) => profile.selected) || profiles[0]
  const saveGroupDraft = () =>
    runAction('Proxy group saved', async () => {
      const targetProfileID = groupDraft.profileId || profiles.find((profile) => profile.selected)?.id || profiles[0]?.id || ''
      const payload = {
        name: groupDraft.name,
        type: groupDraft.type,
        proxies: toList(groupDraft.proxies),
        use: toList(groupDraft.use),
        url: groupDraft.url,
        strategy: groupDraft.strategy,
        interval: Number(groupDraft.interval) || 0,
        tolerance: Number(groupDraft.tolerance) || 0,
      }
      const index = Number(groupDraft.index)
      if (index >= 0) {
        await SandfoxService.UpdateProfileGroup(targetProfileID, index, payload)
      } else {
        await SandfoxService.AddProfileGroup(targetProfileID, payload)
      }
    }).then(() => setGroupDraft((current) => ({ ...current, index: '-1', name: '', proxies: '', use: '', url: '', strategy: '' })))
  const startGroupEdit = (profile: Profile, index: number, group: ProxyGroupConfig) => {
    setGroupDraft({
      profileId: profile.id,
      index: String(index),
      name: group.name,
      type: group.type || 'select',
      proxies: (group.proxies || []).join(', '),
      use: (group.use || []).join(', '),
      url: group.url || '',
      strategy: group.strategy || '',
      interval: String(group.interval || 300),
      tolerance: String(group.tolerance || 50),
    })
  }
  const saveCustomGroupDraft = () =>
    runAction('Custom proxy group saved', async () => {
      const targetProfileID = customGroupDraft.profileId || profiles.find((profile) => profile.selected)?.id || profiles[0]?.id || ''
      const payload = {
        name: customGroupDraft.name,
        type: customGroupDraft.type,
        outbounds: toList(customGroupDraft.outbounds),
        order: activeCustomGroupProfile?.customGroups?.length || 0,
      }
      if (customGroupDraft.originalName) {
        await SandfoxService.UpdateProfileCustomGroup(targetProfileID, customGroupDraft.originalName, payload)
      } else {
        await SandfoxService.AddProfileCustomGroup(targetProfileID, payload)
      }
    }).then(() => setCustomGroupDraft((current) => ({ ...current, originalName: '', name: '', outbounds: '' })))
  const startCustomGroupEdit = (profile: Profile, group: CustomProxyGroup) => {
    setCustomGroupDraft({
      profileId: profile.id,
      originalName: group.name,
      name: group.name,
      type: group.type || 'selector',
      outbounds: (group.outbounds || []).join(', '),
    })
  }

  return (
    <section className="two-column">
      <OutboundDatalist id="profile-outbounds" outbounds={availableOutbounds} />
      <form className="panel form-panel" onSubmit={submit}>
        <PanelTitle icon={Plus} title="Import profile" />
        <label>
          Name
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Airport / personal lab" />
        </label>
        <label>
          URL or content
          <textarea value={source} onChange={(event) => setSource(event.target.value)} placeholder="https://... or Clash YAML / base64 links" />
        </label>
        <button className="button primary" type="submit">Import</button>
        <div className="split-line" />
        <label>
          Local file path
          <input value={filePath} onChange={(event) => setFilePath(event.target.value)} placeholder="/path/to/profile.yaml" />
        </label>
        <button
          className="button ghost"
          type="button"
          onClick={() => runAction('Profile file imported', () => SandfoxService.ImportProfileFile(name, filePath)).then(() => setFilePath(''))}
        >
          Import file
        </button>
        {contentPreview.content && (
          <div className="config-preview">
            <PanelTitle
              icon={Braces}
              title={contentPreview.title || 'Profile content'}
              action={
                <div className="row-actions">
                  {contentPreview.profileId && <button className="button small ghost" type="button" onClick={saveProfileContent}>Save content</button>}
                  <button className="button small ghost" type="button" onClick={() => setContentPreview({ title: '', profileId: '', content: '' })}>Close</button>
                </div>
              }
            />
            <textarea value={contentPreview.content} readOnly={!contentPreview.profileId} onChange={(event) => setContentPreview({ ...contentPreview, content: event.target.value })} />
          </div>
        )}
      </form>
      <div className="panel">
        <PanelTitle icon={Database} title="Profiles" />
        <div className="list">
          {profiles.map((profile, index) => (
            <div className="list-row" key={profile.id}>
              <div>
                <strong>{profile.name}</strong>
                <span>{profile.nodeCount} nodes · {(profile.proxyGroups || []).length} groups · {(profile.proxyProviders || []).length} providers · {profileUsageText(profile)} · {profile.lastError ? `error: ${profile.lastError}` : formatDate(profile.lastUpdated)}</span>
              </div>
              <div className="row-actions">
                <button className="button small ghost" onClick={() => runAction('Profile selected', () => SandfoxService.SelectProfile(profile.id))}>
                  {profile.selected ? 'Selected' : 'Select'}
                </button>
                <button className="button small ghost" onClick={() => startProfileEdit(profile)}>Edit</button>
                <button className="button small ghost" onClick={() => runAction('Profiles reordered', () => SandfoxService.ReorderProfiles(movedIDs(profiles, index, -1)))}>Up</button>
                <button className="button small ghost" onClick={() => runAction('Profiles reordered', () => SandfoxService.ReorderProfiles(movedIDs(profiles, index, 1)))}>Down</button>
                <button className="button small ghost" onClick={() => runAction('Profile refreshed', () => SandfoxService.RefreshProfile(profile.id))}>Refresh</button>
                {(profile.proxyProviders || []).length > 0 && (
                  <button className="button small ghost" onClick={() => runAction('Profile providers refreshed', () => SandfoxService.RefreshProfileProviders(profile.id))}>Providers</button>
                )}
                <button className="button small ghost" onClick={() => viewProfileContent(profile)}>View</button>
                <button className="icon-button" onClick={() => runAction('Profile deleted', () => SandfoxService.DeleteProfile(profile.id))}>
                  <Trash2 size={16} />
                </button>
              </div>
            </div>
          ))}
        </div>
        <div className="split-line" />
        <div className="profile-tools">
          <PanelTitle icon={Settings} title="Profile settings" />
          <input value={profileDraft.name} placeholder="Name" onChange={(event) => setProfileDraft({ ...profileDraft, name: event.target.value })} />
          <input value={profileDraft.url} placeholder="Remote subscription URL" onChange={(event) => setProfileDraft({ ...profileDraft, url: event.target.value })} />
          <input value={profileDraft.updateInterval} placeholder="Update interval hours" onChange={(event) => setProfileDraft({ ...profileDraft, updateInterval: event.target.value })} />
          <input value={profileDraft.filter} placeholder="Provider filter regex" onChange={(event) => setProfileDraft({ ...profileDraft, filter: event.target.value })} />
          <input value={profileDraft.testUrl} placeholder="Delay test URL" onChange={(event) => setProfileDraft({ ...profileDraft, testUrl: event.target.value })} />
          <button className="button ghost" disabled={!profileDraft.id} onClick={() => setProfileDraft({ ...profileDraft, selected: !profileDraft.selected })}>
            {profileDraft.selected ? 'Selected on save' : 'Keep selection'}
          </button>
          <button className="button primary" disabled={!profileDraft.id} onClick={saveProfileDraft}>Save profile</button>
        </div>
        <div className="split-line" />
        <div className="profile-tools">
          <PanelTitle
            icon={Network}
            title="Manual node"
            action={
              <div className="row-actions">
                <button className="button small ghost" disabled={!activeNodeProfile} onClick={() => activeNodeProfile && runAction('Node delays tested', () => SandfoxService.TestProfileNodes(activeNodeProfile.id, activeNodeProfile.testUrl || '', 3000))}>Test delays</button>
                <button className="button small ghost" disabled={!activeNodeProfile} onClick={() => activeNodeProfile && runAction('Nodes sorted', () => SandfoxService.SortProfileNodesByLatency(activeNodeProfile.id))}>Sort latency</button>
              </div>
            }
          />
          <select value={nodeDraft.profileId} onChange={(event) => setNodeDraft({ ...nodeDraft, profileId: event.target.value })}>
            <option value="">Selected profile</option>
            {profiles.map((profile) => <option value={profile.id} key={profile.id}>{profile.name}</option>)}
          </select>
          <input value={nodeDraft.name} placeholder="Node name" onChange={(event) => setNodeDraft({ ...nodeDraft, name: event.target.value })} />
          <select value={nodeDraft.type} onChange={(event) => setNodeDraft({ ...nodeDraft, type: event.target.value })}>
            <option value="vless">vless</option>
            <option value="vmess">vmess</option>
            <option value="trojan">trojan</option>
            <option value="shadowsocks">shadowsocks</option>
            <option value="hysteria2">hysteria2</option>
            <option value="tuic">tuic</option>
            <option value="socks">socks</option>
            <option value="http">http</option>
          </select>
          <input value={nodeDraft.server} placeholder="Server" onChange={(event) => setNodeDraft({ ...nodeDraft, server: event.target.value })} />
          <input value={nodeDraft.port} placeholder="Port" onChange={(event) => setNodeDraft({ ...nodeDraft, port: event.target.value })} />
          <textarea value={nodeDraft.raw} placeholder='Raw JSON, e.g. {"uuid":"...","tls":true}' onChange={(event) => setNodeDraft({ ...nodeDraft, raw: event.target.value })} />
          <button className="button primary" onClick={addManualNode}>{Number(nodeDraft.index) >= 0 ? 'Update node' : 'Add node'}</button>
          <div className="node-edit-list">
            {(activeNodeProfile?.nodes || []).map((node, index) => (
              <div className="logical-rule-item" key={`${activeNodeProfile?.id}-${index}-${node.name}`}>
                <code>{node.name} · {node.type} · {node.server}:{node.port} · {node.latency || '-'}ms</code>
                <div className="row-actions">
                  <button className="button small ghost" onClick={() => activeNodeProfile && startNodeEdit(activeNodeProfile, index, node)}>Edit</button>
                  <button className="button small ghost" onClick={() => activeNodeProfile && runAction('Node moved', () => SandfoxService.MoveProfileNode(activeNodeProfile.id, index, -1))}>Up</button>
                  <button className="button small ghost" onClick={() => activeNodeProfile && runAction('Node moved', () => SandfoxService.MoveProfileNode(activeNodeProfile.id, index, 1))}>Down</button>
                  <button className="icon-button" onClick={() => activeNodeProfile && runAction('Node deleted', () => SandfoxService.DeleteProfileNode(activeNodeProfile.id, index))}><Trash2 size={16} /></button>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="split-line" />
        <div className="profile-tools">
          <PanelTitle icon={Layers3} title="Proxy groups" action={<span className="hint">Members can reference nodes, groups, DIRECT, REJECT, or providers via use</span>} />
          <select value={groupDraft.profileId} onChange={(event) => setGroupDraft({ ...groupDraft, profileId: event.target.value })}>
            <option value="">Selected profile</option>
            {profiles.map((profile) => <option value={profile.id} key={profile.id}>{profile.name}</option>)}
          </select>
          <input value={groupDraft.name} placeholder="Group name" onChange={(event) => setGroupDraft({ ...groupDraft, name: event.target.value })} />
          <select value={groupDraft.type} onChange={(event) => setGroupDraft({ ...groupDraft, type: event.target.value })}>
            <option value="select">select</option>
            <option value="url-test">url-test</option>
            <option value="fallback">fallback</option>
            <option value="load-balance">load-balance</option>
          </select>
          <input list="profile-outbounds" value={groupDraft.proxies} placeholder="node-a, node-b, DIRECT" onChange={(event) => setGroupDraft({ ...groupDraft, proxies: event.target.value })} />
          <input value={groupDraft.use} placeholder="Provider use: provider-a, provider-b" onChange={(event) => setGroupDraft({ ...groupDraft, use: event.target.value })} />
          <input value={groupDraft.url} placeholder="Health check URL" onChange={(event) => setGroupDraft({ ...groupDraft, url: event.target.value })} />
          <input value={groupDraft.strategy} placeholder="Load-balance strategy" onChange={(event) => setGroupDraft({ ...groupDraft, strategy: event.target.value })} />
          <input value={groupDraft.interval} placeholder="Interval seconds" onChange={(event) => setGroupDraft({ ...groupDraft, interval: event.target.value })} />
          <input value={groupDraft.tolerance} placeholder="Tolerance" onChange={(event) => setGroupDraft({ ...groupDraft, tolerance: event.target.value })} />
          <button className="button primary" disabled={!activeGroupProfile} onClick={saveGroupDraft}>{Number(groupDraft.index) >= 0 ? 'Update group' : 'Add group'}</button>
          <div className="node-edit-list">
            {(activeGroupProfile?.proxyGroups || []).map((group, index) => (
              <div className="logical-rule-item" key={`${activeGroupProfile?.id}-${index}-${group.name}`}>
                <code>{group.name} · {group.type} · {(group.proxies || []).join(', ') || 'DIRECT'}{(group.use || []).length ? ` · use ${(group.use || []).join(', ')}` : ''}</code>
                <div className="row-actions">
                  <button className="button small ghost" onClick={() => activeGroupProfile && startGroupEdit(activeGroupProfile, index, group)}>Edit</button>
                  <button className="button small ghost" onClick={() => activeGroupProfile && runAction('Proxy group moved', () => SandfoxService.MoveProfileGroup(activeGroupProfile.id, index, -1))}>Up</button>
                  <button className="button small ghost" onClick={() => activeGroupProfile && runAction('Proxy group moved', () => SandfoxService.MoveProfileGroup(activeGroupProfile.id, index, 1))}>Down</button>
                  <button className="icon-button" onClick={() => activeGroupProfile && runAction('Proxy group deleted', () => SandfoxService.DeleteProfileGroup(activeGroupProfile.id, index))}><Trash2 size={16} /></button>
                </div>
              </div>
            ))}
          </div>
          <div className="split-line" />
          <PanelTitle icon={Layers3} title="Custom proxy groups" action={<span className="hint">Used when customProxyGroups is enabled</span>} />
          <select value={customGroupDraft.profileId} onChange={(event) => setCustomGroupDraft({ ...customGroupDraft, profileId: event.target.value })}>
            <option value="">Selected profile</option>
            {profiles.map((profile) => <option value={profile.id} key={profile.id}>{profile.name}</option>)}
          </select>
          <input value={customGroupDraft.name} placeholder="Custom group name" onChange={(event) => setCustomGroupDraft({ ...customGroupDraft, name: event.target.value })} />
          <select value={customGroupDraft.type} onChange={(event) => setCustomGroupDraft({ ...customGroupDraft, type: event.target.value })}>
            <option value="selector">selector</option>
            <option value="urltest">urltest</option>
          </select>
          <input list="profile-outbounds" value={customGroupDraft.outbounds} placeholder="node-a, node-b" onChange={(event) => setCustomGroupDraft({ ...customGroupDraft, outbounds: event.target.value })} />
          <button className="button primary" disabled={!activeCustomGroupProfile} onClick={saveCustomGroupDraft}>{customGroupDraft.originalName ? 'Update custom group' : 'Add custom group'}</button>
          <div className="node-edit-list">
            {(activeCustomGroupProfile?.customGroups || []).map((group, index) => (
              <div className="logical-rule-item" key={`${activeCustomGroupProfile?.id}-custom-${group.name}`}>
                <code>{group.name} · {group.type} · {(group.outbounds || []).join(', ') || 'No nodes'}</code>
                <div className="row-actions">
                  <button className="button small ghost" onClick={() => activeCustomGroupProfile && startCustomGroupEdit(activeCustomGroupProfile, group)}>Edit</button>
                  <button className="button small ghost" onClick={() => activeCustomGroupProfile && runAction('Custom proxy groups reordered', () => SandfoxService.UpdateProfileCustomGroupsOrder(activeCustomGroupProfile.id, movedCustomGroupOrders(activeCustomGroupProfile.customGroups || [], index, -1)))}>Up</button>
                  <button className="button small ghost" onClick={() => activeCustomGroupProfile && runAction('Custom proxy groups reordered', () => SandfoxService.UpdateProfileCustomGroupsOrder(activeCustomGroupProfile.id, movedCustomGroupOrders(activeCustomGroupProfile.customGroups || [], index, 1)))}>Down</button>
                  <button className="icon-button" onClick={() => activeCustomGroupProfile && runAction('Custom proxy group deleted', () => SandfoxService.DeleteProfileCustomGroup(activeCustomGroupProfile.id, group.name))}><Trash2 size={16} /></button>
                </div>
              </div>
            ))}
          </div>
          {(activeCustomGroupProfile?.customGroups || []).length > 0 && (
            <button className="button ghost" onClick={() => activeCustomGroupProfile && runAction('Custom proxy groups cleared', () => SandfoxService.ClearProfileCustomGroups(activeCustomGroupProfile.id))}>Clear custom groups</button>
          )}
          {(activeGroupProfile?.proxyProviders || []).length > 0 && (
            <div className="node-edit-list">
              {(activeGroupProfile?.proxyProviders || []).map((provider) => (
                <div className="logical-rule-item" key={`${activeGroupProfile?.id}-provider-${provider.name}`}>
                  <code>{provider.name} · {provider.type} · {provider.nodeCount} nodes{provider.health?.length ? ` · ${provider.health.length} checked` : ''}{provider.lastError ? ` · error: ${provider.lastError}` : ''}</code>
                  <div className="row-actions">
                    <button className="button small ghost" onClick={() => activeGroupProfile && runAction('Provider tested', () => SandfoxService.TestProfileProvider(activeGroupProfile.id, provider.name, 3000))}>Test</button>
                    <button className="button small ghost" onClick={() => activeGroupProfile && runAction('Provider refreshed', () => SandfoxService.RefreshProfileProvider(activeGroupProfile.id, provider.name))}>Refresh</button>
                    <button className="button small ghost" onClick={() => activeGroupProfile && viewProviderContent(activeGroupProfile, provider)}>View</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

function PoliciesView({
  profiles,
  policies,
  templates,
  availableOutbounds,
  runAction,
}: {
  profiles: Profile[]
  policies: Policy[]
  templates: BuiltinTemplate[]
  availableOutbounds: AvailableOutbound[]
  runAction: (message: string, action: () => Promise<unknown>) => Promise<void>
}) {
  const selectedProfile = profiles.find((profile) => profile.selected) || profiles[0]
  const [overrideDraft, setOverrideDraft] = useState({ policyId: '', outbound: '' })
  const [draft, setDraft] = useState({
    name: '',
    domain: '',
    domainSuffix: '',
    domainKeyword: '',
    domainRegex: '',
    ipCidr: '',
    sourceIpCidr: '',
    port: '',
    portRange: '',
    sourcePort: '',
    sourcePortRange: '',
    processName: '',
    processPath: '',
    processPathRegex: '',
    packageName: '',
    protocol: '',
    queryType: '',
    network: '',
    networkType: '',
    defaultInterfaceAddress: '',
    wifiSsid: '',
    wifiBssid: '',
    ruleSet: '',
    outbound: 'DIRECT',
  })
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [policyJson, setPolicyJson] = useState('')
  const [policyJsonError, setPolicyJsonError] = useState('')
  const [logicalDraft, setLogicalDraft] = useState({ mode: 'and', field: 'domain_suffix', values: '' })
  const [logicalGroupDraft, setLogicalGroupDraft] = useState({ mode: 'and', invert: false })
  const [rawActionDraft, setRawActionDraft] = useState({ action: 'sniff', field: 'protocol', values: 'tls,http' })
  const createAdvancedPolicy = () => {
    const policy = completePolicyForSave({
      id: '',
      type: 'default',
      name: `Advanced policy ${policies.length + 1}`,
      outbound: 'DIRECT',
      enabled: true,
      priority: policies.length + 1,
      updatedAt: '',
    })
    setSelectedPolicy(policy)
    setPolicyJson(JSON.stringify(policy, null, 2))
    setPolicyJsonError('')
    setLogicalDraft((current) => ({ ...current, mode: 'and' }))
  }
  const startPolicyEdit = (policy: Policy) => {
    setSelectedPolicy(policy)
    setPolicyJson(JSON.stringify(policy, null, 2))
    setPolicyJsonError('')
    const mode = typeof policy.logical_rule?.mode === 'string' ? policy.logical_rule.mode : 'and'
    setLogicalDraft((current) => ({ ...current, mode }))
  }
  const savePolicyJson = () => {
    let parsed: Partial<Policy>
    try {
      parsed = JSON.parse(policyJson) as Partial<Policy>
      setPolicyJsonError('')
    } catch (error) {
      setPolicyJsonError(error instanceof Error ? error.message : String(error))
      return
    }
    runAction('Policy updated', () => SandfoxService.SavePolicy(completePolicyForSave(parsed, selectedPolicy))).then(() => {
      setSelectedPolicy(null)
      setPolicyJson('')
    })
  }
  const logicalPreview = useMemo(() => {
    if (!selectedPolicy || !policyJson) return logicalGroup({}, logicalDraft.mode)
    try {
      const policy = completePolicyForSave(JSON.parse(policyJson) as Partial<Policy>, selectedPolicy)
      const logical = policy.logical_rule && typeof policy.logical_rule === 'object' ? policy.logical_rule : {}
      return logicalGroup(logical, logicalDraft.mode)
    } catch {
      return logicalGroup({}, logicalDraft.mode)
    }
  }, [logicalDraft.mode, policyJson, selectedPolicy])
  const updatePolicyJson = (mutate: (policy: Policy) => void) => {
    if (!selectedPolicy) return
    let parsed: Partial<Policy>
    try {
      parsed = JSON.parse(policyJson || '{}') as Partial<Policy>
      setPolicyJsonError('')
    } catch (error) {
      setPolicyJsonError(error instanceof Error ? error.message : String(error))
      return
    }
    const next = completePolicyForSave(parsed, selectedPolicy)
    mutate(next)
    setPolicyJson(JSON.stringify(next, null, 2))
  }
  const logicalMatcherFromDraft = () => {
    const rawValues = toList(logicalDraft.values)
    const values = ['port', 'source_port'].includes(logicalDraft.field) ? rawValues.map(Number).filter((value) => Number.isFinite(value)) : rawValues
    if (values.length === 0) return null
    return { [logicalDraft.field]: values }
  }
  const addLogicalMatcher = () => {
    const matcher = logicalMatcherFromDraft()
    if (!selectedPolicy || !matcher) return
    addLogicalRuleAtPath([], matcher)
    setLogicalDraft((current) => ({ ...current, values: '' }))
  }
  const setLogicalMode = (mode: string) => {
    setLogicalDraft((current) => ({ ...current, mode }))
    setLogicalGroupModeAtPath([], mode)
  }
  const addLogicalGroup = () => {
    const matcher = logicalMatcherFromDraft()
    if (!selectedPolicy || !matcher) return
    addLogicalRuleAtPath([], logicalGroup({ mode: logicalGroupDraft.mode, invert: logicalGroupDraft.invert, rules: [matcher] }))
    setLogicalDraft((current) => ({ ...current, values: '' }))
  }
  const addLogicalRuleAtPath = (path: number[], rule: Record<string, unknown>) => {
    updatePolicyJson((next) => {
      const root = logicalGroup(next.logical_rule, logicalDraft.mode)
      next.logical_rule = appendLogicalRuleAtPath(root, path, rule)
    })
  }
  const addMatcherToLogicalGroup = (path: number[]) => {
    const matcher = logicalMatcherFromDraft()
    if (!selectedPolicy || !matcher) return
    addLogicalRuleAtPath(path, matcher)
    setLogicalDraft((current) => ({ ...current, values: '' }))
  }
  const addGroupToLogicalGroup = (path: number[]) => {
    addLogicalRuleAtPath(path, logicalGroup({ mode: logicalGroupDraft.mode, invert: logicalGroupDraft.invert, rules: [] }))
  }
  const removeLogicalRuleAtPath = (path: number[]) => {
    updatePolicyJson((next) => {
      const root = logicalGroup(next.logical_rule, logicalDraft.mode)
      next.logical_rule = removeLogicalRuleAtPathInGroup(root, path)
    })
  }
  const moveLogicalRuleAtPath = (path: number[], direction: number) => {
    updatePolicyJson((next) => {
      const root = logicalGroup(next.logical_rule, logicalDraft.mode)
      next.logical_rule = moveLogicalRuleAtPathInGroup(root, path, direction)
    })
  }
  const setLogicalGroupModeAtPath = (path: number[], mode: string) => {
    updatePolicyJson((next) => {
      const root = logicalGroup(next.logical_rule, logicalDraft.mode)
      next.logical_rule = updateLogicalGroupAtPath(root, path, (group) => ({ ...logicalGroup(group, mode), mode }))
    })
  }
  const toggleLogicalInvert = () => {
    toggleLogicalGroupInvertAtPath([])
  }
  const toggleLogicalGroupInvertAtPath = (path: number[]) => {
    updatePolicyJson((next) => {
      const root = logicalGroup(next.logical_rule, logicalDraft.mode)
      next.logical_rule = updateLogicalGroupAtPath(root, path, (group) => ({ ...logicalGroup(group, logicalDraft.mode), invert: group.invert !== true }))
    })
  }
  const setRawActionRule = () => {
    if (!selectedPolicy) return
    const rawValues = toList(rawActionDraft.values)
    const values = ['port', 'source_port'].includes(rawActionDraft.field) ? rawValues.map(Number).filter((value) => Number.isFinite(value)) : rawValues
    updatePolicyJson((next) => {
      const rawData: Record<string, unknown> = { action: rawActionDraft.action }
      if (values.length > 0) {
        rawData[rawActionDraft.field] = values
      }
      next.type = 'raw'
      next.raw_data = rawData
      next.logical_rule = {}
      next.outbound = ''
    })
  }
  return (
    <section className="panel">
      <OutboundDatalist id="policy-outbounds" outbounds={availableOutbounds} />
      <PanelTitle icon={Route} title="Route policies" action={<span className="hint">Comma separated fields generate native sing-box rules</span>} />
      <div className="template-strip">
        {templates.map((template) => (
          <div className="template-card" key={template.id}>
            <strong>{template.name}</strong>
            <span>{template.description}</span>
            <span>{template.policies.length} policies · {template.ruleSets.length} rule sets · {(template.dnsPolicies || []).length} DNS policies</span>
            <div className="row-actions">
              <button className="button small ghost" onClick={() => runAction('Template appended', () => SandfoxService.ApplyBuiltinTemplate(template.id, false))}>Append</button>
              <button className="button small ghost" onClick={() => runAction('Template applied', () => SandfoxService.ApplyBuiltinTemplate(template.id, true))}>Replace</button>
              <button className="button small ghost" onClick={() => runAction('Template fully imported', () => SandfoxService.ImportTemplateComplete(template.path || `builtin/${template.id}`))}>Complete</button>
            </div>
          </div>
        ))}
      </div>
      <div className="policy-editor">
        {[
          ['name', 'Policy name'],
          ['domain', 'Domain'],
          ['domainSuffix', 'Domain suffix'],
          ['domainKeyword', 'Domain keyword'],
          ['domainRegex', 'Domain regex'],
          ['ipCidr', 'IP CIDR'],
          ['sourceIpCidr', 'Source IP CIDR'],
          ['port', 'Port'],
          ['portRange', 'Port range'],
          ['sourcePort', 'Source port'],
          ['sourcePortRange', 'Source port range'],
          ['processName', 'Process name'],
          ['processPath', 'Process path'],
          ['processPathRegex', 'Process path regex'],
          ['packageName', 'Package name'],
          ['protocol', 'Protocol'],
          ['queryType', 'Query type'],
          ['network', 'Network'],
          ['networkType', 'Network type'],
          ['defaultInterfaceAddress', 'Default interface address'],
          ['wifiSsid', 'WiFi SSID'],
          ['wifiBssid', 'WiFi BSSID'],
          ['ruleSet', 'Rule set tags'],
          ['outbound', 'Outbound'],
        ].map(([key, label]) => (
          <label key={key}>
            {label}
            <input list={key === 'outbound' ? 'policy-outbounds' : undefined} value={draft[key as keyof typeof draft]} onChange={(event) => setDraft({ ...draft, [key]: event.target.value })} />
          </label>
        ))}
        <button
          className="button primary"
          onClick={() =>
            runAction('Policy saved', () =>
              SandfoxService.SavePolicy({
                id: '',
                type: 'default',
                name: draft.name,
                match: draft.domainSuffix,
                domain: toList(draft.domain),
                domainSuffix: toList(draft.domainSuffix),
                domainKeyword: toList(draft.domainKeyword),
                domainRegex: toList(draft.domainRegex),
                ipCidr: toList(draft.ipCidr),
                sourceIpCidr: toList(draft.sourceIpCidr),
                port: toList(draft.port),
                portRange: toList(draft.portRange),
                sourcePort: toList(draft.sourcePort),
                sourcePortRange: toList(draft.sourcePortRange),
                processName: toList(draft.processName),
                processPath: toList(draft.processPath),
                processPathRegex: toList(draft.processPathRegex),
                packageName: toList(draft.packageName),
                protocol: toList(draft.protocol),
                queryType: toList(draft.queryType),
                network: toList(draft.network),
                networkType: toList(draft.networkType),
                defaultInterfaceAddress: toList(draft.defaultInterfaceAddress),
                wifiSsid: toList(draft.wifiSsid),
                wifiBssid: toList(draft.wifiBssid),
                networkIsExpensive: false,
                networkIsConstrained: false,
                ipIsPrivate: false,
                ruleSet: toList(draft.ruleSet),
                raw_data: {},
                logical_rule: {},
                outbound: draft.outbound,
                enabled: true,
                priority: policies.length + 1,
                updatedAt: '',
              }),
            ).then(() =>
              setDraft({
                name: '',
                domain: '',
                domainSuffix: '',
                domainKeyword: '',
                domainRegex: '',
                ipCidr: '',
                sourceIpCidr: '',
                port: '',
                portRange: '',
                sourcePort: '',
                sourcePortRange: '',
                processName: '',
                processPath: '',
                processPathRegex: '',
                packageName: '',
                protocol: '',
                queryType: '',
                network: '',
                networkType: '',
                defaultInterfaceAddress: '',
                wifiSsid: '',
                wifiBssid: '',
                ruleSet: '',
                outbound: 'DIRECT',
              }),
            )
          }
        >
          Add policy
        </button>
      </div>
      <Table
        columns={['Name', 'Match', 'Outbound', 'Profile override', 'State', '']}
        rows={policies.map((policy, index) => [
          policy.name,
          policySummary(policy),
          policy.outbound,
          <div className="row-actions">
            <input
              list="policy-outbounds"
              value={overrideDraft.policyId === policy.id ? overrideDraft.outbound : (selectedProfile?.policyOverrides || []).find((override) => override.policyId === policy.id)?.outbound || ''}
              placeholder={selectedProfile ? 'profile outbound' : 'no profile'}
              disabled={!selectedProfile}
              onChange={(event) => setOverrideDraft({ policyId: policy.id, outbound: event.target.value })}
            />
            <button className="button small ghost" disabled={!selectedProfile} onClick={() => selectedProfile && runAction('Policy override saved', () => SandfoxService.SetProfilePolicyOverride(selectedProfile.id, policy.id, overrideDraft.policyId === policy.id ? overrideDraft.outbound : policy.outbound))}>Set</button>
            <button className="button small ghost" disabled={!selectedProfile} onClick={() => selectedProfile && runAction('Policy override cleared', () => SandfoxService.ClearProfilePolicyOverride(selectedProfile.id, policy.id))}>Clear</button>
          </div>,
          policy.enabled ? 'Enabled' : 'Disabled',
          <div className="row-actions">
            <button className="button small ghost" onClick={() => startPolicyEdit(policy)}>Edit</button>
            <button className="button small ghost" onClick={() => runAction('Policies reordered', () => SandfoxService.ReorderPolicies(movedIDs(policies, index, -1)))}>Up</button>
            <button className="button small ghost" onClick={() => runAction('Policies reordered', () => SandfoxService.ReorderPolicies(movedIDs(policies, index, 1)))}>Down</button>
            <button className="icon-button" onClick={() => runAction('Policy deleted', () => SandfoxService.DeletePolicy(policy.id))}><Trash2 size={16} /></button>
          </div>,
        ])}
      />
      <div className="policy-json-editor">
        <PanelTitle
          icon={Braces}
          title="Advanced policy JSON"
          action={
            <div className="row-actions">
              <span className="hint">Edit raw_data and logical_rule directly</span>
              <button className="button small ghost" onClick={createAdvancedPolicy}>New advanced</button>
            </div>
          }
        />
        <div className="logical-builder">
          <select value={logicalDraft.mode} disabled={!selectedPolicy} onChange={(event) => setLogicalMode(event.target.value)}>
            <option value="and">AND</option>
            <option value="or">OR</option>
          </select>
          <select value={logicalDraft.field} disabled={!selectedPolicy} onChange={(event) => setLogicalDraft({ ...logicalDraft, field: event.target.value })}>
            <option value="domain">domain</option>
            <option value="domain_suffix">domain_suffix</option>
            <option value="domain_keyword">domain_keyword</option>
            <option value="domain_regex">domain_regex</option>
            <option value="ip_cidr">ip_cidr</option>
            <option value="source_ip_cidr">source_ip_cidr</option>
            <option value="port">port</option>
            <option value="port_range">port_range</option>
            <option value="source_port">source_port</option>
            <option value="source_port_range">source_port_range</option>
            <option value="process_name">process_name</option>
            <option value="process_path">process_path</option>
            <option value="process_path_regex">process_path_regex</option>
            <option value="package_name">package_name</option>
            <option value="protocol">protocol</option>
            <option value="query_type">query_type</option>
            <option value="network">network</option>
            <option value="network_type">network_type</option>
            <option value="default_interface_address">default_interface_address</option>
            <option value="wifi_ssid">wifi_ssid</option>
            <option value="wifi_bssid">wifi_bssid</option>
            <option value="rule_set">rule_set</option>
          </select>
          <input
            value={logicalDraft.values}
            disabled={!selectedPolicy}
            placeholder="Comma separated matcher values"
            onChange={(event) => setLogicalDraft({ ...logicalDraft, values: event.target.value })}
          />
          <button className="button ghost" disabled={!selectedPolicy} onClick={addLogicalMatcher}>Add matcher</button>
        </div>
        <div className="logical-builder compact">
          <select value={logicalGroupDraft.mode} disabled={!selectedPolicy} onChange={(event) => setLogicalGroupDraft({ ...logicalGroupDraft, mode: event.target.value })}>
            <option value="and">Nested AND</option>
            <option value="or">Nested OR</option>
          </select>
          <button className="switch-row mini" disabled={!selectedPolicy} onClick={() => setLogicalGroupDraft({ ...logicalGroupDraft, invert: !logicalGroupDraft.invert })}>
            <span>nested invert</span>
            <b className={logicalGroupDraft.invert ? 'switch on' : 'switch'} />
          </button>
          <span className="hint">Uses the matcher values above as the first child rule</span>
          <button className="button ghost" disabled={!selectedPolicy} onClick={addLogicalGroup}>Add nested group</button>
        </div>
        <div className="logical-rule-list">
          <div className="logical-rule-meta">
            <span>{logicalPreview.mode.toUpperCase()} · {logicalPreview.rules.length} matchers</span>
            <button className="button small ghost" disabled={!selectedPolicy} onClick={toggleLogicalInvert}>
              {logicalPreview.invert ? 'Invert on' : 'Invert off'}
            </button>
          </div>
          <LogicalRuleTree
            rules={logicalPreview.rules}
            disabled={!selectedPolicy}
            onAddMatcher={addMatcherToLogicalGroup}
            onAddGroup={addGroupToLogicalGroup}
            onSetMode={setLogicalGroupModeAtPath}
            onToggleInvert={toggleLogicalGroupInvertAtPath}
            onRemove={removeLogicalRuleAtPath}
            onMove={moveLogicalRuleAtPath}
          />
        </div>
        <div className="raw-action-builder">
          <select value={rawActionDraft.action} disabled={!selectedPolicy} onChange={(event) => setRawActionDraft({ ...rawActionDraft, action: event.target.value })}>
            <option value="sniff">sniff</option>
            <option value="hijack-dns">hijack-dns</option>
            <option value="resolve">resolve</option>
          </select>
          <select value={rawActionDraft.field} disabled={!selectedPolicy} onChange={(event) => setRawActionDraft({ ...rawActionDraft, field: event.target.value })}>
            <option value="protocol">protocol</option>
            <option value="domain">domain</option>
            <option value="domain_suffix">domain_suffix</option>
            <option value="domain_keyword">domain_keyword</option>
            <option value="domain_regex">domain_regex</option>
            <option value="ip_cidr">ip_cidr</option>
            <option value="source_ip_cidr">source_ip_cidr</option>
            <option value="port">port</option>
            <option value="port_range">port_range</option>
            <option value="source_port">source_port</option>
            <option value="source_port_range">source_port_range</option>
            <option value="rule_set">rule_set</option>
          </select>
          <input
            value={rawActionDraft.values}
            disabled={!selectedPolicy}
            placeholder="Optional comma separated action matchers"
            onChange={(event) => setRawActionDraft({ ...rawActionDraft, values: event.target.value })}
          />
          <button className="button ghost" disabled={!selectedPolicy} onClick={setRawActionRule}>Set raw action</button>
        </div>
        <textarea
          value={policyJson}
          placeholder="Select a policy to inspect or edit its full JSON"
          onChange={(event) => setPolicyJson(event.target.value)}
        />
        {policyJsonError && <p className="platform-note">{policyJsonError}</p>}
        <div className="row-actions">
          <button className="button ghost" disabled={!selectedPolicy} onClick={() => selectedPolicy && startPolicyEdit(selectedPolicy)}>Reset</button>
          <button className="button primary" disabled={!selectedPolicy} onClick={savePolicyJson}>Save JSON</button>
        </div>
      </div>
    </section>
  )
}

function DNSView({
  profiles,
  dnsPolicies,
  dnsServers,
  availableOutbounds,
  runAction,
}: {
  profiles: Profile[]
  dnsPolicies: DNSPolicy[]
  dnsServers: DNSServer[]
  availableOutbounds: AvailableOutbound[]
  runAction: (message: string, action: () => Promise<unknown>) => Promise<void>
}) {
  const selectedProfile = profiles.find((profile) => profile.selected) || profiles[0]
  const [overrideDraft, setOverrideDraft] = useState({ policyId: '', server: '' })
  const [detourDraft, setDetourDraft] = useState({ serverId: '', detour: '' })
  const [draft, setDraft] = useState({ domain: '', domainSuffix: '', domainKeyword: '', ruleSet: '', queryType: '', network: '', server: 'cloudflare', strategy: 'prefer_ipv4' })
  const [serverDraft, setServerDraft] = useState({ tag: '', type: 'doh', address: '', addressResolver: '', addressStrategy: 'prefer_ipv4', detour: 'DIRECT', strategy: 'prefer_ipv4' })
  const [policyDraftId, setPolicyDraftId] = useState('')
  const [serverDraftId, setServerDraftId] = useState('')
  const [dnsProbe, setDNSProbe] = useState<ProbeItem | null>(null)
  const [serverRefs, setServerRefs] = useState<{ tag: string; refs: DNSServerRef[] } | null>(null)
  const resetServerDraft = () => {
    setServerDraft({ tag: '', type: 'doh', address: '', addressResolver: '', addressStrategy: 'prefer_ipv4', detour: 'DIRECT', strategy: 'prefer_ipv4' })
    setServerDraftId('')
  }
  const resetPolicyDraft = () => {
    setDraft({ domain: '', domainSuffix: '', domainKeyword: '', ruleSet: '', queryType: '', network: '', server: dnsServers[0]?.tag || 'cloudflare', strategy: 'prefer_ipv4' })
    setPolicyDraftId('')
  }
  return (
    <section className="page-grid">
      <OutboundDatalist id="dns-outbounds" outbounds={availableOutbounds} />
      <div className="panel">
        <PanelTitle icon={Globe2} title="DNS servers" />
        <InlineEditor
          fields={serverDraft}
          setFields={setServerDraft}
          placeholders={{ tag: 'cloudflare', type: 'doh / dot / udp / tcp', address: 'https://1.1.1.1/dns-query', addressResolver: 'bootstrap DNS tag', addressStrategy: 'prefer_ipv4', detour: 'DIRECT or node tag', strategy: 'prefer_ipv4' }}
          inputLists={{ detour: 'dns-outbounds' }}
          onSubmit={() =>
            runAction('DNS server saved', () =>
              SandfoxService.SaveDNSServer({ ...serverDraft, id: serverDraftId, name: '', server: '', enabled: true }),
            ).then(resetServerDraft)
          }
        />
        {serverDraftId && <button className="button small ghost" onClick={resetServerDraft}>Cancel DNS server edit</button>}
        <Table
          columns={['Tag', 'Type', 'Address', 'Resolver', 'Detour', 'Profile detour', 'Strategy', '']}
          rows={dnsServers.map((server, index) => [
            server.tag,
            server.type || '-',
            server.address,
            server.addressResolver || '-',
            server.detour || '-',
            <div className="row-actions">
              <input
                list="dns-outbounds"
                value={detourDraft.serverId === server.id ? detourDraft.detour : (selectedProfile?.dnsServerDetours || []).find((detour) => detour.serverId === server.id || detour.serverId === server.tag)?.detour || ''}
                placeholder={selectedProfile ? 'profile detour' : 'no profile'}
                disabled={!selectedProfile}
                onChange={(event) => setDetourDraft({ serverId: server.id, detour: event.target.value })}
              />
              <button className="button small ghost" disabled={!selectedProfile} onClick={() => selectedProfile && runAction('DNS server detour saved', () => SandfoxService.SetProfileDNSServerDetour(selectedProfile.id, server.id, detourDraft.serverId === server.id ? detourDraft.detour : server.detour || 'DIRECT'))}>Set</button>
              <button className="button small ghost" disabled={!selectedProfile} onClick={() => selectedProfile && runAction('DNS server detour cleared', () => SandfoxService.ClearProfileDNSServerDetour(selectedProfile.id, server.id))}>Clear</button>
            </div>,
            server.strategy,
            <div className="row-actions">
              <button
                className="button small ghost"
                onClick={() => {
                  setServerDraft({
                    tag: server.tag,
                    type: server.type || guessDNSInputType(server.address),
                    address: server.address,
                    addressResolver: server.addressResolver || '',
                    addressStrategy: server.addressStrategy || 'prefer_ipv4',
                    detour: server.detour || 'DIRECT',
                    strategy: server.strategy || 'prefer_ipv4',
                  })
                  setServerDraftId(server.id)
                }}
              >
                Edit
              </button>
              <button
                className="button small ghost"
                onClick={() =>
                  runAction('DNS server tested', async () => {
                    const result = (await SandfoxService.TestDNSServer(server.id)) as ProbeItem
                    setDNSProbe(result)
                  })
                }
              >
                Test
              </button>
              <button
                className="button small ghost"
                onClick={() =>
                  runAction('DNS server refs loaded', async () => {
                    const refs = (await SandfoxService.GetDNSServerRefs(server.tag)) as DNSServerRef[]
                    setServerRefs({ tag: server.tag, refs })
                  })
                }
              >
                Refs
              </button>
              <button className="button small ghost" onClick={() => runAction('DNS server toggled', () => SandfoxService.ToggleDNSServerEnabled(server.id, !server.enabled))}>
                {server.enabled ? 'Disable' : 'Enable'}
              </button>
              <button className="button small ghost" onClick={() => runAction('DNS servers reordered', () => SandfoxService.ReorderDNSServers(movedIDs(dnsServers, index, -1)))}>Up</button>
              <button className="button small ghost" onClick={() => runAction('DNS servers reordered', () => SandfoxService.ReorderDNSServers(movedIDs(dnsServers, index, 1)))}>Down</button>
              <button className="icon-button" onClick={() => runAction('DNS server deleted', () => SandfoxService.DeleteDNSServer(server.id))}><Trash2 size={16} /></button>
            </div>,
          ])}
        />
        {dnsProbe && <p className="platform-note">{dnsProbe.target}: {dnsProbe.status} · {dnsProbe.delay}ms</p>}
        {serverRefs && (
          <div className="config-preview">
            <div className="logical-rule-meta">
              <span>{serverRefs.tag} · {serverRefs.refs.length} references</span>
            </div>
            <textarea value={serverRefs.refs.map((ref) => `${ref.source}[${ref.index}] ${ref.name}`).join('\n') || 'No references'} readOnly />
          </div>
        )}
      </div>
      <div className="panel">
        <PanelTitle icon={Route} title="DNS policies" />
        <InlineEditor
          fields={draft}
          setFields={setDraft}
          placeholders={{ domain: 'legacy: geosite:cn / domain suffix', domainSuffix: 'example.com,example.org', domainKeyword: 'google,ai', ruleSet: 'geosite-openai', queryType: 'A,AAAA', network: 'tcp,udp', server: 'DNS server tag', strategy: 'prefer_ipv4' }}
          onSubmit={() =>
            runAction('DNS policy saved', () => SandfoxService.SaveDNSPolicy({
              id: policyDraftId,
              type: '',
              name: '',
              domain: draft.domain,
              domainSuffix: toList(draft.domainSuffix),
              domainKeyword: toList(draft.domainKeyword),
              ruleSet: toList(draft.ruleSet),
              queryType: toList(draft.queryType),
              network: toList(draft.network),
              server: draft.server,
              strategy: draft.strategy,
              enabled: true,
            })).then(resetPolicyDraft)
          }
        />
        {policyDraftId && <button className="button small ghost" onClick={resetPolicyDraft}>Cancel DNS policy edit</button>}
        <Table
          columns={['Match', 'Server', 'Profile override', 'Strategy', 'State', '']}
          rows={dnsPolicies.map((policy, index) => [
            dnsPolicySummary(policy),
            policy.server,
            <div className="row-actions">
              <input
                value={overrideDraft.policyId === policy.id ? overrideDraft.server : (selectedProfile?.dnsPolicyOverrides || []).find((override) => override.policyId === policy.id)?.server || ''}
                placeholder={selectedProfile ? 'profile DNS server' : 'no profile'}
                disabled={!selectedProfile}
                onChange={(event) => setOverrideDraft({ policyId: policy.id, server: event.target.value })}
              />
              <button className="button small ghost" disabled={!selectedProfile} onClick={() => selectedProfile && runAction('DNS policy override saved', () => SandfoxService.SetProfileDNSPolicyOverride(selectedProfile.id, policy.id, overrideDraft.policyId === policy.id ? overrideDraft.server : policy.server))}>Set</button>
              <button className="button small ghost" disabled={!selectedProfile} onClick={() => selectedProfile && runAction('DNS policy override cleared', () => SandfoxService.ClearProfileDNSPolicyOverride(selectedProfile.id, policy.id))}>Clear</button>
            </div>,
            policy.strategy,
            policy.enabled ? 'Enabled' : 'Disabled',
            <div className="row-actions">
              <button
                className="button small ghost"
                onClick={() => {
                  setDraft({
                    domain: policy.domain || '',
                    domainSuffix: (policy.domainSuffix || []).join(', '),
                    domainKeyword: (policy.domainKeyword || []).join(', '),
                    ruleSet: (policy.ruleSet || []).join(', '),
                    queryType: (policy.queryType || []).join(', '),
                    network: (policy.network || []).join(', '),
                    server: policy.server,
                    strategy: policy.strategy,
                  })
                  setPolicyDraftId(policy.id)
                }}
              >
                Edit
              </button>
              <button className="button small ghost" onClick={() => runAction('DNS policies reordered', () => SandfoxService.ReorderDNSPolicies(movedIDs(dnsPolicies, index, -1)))}>Up</button>
              <button className="button small ghost" onClick={() => runAction('DNS policies reordered', () => SandfoxService.ReorderDNSPolicies(movedIDs(dnsPolicies, index, 1)))}>Down</button>
              <button className="icon-button" onClick={() => runAction('DNS policy deleted', () => SandfoxService.DeleteDNSPolicy(policy.id))}><Trash2 size={16} /></button>
            </div>,
          ])}
        />
      </div>
    </section>
  )
}

function RuleSetsView({
  ruleSets,
  presetRuleSets,
  availableOutbounds,
  runAction,
}: {
  ruleSets: RuleSet[]
  presetRuleSets: RuleSet[]
  availableOutbounds: AvailableOutbound[]
  runAction: (message: string, action: () => Promise<unknown>) => Promise<void>
}) {
  const [draftId, setDraftId] = useState('')
  const [draft, setDraft] = useState({ tag: '', source: '', type: 'remote', format: 'binary', behavior: '', downloadDetour: 'DIRECT', enabled: true })
  const [preview, setPreview] = useState<ConfigPreview | null>(null)
  const resetDraft = () => {
    setDraftId('')
    setDraft({ tag: '', source: '', type: 'remote', format: 'binary', behavior: '', downloadDetour: 'DIRECT', enabled: true })
  }
  const saveRuleSetDraft = () =>
    runAction('Rule set saved', () => {
      const source = draft.source.trim()
      const type = draft.type || (source.startsWith('http') ? 'remote' : 'local')
      return SandfoxService.SaveRuleSet({
        id: draftId,
        tag: draft.tag,
        type,
        format: draft.format || (source.endsWith('.srs') ? 'binary' : 'source'),
        behavior: draft.behavior,
        path: type === 'local' ? source : '',
        url: type === 'remote' ? source : '',
        localPath: '',
        downloadDetour: draft.downloadDetour,
        enabled: draft.enabled,
        profileId: ruleSets.find((ruleSet) => ruleSet.id === draftId)?.profileId || '',
        lastUpdated: '',
        lastError: '',
        lastWarning: '',
      })
    }).then(resetDraft)
  const startRuleSetEdit = (ruleSet: RuleSet) => {
    setDraftId(ruleSet.id)
    setDraft({
      tag: ruleSet.tag,
      source: ruleSet.url || ruleSet.path,
      type: ruleSet.type || 'remote',
      format: ruleSet.format || 'binary',
      behavior: ruleSet.behavior || '',
      downloadDetour: ruleSet.downloadDetour || 'DIRECT',
      enabled: ruleSet.enabled,
    })
  }
  return (
    <section className="panel">
      <OutboundDatalist id="ruleset-outbounds" outbounds={availableOutbounds} />
      <PanelTitle
        icon={ListFilter}
        title="Rule providers"
        action={
          <div className="row-actions">
            <span className="hint">Use rule-set tags in Policies</span>
            <button className="button small ghost" onClick={() => runAction('Rule sets refreshed', () => SandfoxService.RefreshAllRuleSets())}>Refresh all</button>
          </div>
        }
      />
      {presetRuleSets.length > 0 && (
        <div className="template-strip">
          {presetRuleSets.map((preset) => {
            const installed = ruleSets.some((ruleSet) => ruleSet.tag === preset.tag)
            return (
              <div className="template-card" key={preset.tag}>
                <strong>{preset.tag}</strong>
                <span>{preset.format} · {preset.type}</span>
                <span>{preset.url}</span>
                <button className="button small ghost" onClick={() => runAction(installed ? 'Preset rule set updated' : 'Preset rule set added', () => SandfoxService.AddRuleSetsFromPreset([preset.tag]))}>
                  {installed ? 'Update' : 'Add'}
                </button>
              </div>
            )
          })}
        </div>
      )}
      <div className="inline-editor">
        <input value={draft.tag} placeholder="geosite-ai" onChange={(event) => setDraft({ ...draft, tag: event.target.value })} />
        <input value={draft.source} placeholder="https://.../rule.srs or local path" onChange={(event) => setDraft({ ...draft, source: event.target.value })} />
        <select value={draft.type} onChange={(event) => setDraft({ ...draft, type: event.target.value })}>
          <option value="remote">remote</option>
          <option value="local">local</option>
        </select>
        <select value={draft.format} onChange={(event) => setDraft({ ...draft, format: event.target.value })}>
          <option value="binary">binary</option>
          <option value="source">source</option>
        </select>
        <select value={draft.behavior} onChange={(event) => setDraft({ ...draft, behavior: event.target.value })}>
          <option value="">behavior</option>
          <option value="domain">domain</option>
          <option value="ipcidr">ipcidr</option>
          <option value="classical">classical</option>
        </select>
        <input list="ruleset-outbounds" value={draft.downloadDetour} placeholder="DIRECT or node tag" onChange={(event) => setDraft({ ...draft, downloadDetour: event.target.value })} />
        <button className="button ghost" onClick={() => setDraft({ ...draft, enabled: !draft.enabled })}>{draft.enabled ? 'Enabled' : 'Disabled'}</button>
        <button className="button primary" onClick={saveRuleSetDraft}>{draftId ? 'Update' : 'Add'}</button>
        {draftId && <button className="button ghost" onClick={resetDraft}>Cancel</button>}
      </div>
      <Table
        columns={['Tag', 'Type', 'Format', 'Behavior', 'Source', 'State', 'Cache', 'Updated', '']}
        rows={ruleSets.map((ruleSet, index) => [
          ruleSet.tag,
          ruleSet.type,
          ruleSet.format,
          ruleSet.behavior || '-',
          ruleSet.url || ruleSet.path,
          ruleSet.enabled ? 'Enabled' : 'Disabled',
          ruleSet.lastError || ruleSet.lastWarning || ruleSet.localPath || '-',
          ruleSet.lastError ? 'Failed' : formatDate(ruleSet.lastUpdated),
          <div className="row-actions">
            <button className="button small ghost" onClick={() => startRuleSetEdit(ruleSet)}>Edit</button>
            <button className="button small ghost" onClick={() => runAction('Rule set refreshed', () => SandfoxService.RefreshRuleSet(ruleSet.id))}>Refresh</button>
            <button className="button small ghost" onClick={() => runAction('Rule set loaded', async () => {
              const result = (await SandfoxService.GetRuleSetContent(ruleSet.id)) as ConfigPreview
              setPreview(result)
            })}>View</button>
            <button className="button small ghost" onClick={() => runAction('Rule sets reordered', () => SandfoxService.ReorderRuleSets(movedIDs(ruleSets, index, -1)))}>Up</button>
            <button className="button small ghost" onClick={() => runAction('Rule sets reordered', () => SandfoxService.ReorderRuleSets(movedIDs(ruleSets, index, 1)))}>Down</button>
            <button className="icon-button" onClick={() => runAction('Rule set deleted', () => SandfoxService.DeleteRuleSet(ruleSet.id))}><Trash2 size={16} /></button>
          </div>,
        ])}
      />
      {preview && (
        <div className="config-preview">
          <div className="logical-rule-meta">
            <span>{preview.path}</span>
          </div>
          <textarea value={preview.content} readOnly />
        </div>
      )}
    </section>
  )
}

function ConnectionsView({ connections, runAction }: { connections: Connection[]; runAction: (message: string, action: () => Promise<unknown>) => Promise<void> }) {
  const [query, setQuery] = useState('')
  const [network, setNetwork] = useState('all')
  const [outbound, setOutbound] = useState('all')
  const networks = useMemo(() => Array.from(new Set(connections.map((connection) => connection.network).filter(Boolean))).sort(), [connections])
  const outbounds = useMemo(() => Array.from(new Set(connections.map((connection) => connection.outbound).filter(Boolean))).sort(), [connections])
  const filtered = connections.filter((connection) => {
    const matchesNetwork = network === 'all' || connection.network === network
    const matchesOutbound = outbound === 'all' || connection.outbound === outbound
    const text = `${connection.host} ${connection.network} ${connection.outbound}`.toLowerCase()
    return matchesNetwork && matchesOutbound && text.includes(query.trim().toLowerCase())
  })
  const closeFiltered = () =>
    runAction('Filtered connections closed', async () => {
      await Promise.all(filtered.map((connection) => SandfoxService.CloseConnection(connection.id)))
    })
  return (
    <section className="panel">
      <PanelTitle
        icon={Activity}
        title="Active connections"
        action={
          <div className="row-actions">
            <button className="button small ghost" disabled={filtered.length === 0} onClick={closeFiltered}>Close filtered</button>
            <button className="button small ghost" onClick={() => runAction('All connections closed', () => SandfoxService.CloseAllConnections())}>Close all</button>
          </div>
        }
      />
      <div className="logical-builder">
        <input value={query} placeholder="Search host or outbound" onChange={(event) => setQuery(event.target.value)} />
        <select value={network} onChange={(event) => setNetwork(event.target.value)}>
          <option value="all">All networks</option>
          {networks.map((item) => <option value={item} key={item}>{item}</option>)}
        </select>
        <select value={outbound} onChange={(event) => setOutbound(event.target.value)}>
          <option value="all">All outbounds</option>
          {outbounds.map((item) => <option value={item} key={item}>{item}</option>)}
        </select>
        <span className="hint">{filtered.length} / {connections.length}</span>
      </div>
      <div className="template-strip">
        {outbounds.map((item) => {
          const count = connections.filter((connection) => connection.outbound === item).length
          return (
            <div className="template-card" key={item}>
              <strong>{item || '-'}</strong>
              <span>{count} connections</span>
            </div>
          )
        })}
      </div>
      <Table
        columns={['Host', 'Network', 'Outbound', 'Traffic', 'Age', '']}
        rows={filtered.map((c) => [
          c.host,
          c.network,
          c.outbound,
          `${formatBytes(c.upload)} / ${formatBytes(c.download)}`,
          c.age,
          <button className="button small ghost" onClick={() => runAction('Connection closed', () => SandfoxService.CloseConnection(c.id))}>Close</button>,
        ])}
      />
      {filtered.length === 0 && <EmptyState title="No connections" detail="Adjust filters or start traffic through the core." />}
    </section>
  )
}

function LogsView({ logs, runAction }: { logs: LogEntry[]; runAction: (message: string, action: () => Promise<unknown>) => Promise<void> }) {
  const [query, setQuery] = useState('')
  const [level, setLevel] = useState('all')
  const [source, setSource] = useState('all')
  const [coreLogSearch, setCoreLogSearch] = useState('')
  const [coreLog, setCoreLog] = useState<LogReadResult | null>(null)
  const sources = useMemo(() => Array.from(new Set(logs.map((log) => log.source))).sort(), [logs])
  const filtered = logs.filter((log) => {
    const matchesLevel = level === 'all' || log.level === level
    const matchesSource = source === 'all' || log.source === source
    const text = `${log.level} ${log.source} ${log.message}`.toLowerCase()
    return matchesLevel && matchesSource && text.includes(query.trim().toLowerCase())
  })
  return (
    <section className="panel log-panel">
      <PanelTitle
        icon={FileText}
        title="Runtime logs"
        action={
          <div className="row-actions">
            <button
              className="button small ghost"
              onClick={() =>
                runAction('Core log loaded', async () => {
                  const result = (await SandfoxService.ReadCoreLog({ fromLine: 0, search: coreLogSearch, maxResults: 500 })) as LogReadResult
                  setCoreLog(result)
                })
              }
            >
              Read core log
            </button>
            <button className="button small ghost" onClick={() => runAction('Core log opened', () => SandfoxService.OpenCoreLog())}>Open core log</button>
            <button className="button small ghost" onClick={() => runAction('Core log cleared', () => SandfoxService.ClearCoreLog()).then(() => setCoreLog(null))}>Clear core</button>
            <button className="button small ghost" onClick={() => runAction('Logs cleared', () => SandfoxService.ClearLogs())}>Clear</button>
          </div>
        }
      />
      <div className="logical-builder">
        <input value={query} placeholder="Search logs" onChange={(event) => setQuery(event.target.value)} />
        <input value={coreLogSearch} placeholder="Search core log" onChange={(event) => setCoreLogSearch(event.target.value)} />
        <select value={level} onChange={(event) => setLevel(event.target.value)}>
          <option value="all">All levels</option>
          <option value="info">info</option>
          <option value="warn">warn</option>
          <option value="error">error</option>
        </select>
        <select value={source} onChange={(event) => setSource(event.target.value)}>
          <option value="all">All sources</option>
          {sources.map((item) => <option value={item} key={item}>{item}</option>)}
        </select>
        <span className="hint">{filtered.length} / {logs.length}</span>
      </div>
      {coreLog && (
        <div className="config-preview">
          <PanelTitle icon={FileText} title={`Core log ${coreLog.isSearch ? 'search' : 'tail'} / ${coreLog.totalLines} lines`} action={<button className="button small ghost" onClick={() => setCoreLog(null)}>Close</button>} />
          <textarea value={coreLog.lines.join('\n')} readOnly />
        </div>
      )}
      {filtered.map((log) => (
        <div className="log-line" key={log.id}>
          <span>{formatTime(log.time)}</span>
          <b className={`level ${log.level}`}>{log.level}</b>
          <em>{log.source}</em>
          <p>{log.message}</p>
        </div>
      ))}
      {filtered.length === 0 && <EmptyState title="No logs" detail="Adjust filters or start the core to collect runtime output." />}
    </section>
  )
}

function SettingsView({
  settings,
  platform,
  availableOutbounds,
  setSettings,
  runAction,
}: {
  settings: SettingsState
  platform: PlatformStatus
  availableOutbounds: AvailableOutbound[]
  setSettings: (settings: SettingsState) => void
  runAction: (message: string, action: () => Promise<unknown>) => Promise<void>
}) {
  const [snapshotPath, setSnapshotPath] = useState('')
  const [singBoxConfigPath, setSingBoxConfigPath] = useState('')
  const [clashConfigPath, setClashConfigPath] = useState('')
  const [probe, setProbe] = useState<ClashProbe | null>(null)
  const [coreCheck, setCoreCheck] = useState<CoreCheckResult | null>(null)
  const [databaseStatus, setDatabaseStatus] = useState<DatabaseStatus | null>(null)
  const [serviceStatus, setServiceStatus] = useState<CoreServiceStatus | null>(null)
  const [dnsStatus, setDnsStatus] = useState<DNSRuntimeStatus | null>(null)
  const [singBoxStatus, setSingBoxStatus] = useState<SingBoxRuntimeStatus | null>(null)
  const [launcherStatus, setLauncherStatus] = useState<{ available: boolean; installed: boolean; result?: LauncherTaskResult } | null>(null)
  const [directIp, setDirectIp] = useState<IPInfo | null>(null)
  const [proxyIp, setProxyIp] = useState<IPInfo | null>(null)
  const [buildInfo, setBuildInfo] = useState<BuildInfo | null>(null)
  const [updateSource, setUpdateSource] = useState('')
  const [updateCheck, setUpdateCheck] = useState<UpdateCheckResult | null>(null)
  const [configPreview, setConfigPreview] = useState<ConfigPreview | null>(null)
  const [refreshSchedule, setRefreshSchedule] = useState<RefreshScheduleItem[]>([])
  const [hostsText, setHostsText] = useState('{}')
  const [hostsError, setHostsError] = useState('')
  const [experimentalText, setExperimentalText] = useState('{}')
  const [experimentalError, setExperimentalError] = useState('')
  const [fallbackFilterText, setFallbackFilterText] = useState('{}')
  const [fallbackFilterError, setFallbackFilterError] = useState('')
  const [preferenceDraft, setPreferenceDraft] = useState({ key: '', value: '' })
  const [preferencesText, setPreferencesText] = useState('')
  useEffect(() => {
    setHostsText(JSON.stringify(settings.hosts || {}, null, 2))
    setHostsError('')
  }, [settings.hosts])
  useEffect(() => {
    setExperimentalText(JSON.stringify(settings.experimental || {}, null, 2))
    setExperimentalError('')
  }, [settings.experimental])
  useEffect(() => {
    setFallbackFilterText(JSON.stringify(settings.dnsFallbackFilter || {}, null, 2))
    setFallbackFilterError('')
  }, [settings.dnsFallbackFilter])
  const updateHostsText = (value: string) => {
    setHostsText(value)
    try {
      const parsed = JSON.parse(value) as Record<string, string[] | string>
      const hosts = Object.fromEntries(Object.entries(parsed).map(([host, target]) => [host, Array.isArray(target) ? target.map(String) : [String(target)]]))
      setSettings({ ...settings, hosts })
      setHostsError('')
    } catch (error) {
      setHostsError(error instanceof Error ? error.message : String(error))
    }
  }
  const updateExperimentalText = (value: string) => {
    setExperimentalText(value)
    try {
      const experimental = JSON.parse(value) as Record<string, unknown>
      setSettings({ ...settings, experimental })
      setExperimentalError('')
    } catch (error) {
      setExperimentalError(error instanceof Error ? error.message : String(error))
    }
  }
  const updateFallbackFilterText = (value: string) => {
    setFallbackFilterText(value)
    try {
      const dnsFallbackFilter = JSON.parse(value) as Record<string, unknown>
      setSettings({ ...settings, dnsFallbackFilter })
      setFallbackFilterError('')
    } catch (error) {
      setFallbackFilterError(error instanceof Error ? error.message : String(error))
    }
  }
  const setTunFlag = (key: 'tunAutoRoute' | 'tunStrictRoute' | 'tunAutoDetectInterface') => {
    setSettings({ ...settings, [key]: !(settings[key] ?? true) })
  }
  const entries = useMemo(
    () => [
      ['mixedPort', 'Mixed port'],
      ['mixedListen', 'Mixed listen'],
      ['subscriptionUserAgent', 'Subscription User-Agent'],
      ['apiPort', 'Clash API port'],
      ['apiSecret', 'API secret'],
      ['singBoxPath', 'sing-box path'],
      ['dnsListen', 'Default DNS'],
      ['dnsStrategy', 'DNS strategy'],
      ['finalOutbound', 'Final outbound'],
      ['logLevel', 'Log level'],
      ['mode', 'Mode'],
    ] as const,
    [],
  )
  return (
    <section className="two-column">
      <OutboundDatalist id="settings-outbounds" outbounds={availableOutbounds} />
      <div className="panel form-panel">
        <PanelTitle icon={Settings} title="Core settings" />
        {entries.map(([key, label]) => (
          <label key={key}>
            {label}
            <input
              list={key === 'finalOutbound' ? 'settings-outbounds' : undefined}
              value={String(settings[key])}
              onChange={(event) => setSettings({ ...settings, [key]: key.includes('Port') ? Number(event.target.value) : event.target.value })}
            />
          </label>
        ))}
        <label>
          Hosts
          <textarea value={hostsText} onChange={(event) => updateHostsText(event.target.value)} />
        </label>
        {hostsError && <p className="platform-note">{hostsError}</p>}
        <label>
          Experimental
          <textarea value={experimentalText} onChange={(event) => updateExperimentalText(event.target.value)} />
        </label>
        {experimentalError && <p className="platform-note">{experimentalError}</p>}
        <button className="switch-row" onClick={() => setSettings({ ...settings, dnsFakeIPEnabled: !settings.dnsFakeIPEnabled })}>
          <span>dnsFakeIPEnabled</span>
          <b className={settings.dnsFakeIPEnabled ? 'switch on' : 'switch'} />
        </button>
        <div className="subgrid">
          <label>
            Fake-IP v4 range
            <input value={settings.dnsFakeIPRange || ''} onChange={(event) => setSettings({ ...settings, dnsFakeIPRange: event.target.value })} />
          </label>
          <label>
            Fake-IP v6 range
            <input value={settings.dnsFakeIPv6Range || ''} onChange={(event) => setSettings({ ...settings, dnsFakeIPv6Range: event.target.value })} />
          </label>
        </div>
        <label>
          Fake-IP filter
          <textarea value={(settings.dnsFakeIPFilter || []).join('\n')} onChange={(event) => setSettings({ ...settings, dnsFakeIPFilter: toLineList(event.target.value) })} />
        </label>
        <label>
          Fallback filter
          <textarea value={fallbackFilterText} onChange={(event) => updateFallbackFilterText(event.target.value)} />
        </label>
        {fallbackFilterError && <p className="platform-note">{fallbackFilterError}</p>}
        <button className="button primary" onClick={() => runAction('Settings saved', () => SandfoxService.SaveSettings(settings as never))}>Save settings</button>
        <div className="split-line" />
        <PanelTitle icon={Database} title="Preferences" />
        <div className="inline-editor settings-preference-editor">
          <input value={preferenceDraft.key} placeholder="theme / language / page setting" onChange={(event) => setPreferenceDraft({ ...preferenceDraft, key: event.target.value })} />
          <input value={preferenceDraft.value} placeholder="value" onChange={(event) => setPreferenceDraft({ ...preferenceDraft, value: event.target.value })} />
          <button className="button ghost" onClick={() => runAction('Preference saved', () => SandfoxService.SetPreference(preferenceDraft.key, preferenceDraft.value))}>Set</button>
          <button className="button ghost" onClick={() => runAction('Preference deleted', () => SandfoxService.DeletePreference(preferenceDraft.key))}>Delete</button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Preferences loaded', async () => {
                const result = await SandfoxService.GetPreferences()
                setPreferencesText(JSON.stringify(result, null, 2))
              })
            }
          >
            Load all
          </button>
        </div>
        {preferencesText && <textarea value={preferencesText} readOnly />}
      </div>
      <div className="panel">
        <PanelTitle icon={Shield} title="System toggles" />
        <button className="switch-row" onClick={() => setSettings({ ...settings, allowLan: !settings.allowLan, mixedListen: !settings.allowLan ? '0.0.0.0' : '127.0.0.1' })}>
          <span>allowLan</span>
          <b className={settings.allowLan ? 'switch on' : 'switch'} />
        </button>
        {(['tunEnabled', 'systemProxy', 'autoStart', 'autoStartProxy', 'sniffEnabled', 'sniffOverrideDestination', 'ipv6', 'overrideRules', 'customProxyGroups'] as const).map((key) => (
          <button className="switch-row" key={key} onClick={() => setSettings({ ...settings, [key]: !settings[key] })}>
            <span>{key}</span>
            <b className={settings[key] ? 'switch on' : 'switch'} />
          </button>
        ))}
        <div className="subgrid">
          <label>
            TUN stack
            <input value={settings.tunStack || 'system'} onChange={(event) => setSettings({ ...settings, tunStack: event.target.value })} />
          </label>
          <label>
            TUN interface
            <input value={settings.tunInterfaceName || 'sandfox0'} onChange={(event) => setSettings({ ...settings, tunInterfaceName: event.target.value })} />
          </label>
          <label>
            TUN MTU
            <input type="number" value={settings.tunMTU || 0} onChange={(event) => setSettings({ ...settings, tunMTU: Number(event.target.value) })} />
          </label>
        </div>
        {(['tunAutoRoute', 'tunStrictRoute', 'tunAutoDetectInterface'] as const).map((key) => (
          <button className="switch-row" key={key} onClick={() => setTunFlag(key)}>
            <span>{key}</span>
            <b className={(settings[key] ?? true) ? 'switch on' : 'switch'} />
          </button>
        ))}
        <label>
          TUN address
          <textarea value={(settings.tunAddress || []).join('\n')} onChange={(event) => setSettings({ ...settings, tunAddress: toLineList(event.target.value) })} />
        </label>
        <label>
          TUN DNS hijack
          <textarea value={(settings.tunDNSHijack || []).join('\n')} onChange={(event) => setSettings({ ...settings, tunDNSHijack: toLineList(event.target.value) })} />
        </label>
        <label>
          TUN route address
          <textarea value={(settings.tunRouteAddress || []).join('\n')} onChange={(event) => setSettings({ ...settings, tunRouteAddress: toLineList(event.target.value) })} />
        </label>
        <label>
          TUN route exclude address
          <textarea value={(settings.tunRouteExcludeAddress || []).join('\n')} onChange={(event) => setSettings({ ...settings, tunRouteExcludeAddress: toLineList(event.target.value) })} />
        </label>
        <div className="settings-action-grid">
          <button className="button ghost" onClick={() => runAction('Config generated', () => SandfoxService.GenerateConfig())}>
            <Braces size={16} />
            Generate config
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Config preview loaded', async () => {
                const result = (await SandfoxService.PreviewConfig()) as ConfigPreview
                setConfigPreview(result)
              })
            }
          >
            <Braces size={16} />
            Preview config
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Config diff loaded', async () => {
                const result = (await SandfoxService.PreviewConfigDiff()) as ConfigPreview
                setConfigPreview(result)
              })
            }
          >
            <Braces size={16} />
            Preview diff
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Active config loaded', async () => {
                const result = await SandfoxService.GetActiveConfig()
                setConfigPreview({ path: 'active config', content: JSON.stringify(result, null, 2), changed: false })
              })
            }
          >
            <Braces size={16} />
            Active config
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Current config rules loaded', async () => {
                const result = await SandfoxService.GetCurrentConfigRules()
                setConfigPreview({ path: 'current route rules', content: JSON.stringify(result, null, 2), changed: false })
              })
            }
          >
            <Route size={16} />
            Current rules
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Config validated', async () => {
                const result = (await SandfoxService.ValidateConfig()) as CoreCheckResult
                setCoreCheck(result)
                if (!result.ok) throw new Error(result.message)
              })
            }
          >
            <BadgeCheck size={16} />
            Validate config
          </button>
          <button className="button ghost" onClick={() => runAction('Core restarted', () => SandfoxService.RestartCore())}>
            <RefreshCw size={16} />
            Restart core
          </button>
          <button className="button ghost" onClick={() => runAction('Privileged core service installed', () => SandfoxService.InstallCoreService())}>
            <Shield size={16} />
            Install core service
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Core service status loaded', async () => {
                const result = (await SandfoxService.GetCoreServiceStatus()) as CoreServiceStatus
                setServiceStatus(result)
              })
            }
          >
            <BadgeCheck size={16} />
            Service status
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('sing-box runtime status loaded', async () => {
                const result = (await SandfoxService.GetSingboxStatus()) as SingBoxRuntimeStatus
                setSingBoxStatus(result)
              })
            }
          >
            <BadgeCheck size={16} />
            sing-box status
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('DNS runtime status loaded', async () => {
                const result = (await SandfoxService.GetDnsStatus()) as DNSRuntimeStatus
                setDnsStatus(result)
              })
            }
          >
            <BadgeCheck size={16} />
            DNS status
          </button>
          <button className="button ghost" onClick={() => runAction('Privileged core service started', () => SandfoxService.StartCoreService())}>
            <Power size={16} />
            Start service
          </button>
          <button className="button ghost" onClick={() => runAction('Privileged core service stopped', () => SandfoxService.StopCoreService())}>
            <Power size={16} />
            Stop service
          </button>
          <button className="button ghost" onClick={() => runAction('Privileged core service uninstalled', () => SandfoxService.UninstallCoreService())}>
            <Trash2 size={16} />
            Uninstall service
          </button>
          <button className="button ghost" onClick={() => runAction('Platform settings applied', () => SandfoxService.ApplyPlatformSettings())}>
            <Shield size={16} />
            Apply platform settings
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Launcher status loaded', async () => {
                const [available, installed] = await Promise.all([SandfoxService.IsLauncherAvailable(), SandfoxService.IsLauncherTaskInstalled()])
                setLauncherStatus({ available: Boolean(available), installed: Boolean(installed) })
              })
            }
          >
            <BadgeCheck size={16} />
            Launcher status
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Launcher task installed', async () => {
                const result = (await SandfoxService.InstallLauncherTask()) as LauncherTaskResult
                setLauncherStatus({ available: true, installed: result.success, result })
                if (!result.success) throw new Error(result.error || 'Launcher install failed')
              })
            }
          >
            <Power size={16} />
            Install launcher
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Launcher task run', async () => {
                const result = (await SandfoxService.RunLauncherTaskNow()) as LauncherTaskResult
                setLauncherStatus((current) => ({ available: current?.available ?? true, installed: current?.installed ?? false, result }))
                if (!result.success) throw new Error(result.error || 'Launcher run failed')
              })
            }
          >
            <Power size={16} />
            Run launcher
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Launcher task uninstalled', async () => {
                const result = (await SandfoxService.UninstallLauncherTask()) as LauncherTaskResult
                setLauncherStatus({ available: true, installed: false, result })
                if (!result.success) throw new Error(result.error || 'Launcher uninstall failed')
              })
            }
          >
            <Trash2 size={16} />
            Uninstall launcher
          </button>
          <button className="button ghost" onClick={() => runAction('sing-box detected', () => SandfoxService.DetectSingBox())}>
            <Search size={16} />
            Detect sing-box
          </button>
          <button className="button ghost" onClick={() => runAction('Opened data directory', () => SandfoxService.OpenDataDir())}>
            <Database size={16} />
            Open data directory
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Build info loaded', async () => {
                const result = (await SandfoxService.GetBuildInfo()) as BuildInfo
                setBuildInfo(result)
              })
            }
          >
            <BadgeCheck size={16} />
            Build info
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Direct IP loaded', async () => {
                const result = (await SandfoxService.FetchIPDirect()) as IPInfo
                setDirectIp(result)
              })
            }
          >
            <Globe2 size={16} />
            Direct IP
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Proxy IP loaded', async () => {
                const result = (await SandfoxService.FetchIPThroughProxy()) as IPInfo
                setProxyIp(result)
              })
            }
          >
            <Globe2 size={16} />
            Proxy IP
          </button>
          <button className="button ghost" onClick={() => runAction('Config snapshot exported', () => SandfoxService.ExportConfigSnapshot())}>
            <FileText size={16} />
            Export snapshot
          </button>
          <button className="button ghost" onClick={() => runAction('Config backup exported', () => SandfoxService.ExportConfigBackup())}>
            <FileText size={16} />
            Export backup
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Database status loaded', async () => {
                const result = (await SandfoxService.GetDatabaseStatus()) as DatabaseStatus
                setDatabaseStatus(result)
              })
            }
          >
            <Database size={16} />
            Database status
          </button>
          <button className="button ghost" onClick={() => runAction('Scheduled refresh completed', () => SandfoxService.RunScheduledRefresh())}>
            <RefreshCw size={16} />
            Refresh subscriptions
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Refresh schedule loaded', async () => {
                const result = (await SandfoxService.GetRefreshSchedule()) as RefreshScheduleItem[]
                setRefreshSchedule(result)
              })
            }
          >
            <RefreshCw size={16} />
            Refresh schedule
          </button>
        </div>
      </div>
      <div className="panel platform-panel">
        <PanelTitle icon={BadgeCheck} title="Platform status" />
        <dl className="status-list">
          <div><dt>OS</dt><dd>{platform.os}</dd></div>
          <div><dt>sing-box</dt><dd>{platform.singBoxVersion || 'Not found'}</dd></div>
          <div><dt>Path</dt><dd>{platform.singBoxPath || settings.singBoxPath || 'PATH lookup failed'}</dd></div>
          <div><dt>Proxy API</dt><dd>{platform.supportedProxyApi ? 'Supported' : 'Manual'}</dd></div>
          <div><dt>TUN</dt><dd>{platform.tunReady ? 'Config ready' : 'Unsupported'}</dd></div>
          <div><dt>Core service</dt><dd>{platform.coreService ? 'Installed' : 'Not installed'}</dd></div>
          <div><dt>Config</dt><dd>{platform.generatedConfig}</dd></div>
        </dl>
        <p className="platform-note">{platform.platformMessage}</p>
        {coreCheck && <p className="platform-note">{coreCheck.ok ? `Config OK: ${coreCheck.path}` : coreCheck.message}</p>}
        {databaseStatus && (
          <dl className="status-list compact">
            <div><dt>Schema</dt><dd>{databaseStatus.schemaVersion} / {databaseStatus.currentVersion}</dd></div>
            <div><dt>Migration</dt><dd>{databaseStatus.needsMigration ? 'Needed' : 'Current'}</dd></div>
            <div><dt>Database</dt><dd>{databaseStatus.path}</dd></div>
            <div><dt>Backup dir</dt><dd>{databaseStatus.backupDir}</dd></div>
            <div><dt>Rows</dt><dd>{databaseStatus.profiles} profiles · {databaseStatus.policies} policies · {databaseStatus.ruleSets} rule sets · {databaseStatus.preferences} preferences</dd></div>
            <div><dt>Updated</dt><dd>{formatDate(databaseStatus.updatedAt)}</dd></div>
          </dl>
        )}
        {serviceStatus && (
          <dl className="status-list compact">
            <div><dt>Service</dt><dd>{serviceStatus.supported ? 'Supported' : 'Unsupported'}</dd></div>
            <div><dt>Installed</dt><dd>{serviceStatus.binaryInstalled ? 'Yes' : 'No'}</dd></div>
            <div><dt>Loaded</dt><dd>{serviceStatus.serviceLoaded ? 'Yes' : 'No'}</dd></div>
            <div><dt>Running</dt><dd>{serviceStatus.running ? `Yes${serviceStatus.pid ? `, PID ${serviceStatus.pid}` : ''}` : 'No'}</dd></div>
            <div><dt>Socket</dt><dd>{serviceStatus.socketAvailable ? 'Available' : 'Unavailable'}</dd></div>
            {serviceStatus.singboxRunning !== undefined && <div><dt>Service sing-box</dt><dd>{serviceStatus.singboxRunning ? `Running${serviceStatus.singboxPid ? `, PID ${serviceStatus.singboxPid}` : ''}` : 'Stopped'}</dd></div>}
            {serviceStatus.version && <div><dt>Version</dt><dd>{serviceStatus.version}</dd></div>}
            {serviceStatus.servicePath && <div><dt>Service path</dt><dd>{serviceStatus.servicePath}</dd></div>}
            {serviceStatus.message && <div><dt>Message</dt><dd>{serviceStatus.message}</dd></div>}
          </dl>
        )}
        {launcherStatus && (
          <dl className="status-list compact">
            <div><dt>Launcher</dt><dd>{launcherStatus.available ? 'Available' : 'Unsupported'}</dd></div>
            <div><dt>Installed</dt><dd>{launcherStatus.installed ? 'Yes' : 'No'}</dd></div>
            {launcherStatus.result && <div><dt>Last action</dt><dd>{launcherStatus.result.success ? 'OK' : launcherStatus.result.error || 'Failed'}</dd></div>}
          </dl>
        )}
        {(singBoxStatus || dnsStatus) && (
          <dl className="status-list compact">
            {singBoxStatus && <div><dt>sing-box</dt><dd>{singBoxStatus.data?.running ? `Running, PID ${singBoxStatus.data.pid || '-'}` : 'Stopped'}</dd></div>}
            {singBoxStatus?.data?.binaryPath && <div><dt>Binary</dt><dd>{singBoxStatus.data.binaryPath}</dd></div>}
            {singBoxStatus?.data?.configPath && <div><dt>Config path</dt><dd>{singBoxStatus.data.configPath}</dd></div>}
            {dnsStatus && <div><dt>DNS</dt><dd>{dnsStatus.success ? (dnsStatus.data?.running ? 'Core running' : 'Core stopped') : dnsStatus.error || 'Unavailable'}</dd></div>}
            {dnsStatus?.data?.address && <div><dt>DNS address</dt><dd>{dnsStatus.data.address}</dd></div>}
          </dl>
        )}
        {(directIp || proxyIp) && (
          <dl className="status-list compact">
            {directIp && <div><dt>Direct IP</dt><dd>{directIp.ip} {directIp.countryCode || directIp.country}</dd></div>}
            {proxyIp && <div><dt>Proxy IP</dt><dd>{proxyIp.ip} {proxyIp.countryCode || proxyIp.country}</dd></div>}
          </dl>
        )}
        {buildInfo && (
          <dl className="status-list compact">
            <div><dt>App version</dt><dd>{buildInfo.appVersion}</dd></div>
            <div><dt>Build number</dt><dd>{buildInfo.buildNumber}</dd></div>
            <div><dt>Build time</dt><dd>{buildInfo.buildTime || '-'}</dd></div>
            <div><dt>Commit</dt><dd>{buildInfo.commitSha}</dd></div>
            <div><dt>sing-box version</dt><dd>{buildInfo.singBoxVersion || 'Not found'}</dd></div>
          </dl>
        )}
        <div className="inline-editor import-snapshot">
          <input value={updateSource} onChange={(event) => setUpdateSource(event.target.value)} placeholder="Release manifest URL or JSON path" />
          <button
            className="button ghost"
            onClick={() =>
              runAction('Update check completed', async () => {
                const result = (await SandfoxService.CheckForUpdates(updateSource)) as UpdateCheckResult
                setUpdateCheck(result)
                if (result.error) throw new Error(result.error)
              })
            }
          >
            Check updates
          </button>
        </div>
        {updateCheck && (
          <dl className="status-list compact">
            <div><dt>Update</dt><dd>{updateCheck.available ? `Available: ${updateCheck.latestVersion}` : `Current: ${updateCheck.currentVersion}`}</dd></div>
            <div><dt>Source</dt><dd>{updateCheck.source}</dd></div>
            {updateCheck.manifest.buildNumber && <div><dt>Build</dt><dd>{updateCheck.manifest.buildNumber}</dd></div>}
            {updateCheck.manifest.releaseUrl && <div><dt>Release</dt><dd>{updateCheck.manifest.releaseUrl}</dd></div>}
            {updateCheck.manifest.downloadUrl && <div><dt>Download</dt><dd>{updateCheck.manifest.downloadUrl}</dd></div>}
            {updateCheck.manifest.sha256 && <div><dt>SHA256</dt><dd>{updateCheck.manifest.sha256}</dd></div>}
          </dl>
        )}
        <div className="inline-editor import-snapshot">
          <input value={snapshotPath} onChange={(event) => setSnapshotPath(event.target.value)} placeholder="Snapshot JSON path to import" />
          <button className="button ghost" onClick={() => runAction('Config snapshot imported', () => SandfoxService.ImportConfigSnapshot(snapshotPath))}>
            Import snapshot
          </button>
          <button className="button ghost" onClick={() => runAction('Config backup imported', () => SandfoxService.ImportConfigBackup(snapshotPath))}>
            Import backup
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Clash API checked', async () => {
                const result = (await SandfoxService.TestClashAPI()) as ClashProbe
                setProbe(result)
                if (!result.available) throw new Error(result.message)
              })
            }
          >
            Test Clash API
          </button>
        </div>
        <div className="inline-editor import-snapshot">
          <input value={singBoxConfigPath} onChange={(event) => setSingBoxConfigPath(event.target.value)} placeholder="sing-box config.json path to import routes" />
          <button
            className="button ghost"
            onClick={() =>
              runAction('sing-box routes imported', async () => {
                const result = (await SandfoxService.ImportSingBoxConfigFile(singBoxConfigPath, false)) as ConfigImportResult
                return `${result.policies} policies / ${result.ruleSets} rule sets`
              })
            }
          >
            Import routes
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('sing-box routes replaced', async () => {
                const result = (await SandfoxService.ImportSingBoxConfigFile(singBoxConfigPath, true)) as ConfigImportResult
                return `${result.policies} policies / ${result.ruleSets} rule sets`
              })
            }
          >
            Replace routes
          </button>
        </div>
        <div className="inline-editor import-snapshot">
          <input value={clashConfigPath} onChange={(event) => setClashConfigPath(event.target.value)} placeholder="Clash YAML path to import rules" />
          <button
            className="button ghost"
            onClick={() =>
              runAction('Clash rules imported', async () => {
                const result = (await SandfoxService.ImportClashConfigFile(clashConfigPath, false)) as ConfigImportResult
                return `${result.policies} policies / ${result.ruleSets} rule sets`
              })
            }
          >
            Import Clash rules
          </button>
          <button
            className="button ghost"
            onClick={() =>
              runAction('Clash rules replaced', async () => {
                const result = (await SandfoxService.ImportClashConfigFile(clashConfigPath, true)) as ConfigImportResult
                return `${result.policies} policies / ${result.ruleSets} rule sets`
              })
            }
          >
            Replace Clash rules
          </button>
        </div>
        {probe && <p className="platform-note">{probe.available ? `Connected: ${probe.version || probe.url}` : probe.message}</p>}
        {refreshSchedule.length > 0 && (
          <div className="schedule-list">
            <PanelTitle icon={RefreshCw} title="Refresh schedule" />
            {refreshSchedule.map((item) => (
              <div className="logical-rule-item" key={`${item.kind}-${item.id}`}>
                <code>{item.kind} · {item.name} · {item.due ? 'due' : `next ${formatDate(item.nextRefresh)}`} · every {item.intervalSeconds ? `${item.intervalSeconds}s` : `${item.intervalHours}h`}</code>
                <span className={item.lastError ? 'level error' : 'level info'}>{item.lastError || 'ok'}</span>
              </div>
            ))}
          </div>
        )}
        {configPreview && (
          <div className="config-preview">
            <div className="logical-rule-meta">
              <span>{configPreview.changed ? 'Changed' : 'No changes'} · {configPreview.path}</span>
            </div>
            {(configPreview.warnings || []).map((warning) => <p className="platform-note" key={warning}>{warning}</p>)}
            <textarea value={configPreview.content} readOnly />
          </div>
        )}
      </div>
    </section>
  )
}

function InlineEditor<T extends Record<string, string>>({
  fields,
  setFields,
  placeholders,
  inputLists,
  onSubmit,
}: {
  fields: T
  setFields: (fields: T) => void
  placeholders: Record<keyof T, string>
  inputLists?: Partial<Record<keyof T, string>>
  onSubmit: () => void
}) {
  return (
    <div className="inline-editor">
      {Object.keys(fields).map((key) => (
        <input
          key={key}
          value={fields[key]}
          placeholder={placeholders[key]}
          list={inputLists?.[key]}
          onChange={(event) => setFields({ ...fields, [key]: event.target.value })}
        />
      ))}
      <button className="button primary" onClick={onSubmit}>Add</button>
    </div>
  )
}

function OutboundDatalist({ id, outbounds }: { id: string; outbounds: AvailableOutbound[] }) {
  return (
    <datalist id={id}>
      {outbounds.map((outbound) => (
        <option value={outbound.tag} label={`${outbound.kind} · ${outbound.type}`} key={`${id}-${outbound.kind}-${outbound.tag}`} />
      ))}
    </datalist>
  )
}

function PanelTitle({ icon: Icon, title, action }: { icon: IconComponent; title: string; action?: ReactNode }) {
  return (
    <div className="panel-title">
      <div>
        <Icon size={18} />
        <h2>{title}</h2>
      </div>
      {action}
    </div>
  )
}

function Table({ columns, rows }: { columns: string[]; rows: ReactNode[][] }) {
  const style = { '--cols': columns.length } as CSSProperties
  return (
    <div className="table">
      <div className="table-row table-head" style={style}>{columns.map((column) => <span key={column}>{column}</span>)}</div>
      {rows.map((row, index) => (
        <div className="table-row" key={index} style={style}>
          {row.map((cell, cellIndex) => <span key={cellIndex}>{cell}</span>)}
        </div>
      ))}
    </div>
  )
}

function SearchBox() {
  return (
    <div className="search-box">
      <Search size={15} />
      <span>Filter</span>
    </div>
  )
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty-state">
      <CircleDot size={22} />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  )
}

function formatBytes(value: number) {
  if (value > 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`
  if (value > 1024) return `${(value / 1024).toFixed(1)} KB`
  return `${value} B`
}

function profileUsageText(profile: Profile) {
  const info = profile.subscriptionUserinfo
  if (!info) return 'usage n/a'
  const used = (info.upload || 0) + (info.download || 0)
  const expire = info.expire ? new Date(info.expire * 1000).toLocaleDateString() : 'no expiry'
  return `${formatBytes(used)} / ${formatBytes(info.total || 0)} · ${expire}`
}

function formatDate(value: string) {
  if (!value) return 'Never'
  return new Date(value).toLocaleString()
}

function formatTime(value: string) {
  return new Date(value).toLocaleTimeString()
}

function toList(value: string) {
  return value.split(',').map((item) => item.trim()).filter(Boolean)
}

function toLineList(value: string) {
  return value.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean)
}

function movedIDs<T extends { id: string }>(items: T[], index: number, direction: number) {
  const next = items.map((item) => item.id)
  const target = index + direction
  if (target < 0 || target >= next.length) return next
  const [id] = next.splice(index, 1)
  next.splice(target, 0, id)
  return next
}

function movedCustomGroupOrders(groups: CustomProxyGroup[], index: number, direction: number) {
  const next = groups.map((group) => group.name)
  const target = index + direction
  if (target < 0 || target >= next.length) {
    return next.map((name, order) => ({ name, order }))
  }
  const [name] = next.splice(index, 1)
  next.splice(target, 0, name)
  return next.map((name, order) => ({ name, order }))
}

function completePolicyForSave(source: Partial<Policy>, fallback?: Policy | null): Policy {
  const policy = {
    id: '',
    type: 'default',
    name: '',
    match: '',
    domain: [],
    domainSuffix: [],
    domainKeyword: [],
    domainRegex: [],
    ipCidr: [],
    sourceIpCidr: [],
    port: [],
    portRange: [],
    sourcePort: [],
    sourcePortRange: [],
    processName: [],
    processPath: [],
    processPathRegex: [],
    packageName: [],
    protocol: [],
    queryType: [],
    network: [],
    networkType: [],
    defaultInterfaceAddress: [],
    wifiSsid: [],
    wifiBssid: [],
    networkIsExpensive: false,
    networkIsConstrained: false,
    ipIsPrivate: false,
    ruleSet: [],
    raw_data: {},
    logical_rule: {},
    outbound: 'DIRECT',
    enabled: true,
    priority: 0,
    updatedAt: '',
    ...(fallback || {}),
    ...source,
  } as Policy
  policy.domain = Array.isArray(policy.domain) ? policy.domain : []
  policy.domainSuffix = Array.isArray(policy.domainSuffix) ? policy.domainSuffix : []
  policy.domainKeyword = Array.isArray(policy.domainKeyword) ? policy.domainKeyword : []
  policy.domainRegex = Array.isArray(policy.domainRegex) ? policy.domainRegex : []
  policy.ipCidr = Array.isArray(policy.ipCidr) ? policy.ipCidr : []
  policy.sourceIpCidr = Array.isArray(policy.sourceIpCidr) ? policy.sourceIpCidr : []
  policy.port = Array.isArray(policy.port) ? policy.port : []
  policy.portRange = Array.isArray(policy.portRange) ? policy.portRange : []
  policy.sourcePort = Array.isArray(policy.sourcePort) ? policy.sourcePort : []
  policy.sourcePortRange = Array.isArray(policy.sourcePortRange) ? policy.sourcePortRange : []
  policy.processName = Array.isArray(policy.processName) ? policy.processName : []
  policy.processPath = Array.isArray(policy.processPath) ? policy.processPath : []
  policy.processPathRegex = Array.isArray(policy.processPathRegex) ? policy.processPathRegex : []
  policy.packageName = Array.isArray(policy.packageName) ? policy.packageName : []
  policy.protocol = Array.isArray(policy.protocol) ? policy.protocol : []
  policy.queryType = Array.isArray(policy.queryType) ? policy.queryType : []
  policy.network = Array.isArray(policy.network) ? policy.network : []
  policy.networkType = Array.isArray(policy.networkType) ? policy.networkType : []
  policy.defaultInterfaceAddress = Array.isArray(policy.defaultInterfaceAddress) ? policy.defaultInterfaceAddress : []
  policy.wifiSsid = Array.isArray(policy.wifiSsid) ? policy.wifiSsid : []
  policy.wifiBssid = Array.isArray(policy.wifiBssid) ? policy.wifiBssid : []
  policy.ruleSet = Array.isArray(policy.ruleSet) ? policy.ruleSet : []
  policy.raw_data = policy.raw_data && typeof policy.raw_data === 'object' ? policy.raw_data : {}
  policy.logical_rule = policy.logical_rule && typeof policy.logical_rule === 'object' ? policy.logical_rule : {}
  return policy
}

function logicalGroup(rule: unknown, fallbackMode = 'and'): Record<string, unknown> & { rules: Record<string, unknown>[]; mode: string; invert: boolean } {
  const source = rule && typeof rule === 'object' ? (rule as Record<string, unknown>) : {}
  const rules = Array.isArray(source.rules) ? source.rules.filter(isRecord) : []
  return {
    ...source,
    type: 'logical',
    mode: typeof source.mode === 'string' ? source.mode : fallbackMode,
    invert: source.invert === true,
    rules,
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function updateLogicalGroupAtPath(
  group: Record<string, unknown>,
  path: number[],
  updater: (group: Record<string, unknown>) => Record<string, unknown>,
): Record<string, unknown> {
  if (path.length === 0) {
    return updater(group)
  }
  const [index, ...rest] = path
  const current = logicalGroup(group)
  const rules = [...current.rules]
  const child = rules[index]
  if (!isRecord(child)) {
    return current
  }
  rules[index] = updateLogicalGroupAtPath(child, rest, updater)
  return { ...current, rules }
}

function appendLogicalRuleAtPath(group: Record<string, unknown>, path: number[], rule: Record<string, unknown>) {
  return updateLogicalGroupAtPath(group, path, (target) => {
    const current = logicalGroup(target)
    return { ...current, rules: [...current.rules, rule] }
  })
}

function removeLogicalRuleAtPathInGroup(group: Record<string, unknown>, path: number[]) {
  const parentPath = path.slice(0, -1)
  const removeIndex = path[path.length - 1]
  return updateLogicalGroupAtPath(group, parentPath, (target) => {
    const current = logicalGroup(target)
    return { ...current, rules: current.rules.filter((_, index) => index !== removeIndex) }
  })
}

function moveLogicalRuleAtPathInGroup(group: Record<string, unknown>, path: number[], direction: number) {
  const parentPath = path.slice(0, -1)
  const from = path[path.length - 1]
  return updateLogicalGroupAtPath(group, parentPath, (target) => {
    const current = logicalGroup(target)
    const rules = [...current.rules]
    const to = from + direction
    if (from < 0 || to < 0 || from >= rules.length || to >= rules.length) {
      return current
    }
    const [item] = rules.splice(from, 1)
    rules.splice(to, 0, item)
    return { ...current, rules }
  })
}

function LogicalRuleTree({
  rules,
  disabled,
  path = [],
  onAddMatcher,
  onAddGroup,
  onSetMode,
  onToggleInvert,
  onRemove,
  onMove,
}: {
  rules: Record<string, unknown>[]
  disabled: boolean
  path?: number[]
  onAddMatcher: (path: number[]) => void
  onAddGroup: (path: number[]) => void
  onSetMode: (path: number[], mode: string) => void
  onToggleInvert: (path: number[]) => void
  onRemove: (path: number[]) => void
  onMove: (path: number[], direction: number) => void
}) {
  if (rules.length === 0) {
    return <p className="platform-note">No logical rules in this group.</p>
  }
  return (
    <div className={path.length > 0 ? 'logical-tree nested' : 'logical-tree'}>
      {rules.map((rule, index) => {
        const currentPath = [...path, index]
        const isGroup = rule.type === 'logical' || Array.isArray(rule.rules)
        const childRules = isGroup ? logicalGroup(rule).rules : []
        return (
          <div className="logical-tree-node" key={`${currentPath.join('.')}-${JSON.stringify(rule)}`}>
            <div className="logical-rule-item">
              <div className="logical-rule-content">
                <code>{formatLogicalRule(rule)}</code>
              </div>
              <div className="row-actions">
                <button className="button small ghost" disabled={disabled || index === 0} onClick={() => onMove(currentPath, -1)}>Up</button>
                <button className="button small ghost" disabled={disabled || index === rules.length - 1} onClick={() => onMove(currentPath, 1)}>Down</button>
                {isGroup && (
                  <>
                    <select className="compact-select" disabled={disabled} value={typeof rule.mode === 'string' ? rule.mode : 'and'} onChange={(event) => onSetMode(currentPath, event.target.value)}>
                      <option value="and">AND</option>
                      <option value="or">OR</option>
                    </select>
                    <button className="button small ghost" disabled={disabled} onClick={() => onToggleInvert(currentPath)}>{rule.invert === true ? 'Invert on' : 'Invert off'}</button>
                    <button className="button small ghost" disabled={disabled} onClick={() => onAddMatcher(currentPath)}>Add child</button>
                    <button className="button small ghost" disabled={disabled} onClick={() => onAddGroup(currentPath)}>Add group</button>
                  </>
                )}
                <button className="icon-button" disabled={disabled} onClick={() => onRemove(currentPath)}><Trash2 size={16} /></button>
              </div>
            </div>
            {isGroup && childRules.length > 0 && (
              <LogicalRuleTree
                rules={childRules}
                disabled={disabled}
                path={currentPath}
                onAddMatcher={onAddMatcher}
                onAddGroup={onAddGroup}
                onSetMode={onSetMode}
                onToggleInvert={onToggleInvert}
                onRemove={onRemove}
                onMove={onMove}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}

function policySummary(policy: Policy) {
  if (policy.type === 'raw') {
    const action = typeof policy.raw_data?.action === 'string' ? policy.raw_data.action : ''
    return action ? `raw:${action}` : 'raw rule'
  }
  const parts = [
    ['domain', policy.domain],
    ['suffix', policy.domainSuffix],
    ['keyword', policy.domainKeyword],
    ['regex', policy.domainRegex],
    ['ip', policy.ipCidr],
    ['src-ip', policy.sourceIpCidr],
    ['port', policy.port],
    ['src-port', policy.sourcePort],
    ['process', policy.processName],
    ['package', policy.packageName],
    ['protocol', policy.protocol],
    ['qtype', policy.queryType],
    ['network', policy.network],
    ['rule-set', policy.ruleSet],
  ]
    .filter(([, values]) => Array.isArray(values) && values.length > 0)
    .map(([label, values]) => `${label}:${(values as string[]).join(',')}`)
  if (policy.logical_rule && Object.keys(policy.logical_rule).length > 0) {
    const rules = Array.isArray(policy.logical_rule.rules) ? policy.logical_rule.rules.length : 0
    parts.push(`logical:${policy.logical_rule.mode || 'or'}(${rules})`)
  }
  return parts.join(' · ') || policy.match || '-'
}

function formatLogicalRule(rule: Record<string, unknown>) {
  if (rule.type === 'logical' || Array.isArray(rule.rules)) {
    const mode = typeof rule.mode === 'string' ? rule.mode.toUpperCase() : 'AND'
    const rules = Array.isArray(rule.rules) ? rule.rules.length : 0
    return `${rule.invert === true ? 'NOT ' : ''}${mode} group · ${rules} child rule${rules === 1 ? '' : 's'}`
  }
  return JSON.stringify(rule)
}

function dnsPolicySummary(policy: DNSPolicy) {
  const parts = [
    ['legacy', policy.domain ? [policy.domain] : []],
    ['suffix', policy.domainSuffix],
    ['keyword', policy.domainKeyword],
    ['rule-set', policy.ruleSet],
    ['qtype', policy.queryType],
    ['network', policy.network],
  ]
    .filter(([, values]) => Array.isArray(values) && values.length > 0)
    .map(([label, values]) => `${label}:${(values as string[]).join(',')}`)
  return parts.join(' · ') || '-'
}

function guessDNSInputType(address: string) {
  const lower = address.trim().toLowerCase()
  if (lower.startsWith('https://')) return 'doh'
  if (lower.startsWith('tls://')) return 'dot'
  if (lower.startsWith('udp://')) return 'udp'
  if (lower.startsWith('tcp://')) return 'tcp'
  if (lower.startsWith('quic://')) return 'doq'
  return 'plain'
}

export default App
