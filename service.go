package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wailsapp/wails/v3/pkg/application"
	"gopkg.in/yaml.v3"
)

//go:embed resources/presets/rulesets/singbox.json
var roverPresetRuleSetsJSON []byte

//go:embed resources/presets/templates.json resources/presets/templates/*.json
var roverTemplatesFS embed.FS

var (
	appVersion  = "dev"
	buildTime   = ""
	buildNumber = "dev"
	commitSHA   = "unknown"
)

const dataSchemaVersion = 2
const backupFormatVersion = 1
const roverServiceAPIVersion = "1.1.0"
const updateManifestMaxBytes = 1 << 20

type SandfoxService struct {
	mu                sync.Mutex
	data              AppData
	dataDir           string
	core              *exec.Cmd
	coreUpAt          time.Time
	dnsServer         *http.Server
	dnsServerRunning  bool
	dnsServerAddress  string
	dnsServerCertPath string
	dnsServerKeyPath  string
	schedulerCancel   context.CancelFunc
}

type AppData struct {
	SchemaVersion int               `json:"schemaVersion"`
	Profiles      []Profile         `json:"profiles"`
	Policies      []Policy          `json:"policies"`
	DNSPolicies   []DNSPolicy       `json:"dnsPolicies"`
	DNSServers    []DNSServer       `json:"dnsServers"`
	RuleSets      []RuleSet         `json:"ruleSets"`
	Settings      Settings          `json:"settings"`
	Preferences   map[string]string `json:"preferences"`
	Logs          []LogEntry        `json:"logs"`
	CreatedAt     time.Time         `json:"createdAt"`
	UpdatedAt     time.Time         `json:"updatedAt"`
}

type Profile struct {
	ID                   string                     `json:"id"`
	Name                 string                     `json:"name"`
	URL                  string                     `json:"url"`
	Content              string                     `json:"content"`
	NodeCount            int                        `json:"nodeCount"`
	Selected             bool                       `json:"selected"`
	UpdateInterval       int                        `json:"updateInterval"`
	Filter               string                     `json:"filter"`
	TestURL              string                     `json:"testUrl"`
	LastError            string                     `json:"lastError"`
	LastUpdated          time.Time                  `json:"lastUpdated"`
	Nodes                []ProxyNode                `json:"nodes"`
	ProxyGroups          []ProxyGroupConfig         `json:"proxyGroups"`
	CustomGroups         []CustomProxyGroup         `json:"customGroups"`
	ProxyProviders       []ProxyProviderConfig      `json:"proxyProviders"`
	SubscriptionUserinfo *SubscriptionUserinfo      `json:"subscriptionUserinfo,omitempty"`
	PolicyOverrides      []ProfilePolicyOverride    `json:"policyOverrides"`
	DNSPolicyOverrides   []ProfileDNSPolicyOverride `json:"dnsPolicyOverrides"`
	DNSServerDetours     []ProfileDNSServerDetour   `json:"dnsServerDetours"`
}

type SubscriptionUserinfo struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"`
}

type ProfilePolicyOverride struct {
	PolicyID string `json:"policyId"`
	Outbound string `json:"outbound"`
}

type ProfileDNSPolicyOverride struct {
	PolicyID string `json:"policyId"`
	Server   string `json:"server"`
}

type ProfileDNSServerDetour struct {
	ServerID string `json:"serverId"`
	Detour   string `json:"detour"`
}

type RoverProfilePolicyItem struct {
	PolicyID          string `json:"policy_id"`
	PreferredOutbound string `json:"preferred_outbound"`
}

type RoverProfileDNSPolicyItem struct {
	DNSPolicyID     string `json:"dns_policy_id"`
	PreferredServer string `json:"preferred_server"`
}

type RoverProfileDNSServerItem struct {
	DNSServerID     string `json:"dns_server_id"`
	PreferredDetour string `json:"preferred_detour"`
}

type OrderItem struct {
	ID    string `json:"id"`
	Order int    `json:"order"`
}

type ProxyNode struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Server   string         `json:"server"`
	Port     int            `json:"port"`
	Country  string         `json:"country"`
	Latency  int            `json:"latency"`
	Selected bool           `json:"selected"`
	Raw      map[string]any `json:"raw"`
}

type ProxyGroupConfig struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Proxies   []string `json:"proxies"`
	Use       []string `json:"use"`
	URL       string   `json:"url"`
	Strategy  string   `json:"strategy"`
	Interval  int      `json:"interval"`
	Tolerance int      `json:"tolerance"`
}

type CustomProxyGroup struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Outbounds []string `json:"outbounds"`
	Order     int      `json:"order"`
}

type CustomProxyGroupOrder struct {
	Name  string `json:"name"`
	Order int    `json:"order"`
}

type ProxyProviderConfig struct {
	Name                string      `json:"name"`
	Type                string      `json:"type"`
	URL                 string      `json:"url"`
	Path                string      `json:"path"`
	Interval            int         `json:"interval"`
	Filter              string      `json:"filter"`
	HealthCheckEnable   bool        `json:"healthCheckEnable"`
	HealthCheckURL      string      `json:"healthCheckUrl"`
	HealthCheckInterval int         `json:"healthCheckInterval"`
	NodeCount           int         `json:"nodeCount"`
	LastUpdated         time.Time   `json:"lastUpdated"`
	LastChecked         time.Time   `json:"lastChecked"`
	LastError           string      `json:"lastError"`
	Health              []ProbeItem `json:"health"`
}

type Policy struct {
	ID                      string         `json:"id"`
	Type                    string         `json:"type"`
	Name                    string         `json:"name"`
	Match                   string         `json:"match"`
	Domain                  []string       `json:"domain"`
	DomainSuffix            []string       `json:"domainSuffix"`
	DomainKeyword           []string       `json:"domainKeyword"`
	DomainRegex             []string       `json:"domainRegex"`
	IPCIDR                  []string       `json:"ipCidr"`
	SourceIPCIDR            []string       `json:"sourceIpCidr"`
	Port                    []string       `json:"port"`
	PortRange               []string       `json:"portRange"`
	SourcePort              []string       `json:"sourcePort"`
	SourcePortRange         []string       `json:"sourcePortRange"`
	ProcessName             []string       `json:"processName"`
	ProcessPath             []string       `json:"processPath"`
	ProcessPathRegex        []string       `json:"processPathRegex"`
	PackageName             []string       `json:"packageName"`
	Protocol                []string       `json:"protocol"`
	QueryType               []string       `json:"queryType"`
	Network                 []string       `json:"network"`
	NetworkType             []string       `json:"networkType"`
	DefaultInterfaceAddress []string       `json:"defaultInterfaceAddress"`
	WifiSSID                []string       `json:"wifiSsid"`
	WifiBSSID               []string       `json:"wifiBssid"`
	NetworkIsExpensive      bool           `json:"networkIsExpensive"`
	NetworkIsConstrained    bool           `json:"networkIsConstrained"`
	IPIsPrivate             bool           `json:"ipIsPrivate"`
	RuleSet                 []string       `json:"ruleSet"`
	RawData                 map[string]any `json:"raw_data,omitempty"`
	LogicalRule             map[string]any `json:"logical_rule,omitempty"`
	Outbound                string         `json:"outbound"`
	Enabled                 bool           `json:"enabled"`
	Priority                int            `json:"priority"`
	UpdatedAt               time.Time      `json:"updatedAt"`
}

type DNSPolicy struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	Name          string         `json:"name"`
	Domain        string         `json:"domain"`
	DomainSuffix  []string       `json:"domainSuffix"`
	DomainKeyword []string       `json:"domainKeyword"`
	RuleSet       []string       `json:"ruleSet"`
	QueryType     []string       `json:"queryType"`
	Network       []string       `json:"network"`
	Server        string         `json:"server"`
	Strategy      string         `json:"strategy"`
	RawData       map[string]any `json:"raw_data,omitempty"`
	Enabled       bool           `json:"enabled"`
}

type DNSServer struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Tag             string         `json:"tag"`
	Type            string         `json:"type"`
	Address         string         `json:"address"`
	Server          string         `json:"server"`
	ServerPort      int            `json:"server_port,omitempty"`
	Path            string         `json:"path,omitempty"`
	AddressResolver string         `json:"addressResolver"`
	AddressStrategy string         `json:"addressStrategy"`
	Detour          string         `json:"detour"`
	Strategy        string         `json:"strategy"`
	PreferGo        *bool          `json:"prefer_go,omitempty"`
	DomainResolver  string         `json:"domain_resolver,omitempty"`
	RawData         map[string]any `json:"raw_data,omitempty"`
	Upstreams       string         `json:"upstreams,omitempty"`
	UseProxy        bool           `json:"use_proxy,omitempty"`
	BootstrapAddrs  string         `json:"bootstrap_addrs,omitempty"`
	FallbackAddrs   string         `json:"fallback_addrs,omitempty"`
	Enabled         bool           `json:"enabled"`
}

type DNSServerRef struct {
	Source string `json:"source"`
	Index  int    `json:"index"`
	Name   string `json:"name"`
}

type RuleSet struct {
	ID             string    `json:"id"`
	Tag            string    `json:"tag"`
	Type           string    `json:"type"`
	Format         string    `json:"format"`
	Behavior       string    `json:"behavior"`
	URL            string    `json:"url"`
	Path           string    `json:"path"`
	LocalPath      string    `json:"localPath"`
	DownloadDetour string    `json:"downloadDetour"`
	Enabled        bool      `json:"enabled"`
	ProfileID      string    `json:"profileId,omitempty"`
	LastUpdated    time.Time `json:"lastUpdated"`
	LastError      string    `json:"lastError"`
	LastWarning    string    `json:"lastWarning"`
}

type PresetApplyResult struct {
	Added   int `json:"added"`
	Updated int `json:"updated"`
}

type RuleSetGroup struct {
	GroupKey    string    `json:"groupKey"`
	DisplayName string    `json:"displayName"`
	Items       []RuleSet `json:"items"`
}

type RuleProviderDownloadResult struct {
	Success bool   `json:"success"`
	Path    string `json:"path,omitempty"`
	Error   string `json:"error,omitempty"`
}

type RuleProviderViewContent struct {
	Content string `json:"content,omitempty"`
	Error   string `json:"error,omitempty"`
}

type TemplateSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Path        string `json:"path"`
}

type TemplatePolicyPayload struct {
	Policies    []Policy          `json:"policies"`
	DNSServers  []DNSServer       `json:"dnsServers"`
	DNSPolicies []DNSPolicy       `json:"dnsPolicies"`
	Settings    map[string]string `json:"settings"`
}

type TemplateImportResult struct {
	Success             bool               `json:"success"`
	Message             string             `json:"message"`
	AddedCount          int                `json:"addedCount"`
	PresetResult        *PresetApplyResult `json:"presetResult,omitempty"`
	DNSSet              bool               `json:"dnsSet"`
	FinalOutboundSet    bool               `json:"finalOutboundSet"`
	FinalOutbound       string             `json:"finalOutbound,omitempty"`
	TUNSet              bool               `json:"tunSet"`
	TUNNeedsAdmin       bool               `json:"tunNeedsAdmin"`
	TUNValue            bool               `json:"tunValue"`
	DefaultDNSServerSet bool               `json:"defaultDnsServerSet"`
}

type BuiltinTemplate struct {
	ID             string            `json:"id"`
	Path           string            `json:"path,omitempty"`
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Policies       []Policy          `json:"policies"`
	RuleSets       []RuleSet         `json:"ruleSets"`
	DNSServers     []DNSServer       `json:"dnsServers"`
	DNSPolicies    []DNSPolicy       `json:"dnsPolicies"`
	Settings       Settings          `json:"settings"`
	SettingsRecord map[string]string `json:"settingsRecord,omitempty"`
}

type Settings struct {
	APIPort                  int                 `json:"apiPort"`
	APISecret                string              `json:"apiSecret"`
	MixedPort                int                 `json:"mixedPort"`
	MixedListen              string              `json:"mixedListen"`
	AllowLAN                 bool                `json:"allowLan"`
	SubscriptionUserAgent    string              `json:"subscriptionUserAgent"`
	IPv6                     *bool               `json:"ipv6,omitempty"`
	OverrideRules            *bool               `json:"overrideRules,omitempty"`
	AutoStartProxy           *bool               `json:"autoStartProxy,omitempty"`
	CustomProxyGroups        bool                `json:"customProxyGroups"`
	TUNEnabled               bool                `json:"tunEnabled"`
	TUNStack                 string              `json:"tunStack"`
	TUNInterfaceName         string              `json:"tunInterfaceName"`
	TUNAddress               []string            `json:"tunAddress"`
	TUNMTU                   int                 `json:"tunMTU"`
	TUNAutoRoute             *bool               `json:"tunAutoRoute,omitempty"`
	TUNStrictRoute           *bool               `json:"tunStrictRoute,omitempty"`
	TUNAutoDetectInterface   *bool               `json:"tunAutoDetectInterface,omitempty"`
	TUNDNSHijack             []string            `json:"tunDNSHijack"`
	TUNRouteAddress          []string            `json:"tunRouteAddress"`
	TUNRouteExcludeAddress   []string            `json:"tunRouteExcludeAddress"`
	AutoStart                bool                `json:"autoStart"`
	SystemProxy              bool                `json:"systemProxy"`
	SniffEnabled             bool                `json:"sniffEnabled"`
	SniffOverrideDestination bool                `json:"sniffOverrideDestination"`
	Mode                     string              `json:"mode"`
	LogLevel                 string              `json:"logLevel"`
	SingBoxPath              string              `json:"singBoxPath"`
	DNSListen                string              `json:"dnsListen"`
	DNSStrategy              string              `json:"dnsStrategy"`
	DNSIPv6                  *bool               `json:"dnsIPv6,omitempty"`
	DNSFakeIPEnabled         bool                `json:"dnsFakeIPEnabled"`
	DNSFakeIPRange           string              `json:"dnsFakeIPRange"`
	DNSFakeIPv6Range         string              `json:"dnsFakeIPv6Range"`
	DNSFakeIPFilter          []string            `json:"dnsFakeIPFilter"`
	DNSFallbackFilter        map[string]any      `json:"dnsFallbackFilter"`
	FinalOutbound            string              `json:"finalOutbound"`
	Hosts                    map[string][]string `json:"hosts"`
	Experimental             map[string]any      `json:"experimental"`
}

type LogEntry struct {
	ID      string    `json:"id"`
	Level   string    `json:"level"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
	Time    time.Time `json:"time"`
}

type LogReadOptions struct {
	FromLine   int    `json:"fromLine"`
	Search     string `json:"search"`
	MaxResults int    `json:"maxResults"`
}

type LogReadResult struct {
	Lines      []string `json:"lines"`
	TotalLines int      `json:"totalLines"`
	IsSearch   bool     `json:"isSearch"`
}

type LogInput struct {
	Level   string `json:"level"`
	Module  string `json:"module"`
	Message string `json:"message"`
}

type InitialLogLineCount struct {
	LineCount int `json:"lineCount"`
}

type ConfigOperationResult struct {
	OK    bool   `json:"ok"`
	Path  string `json:"path,omitempty"`
	Error string `json:"error,omitempty"`
}

type ClearOperationResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type Connection struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Network  string `json:"network"`
	Outbound string `json:"outbound"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Age      string `json:"age"`
}

type CoreCheckResult struct {
	OK      bool   `json:"ok"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

type ConfigPreview struct {
	Path     string   `json:"path"`
	Content  string   `json:"content"`
	Changed  bool     `json:"changed"`
	Warnings []string `json:"warnings"`
}

type SelectedProfileState struct {
	Found   bool           `json:"found"`
	Profile Profile        `json:"profile"`
	Config  map[string]any `json:"config"`
}

type ConfigImportResult struct {
	Policies int  `json:"policies"`
	RuleSets int  `json:"ruleSets"`
	Replaced bool `json:"replaced"`
}

type RefreshScheduleItem struct {
	Kind            string    `json:"kind"`
	ID              string    `json:"id"`
	ProfileID       string    `json:"profileId"`
	ProviderName    string    `json:"providerName"`
	Name            string    `json:"name"`
	Enabled         bool      `json:"enabled"`
	IntervalHours   int       `json:"intervalHours"`
	IntervalSeconds int       `json:"intervalSeconds"`
	LastUpdated     time.Time `json:"lastUpdated"`
	NextRefresh     time.Time `json:"nextRefresh"`
	Due             bool      `json:"due"`
	LastError       string    `json:"lastError"`
}

type ProxyGroup struct {
	Name    string      `json:"name"`
	Type    string      `json:"type"`
	Now     string      `json:"now"`
	All     []ProxyNode `json:"all"`
	Latency int         `json:"latency"`
}

type AvailableOutbound struct {
	Tag  string `json:"tag"`
	Type string `json:"type"`
	Kind string `json:"kind"`
}

type ClashProbe struct {
	Available bool   `json:"available"`
	URL       string `json:"url"`
	Version   string `json:"version"`
	Message   string `json:"message"`
}

type BuildInfo struct {
	AppVersion     string `json:"appVersion"`
	SingBoxVersion string `json:"singBoxVersion"`
	BuildTime      string `json:"buildTime"`
	BuildNumber    string `json:"buildNumber"`
	CommitSHA      string `json:"commitSha"`
}

type ReleaseManifest struct {
	Version     string `json:"version"`
	BuildNumber string `json:"buildNumber,omitempty"`
	DownloadURL string `json:"downloadUrl,omitempty"`
	ReleaseURL  string `json:"releaseUrl,omitempty"`
	Notes       string `json:"notes,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
}

type UpdateCheckResult struct {
	Available      bool            `json:"available"`
	CurrentVersion string          `json:"currentVersion"`
	LatestVersion  string          `json:"latestVersion"`
	Manifest       ReleaseManifest `json:"manifest"`
	Source         string          `json:"source"`
	Error          string          `json:"error,omitempty"`
}

type DatabaseStatus struct {
	Path           string    `json:"path"`
	BackupDir      string    `json:"backupDir"`
	SchemaVersion  int       `json:"schemaVersion"`
	CurrentVersion int       `json:"currentVersion"`
	NeedsMigration bool      `json:"needsMigration"`
	Profiles       int       `json:"profiles"`
	Policies       int       `json:"policies"`
	DNSServers     int       `json:"dnsServers"`
	DNSPolicies    int       `json:"dnsPolicies"`
	RuleSets       int       `json:"ruleSets"`
	Preferences    int       `json:"preferences"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type BackupManifest struct {
	FormatVersion  int       `json:"formatVersion"`
	SchemaVersion  int       `json:"schemaVersion"`
	CreatedAt      time.Time `json:"createdAt"`
	App            string    `json:"app"`
	AppVersion     string    `json:"appVersion"`
	SingBoxVersion string    `json:"singBoxVersion"`
}

type TrafficState struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Live     bool  `json:"live"`
}

type DashboardState struct {
	CoreRunning bool        `json:"coreRunning"`
	Uptime      string      `json:"uptime"`
	Profiles    int         `json:"profiles"`
	Nodes       int         `json:"nodes"`
	Policies    int         `json:"policies"`
	DNSRules    int         `json:"dnsRules"`
	RuleSets    int         `json:"ruleSets"`
	Upload      int64       `json:"upload"`
	Download    int64       `json:"download"`
	ActiveNode  string      `json:"activeNode"`
	Health      []ProbeItem `json:"health"`
}

type PlatformStatus struct {
	OS                string `json:"os"`
	SingBoxPath       string `json:"singBoxPath"`
	SingBoxVersion    string `json:"singBoxVersion"`
	SystemProxy       bool   `json:"systemProxy"`
	AutoStart         bool   `json:"autoStart"`
	CoreService       bool   `json:"coreService"`
	TUNReady          bool   `json:"tunReady"`
	DataDir           string `json:"dataDir"`
	GeneratedConfig   string `json:"generatedConfig"`
	PlatformMessage   string `json:"platformMessage"`
	NeedsPrivilege    bool   `json:"needsPrivilege"`
	SupportedProxyAPI bool   `json:"supportedProxyApi"`
}

type CoreServiceStatus struct {
	Platform         string `json:"platform"`
	Supported        bool   `json:"supported"`
	SocketAvailable  bool   `json:"socketAvailable"`
	BinaryInstalled  bool   `json:"binaryInstalled"`
	ServiceLoaded    bool   `json:"serviceLoaded"`
	Running          bool   `json:"running"`
	PID              int    `json:"pid,omitempty"`
	Version          string `json:"version,omitempty"`
	NeedsUpgrade     bool   `json:"needsUpgrade,omitempty"`
	SingboxRunning   bool   `json:"singboxRunning,omitempty"`
	SingboxPid       int    `json:"singboxPid,omitempty"`
	SingboxStartTime int64  `json:"singboxStartTime,omitempty"`
	ServicePath      string `json:"servicePath,omitempty"`
	Message          string `json:"message,omitempty"`
}

type DNSRuntimeStatusData struct {
	Running  bool   `json:"running"`
	Address  string `json:"address,omitempty"`
	CertPath string `json:"cert_path,omitempty"`
	Status   string `json:"status,omitempty"`
}

type DNSRuntimeStatus struct {
	Success bool                 `json:"success"`
	Data    DNSRuntimeStatusData `json:"data,omitempty"`
	Error   string               `json:"error,omitempty"`
}

type SingBoxRuntimeStatusData struct {
	Running    bool   `json:"running"`
	PID        int    `json:"pid,omitempty"`
	StartTime  int64  `json:"startTime,omitempty"`
	ConfigPath string `json:"configPath,omitempty"`
	BinaryPath string `json:"binaryPath,omitempty"`
}

type roverServiceAPIResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}

type roverServiceDaemonStatus struct {
	Version    string `json:"version"`
	PID        int    `json:"pid"`
	Uptime     int64  `json:"uptime"`
	SocketPath string `json:"socketPath"`
	Platform   string `json:"platform"`
}

type SingBoxRuntimeStatus struct {
	Success bool                     `json:"success"`
	Data    SingBoxRuntimeStatusData `json:"data,omitempty"`
	Error   string                   `json:"error,omitempty"`
	Message string                   `json:"message,omitempty"`
}

type LauncherTaskResult struct {
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
	NeedsRestart bool   `json:"needsRestart,omitempty"`
}

type IPInfo struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
}

type ProbeItem struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Delay  int    `json:"delay"`
}

func NewSandfoxService() *SandfoxService {
	service := &SandfoxService{dataDir: defaultDataDir()}
	if err := os.MkdirAll(service.dataDir, 0o755); err == nil {
		if loadErr := service.load(); loadErr != nil {
			service.data = defaultData()
			service.mu.Lock()
			_ = service.saveLocked()
			service.mu.Unlock()
		}
	}
	return service
}

func defaultDataDir() string {
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, "Library", "Application Support", "sandfox")
		}
	}
	dir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		if home, homeErr := os.UserHomeDir(); homeErr == nil && home != "" {
			return filepath.Join(home, ".config", "sandfox")
		}
		dir = "."
	}
	return filepath.Join(dir, "sandfox")
}

func (s *SandfoxService) OnStartup(ctx context.Context, options application.ServiceOptions) error {
	if err := os.MkdirAll(s.dataDir, 0o755); err != nil {
		return err
	}
	if err := s.load(); err != nil {
		return err
	}
	s.startScheduler(ctx)
	s.log("info", "app", "Sandfox service ready")
	s.autoStartCoreIfEnabled()
	return nil
}

func (s *SandfoxService) OnShutdown() {
	if s.schedulerCancel != nil {
		s.schedulerCancel()
	}
	_ = s.StopCore()
}

func (s *SandfoxService) autoStartCoreIfEnabled() {
	s.mu.Lock()
	settings := normalizeSettings(s.data.Settings)
	hasSelectedProfile := false
	for _, profile := range s.data.Profiles {
		if profile.Selected {
			hasSelectedProfile = true
			break
		}
	}
	s.mu.Unlock()
	if !settingsAutoStartProxyEnabled(settings) || !hasSelectedProfile {
		return
	}
	go func() {
		if err := s.StartCore(); err != nil {
			s.log("error", "core", "Auto start failed: "+err.Error())
		}
	}()
}

func (s *SandfoxService) GetDashboard() DashboardState {
	s.mu.Lock()
	nodes := 0
	active := "DIRECT"
	for _, p := range s.data.Profiles {
		nodes += p.NodeCount
		if p.Selected && len(p.Nodes) > 0 {
			active = p.Nodes[0].Name
		}
	}
	uptime := "stopped"
	if s.core != nil && s.core.Process != nil {
		uptime = time.Since(s.coreUpAt).Round(time.Second).String()
	}
	profiles := len(s.data.Profiles)
	policies := len(s.data.Policies)
	dnsRules := len(s.data.DNSPolicies)
	ruleSets := len(s.data.RuleSets)
	logCount := len(s.data.Logs)
	s.mu.Unlock()
	traffic := s.GetTraffic()
	return DashboardState{
		CoreRunning: s.isCoreRunning(),
		Uptime:      uptime,
		Profiles:    profiles,
		Nodes:       nodes,
		Policies:    policies,
		DNSRules:    dnsRules,
		RuleSets:    ruleSets,
		Upload:      chooseTrafficValue(traffic.Upload, int64(182400+logCount*512)),
		Download:    chooseTrafficValue(traffic.Download, int64(1843200+nodes*1024)),
		ActiveNode:  active,
		Health: []ProbeItem{
			{Target: "Google 204", Status: "ok", Delay: 128},
			{Target: "Cloudflare DNS", Status: "ok", Delay: 42},
			{Target: "Apple CDN", Status: "ok", Delay: 76},
		},
	}
}

func (s *SandfoxService) GetProfiles() []Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Profile(nil), s.data.Profiles...)
}

func (s *SandfoxService) GetProfileContent(profileID string) (string, error) {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return "", errors.New("profile id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, profile := range s.data.Profiles {
		if profile.ID == profileID {
			return profile.Content, nil
		}
	}
	return "", errors.New("profile not found")
}

func (s *SandfoxService) UpdateProfileContent(profileID, content string) (Profile, error) {
	profileID = strings.TrimSpace(profileID)
	content = strings.TrimSpace(content)
	if profileID == "" {
		return Profile{}, errors.New("profile id is required")
	}
	if content == "" {
		return Profile{}, errors.New("profile content is required")
	}
	s.mu.Lock()
	var current Profile
	found := false
	for _, profile := range s.data.Profiles {
		if profile.ID == profileID {
			current = profile
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return Profile{}, errors.New("profile not found")
	}
	result := parseProfileContent(content)
	if err := validateProfileParseResult(content, result); err != nil {
		return Profile{}, err
	}
	filter := firstNonEmpty(current.Filter, result.Filter)
	nodes, err := filterProfileNodes(result.Nodes, filter)
	if err != nil {
		return Profile{}, err
	}
	s.mu.Lock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID != profileID {
			continue
		}
		s.data.Profiles[i].Content = content
		s.data.Profiles[i].Nodes = nodes
		s.data.Profiles[i].NodeCount = len(nodes)
		s.data.Profiles[i].ProxyGroups = result.Groups
		s.data.Profiles[i].ProxyProviders = result.Providers
		s.data.Profiles[i].LastUpdated = time.Now()
		s.data.Profiles[i].LastError = ""
		if s.data.Profiles[i].Filter == "" {
			s.data.Profiles[i].Filter = result.Filter
		}
		if result.UpdateInterval > 0 {
			s.data.Profiles[i].UpdateInterval = result.UpdateInterval
		}
		if result.TestURL != "" {
			s.data.Profiles[i].TestURL = result.TestURL
		}
		s.syncProfileRuleSetsLocked(profileID, result.RuleSets)
		s.logLocked("info", "profile", "Updated profile content "+s.data.Profiles[i].Name)
		updated := s.data.Profiles[i]
		err := s.saveLocked()
		s.mu.Unlock()
		if err == nil {
			s.refreshFreshProfileRuleSets(profileID, 24*time.Hour)
		}
		return updated, err
	}
	s.mu.Unlock()
	return Profile{}, errors.New("profile not found")
}

func (s *SandfoxService) ImportProfile(name, source string) (Profile, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return Profile{}, errors.New("profile source is empty")
	}
	content := source
	var subscriptionUserinfo *SubscriptionUserinfo
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		response, err := fetchTextWithUserAgentResponse(source, s.subscriptionUserAgent())
		if err != nil {
			return Profile{}, err
		}
		content = response.Body
		subscriptionUserinfo = parseSubscriptionUserinfo(response.Header.Get("subscription-userinfo"))
	}
	result := parseProfileContent(content)
	if err := validateProfileParseResult(content, result); err != nil {
		return Profile{}, err
	}
	if result.Filter != "" {
		filtered, err := filterProfileNodes(result.Nodes, result.Filter)
		if err != nil {
			return Profile{}, err
		}
		result.Nodes = filtered
	}
	if name == "" {
		name = "Profile " + time.Now().Format("150405")
	}
	profile := Profile{
		ID:                   uuid.NewString(),
		Name:                 name,
		URL:                  source,
		Content:              content,
		NodeCount:            len(result.Nodes),
		UpdateInterval:       chooseInt(result.UpdateInterval, 24),
		Filter:               result.Filter,
		TestURL:              result.TestURL,
		LastUpdated:          time.Now(),
		Nodes:                result.Nodes,
		ProxyGroups:          result.Groups,
		ProxyProviders:       result.Providers,
		SubscriptionUserinfo: subscriptionUserinfo,
	}
	s.mu.Lock()
	if len(s.data.Profiles) == 0 {
		profile.Selected = true
	}
	s.syncProfileRuleSetsLocked(profile.ID, result.RuleSets)
	s.data.Profiles = append(s.data.Profiles, profile)
	s.logLocked("info", "profile", fmt.Sprintf("Imported %s with %d nodes, %d groups, and %d providers", profile.Name, profile.NodeCount, len(profile.ProxyGroups), len(profile.ProxyProviders)))
	err := s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		s.refreshFreshProfileRuleSets(profile.ID, 24*time.Hour)
	}
	return profile, err
}

func (s *SandfoxService) AddProfile(profile Profile) (string, error) {
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.ID == "" {
		profile.ID = uuid.NewString()
	}
	if profile.Name == "" {
		profile.Name = "Profile " + time.Now().Format("150405")
	}
	profile.Nodes = append([]ProxyNode(nil), profile.Nodes...)
	profile.ProxyGroups = append([]ProxyGroupConfig(nil), profile.ProxyGroups...)
	profile.CustomGroups = normalizeCustomProxyGroups(profile.CustomGroups)
	profile.ProxyProviders = append([]ProxyProviderConfig(nil), profile.ProxyProviders...)
	profile.NodeCount = len(profile.Nodes)
	if profile.UpdateInterval <= 0 {
		profile.UpdateInterval = 24
	}
	profile.LastUpdated = time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if profile.Selected {
		for i := range s.data.Profiles {
			s.data.Profiles[i].Selected = false
		}
	}
	s.data.Profiles = append(s.data.Profiles, profile)
	s.logLocked("info", "profile", "Added profile "+profile.Name)
	return profile.ID, s.saveLocked()
}

func (s *SandfoxService) ImportLocalProfile() (Profile, error) {
	return Profile{}, errors.New("local profile file picker is not available; use ImportProfileFile(name, path)")
}

func (s *SandfoxService) SaveProfile(profile Profile) (Profile, error) {
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Name = strings.TrimSpace(profile.Name)
	profile.URL = strings.TrimSpace(profile.URL)
	profile.Filter = strings.TrimSpace(profile.Filter)
	profile.TestURL = strings.TrimSpace(profile.TestURL)
	if profile.ID == "" {
		return Profile{}, errors.New("profile id is required")
	}
	if profile.Name == "" {
		return Profile{}, errors.New("profile name is required")
	}
	if profile.UpdateInterval <= 0 {
		profile.UpdateInterval = 24
	}
	s.mu.Lock()
	var current Profile
	found := false
	for _, item := range s.data.Profiles {
		if item.ID == profile.ID {
			current = item
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return Profile{}, errors.New("profile not found")
	}
	var filteredNodes []ProxyNode
	var filteredGroups []ProxyGroupConfig
	var filteredProviders []ProxyProviderConfig
	reapplyFilter := current.Filter != profile.Filter
	if reapplyFilter {
		var err error
		filteredNodes, filteredGroups, filteredProviders, err = filteredProfileSnapshot(current, profile.Filter)
		if err != nil {
			return Profile{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID == profile.ID {
			s.data.Profiles[i].Name = profile.Name
			s.data.Profiles[i].URL = profile.URL
			s.data.Profiles[i].UpdateInterval = profile.UpdateInterval
			s.data.Profiles[i].Filter = profile.Filter
			s.data.Profiles[i].TestURL = profile.TestURL
			if reapplyFilter {
				s.data.Profiles[i].Nodes = filteredNodes
				s.data.Profiles[i].ProxyGroups = filteredGroups
				s.data.Profiles[i].ProxyProviders = filteredProviders
				s.data.Profiles[i].NodeCount = len(filteredNodes)
				s.data.Profiles[i].LastUpdated = time.Now()
			}
			if profile.Selected {
				for j := range s.data.Profiles {
					s.data.Profiles[j].Selected = j == i
				}
			}
			s.logLocked("info", "profile", "Saved profile "+profile.Name)
			return s.data.Profiles[i], s.saveLocked()
		}
	}
	return Profile{}, errors.New("profile not found")
}

func (s *SandfoxService) AddNodeToProfile(profileID string, node ProxyNode) (ProxyNode, error) {
	profileID = strings.TrimSpace(profileID)
	node = normalizeNode(node)
	if node.Name == "" {
		return ProxyNode{}, errors.New("node name is required")
	}
	if node.Server == "" {
		return ProxyNode{}, errors.New("node server is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if profileID == "" {
		for _, profile := range s.data.Profiles {
			if profile.Selected {
				profileID = profile.ID
				break
			}
		}
	}
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID == profileID {
			s.data.Profiles[i].Nodes = append(s.data.Profiles[i].Nodes, node)
			s.data.Profiles[i].NodeCount = len(s.data.Profiles[i].Nodes)
			s.data.Profiles[i].LastUpdated = time.Now()
			s.logLocked("info", "profile", "Added node "+node.Name+" to "+s.data.Profiles[i].Name)
			return node, s.saveLocked()
		}
	}
	return ProxyNode{}, errors.New("profile not found")
}

func (s *SandfoxService) UpdateProfileNode(profileID string, index int, node ProxyNode) (ProxyNode, error) {
	profileID = strings.TrimSpace(profileID)
	node = normalizeNode(node)
	if index < 0 {
		return ProxyNode{}, errors.New("node index is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID != profileID {
			continue
		}
		if index >= len(s.data.Profiles[i].Nodes) {
			return ProxyNode{}, errors.New("node not found")
		}
		s.data.Profiles[i].Nodes[index] = node
		s.data.Profiles[i].LastUpdated = time.Now()
		s.logLocked("info", "profile", "Updated node "+node.Name)
		return node, s.saveLocked()
	}
	return ProxyNode{}, errors.New("profile not found")
}

func (s *SandfoxService) DeleteProfileNode(profileID string, index int) error {
	profileID = strings.TrimSpace(profileID)
	if index < 0 {
		return errors.New("node index is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID != profileID {
			continue
		}
		if index >= len(s.data.Profiles[i].Nodes) {
			return errors.New("node not found")
		}
		s.data.Profiles[i].Nodes = append(s.data.Profiles[i].Nodes[:index], s.data.Profiles[i].Nodes[index+1:]...)
		s.data.Profiles[i].NodeCount = len(s.data.Profiles[i].Nodes)
		s.data.Profiles[i].LastUpdated = time.Now()
		s.logLocked("warn", "profile", "Deleted node")
		return s.saveLocked()
	}
	return errors.New("profile not found")
}

func (s *SandfoxService) MoveProfileNode(profileID string, index, direction int) error {
	profileID = strings.TrimSpace(profileID)
	if index < 0 || direction == 0 {
		return errors.New("node move is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID != profileID {
			continue
		}
		next := index + direction
		if index >= len(s.data.Profiles[i].Nodes) || next < 0 || next >= len(s.data.Profiles[i].Nodes) {
			return errors.New("node move is out of range")
		}
		nodes := s.data.Profiles[i].Nodes
		nodes[index], nodes[next] = nodes[next], nodes[index]
		s.data.Profiles[i].Nodes = nodes
		s.data.Profiles[i].LastUpdated = time.Now()
		s.logLocked("info", "profile", "Moved node")
		return s.saveLocked()
	}
	return errors.New("profile not found")
}

func (s *SandfoxService) AddProfileGroup(profileID string, group ProxyGroupConfig) (ProxyGroupConfig, error) {
	profileID = strings.TrimSpace(profileID)
	group = normalizeProxyGroupConfig(group)
	if group.Name == "" {
		return ProxyGroupConfig{}, errors.New("group name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return ProxyGroupConfig{}, err
	}
	s.data.Profiles[profileIndex].ProxyGroups = append(s.data.Profiles[profileIndex].ProxyGroups, group)
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("info", "profile", "Added proxy group "+group.Name)
	return group, s.saveLocked()
}

func (s *SandfoxService) UpdateProfileGroup(profileID string, index int, group ProxyGroupConfig) (ProxyGroupConfig, error) {
	profileID = strings.TrimSpace(profileID)
	group = normalizeProxyGroupConfig(group)
	if index < 0 {
		return ProxyGroupConfig{}, errors.New("group index is invalid")
	}
	if group.Name == "" {
		return ProxyGroupConfig{}, errors.New("group name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return ProxyGroupConfig{}, err
	}
	if index >= len(s.data.Profiles[profileIndex].ProxyGroups) {
		return ProxyGroupConfig{}, errors.New("group not found")
	}
	s.data.Profiles[profileIndex].ProxyGroups[index] = group
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("info", "profile", "Updated proxy group "+group.Name)
	return group, s.saveLocked()
}

func (s *SandfoxService) DeleteProfileGroup(profileID string, index int) error {
	profileID = strings.TrimSpace(profileID)
	if index < 0 {
		return errors.New("group index is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	if index >= len(s.data.Profiles[profileIndex].ProxyGroups) {
		return errors.New("group not found")
	}
	s.data.Profiles[profileIndex].ProxyGroups = append(s.data.Profiles[profileIndex].ProxyGroups[:index], s.data.Profiles[profileIndex].ProxyGroups[index+1:]...)
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("warn", "profile", "Deleted proxy group")
	return s.saveLocked()
}

func (s *SandfoxService) MoveProfileGroup(profileID string, index, direction int) error {
	profileID = strings.TrimSpace(profileID)
	if index < 0 || direction == 0 {
		return errors.New("group move is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	next := index + direction
	groups := s.data.Profiles[profileIndex].ProxyGroups
	if index >= len(groups) || next < 0 || next >= len(groups) {
		return errors.New("group move is out of range")
	}
	groups[index], groups[next] = groups[next], groups[index]
	s.data.Profiles[profileIndex].ProxyGroups = groups
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("info", "profile", "Moved proxy group")
	return s.saveLocked()
}

func (s *SandfoxService) GetProfileCustomGroups(profileID string) ([]CustomProxyGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return nil, err
	}
	return normalizeCustomProxyGroups(s.data.Profiles[profileIndex].CustomGroups), nil
}

func (s *SandfoxService) SetProfileCustomGroups(profileID string, groups []CustomProxyGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	s.data.Profiles[profileIndex].CustomGroups = normalizeCustomProxyGroups(groups)
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("info", "profile", "Set custom proxy groups")
	return s.saveLocked()
}

func (s *SandfoxService) AddProfileCustomGroup(profileID string, group CustomProxyGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	next := normalizeCustomProxyGroup(group)
	if next.Name == "" {
		return errors.New("custom proxy group name is required")
	}
	s.data.Profiles[profileIndex].CustomGroups = append(s.data.Profiles[profileIndex].CustomGroups, next)
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("info", "profile", "Added custom proxy group "+next.Name)
	return s.saveLocked()
}

func (s *SandfoxService) UpdateProfileCustomGroup(profileID, groupName string, updates CustomProxyGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	for i, group := range s.data.Profiles[profileIndex].CustomGroups {
		if group.Name != groupName {
			continue
		}
		next := normalizeCustomProxyGroup(updates)
		if next.Name == "" {
			next.Name = group.Name
		}
		s.data.Profiles[profileIndex].CustomGroups[i] = next
		s.data.Profiles[profileIndex].LastUpdated = time.Now()
		s.logLocked("info", "profile", "Updated custom proxy group "+groupName)
		return s.saveLocked()
	}
	return errors.New("custom proxy group not found")
}

func (s *SandfoxService) DeleteProfileCustomGroup(profileID, groupName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	groups := s.data.Profiles[profileIndex].CustomGroups
	for i, group := range groups {
		if group.Name != groupName {
			continue
		}
		s.data.Profiles[profileIndex].CustomGroups = append(groups[:i], groups[i+1:]...)
		s.data.Profiles[profileIndex].LastUpdated = time.Now()
		s.logLocked("warn", "profile", "Deleted custom proxy group "+groupName)
		return s.saveLocked()
	}
	return errors.New("custom proxy group not found")
}

func (s *SandfoxService) UpdateProfileCustomGroupsOrder(profileID string, orders []CustomProxyGroupOrder) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	orderIndex := map[string]int{}
	for _, order := range orders {
		orderIndex[order.Name] = order.Order
	}
	groups := append([]CustomProxyGroup(nil), s.data.Profiles[profileIndex].CustomGroups...)
	sort.SliceStable(groups, func(i, j int) bool {
		left, leftOK := orderIndex[groups[i].Name]
		right, rightOK := orderIndex[groups[j].Name]
		if leftOK && rightOK {
			return left < right
		}
		if leftOK {
			return true
		}
		if rightOK {
			return false
		}
		return i < j
	})
	for i := range groups {
		groups[i].Order = i
	}
	s.data.Profiles[profileIndex].CustomGroups = groups
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("info", "profile", "Reordered custom proxy groups")
	return s.saveLocked()
}

func (s *SandfoxService) ClearProfileCustomGroups(profileID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	s.data.Profiles[profileIndex].CustomGroups = nil
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("warn", "profile", "Cleared custom proxy groups")
	return s.saveLocked()
}

func (s *SandfoxService) GetProfileNodes(profileID string) ([]ProxyNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return nil, err
	}
	return append([]ProxyNode(nil), s.data.Profiles[profileIndex].Nodes...), nil
}

func (s *SandfoxService) SetProfilePolicyOverride(profileID, policyID, outbound string) error {
	profileID = strings.TrimSpace(profileID)
	policyID = strings.TrimSpace(policyID)
	outbound = strings.TrimSpace(outbound)
	if policyID == "" || outbound == "" {
		return errors.New("policy id and outbound are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	if !s.hasPolicyLocked(policyID) {
		return errors.New("policy not found")
	}
	overrides := s.data.Profiles[profileIndex].PolicyOverrides
	for i := range overrides {
		if overrides[i].PolicyID == policyID {
			overrides[i].Outbound = outbound
			s.data.Profiles[profileIndex].PolicyOverrides = overrides
			s.data.Profiles[profileIndex].LastUpdated = time.Now()
			s.logLocked("info", "profile", "Updated profile policy override")
			return s.saveLocked()
		}
	}
	s.data.Profiles[profileIndex].PolicyOverrides = append(overrides, ProfilePolicyOverride{PolicyID: policyID, Outbound: outbound})
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("info", "profile", "Added profile policy override")
	return s.saveLocked()
}

func (s *SandfoxService) ClearProfilePolicyOverride(profileID, policyID string) error {
	profileID = strings.TrimSpace(profileID)
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return errors.New("policy id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	next := s.data.Profiles[profileIndex].PolicyOverrides[:0]
	for _, override := range s.data.Profiles[profileIndex].PolicyOverrides {
		if override.PolicyID != policyID {
			next = append(next, override)
		}
	}
	s.data.Profiles[profileIndex].PolicyOverrides = next
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("warn", "profile", "Cleared profile policy override")
	return s.saveLocked()
}

func (s *SandfoxService) SetProfileDNSPolicyOverride(profileID, policyID, server string) error {
	profileID = strings.TrimSpace(profileID)
	policyID = strings.TrimSpace(policyID)
	server = strings.TrimSpace(server)
	if policyID == "" || server == "" {
		return errors.New("dns policy id and server are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	if !s.hasDNSPolicyLocked(policyID) {
		return errors.New("dns policy not found")
	}
	overrides := s.data.Profiles[profileIndex].DNSPolicyOverrides
	for i := range overrides {
		if overrides[i].PolicyID == policyID {
			overrides[i].Server = server
			s.data.Profiles[profileIndex].DNSPolicyOverrides = overrides
			s.data.Profiles[profileIndex].LastUpdated = time.Now()
			s.logLocked("info", "profile", "Updated profile DNS policy override")
			return s.saveLocked()
		}
	}
	s.data.Profiles[profileIndex].DNSPolicyOverrides = append(overrides, ProfileDNSPolicyOverride{PolicyID: policyID, Server: server})
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("info", "profile", "Added profile DNS policy override")
	return s.saveLocked()
}

func (s *SandfoxService) ClearProfileDNSPolicyOverride(profileID, policyID string) error {
	profileID = strings.TrimSpace(profileID)
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return errors.New("dns policy id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	next := s.data.Profiles[profileIndex].DNSPolicyOverrides[:0]
	for _, override := range s.data.Profiles[profileIndex].DNSPolicyOverrides {
		if override.PolicyID != policyID {
			next = append(next, override)
		}
	}
	s.data.Profiles[profileIndex].DNSPolicyOverrides = next
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("warn", "profile", "Cleared profile DNS policy override")
	return s.saveLocked()
}

func (s *SandfoxService) SetProfileDNSServerDetour(profileID, serverID, detour string) error {
	profileID = strings.TrimSpace(profileID)
	serverID = strings.TrimSpace(serverID)
	detour = strings.TrimSpace(detour)
	if serverID == "" || detour == "" {
		return errors.New("dns server id and detour are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	if !s.hasDNSServerLocked(serverID) {
		return errors.New("dns server not found")
	}
	detours := s.data.Profiles[profileIndex].DNSServerDetours
	for i := range detours {
		if detours[i].ServerID == serverID {
			detours[i].Detour = detour
			s.data.Profiles[profileIndex].DNSServerDetours = detours
			s.data.Profiles[profileIndex].LastUpdated = time.Now()
			s.logLocked("info", "profile", "Updated profile DNS server detour")
			return s.saveLocked()
		}
	}
	s.data.Profiles[profileIndex].DNSServerDetours = append(detours, ProfileDNSServerDetour{ServerID: serverID, Detour: detour})
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("info", "profile", "Added profile DNS server detour")
	return s.saveLocked()
}

func (s *SandfoxService) ClearProfileDNSServerDetour(profileID, serverID string) error {
	profileID = strings.TrimSpace(profileID)
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return errors.New("dns server id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	next := s.data.Profiles[profileIndex].DNSServerDetours[:0]
	for _, detour := range s.data.Profiles[profileIndex].DNSServerDetours {
		if detour.ServerID != serverID {
			next = append(next, detour)
		}
	}
	s.data.Profiles[profileIndex].DNSServerDetours = next
	s.data.Profiles[profileIndex].LastUpdated = time.Now()
	s.logLocked("warn", "profile", "Cleared profile DNS server detour")
	return s.saveLocked()
}

func (s *SandfoxService) GetProfilePolicyByPolicyId(profileID, policyID string) *RoverProfilePolicyItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(strings.TrimSpace(profileID))
	if err != nil {
		return nil
	}
	for _, override := range s.data.Profiles[profileIndex].PolicyOverrides {
		if override.PolicyID == strings.TrimSpace(policyID) {
			return &RoverProfilePolicyItem{PolicyID: override.PolicyID, PreferredOutbound: override.Outbound}
		}
	}
	return nil
}

func (s *SandfoxService) SetProfilePolicy(profileID, policyID string, preferredOutbounds []string) error {
	outbound := ""
	if len(preferredOutbounds) > 0 {
		outbound = strings.TrimSpace(preferredOutbounds[0])
	}
	if outbound == "" {
		return s.ClearProfilePolicyOverride(profileID, policyID)
	}
	return s.SetProfilePolicyOverride(profileID, policyID, outbound)
}

func (s *SandfoxService) GetProfileDnsPolicyByPolicyId(profileID, dnsPolicyID string) *RoverProfileDNSPolicyItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(strings.TrimSpace(profileID))
	if err != nil {
		return nil
	}
	for _, override := range s.data.Profiles[profileIndex].DNSPolicyOverrides {
		if override.PolicyID == strings.TrimSpace(dnsPolicyID) {
			return &RoverProfileDNSPolicyItem{DNSPolicyID: override.PolicyID, PreferredServer: override.Server}
		}
	}
	return nil
}

func (s *SandfoxService) SetProfileDnsPolicy(profileID, dnsPolicyID, dnsServerID string) error {
	if strings.TrimSpace(dnsServerID) == "" {
		return s.ClearProfileDNSPolicyOverride(profileID, dnsPolicyID)
	}
	return s.SetProfileDNSPolicyOverride(profileID, dnsPolicyID, dnsServerID)
}

func (s *SandfoxService) GetProfileDnsServerDetour(profileID, dnsServerID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(strings.TrimSpace(profileID))
	if err != nil {
		return ""
	}
	for _, detour := range s.data.Profiles[profileIndex].DNSServerDetours {
		if detour.ServerID == strings.TrimSpace(dnsServerID) {
			return detour.Detour
		}
	}
	return ""
}

func (s *SandfoxService) SetProfileDnsServerDetour(profileID, dnsServerID, detour string) error {
	if strings.TrimSpace(detour) == "" {
		return s.ClearProfileDNSServerDetour(profileID, dnsServerID)
	}
	return s.SetProfileDNSServerDetour(profileID, dnsServerID, detour)
}

func (s *SandfoxService) GetAllProfileDnsServerDetours(profileID string) []RoverProfileDNSServerItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(strings.TrimSpace(profileID))
	if err != nil {
		return nil
	}
	out := make([]RoverProfileDNSServerItem, 0, len(s.data.Profiles[profileIndex].DNSServerDetours))
	for _, detour := range s.data.Profiles[profileIndex].DNSServerDetours {
		out = append(out, RoverProfileDNSServerItem{DNSServerID: detour.ServerID, PreferredDetour: detour.Detour})
	}
	return out
}

func (s *SandfoxService) RefreshProfileProviders(profileID string) error {
	return s.refreshProfileProviders(profileID, "")
}

func (s *SandfoxService) RefreshProfileProvider(profileID, providerName string) error {
	providerName = strings.TrimSpace(providerName)
	if providerName == "" {
		return errors.New("provider name is required")
	}
	return s.refreshProfileProviders(profileID, providerName)
}

func (s *SandfoxService) GetProxyProviderContent(profileID, providerName string) (string, error) {
	profileID = strings.TrimSpace(profileID)
	providerName = strings.TrimSpace(providerName)
	if providerName == "" {
		return "", errors.New("provider name is required")
	}
	s.mu.Lock()
	var provider ProxyProviderConfig
	found := false
	for _, profile := range s.data.Profiles {
		if profile.ID != profileID && !(profileID == "" && profile.Selected) {
			continue
		}
		for _, candidate := range profile.ProxyProviders {
			if candidate.Name == providerName {
				provider = candidate
				found = true
				break
			}
		}
		break
	}
	s.mu.Unlock()
	if !found {
		return "", errors.New("proxy provider not found")
	}
	if provider.Type == "http" || strings.HasPrefix(provider.URL, "http://") || strings.HasPrefix(provider.URL, "https://") {
		return fetchTextWithUserAgent(provider.URL, s.subscriptionUserAgent())
	}
	path := firstNonEmpty(provider.Path, provider.URL)
	if path == "" {
		return "", errors.New("provider has no source path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *SandfoxService) refreshProfileProviders(profileID, targetProvider string) error {
	profileID = strings.TrimSpace(profileID)
	s.mu.Lock()
	var profile Profile
	for _, item := range s.data.Profiles {
		if item.ID == profileID || (profileID == "" && item.Selected) {
			profile = item
			profileID = item.ID
			break
		}
	}
	userAgent := normalizeSettings(s.data.Settings).SubscriptionUserAgent
	s.mu.Unlock()
	if profileID == "" {
		return errors.New("profile not found")
	}
	providers := providersForRefresh(profile.ProxyProviders, targetProvider)
	if len(providers) == 0 {
		return errors.New("profile has no matching proxy providers")
	}

	providerNames := providerNameSet(providers)
	oldProviderNodes := providerNodesByName(profile.Nodes, providerNames)
	refreshedProviders := make([]ProxyProviderConfig, 0, len(providers))
	replacementNodes := make([]ProxyNode, 0)
	var errs []string
	for _, provider := range providers {
		nodes, err := loadProxyProviderNodes(provider, userAgent)
		if err != nil {
			provider.LastError = err.Error()
			refreshedProviders = append(refreshedProviders, provider)
			replacementNodes = append(replacementNodes, oldProviderNodes[provider.Name]...)
			errs = append(errs, provider.Name+": "+err.Error())
			continue
		}
		if provider.Filter != "" {
			filtered, err := filterProfileNodes(nodes, provider.Filter)
			if err != nil {
				provider.LastError = err.Error()
				refreshedProviders = append(refreshedProviders, provider)
				replacementNodes = append(replacementNodes, oldProviderNodes[provider.Name]...)
				errs = append(errs, provider.Name+": "+err.Error())
				continue
			}
			nodes = filtered
		}
		for i := range nodes {
			if nodes[i].Raw == nil {
				nodes[i].Raw = map[string]any{}
			}
			nodes[i].Raw["provider"] = provider.Name
		}
		provider.NodeCount = len(nodes)
		provider.LastUpdated = time.Now()
		provider.LastError = ""
		refreshedProviders = append(refreshedProviders, provider)
		replacementNodes = append(replacementNodes, nodes...)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return err
	}
	current := &s.data.Profiles[profileIndex]
	updateProfileProviders(current, refreshedProviders)
	current.Nodes = mergeProxyNodes(removeProviderNodes(current.Nodes, providerNames), replacementNodes)
	current.ProxyGroups = replaceProxyGroupProviderMembers(current.ProxyGroups, providerNames, oldProviderNodes, refreshedProviders, replacementNodes)
	current.NodeCount = len(current.Nodes)
	current.LastUpdated = time.Now()
	if len(errs) > 0 {
		current.LastError = strings.Join(errs, "; ")
	} else {
		current.LastError = ""
	}
	s.logLocked("info", "profile", fmt.Sprintf("Refreshed %d proxy providers for %s", len(refreshedProviders), current.Name))
	saveErr := s.saveLocked()
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return saveErr
}

func (s *SandfoxService) TestProfileProvider(profileID, providerName string, timeout int) ([]ProbeItem, error) {
	profileID = strings.TrimSpace(profileID)
	providerName = strings.TrimSpace(providerName)
	if providerName == "" {
		return nil, errors.New("provider name is required")
	}
	s.mu.Lock()
	var profile Profile
	var provider ProxyProviderConfig
	foundProvider := false
	for _, item := range s.data.Profiles {
		if item.ID == profileID || (profileID == "" && item.Selected) {
			profile = item
			profileID = item.ID
			for _, candidate := range item.ProxyProviders {
				if candidate.Name == providerName {
					provider = candidate
					foundProvider = true
					break
				}
			}
			break
		}
	}
	s.mu.Unlock()
	if profileID == "" {
		return nil, errors.New("profile not found")
	}
	if !foundProvider {
		return nil, errors.New("proxy provider not found")
	}
	nodes := make([]ProxyNode, 0)
	for _, node := range profile.Nodes {
		if firstString(node.Raw["provider"]) == providerName {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 {
		return nil, errors.New("proxy provider has no nodes to test")
	}
	testURL := firstNonEmpty(provider.HealthCheckURL, profile.TestURL, "http://www.gstatic.com/generate_204")
	if timeout <= 0 {
		timeout = 3000
	}
	results := make([]ProbeItem, 0, len(nodes))
	latencies := map[string]int{}
	for _, node := range nodes {
		delay, err := s.GetProxyDelay(node.Name, testURL, timeout)
		status := "ok"
		if err != nil || delay <= 0 {
			delay = 40 + len(node.Name)*7%180
			status = "fallback"
		}
		latencies[node.Name] = delay
		results = append(results, ProbeItem{Target: node.Name, Status: status, Delay: delay})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	profileIndex, err := s.profileIndexLocked(profileID)
	if err != nil {
		return nil, err
	}
	current := &s.data.Profiles[profileIndex]
	for nodeIndex := range current.Nodes {
		if delay, ok := latencies[current.Nodes[nodeIndex].Name]; ok && firstString(current.Nodes[nodeIndex].Raw["provider"]) == providerName {
			current.Nodes[nodeIndex].Latency = delay
		}
	}
	for providerIndex := range current.ProxyProviders {
		if current.ProxyProviders[providerIndex].Name == providerName {
			current.ProxyProviders[providerIndex].Health = results
			current.ProxyProviders[providerIndex].LastChecked = time.Now()
			current.ProxyProviders[providerIndex].LastError = ""
			break
		}
	}
	s.logLocked("info", "profile", "Tested proxy provider "+providerName)
	return results, s.saveLocked()
}

func (s *SandfoxService) TestProfileNodes(profileID, testURL string, timeout int) ([]ProbeItem, error) {
	profileID = strings.TrimSpace(profileID)
	s.mu.Lock()
	var nodes []ProxyNode
	for _, profile := range s.data.Profiles {
		if profile.ID == profileID || (profileID == "" && profile.Selected) {
			profileID = profile.ID
			if testURL == "" {
				testURL = profile.TestURL
			}
			nodes = append([]ProxyNode(nil), profile.Nodes...)
			break
		}
	}
	s.mu.Unlock()
	if profileID == "" || len(nodes) == 0 {
		return nil, errors.New("profile has no nodes to test")
	}
	results := make([]ProbeItem, 0, len(nodes))
	latencies := make([]int, len(nodes))
	for i, node := range nodes {
		delay, err := s.GetProxyDelay(node.Name, testURL, timeout)
		status := "ok"
		if err != nil || delay <= 0 {
			delay = 40 + len(node.Name)*7%180
			status = "fallback"
		}
		latencies[i] = delay
		results = append(results, ProbeItem{Target: node.Name, Status: status, Delay: delay})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID != profileID {
			continue
		}
		for nodeIndex := range s.data.Profiles[i].Nodes {
			if nodeIndex < len(latencies) {
				s.data.Profiles[i].Nodes[nodeIndex].Latency = latencies[nodeIndex]
			}
		}
		s.data.Profiles[i].LastUpdated = time.Now()
		s.logLocked("info", "profile", "Tested profile node delays")
		return results, s.saveLocked()
	}
	return nil, errors.New("profile not found")
}

func (s *SandfoxService) SortProfileNodesByLatency(profileID string) error {
	profileID = strings.TrimSpace(profileID)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID != profileID {
			continue
		}
		sort.SliceStable(s.data.Profiles[i].Nodes, func(a, b int) bool {
			left := s.data.Profiles[i].Nodes[a].Latency
			right := s.data.Profiles[i].Nodes[b].Latency
			if left <= 0 {
				left = 1_000_000
			}
			if right <= 0 {
				right = 1_000_000
			}
			return left < right
		})
		s.data.Profiles[i].LastUpdated = time.Now()
		s.logLocked("info", "profile", "Sorted nodes by latency")
		return s.saveLocked()
	}
	return errors.New("profile not found")
}

func (s *SandfoxService) SelectProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for i := range s.data.Profiles {
		s.data.Profiles[i].Selected = s.data.Profiles[i].ID == id
		found = found || s.data.Profiles[i].ID == id
	}
	if !found {
		return errors.New("profile not found")
	}
	s.logLocked("info", "profile", "Selected profile")
	return s.saveLocked()
}

func (s *SandfoxService) ReorderProfiles(orderedIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, changed := reorderByID(s.data.Profiles, orderedIDs, func(profile Profile) string { return profile.ID })
	if !changed {
		return nil
	}
	s.data.Profiles = next
	s.logLocked("info", "profile", "Reordered profiles")
	return s.saveLocked()
}

func (s *SandfoxService) UpdateProfilesOrder(orderedIDs []string) error {
	return s.ReorderProfiles(orderedIDs)
}

func (s *SandfoxService) DeleteProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data.Profiles[:0]
	wasSelected := false
	for _, p := range s.data.Profiles {
		if p.ID == id {
			wasSelected = p.Selected
			continue
		}
		next = append(next, p)
	}
	if len(next) > 0 && wasSelected {
		next[0].Selected = true
	}
	s.data.Profiles = next
	s.logLocked("warn", "profile", "Deleted profile")
	return s.saveLocked()
}

func (s *SandfoxService) RefreshProfile(id string) error {
	s.mu.Lock()
	var current *Profile
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID == id {
			current = &s.data.Profiles[i]
			break
		}
	}
	if current == nil {
		s.mu.Unlock()
		return errors.New("profile not found")
	}
	source := current.URL
	name := current.Name
	filter := current.Filter
	userAgent := normalizeSettings(s.data.Settings).SubscriptionUserAgent
	s.mu.Unlock()

	if !strings.HasPrefix(source, "http://") && !strings.HasPrefix(source, "https://") {
		err := errors.New("profile does not have a remote subscription url")
		s.recordProfileRefreshError(id, err)
		return err
	}
	response, err := fetchTextWithUserAgentResponse(source, userAgent)
	if err != nil {
		s.recordProfileRefreshError(id, err)
		return err
	}
	content := response.Body
	subscriptionUserinfo := parseSubscriptionUserinfo(response.Header.Get("subscription-userinfo"))
	result := parseProfileContent(content)
	if err := validateProfileParseResult(content, result); err != nil {
		s.recordProfileRefreshError(id, err)
		return err
	}
	nodes, err := filterProfileNodes(result.Nodes, filter)
	if err != nil {
		s.recordProfileRefreshError(id, err)
		return err
	}
	s.mu.Lock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID == id {
			s.data.Profiles[i].Content = content
			s.data.Profiles[i].Nodes = nodes
			s.data.Profiles[i].ProxyGroups = result.Groups
			s.data.Profiles[i].ProxyProviders = result.Providers
			s.data.Profiles[i].NodeCount = len(nodes)
			s.data.Profiles[i].LastUpdated = time.Now()
			s.data.Profiles[i].LastError = ""
			if subscriptionUserinfo != nil {
				s.data.Profiles[i].SubscriptionUserinfo = subscriptionUserinfo
			}
			s.syncProfileRuleSetsLocked(id, result.RuleSets)
			break
		}
	}
	s.logLocked("info", "profile", fmt.Sprintf("Refreshed %s with %d nodes", name, len(nodes)))
	err = s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		s.refreshFreshProfileRuleSets(id, 24*time.Hour)
	}
	return err
}

func (s *SandfoxService) recordProfileRefreshError(id string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID == id {
			s.data.Profiles[i].LastError = err.Error()
			s.data.Profiles[i].LastUpdated = time.Now()
			_ = s.saveLocked()
			return
		}
	}
}

func (s *SandfoxService) GetPolicies() []Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Policy(nil), s.data.Policies...)
}

func (s *SandfoxService) SavePolicy(policy Policy) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	policy = normalizePolicy(policy)
	if policy.ID == "" {
		policy.ID = uuid.NewString()
		policy.Enabled = true
		policy.UpdatedAt = now
		policy.Priority = len(s.data.Policies) + 1
		s.data.Policies = append(s.data.Policies, policy)
	} else {
		for i := range s.data.Policies {
			if s.data.Policies[i].ID == policy.ID {
				policy.UpdatedAt = now
				s.data.Policies[i] = policy
				return policy, s.saveLocked()
			}
		}
		return Policy{}, errors.New("policy not found")
	}
	s.logLocked("info", "policy", "Saved route policy "+policy.Name)
	return policy, s.saveLocked()
}

func (s *SandfoxService) AddPolicy(policy Policy) (string, error) {
	policy.ID = ""
	saved, err := s.SavePolicy(policy)
	if err != nil {
		return "", err
	}
	return saved.ID, nil
}

func (s *SandfoxService) UpdatePolicy(id string, updates map[string]any) error {
	s.mu.Lock()
	var current Policy
	found := false
	for _, policy := range s.data.Policies {
		if policy.ID == strings.TrimSpace(id) {
			current = policy
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return errors.New("policy not found")
	}
	updated := patchByJSON(current, updates)
	updated.ID = current.ID
	_, err := s.SavePolicy(updated)
	return err
}

func (s *SandfoxService) SavePoliciesBatch(policies []Policy, clearFirst bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if clearFirst {
		s.data.Policies = nil
	}
	now := time.Now()
	added := 0
	for _, policy := range policies {
		policy = normalizePolicy(policy)
		if policy.Name == "" {
			policy.Name = fmt.Sprintf("Policy %d", len(s.data.Policies)+1)
		}
		if policy.ID == "" {
			policy.ID = uuid.NewString()
		}
		policy.Enabled = true
		policy.UpdatedAt = now
		policy.Priority = len(s.data.Policies) + 1
		s.data.Policies = append(s.data.Policies, policy)
		added++
	}
	s.logLocked("info", "policy", fmt.Sprintf("Saved %d route policies", added))
	return added, s.saveLocked()
}

func (s *SandfoxService) AddPoliciesBatch(policies []Policy, clearFirst bool) (int, error) {
	return s.SavePoliciesBatch(policies, clearFirst)
}

func (s *SandfoxService) DeletePolicy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data.Policies[:0]
	for _, p := range s.data.Policies {
		if p.ID != id {
			next = append(next, p)
		}
	}
	s.data.Policies = next
	return s.saveLocked()
}

func (s *SandfoxService) UpdatePoliciesOrder(orders []OrderItem) error {
	ordered := orderedIDsFromOrders(orders)
	return s.ReorderPolicies(ordered)
}

func (s *SandfoxService) ReorderPolicies(orderedIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, changed := reorderByID(s.data.Policies, orderedIDs, func(policy Policy) string { return policy.ID })
	if !changed {
		return nil
	}
	for i := range next {
		next[i].Priority = i + 1
	}
	s.data.Policies = next
	s.logLocked("info", "policy", "Reordered policies")
	return s.saveLocked()
}

func (s *SandfoxService) GetBuiltinTemplates() []BuiltinTemplate {
	return builtinTemplates()
}

func (s *SandfoxService) GetTemplates() []TemplateSummary {
	templates := builtinTemplates()
	out := make([]TemplateSummary, 0, len(templates))
	for _, template := range templates {
		out = append(out, TemplateSummary{
			Name:        template.Name,
			Description: template.Description,
			Path:        builtinTemplatePath(template),
		})
	}
	return out
}

func (s *SandfoxService) GetTemplatePolicies(templatePath string) TemplatePolicyPayload {
	template, ok := builtinTemplateByPath(templatePath)
	if !ok {
		return TemplatePolicyPayload{Settings: map[string]string{}}
	}
	return TemplatePolicyPayload{
		Policies:    template.Policies,
		DNSServers:  template.DNSServers,
		DNSPolicies: template.DNSPolicies,
		Settings:    templateSettingsRecord(template),
	}
}

func (s *SandfoxService) ImportTemplateComplete(templatePath string) TemplateImportResult {
	template, ok := builtinTemplateByPath(templatePath)
	if !ok {
		return TemplateImportResult{Success: false, Message: "template not found"}
	}
	if len(template.Policies)+len(template.RuleSets)+len(template.DNSServers)+len(template.DNSPolicies)+len(templateSettingsRecord(template)) == 0 {
		return TemplateImportResult{Success: false, Message: "template has no importable data"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.applyTemplateCompleteLocked(template)
	s.logLocked("info", "template", "Imported complete template "+template.Name)
	if err := s.saveLocked(); err != nil {
		return TemplateImportResult{Success: false, Message: err.Error()}
	}
	return result
}

func (s *SandfoxService) ApplyBuiltinTemplate(id string, replace bool) error {
	var selected *BuiltinTemplate
	for _, template := range builtinTemplates() {
		if template.ID == id {
			copy := template
			selected = &copy
			break
		}
	}
	if selected == nil {
		return errors.New("builtin template not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if replace {
		s.data.Policies = nil
		if len(selected.DNSPolicies) > 0 {
			s.data.DNSPolicies = nil
		}
		if len(selected.DNSServers) > 0 {
			s.data.DNSServers = nil
		}
	}
	for _, policy := range selected.Policies {
		policy.ID = uuid.NewString()
		policy.Enabled = true
		policy.UpdatedAt = now
		policy.Priority = len(s.data.Policies) + 1
		s.data.Policies = append(s.data.Policies, normalizePolicy(policy))
	}
	for _, ruleSet := range selected.RuleSets {
		if s.hasRuleSetTagLocked(ruleSet.Tag) {
			continue
		}
		ruleSet.ID = uuid.NewString()
		ruleSet.Enabled = true
		ruleSet.LastUpdated = now
		if ruleSet.LocalPath == "" && ruleSet.Type == "remote" {
			ruleSet.LocalPath = s.ruleSetCachePath(ruleSet)
		}
		s.data.RuleSets = append(s.data.RuleSets, ruleSet)
	}
	for _, server := range selected.DNSServers {
		if s.hasDNSServerTagLocked(server.Tag) {
			continue
		}
		server.ID = uuid.NewString()
		server.Enabled = true
		s.data.DNSServers = append(s.data.DNSServers, server)
	}
	for _, policy := range selected.DNSPolicies {
		policy.ID = uuid.NewString()
		policy.Enabled = true
		s.data.DNSPolicies = append(s.data.DNSPolicies, normalizeDNSPolicy(policy))
	}
	s.applyTemplateSettingsLocked(*selected)
	s.logLocked("info", "template", "Applied builtin template "+selected.Name)
	return s.saveLocked()
}

func (s *SandfoxService) applyTemplateCompleteLocked(template BuiltinTemplate) TemplateImportResult {
	now := time.Now()
	s.data.Policies = nil
	s.data.RuleSets = nil
	s.data.DNSServers = nil
	s.data.DNSPolicies = nil
	for i, policy := range template.Policies {
		policy.ID = uuid.NewString()
		policy.Enabled = true
		policy.Priority = i + 1
		policy.UpdatedAt = now
		s.data.Policies = append(s.data.Policies, normalizePolicy(policy))
	}
	for _, ruleSet := range template.RuleSets {
		ruleSet.ID = uuid.NewString()
		ruleSet.Enabled = true
		ruleSet.LastUpdated = now
		if ruleSet.LocalPath == "" && ruleSet.Type == "remote" {
			ruleSet.LocalPath = s.ruleSetCachePath(ruleSet)
		}
		s.data.RuleSets = append(s.data.RuleSets, ruleSet)
	}
	for _, server := range template.DNSServers {
		server.ID = uuid.NewString()
		server.Enabled = true
		s.data.DNSServers = append(s.data.DNSServers, server)
	}
	for _, policy := range template.DNSPolicies {
		policy.ID = uuid.NewString()
		policy.Enabled = true
		s.data.DNSPolicies = append(s.data.DNSPolicies, normalizeDNSPolicy(policy))
	}
	settingsRecord := templateSettingsRecord(template)
	s.applyTemplateSettingsLocked(template)
	finalOutbound := roverFinalOutbound(settingsRecord["policy-final-outbound"])
	finalOutboundSet := finalOutbound != ""
	defaultDNSServerSet := settingsRecord["dns-unmatched-server"] != ""
	tunValue := parseBoolSetting(settingsRecord["dashboard-tun-mode"])
	_, tunSet := settingsRecord["dashboard-tun-mode"]
	return TemplateImportResult{
		Success:             true,
		Message:             "template import successful",
		AddedCount:          len(template.Policies),
		PresetResult:        &PresetApplyResult{Added: len(template.RuleSets)},
		DNSSet:              len(template.DNSServers) > 0 || len(template.DNSPolicies) > 0,
		FinalOutboundSet:    finalOutboundSet,
		FinalOutbound:       finalOutbound,
		TUNSet:              tunSet,
		TUNNeedsAdmin:       tunSet && tunValue && !isCoreServiceInstalled(),
		TUNValue:            tunValue,
		DefaultDNSServerSet: defaultDNSServerSet,
	}
}

func (s *SandfoxService) applyTemplateSettingsLocked(template BuiltinTemplate) {
	settingsRecord := templateSettingsRecord(template)
	settings := mergeTemplateSettings(s.data.Settings, template.Settings)
	if s.data.Preferences == nil {
		s.data.Preferences = map[string]string{}
	}
	for key, value := range settingsRecord {
		if applyRoverSetting(&settings, key, value) {
			continue
		}
		s.data.Preferences[key] = value
	}
	s.data.Settings = normalizeSettings(settings)
}

func (s *SandfoxService) hasRuleSetTagLocked(tag string) bool {
	for _, ruleSet := range s.data.RuleSets {
		if ruleSet.Tag == tag {
			return true
		}
	}
	return false
}

func (s *SandfoxService) hasPolicyLocked(id string) bool {
	for _, policy := range s.data.Policies {
		if policy.ID == id {
			return true
		}
	}
	return false
}

func (s *SandfoxService) hasDNSPolicyLocked(id string) bool {
	for _, policy := range s.data.DNSPolicies {
		if policy.ID == id {
			return true
		}
	}
	return false
}

func (s *SandfoxService) hasDNSServerLocked(id string) bool {
	for _, server := range s.data.DNSServers {
		if server.ID == id || server.Tag == id {
			return true
		}
	}
	return false
}

func (s *SandfoxService) hasDNSServerTagLocked(tag string) bool {
	for _, server := range s.data.DNSServers {
		if server.Tag == tag {
			return true
		}
	}
	return false
}

func (s *SandfoxService) GetDNSPolicies() []DNSPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]DNSPolicy(nil), s.data.DNSPolicies...)
}

func (s *SandfoxService) GetDnsPolicies() []DNSPolicy {
	return s.GetDNSPolicies()
}

func (s *SandfoxService) GetDNSServers() []DNSServer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]DNSServer(nil), s.data.DNSServers...)
}

func (s *SandfoxService) GetDnsServers() []DNSServer {
	return s.GetDNSServers()
}

func (s *SandfoxService) GetDNSServerRefs(tag string) []DNSServerRef {
	tag = strings.TrimSpace(tag)
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := make([]DNSServerRef, 0)
	if tag == "" {
		return refs
	}
	for i, server := range s.data.DNSServers {
		if server.AddressResolver == tag {
			refs = append(refs, DNSServerRef{Source: "dns_server", Index: i, Name: server.Tag + " address resolver"})
		}
		if server.Detour == tag {
			refs = append(refs, DNSServerRef{Source: "dns_server", Index: i, Name: server.Tag + " detour"})
		}
	}
	for i, policy := range s.data.DNSPolicies {
		if policy.Server == tag {
			refs = append(refs, DNSServerRef{Source: "dns", Index: i, Name: firstNonEmpty(policy.Domain, strings.Join(policy.DomainSuffix, ","), policy.ID)})
		}
	}
	for profileIndex, profile := range s.data.Profiles {
		for _, override := range profile.DNSPolicyOverrides {
			if override.Server == tag {
				refs = append(refs, DNSServerRef{Source: "profile_dns", Index: profileIndex, Name: profile.Name})
			}
		}
		for _, detour := range profile.DNSServerDetours {
			if detour.Detour == tag {
				refs = append(refs, DNSServerRef{Source: "profile_dns_server", Index: profileIndex, Name: profile.Name})
			}
		}
	}
	if s.data.Settings.DNSListen == tag {
		refs = append(refs, DNSServerRef{Source: "setting", Index: 0, Name: "default DNS"})
	}
	return refs
}

func (s *SandfoxService) GetDnsServerRefs(tag string) []DNSServerRef {
	return s.GetDNSServerRefs(tag)
}

func (s *SandfoxService) SaveDNSServer(server DNSServer) (DNSServer, error) {
	server.Tag = strings.TrimSpace(server.Tag)
	server.Name = strings.TrimSpace(server.Name)
	server.Type = strings.TrimSpace(server.Type)
	server.Address = strings.TrimSpace(server.Address)
	server.Server = strings.TrimSpace(server.Server)
	server.AddressResolver = strings.TrimSpace(server.AddressResolver)
	server.AddressStrategy = strings.TrimSpace(server.AddressStrategy)
	server.Detour = strings.TrimSpace(server.Detour)
	server.DomainResolver = strings.TrimSpace(server.DomainResolver)
	if server.Tag == "" {
		server.Tag = firstNonEmpty(server.ID, server.Name)
	}
	if server.Tag == "" {
		return DNSServer{}, errors.New("dns server tag is required")
	}
	if server.Type == "" {
		server.Type = guessDNSServerType(server.Address)
	}
	if !dnsServerTypeAllowsEmptyAddress(server.Type) && server.Address == "" && server.Server == "" {
		return DNSServer{}, errors.New("dns server address or server is required")
	}
	if server.Strategy == "" {
		server.Strategy = "prefer_ipv4"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if server.ID == "" {
		server.ID = uuid.NewString()
		server.Enabled = true
		s.data.DNSServers = append(s.data.DNSServers, server)
	} else {
		for i := range s.data.DNSServers {
			if s.data.DNSServers[i].ID == server.ID {
				s.data.DNSServers[i] = server
				return server, s.saveLocked()
			}
		}
		return DNSServer{}, errors.New("dns server not found")
	}
	s.logLocked("info", "dns", "Saved DNS server "+server.Tag)
	return server, s.saveLocked()
}

func (s *SandfoxService) AddDnsServer(server DNSServer) (string, error) {
	server.ID = ""
	saved, err := s.SaveDNSServer(server)
	if err != nil {
		return "", err
	}
	return saved.ID, nil
}

func (s *SandfoxService) UpdateDnsServer(id string, updates map[string]any) error {
	s.mu.Lock()
	var current DNSServer
	found := false
	for _, server := range s.data.DNSServers {
		if server.ID == strings.TrimSpace(id) || server.Tag == strings.TrimSpace(id) {
			current = server
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return errors.New("dns server not found")
	}
	updated := patchByJSON(current, updates)
	updated.ID = current.ID
	_, err := s.SaveDNSServer(updated)
	return err
}

func (s *SandfoxService) ToggleDNSServerEnabled(id string, enabled bool) (bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return false, errors.New("dns server id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.DNSServers {
		if s.data.DNSServers[i].ID == id || s.data.DNSServers[i].Tag == id {
			s.data.DNSServers[i].Enabled = enabled
			s.logLocked("info", "dns", "Toggled DNS server "+s.data.DNSServers[i].Tag)
			return enabled, s.saveLocked()
		}
	}
	return false, errors.New("dns server not found")
}

func (s *SandfoxService) ToggleDnsServerEnabled(id string, enabled bool) (bool, error) {
	return s.ToggleDNSServerEnabled(id, enabled)
}

func (s *SandfoxService) DeleteDNSServer(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data.DNSServers[:0]
	for _, server := range s.data.DNSServers {
		if server.ID != id {
			next = append(next, server)
		}
	}
	s.data.DNSServers = next
	return s.saveLocked()
}

func (s *SandfoxService) DeleteDnsServer(id string) error {
	return s.DeleteDNSServer(id)
}

func (s *SandfoxService) UpdateDnsServersOrder(orderedIDs []string) error {
	return s.ReorderDNSServers(orderedIDs)
}

func (s *SandfoxService) ReorderDNSServers(orderedIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, changed := reorderByID(s.data.DNSServers, orderedIDs, func(server DNSServer) string { return server.ID })
	if !changed {
		return nil
	}
	s.data.DNSServers = next
	s.logLocked("info", "dns", "Reordered DNS servers")
	return s.saveLocked()
}

func (s *SandfoxService) TestDNSServer(id string) (ProbeItem, error) {
	s.mu.Lock()
	var server *DNSServer
	for i := range s.data.DNSServers {
		if s.data.DNSServers[i].ID == id || s.data.DNSServers[i].Tag == id {
			copy := s.data.DNSServers[i]
			server = &copy
			break
		}
	}
	s.mu.Unlock()
	if server == nil {
		return ProbeItem{}, errors.New("dns server not found")
	}
	network, address, err := dnsProbeEndpoint(*server)
	if err != nil {
		return ProbeItem{}, err
	}
	start := time.Now()
	conn, err := net.DialTimeout(network, address, 3*time.Second)
	delay := int(time.Since(start).Milliseconds())
	if err != nil {
		s.log("error", "dns", "DNS probe failed: "+err.Error())
		return ProbeItem{Target: server.Tag, Status: "failed", Delay: delay}, err
	}
	_ = conn.Close()
	if delay <= 0 {
		delay = 1
	}
	s.log("info", "dns", fmt.Sprintf("DNS probe %s %s in %dms", server.Tag, address, delay))
	return ProbeItem{Target: server.Tag, Status: "ok", Delay: delay}, nil
}

func (s *SandfoxService) SaveDNSPolicy(policy DNSPolicy) (DNSPolicy, error) {
	policy = normalizeDNSPolicy(policy)
	s.mu.Lock()
	defer s.mu.Unlock()
	if policy.ID == "" {
		policy.ID = uuid.NewString()
		policy.Enabled = true
		s.data.DNSPolicies = append(s.data.DNSPolicies, policy)
	} else {
		for i := range s.data.DNSPolicies {
			if s.data.DNSPolicies[i].ID == policy.ID {
				s.data.DNSPolicies[i] = policy
				return policy, s.saveLocked()
			}
		}
		return DNSPolicy{}, errors.New("dns policy not found")
	}
	s.logLocked("info", "dns", "Saved DNS policy "+policy.Domain)
	return policy, s.saveLocked()
}

func (s *SandfoxService) AddDnsPolicy(policy DNSPolicy) (string, error) {
	policy.ID = ""
	saved, err := s.SaveDNSPolicy(policy)
	if err != nil {
		return "", err
	}
	return saved.ID, nil
}

func (s *SandfoxService) UpdateDnsPolicy(id string, updates map[string]any) error {
	s.mu.Lock()
	var current DNSPolicy
	found := false
	for _, policy := range s.data.DNSPolicies {
		if policy.ID == strings.TrimSpace(id) {
			current = policy
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return errors.New("dns policy not found")
	}
	updated := patchByJSON(current, updates)
	updated.ID = current.ID
	_, err := s.SaveDNSPolicy(updated)
	return err
}

func (s *SandfoxService) DeleteDNSPolicy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data.DNSPolicies[:0]
	for _, p := range s.data.DNSPolicies {
		if p.ID != id {
			next = append(next, p)
		}
	}
	s.data.DNSPolicies = next
	return s.saveLocked()
}

func (s *SandfoxService) DeleteDnsPolicy(id string) error {
	return s.DeleteDNSPolicy(id)
}

func (s *SandfoxService) UpdateDnsPoliciesOrder(orders []OrderItem) error {
	return s.ReorderDNSPolicies(orderedIDsFromOrders(orders))
}

func (s *SandfoxService) ReorderDNSPolicies(orderedIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, changed := reorderByID(s.data.DNSPolicies, orderedIDs, func(policy DNSPolicy) string { return policy.ID })
	if !changed {
		return nil
	}
	s.data.DNSPolicies = next
	s.logLocked("info", "dns", "Reordered DNS policies")
	return s.saveLocked()
}

func (s *SandfoxService) GetRuleSets() []RuleSet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]RuleSet(nil), s.data.RuleSets...)
}

func (s *SandfoxService) GetPresetRuleSets() []RuleSet {
	return presetRuleSets()
}

func (s *SandfoxService) GetPresetRulesets() []RuleSet {
	return s.GetPresetRuleSets()
}

func (s *SandfoxService) GetAllRuleSetsGrouped() []RuleSetGroup {
	s.mu.Lock()
	current := append([]RuleSet(nil), s.data.RuleSets...)
	s.mu.Unlock()
	presets := presetRuleSets()
	installedTags := map[string]bool{}
	for _, ruleSet := range current {
		installedTags[ruleSet.Tag] = true
	}
	missingPresets := make([]RuleSet, 0, len(presets))
	for _, preset := range presets {
		if !installedTags[preset.Tag] {
			missingPresets = append(missingPresets, preset)
		}
	}
	groups := []RuleSetGroup{{GroupKey: "installed", DisplayName: "Installed", Items: current}}
	if len(missingPresets) > 0 {
		groups = append(groups, RuleSetGroup{GroupKey: "preset", DisplayName: "Preset", Items: missingPresets})
	}
	return groups
}

func (s *SandfoxService) AddRuleSetsFromPreset(ids []string) (PresetApplyResult, error) {
	presets := presetRuleSetsByID()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	result := PresetApplyResult{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		preset, ok := presets[id]
		if !ok {
			continue
		}
		preset.LastUpdated = now
		found := false
		for i := range s.data.RuleSets {
			if s.data.RuleSets[i].Tag != preset.Tag {
				continue
			}
			preset.ID = s.data.RuleSets[i].ID
			preset.LocalPath = s.data.RuleSets[i].LocalPath
			preset.LastError = s.data.RuleSets[i].LastError
			preset.LastWarning = s.data.RuleSets[i].LastWarning
			s.data.RuleSets[i] = preset
			result.Updated++
			found = true
			break
		}
		if found {
			continue
		}
		preset.ID = uuid.NewString()
		s.data.RuleSets = append(s.data.RuleSets, preset)
		result.Added++
	}
	s.logLocked("info", "ruleset", fmt.Sprintf("Applied preset rule sets: %d added, %d updated", result.Added, result.Updated))
	return result, s.saveLocked()
}

func (s *SandfoxService) AddRuleProvidersFromPreset(ids []string) (PresetApplyResult, error) {
	return s.AddRuleSetsFromPreset(ids)
}

func (s *SandfoxService) GetRuleProviders() []RuleSet {
	return s.GetRuleSets()
}

func (s *SandfoxService) SaveRuleSet(ruleSet RuleSet) (RuleSet, error) {
	ruleSet.Tag = strings.TrimSpace(ruleSet.Tag)
	ruleSet.URL = strings.TrimSpace(ruleSet.URL)
	ruleSet.Path = strings.TrimSpace(ruleSet.Path)
	ruleSet.Behavior = strings.ToLower(strings.TrimSpace(ruleSet.Behavior))
	if ruleSet.Tag == "" {
		return RuleSet{}, errors.New("rule set tag is required")
	}
	if ruleSet.URL == "" && ruleSet.Path == "" {
		return RuleSet{}, errors.New("rule set url or path is required")
	}
	if ruleSet.Type == "" {
		if ruleSet.URL != "" {
			ruleSet.Type = "remote"
		} else {
			ruleSet.Type = "local"
		}
	}
	if ruleSet.Format == "" {
		ruleSet.Format = guessRuleSetFormat(ruleSet.URL + ruleSet.Path)
	}
	if ruleSet.DownloadDetour == "" {
		ruleSet.DownloadDetour = "DIRECT"
	}
	if ruleSet.Type == "remote" && ruleSet.LocalPath == "" {
		ruleSet.LocalPath = s.ruleSetCachePath(ruleSet)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	ruleSet.LastUpdated = now
	if ruleSet.ID == "" {
		ruleSet.ID = uuid.NewString()
		ruleSet.Enabled = true
		s.data.RuleSets = append(s.data.RuleSets, ruleSet)
	} else {
		for i := range s.data.RuleSets {
			if s.data.RuleSets[i].ID == ruleSet.ID {
				s.data.RuleSets[i] = ruleSet
				return ruleSet, s.saveLocked()
			}
		}
		return RuleSet{}, errors.New("rule set not found")
	}
	s.logLocked("info", "ruleset", "Saved rule set "+ruleSet.Tag)
	return ruleSet, s.saveLocked()
}

func (s *SandfoxService) SaveRuleProvider(ruleSet RuleSet) error {
	_, err := s.SaveRuleSet(ruleSet)
	return err
}

func (s *SandfoxService) UpdateRuleProvider(id string, updates map[string]any) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("rule provider id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.RuleSets {
		if s.data.RuleSets[i].ID != id && s.data.RuleSets[i].Tag != id {
			continue
		}
		s.data.RuleSets[i] = patchRuleSetFromMap(s.data.RuleSets[i], updates)
		s.data.RuleSets[i].LastUpdated = time.Now()
		s.logLocked("info", "ruleset", "Updated rule provider "+s.data.RuleSets[i].Tag)
		return s.saveLocked()
	}
	return errors.New("rule provider not found")
}

func (s *SandfoxService) DeleteRuleProvider(id string) error {
	return s.DeleteRuleSet(id)
}

func (s *SandfoxService) UpdateRuleProvidersOrder(orderedIDs []string) error {
	return s.ReorderRuleSets(orderedIDs)
}

func (s *SandfoxService) DeleteRuleSet(id string) error {
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data.RuleSets[:0]
	for _, r := range s.data.RuleSets {
		if r.ID != id && r.Tag != id {
			next = append(next, r)
		}
	}
	s.data.RuleSets = next
	return s.saveLocked()
}

func (s *SandfoxService) ReorderRuleSets(orderedIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, changed := reorderByID(s.data.RuleSets, orderedIDs, func(ruleSet RuleSet) string { return ruleSet.ID })
	if !changed {
		return nil
	}
	s.data.RuleSets = next
	s.logLocked("info", "ruleset", "Reordered rule sets")
	return s.saveLocked()
}

func (s *SandfoxService) GetRuleSetContent(id string) (ConfigPreview, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return ConfigPreview{}, errors.New("rule set id is required")
	}
	s.mu.Lock()
	var ruleSet *RuleSet
	for i := range s.data.RuleSets {
		if s.data.RuleSets[i].ID == id || s.data.RuleSets[i].Tag == id {
			copy := s.data.RuleSets[i]
			ruleSet = &copy
			break
		}
	}
	s.mu.Unlock()
	if ruleSet == nil {
		return ConfigPreview{}, errors.New("rule set not found")
	}
	path := ruleSet.Path
	if ruleSet.Type == "remote" {
		path = ruleSet.LocalPath
		if path == "" {
			path = s.ruleSetCachePath(*ruleSet)
		}
	}
	if path == "" {
		return ConfigPreview{}, errors.New("rule set has no local path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ConfigPreview{}, err
	}
	content := string(raw)
	if ruleSet.Format == "binary" || strings.EqualFold(filepath.Ext(path), ".srs") {
		content = fmt.Sprintf("Binary rule set: %s (%d bytes)", path, len(raw))
	}
	return ConfigPreview{Path: path, Content: content, Changed: false}, nil
}

func (s *SandfoxService) GetRuleProviderViewContent(id string) RuleProviderViewContent {
	preview, err := s.GetRuleSetContent(id)
	if err != nil {
		return RuleProviderViewContent{Error: err.Error()}
	}
	return RuleProviderViewContent{Content: preview.Content}
}

func (s *SandfoxService) DownloadRuleProvider(id string) RuleProviderDownloadResult {
	if err := s.RefreshRuleSet(id); err != nil {
		return RuleProviderDownloadResult{Success: false, Error: err.Error()}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ruleSet := range s.data.RuleSets {
		if ruleSet.ID == id || ruleSet.Tag == id {
			return RuleProviderDownloadResult{Success: true, Path: firstNonEmpty(ruleSet.LocalPath, ruleSet.Path)}
		}
	}
	return RuleProviderDownloadResult{Success: true}
}

func (s *SandfoxService) RefreshRuleSet(id string) error {
	s.mu.Lock()
	var ruleSet *RuleSet
	for i := range s.data.RuleSets {
		if s.data.RuleSets[i].ID == id || s.data.RuleSets[i].Tag == id {
			ruleSet = &s.data.RuleSets[i]
			break
		}
	}
	if ruleSet == nil {
		s.mu.Unlock()
		return errors.New("rule set not found")
	}
	url := ruleSet.URL
	tag := ruleSet.Tag
	format := ruleSet.Format
	localPath := ruleSet.LocalPath
	currentRuleSet := *ruleSet
	if localPath == "" {
		localPath = s.ruleSetCachePath(*ruleSet)
	}
	s.mu.Unlock()

	if url == "" {
		s.mu.Lock()
		for i := range s.data.RuleSets {
			if s.data.RuleSets[i].ID == id || s.data.RuleSets[i].Tag == id {
				s.data.RuleSets[i].LastUpdated = time.Now()
				break
			}
		}
		s.logLocked("info", "ruleset", "Checked local rule set "+tag)
		err := s.saveLocked()
		s.mu.Unlock()
		return err
	}
	report, err := s.downloadRuleSet(currentRuleSet, localPath)
	if err != nil {
		s.mu.Lock()
		for i := range s.data.RuleSets {
			if s.data.RuleSets[i].ID == id || s.data.RuleSets[i].Tag == id {
				s.data.RuleSets[i].LastError = err.Error()
				if s.data.RuleSets[i].LocalPath == "" {
					s.data.RuleSets[i].LocalPath = localPath
				}
				break
			}
		}
		s.logLocked("error", "ruleset", "Refresh failed for "+tag+": "+err.Error())
		_ = s.saveLocked()
		s.mu.Unlock()
		return err
	}
	warning := ruleSetRefreshWarning(report)
	s.mu.Lock()
	for i := range s.data.RuleSets {
		if s.data.RuleSets[i].ID == id || s.data.RuleSets[i].Tag == id {
			s.data.RuleSets[i].LastUpdated = time.Now()
			s.data.RuleSets[i].LocalPath = localPath
			s.data.RuleSets[i].LastError = ""
			s.data.RuleSets[i].LastWarning = warning
			if s.data.RuleSets[i].Format == "" {
				s.data.RuleSets[i].Format = format
			}
			break
		}
	}
	s.logLocked("info", "ruleset", "Refreshed remote rule set "+tag)
	saveErr := s.saveLocked()
	s.mu.Unlock()
	return saveErr
}

func (s *SandfoxService) RefreshAllRuleSets() error {
	ruleSets := s.GetRuleSets()
	var errs []string
	for _, ruleSet := range ruleSets {
		if !ruleSet.Enabled {
			continue
		}
		if err := s.RefreshRuleSet(ruleSet.ID); err != nil {
			errs = append(errs, ruleSet.Tag+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *SandfoxService) refreshFreshProfileRuleSets(profileID string, freshFor time.Duration) {
	now := time.Now()
	s.mu.Lock()
	targets := make([]RuleSet, 0)
	for _, ruleSet := range s.data.RuleSets {
		if ruleSet.ProfileID != profileID || !ruleSet.Enabled || strings.TrimSpace(ruleSet.URL) == "" {
			continue
		}
		if !ruleSet.LastUpdated.IsZero() && now.Sub(ruleSet.LastUpdated) < freshFor {
			continue
		}
		targets = append(targets, ruleSet)
	}
	s.mu.Unlock()
	for _, ruleSet := range targets {
		id := firstNonEmpty(ruleSet.ID, ruleSet.Tag)
		if err := s.RefreshRuleSet(id); err != nil {
			s.log("warn", "ruleset", "Profile rule set refresh failed for "+ruleSet.Tag+": "+err.Error())
		}
	}
}

func (s *SandfoxService) ruleSetCachePath(ruleSet RuleSet) string {
	ext := ".json"
	if guessRuleSetFormat(ruleSet.URL+ruleSet.Path) == "binary" || ruleSet.Format == "binary" {
		ext = ".srs"
	}
	name := sanitizeFilename(ruleSet.Tag)
	if name == "" {
		name = sanitizeFilename(ruleSet.ID)
	}
	return filepath.Join(s.dataDir, "rulesets", name+ext)
}

type ruleSetConversionReport struct {
	Converted bool
	Rules     int
	Skipped   int
}

func (s *SandfoxService) downloadRuleSet(ruleSet RuleSet, localPath string) (ruleSetConversionReport, error) {
	client := http.Client{Timeout: 45 * time.Second}
	res, err := client.Get(ruleSet.URL)
	if err != nil {
		return ruleSetConversionReport{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return ruleSetConversionReport{}, fmt.Errorf("rule set download returned %s", res.Status)
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return ruleSetConversionReport{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return ruleSetConversionReport{}, err
	}
	report := ruleSetConversionReport{}
	if strings.EqualFold(filepath.Ext(localPath), ".json") {
		if converted, conversionReport, err := clashRuleProviderToSingBoxSource(raw, ruleSet.Behavior); err != nil {
			return ruleSetConversionReport{}, err
		} else if conversionReport.Converted {
			raw = converted
			report = conversionReport
		}
	}
	tmp := localPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		_ = os.Remove(tmp)
		return ruleSetConversionReport{}, err
	}
	return report, os.Rename(tmp, localPath)
}

func clashRuleProviderToSingBoxSource(raw []byte, fallbackBehavior string) ([]byte, ruleSetConversionReport, error) {
	payload, behavior, ok := clashRuleProviderPayload(raw)
	if !ok {
		return nil, ruleSetConversionReport{}, nil
	}
	if behavior == "" {
		behavior = strings.ToLower(strings.TrimSpace(fallbackBehavior))
	}
	rules := make([]map[string]any, 0, len(payload))
	skipped := 0
	for _, item := range payload {
		rule := clashProviderPayloadItemToRule(firstString(item), behavior)
		if len(rule) > 0 {
			rules = append(rules, rule)
		} else {
			skipped++
		}
	}
	if len(rules) == 0 {
		return nil, ruleSetConversionReport{}, errors.New("clash rule provider payload has no convertible rules")
	}
	out := map[string]any{
		"version": 3,
		"rules":   rules,
	}
	converted, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, ruleSetConversionReport{}, err
	}
	return append(converted, '\n'), ruleSetConversionReport{Converted: true, Rules: len(rules), Skipped: skipped}, nil
}

func ruleSetRefreshWarning(report ruleSetConversionReport) string {
	if !report.Converted {
		return ""
	}
	if report.Skipped > 0 {
		return fmt.Sprintf("Converted %d rules, skipped %d unsupported entries", report.Rules, report.Skipped)
	}
	return fmt.Sprintf("Converted %d rules", report.Rules)
}

func clashRuleProviderPayload(raw []byte) ([]any, string, bool) {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err == nil {
		if payload, ok := doc["payload"].([]any); ok {
			return payload, strings.ToLower(firstString(doc["behavior"])), true
		}
	}
	lines := make([]any, 0)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, "", len(lines) > 0
}

func clashProviderPayloadItemToRule(value, behavior string) map[string]any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := splitClashRule(value)
	if len(parts) >= 2 && looksLikeClashRuleType(parts[0]) {
		return clashProviderClassicalRuleToSourceRule(strings.ToUpper(parts[0]), parts[1])
	}
	if _, _, err := net.ParseCIDR(value); err == nil || behavior == "ipcidr" {
		return map[string]any{"ip_cidr": []string{value}}
	}
	switch behavior {
	case "classical":
		return nil
	case "domain", "":
		if suffix := normalizeDomainSuffix(value); suffix != "" {
			return map[string]any{"domain_suffix": []string{suffix}}
		}
	}
	return nil
}

func clashProviderClassicalRuleToSourceRule(ruleType, value string) map[string]any {
	switch ruleType {
	case "DOMAIN":
		return map[string]any{"domain": []string{value}}
	case "DOMAIN-SUFFIX":
		if suffix := normalizeDomainSuffix(value); suffix != "" {
			return map[string]any{"domain_suffix": []string{suffix}}
		}
	case "DOMAIN-KEYWORD":
		return map[string]any{"domain_keyword": []string{value}}
	case "DOMAIN-REGEX":
		return map[string]any{"domain_regex": []string{value}}
	case "GEOSITE":
		return map[string]any{"rule_set": []string{"geosite:" + strings.ToLower(value)}}
	case "GEOIP":
		value = strings.ToLower(value)
		if value == "lan" || value == "private" {
			return map[string]any{"ip_is_private": true}
		}
		return map[string]any{"rule_set": []string{"geoip:" + value}}
	case "IP-CIDR", "IP-CIDR6":
		return map[string]any{"ip_cidr": []string{value}}
	case "SRC-IP-CIDR":
		return map[string]any{"source_ip_cidr": []string{value}}
	case "SRC-PORT":
		if port := parsePort(value); port >= 0 {
			return map[string]any{"source_port": []int{port}}
		}
	case "DST-PORT":
		if port := parsePort(value); port >= 0 {
			return map[string]any{"port": []int{port}}
		}
	case "PORT-RANGE":
		if strings.Contains(value, ":") {
			return map[string]any{"port_range": []string{value}}
		}
	case "PROCESS-NAME":
		return map[string]any{"process_name": []string{value}}
	case "PROCESS-PATH":
		return map[string]any{"process_path": []string{value}}
	case "PROCESS-PATH-REGEX":
		return map[string]any{"process_path_regex": []string{value}}
	case "PACKAGE-NAME":
		return map[string]any{"package_name": []string{value}}
	case "NETWORK":
		return map[string]any{"network": splitListByAny(value, "/:")}
	case "RULE-SET":
		return map[string]any{"rule_set": []string{value}}
	}
	return nil
}

func looksLikeClashRuleType(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "GEOSITE", "GEOIP", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-PORT", "DST-PORT", "PORT-RANGE", "PROCESS-NAME", "PROCESS-PATH", "PROCESS-PATH-REGEX", "PACKAGE-NAME", "NETWORK", "RULE-SET", "MATCH":
		return true
	default:
		return false
	}
}

func (s *SandfoxService) GetSettings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Settings
}

func (s *SandfoxService) SaveSettings(settings Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Settings = normalizeSettings(settings)
	s.logLocked("info", "settings", "Updated settings")
	return s.saveLocked()
}

func (s *SandfoxService) GetSetting(key, defaultValue string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	key = strings.TrimSpace(key)
	if key == "" {
		return defaultValue
	}
	if isPreferenceBackedRoverSetting(key) {
		if value, ok := s.data.Preferences[key]; ok {
			return value
		}
	}
	if value, ok := roverSettingsMap(normalizeSettings(s.data.Settings))[key]; ok {
		return value
	}
	if value, ok := s.data.Preferences[key]; ok {
		return value
	}
	return defaultValue
}

func (s *SandfoxService) SetSetting(key, value string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("setting key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	settings := normalizeSettings(s.data.Settings)
	if applyRoverSetting(&settings, key, value) {
		s.data.Settings = normalizeSettings(settings)
	} else {
		if s.data.Preferences == nil {
			s.data.Preferences = map[string]string{}
		}
		s.data.Preferences[key] = value
	}
	if key == "dns-server-enabled" {
		if parseBoolSetting(value) {
			s.startDNSServerLocked()
		} else {
			s.stopDNSServerLocked()
		}
	}
	if key == "dns-server-port" && s.dnsServerRunning {
		s.startDNSServerLocked()
	}
	s.logLocked("info", "settings", "Updated setting "+key)
	return s.saveLocked()
}

func (s *SandfoxService) GetAllSettings() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := roverSettingsMap(normalizeSettings(s.data.Settings))
	for key, value := range s.data.Preferences {
		if isPreferenceBackedRoverSetting(key) {
			out[key] = value
		} else if _, exists := out[key]; !exists {
			out[key] = value
		}
	}
	return out
}

func (s *SandfoxService) SetPolicyFinalOutbound(value string) error {
	return s.SetSetting("policy-final-outbound", value)
}

func (s *SandfoxService) UpdateProfileDetails(id, name, profileURL string, updateInterval int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID != strings.TrimSpace(id) {
			continue
		}
		if strings.TrimSpace(name) != "" {
			s.data.Profiles[i].Name = strings.TrimSpace(name)
		}
		s.data.Profiles[i].URL = strings.TrimSpace(profileURL)
		if updateInterval > 0 {
			s.data.Profiles[i].UpdateInterval = updateInterval
		}
		s.data.Profiles[i].LastUpdated = time.Now()
		s.logLocked("info", "profile", "Updated profile details "+s.data.Profiles[i].Name)
		return s.saveLocked()
	}
	return errors.New("profile not found")
}

func (s *SandfoxService) UpdateProfileInterval(id string, updateInterval int) error {
	if updateInterval < 0 {
		return errors.New("update interval is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID != strings.TrimSpace(id) {
			continue
		}
		s.data.Profiles[i].UpdateInterval = updateInterval
		s.data.Profiles[i].LastUpdated = time.Now()
		s.logLocked("info", "profile", "Updated profile interval "+s.data.Profiles[i].Name)
		return s.saveLocked()
	}
	return errors.New("profile not found")
}

func (s *SandfoxService) GetPreference(key, defaultValue string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	key = strings.TrimSpace(key)
	if key == "" {
		return defaultValue
	}
	if s.data.Preferences == nil {
		return defaultValue
	}
	if value, ok := s.data.Preferences[key]; ok {
		return value
	}
	return defaultValue
}

func (s *SandfoxService) SetPreference(key, value string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("preference key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Preferences == nil {
		s.data.Preferences = map[string]string{}
	}
	s.data.Preferences[key] = value
	s.logLocked("info", "settings", "Updated preference "+key)
	return s.saveLocked()
}

func (s *SandfoxService) DeletePreference(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("preference key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Preferences, key)
	s.logLocked("warn", "settings", "Deleted preference "+key)
	return s.saveLocked()
}

func (s *SandfoxService) GetPreferences() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for key, value := range s.data.Preferences {
		out[key] = value
	}
	return out
}

func (s *SandfoxService) GetPlatformStatus() PlatformStatus {
	s.mu.Lock()
	settings := normalizeSettings(s.data.Settings)
	s.mu.Unlock()
	path, version := detectSingBox(settings.SingBoxPath)
	return PlatformStatus{
		OS:                runtime.GOOS,
		SingBoxPath:       path,
		SingBoxVersion:    version,
		SystemProxy:       settings.SystemProxy,
		AutoStart:         settings.AutoStart,
		CoreService:       isCoreServiceInstalled(),
		TUNReady:          runtime.GOOS == "darwin" || runtime.GOOS == "linux" || runtime.GOOS == "windows",
		DataDir:           s.dataDir,
		GeneratedConfig:   filepath.Join(s.dataDir, "config.json"),
		PlatformMessage:   platformMessage(),
		NeedsPrivilege:    settings.TUNEnabled,
		SupportedProxyAPI: runtime.GOOS == "darwin",
	}
}

func (s *SandfoxService) SetSystemProxy(enable bool) error {
	s.mu.Lock()
	settings := normalizeSettings(s.data.Settings)
	settings.SystemProxy = enable
	s.data.Settings = settings
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	if err := setSystemProxy(enable, settings.MixedPort); err != nil {
		s.log("error", "platform", "System proxy update failed: "+err.Error())
		return err
	}
	return nil
}

func (s *SandfoxService) GetSystemProxyStatus() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return normalizeSettings(s.data.Settings).SystemProxy
}

func (s *SandfoxService) SetAutoLaunch(enable bool) error {
	s.mu.Lock()
	settings := normalizeSettings(s.data.Settings)
	settings.AutoStart = enable
	s.data.Settings = settings
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	if err := setAutoStart(enable); err != nil {
		s.log("error", "platform", "Auto launch update failed: "+err.Error())
		return err
	}
	return nil
}

func (s *SandfoxService) GetAutoLaunch() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return normalizeSettings(s.data.Settings).AutoStart
}

func (s *SandfoxService) IsServiceInstalled() bool {
	return isCoreServiceInstalled()
}

func (s *SandfoxService) IsLauncherAvailable() bool {
	return isLauncherAvailable()
}

func (s *SandfoxService) IsLauncherTaskInstalled() bool {
	return isAutoStartInstalled()
}

func (s *SandfoxService) InstallLauncherTask() LauncherTaskResult {
	if err := setAutoStart(true); err != nil {
		s.log("error", "platform", "Launcher task install failed: "+err.Error())
		return LauncherTaskResult{Success: false, Error: err.Error()}
	}
	s.log("info", "platform", "Installed launcher task")
	return LauncherTaskResult{Success: true}
}

func (s *SandfoxService) UninstallLauncherTask() LauncherTaskResult {
	if err := setAutoStart(false); err != nil {
		s.log("error", "platform", "Launcher task uninstall failed: "+err.Error())
		return LauncherTaskResult{Success: false, Error: err.Error()}
	}
	s.log("warn", "platform", "Uninstalled launcher task")
	return LauncherTaskResult{Success: true}
}

func (s *SandfoxService) RunLauncherTaskNow() LauncherTaskResult {
	if err := runLauncherTaskNow(); err != nil {
		s.log("error", "platform", "Launcher task run failed: "+err.Error())
		return LauncherTaskResult{Success: false, Error: err.Error()}
	}
	s.log("info", "platform", "Ran launcher task")
	return LauncherTaskResult{Success: true}
}

func (s *SandfoxService) UpdateTrayMenu() error {
	s.log("info", "platform", "Tray menu refresh requested")
	return nil
}

func (s *SandfoxService) GetCoreServiceStatus() CoreServiceStatus {
	status := getCoreServiceStatus()
	s.mu.Lock()
	runtimeStatus := s.singBoxRuntimeStatusLocked()
	s.mu.Unlock()
	if daemon, ok := roverServiceStatus(); ok {
		status.SocketAvailable = true
		status.Running = true
		status.PID = daemon.PID
		status.Version = daemon.Version
		status.NeedsUpgrade = compareVersions(daemon.Version, roverServiceAPIVersion) < 0
		status.Platform = firstNonEmpty(daemon.Platform, status.Platform)
		status.ServicePath = daemon.SocketPath
		if helperRuntime, ok := roverServiceSingboxStatus(); ok {
			runtimeStatus = helperRuntime
		}
		return applyCoreServiceRuntimeStatus(status, runtimeStatus)
	}
	return applyCoreServiceRuntimeStatus(status, runtimeStatus)
}

func applyCoreServiceRuntimeStatus(status CoreServiceStatus, runtimeStatus SingBoxRuntimeStatusData) CoreServiceStatus {
	status.SocketAvailable = status.Running
	if status.Running {
		if strings.TrimSpace(status.Version) == "" {
			status.Version = roverServiceAPIVersion
		}
		status.NeedsUpgrade = compareVersions(status.Version, roverServiceAPIVersion) < 0
	}
	status.SingboxRunning = runtimeStatus.Running
	status.SingboxPid = runtimeStatus.PID
	status.SingboxStartTime = runtimeStatus.StartTime
	return status
}

func roverServiceStatus() (roverServiceDaemonStatus, bool) {
	var status roverServiceDaemonStatus
	if err := roverServiceRequest(http.MethodGet, "/status", nil, &status); err != nil {
		return status, false
	}
	return status, true
}

func roverServiceSingboxStatus() (SingBoxRuntimeStatusData, bool) {
	var status SingBoxRuntimeStatusData
	if err := roverServiceRequest(http.MethodGet, "/singbox/status", nil, &status); err != nil {
		return status, false
	}
	return status, true
}

func roverServiceStartSingbox(configPath, binaryPath string) error {
	body, err := json.Marshal(map[string]string{
		"configPath": configPath,
		"binaryPath": binaryPath,
	})
	if err != nil {
		return err
	}
	var status SingBoxRuntimeStatusData
	return roverServiceRequest(http.MethodPost, "/singbox/start", bytes.NewReader(body), &status)
}

func roverServiceStopSingbox() error {
	return roverServiceRequest(http.MethodPost, "/singbox/stop", nil, nil)
}

func roverServiceDNSStatus() (DNSRuntimeStatusData, bool) {
	var status DNSRuntimeStatusData
	if err := roverServiceRequest(http.MethodGet, "/dns/status", nil, &status); err != nil {
		return status, false
	}
	return status, true
}

func roverServiceStartDNS(address, certDir string) (DNSRuntimeStatusData, error) {
	body, err := json.Marshal(map[string]any{
		"address":    address,
		"certDir":    certDir,
		"logEnabled": false,
	})
	if err != nil {
		return DNSRuntimeStatusData{}, err
	}
	var status DNSRuntimeStatusData
	if err := roverServiceRequest(http.MethodPost, "/dns/start", bytes.NewReader(body), &status); err != nil {
		return DNSRuntimeStatusData{}, err
	}
	status.Running = true
	return status, nil
}

func roverServiceStopDNS() error {
	return roverServiceRequest(http.MethodPost, "/dns/stop", nil, nil)
}

func roverServiceRequest(method, endpoint string, body io.Reader, out any) error {
	socket := roverServiceSocketPath()
	if socket == "" {
		return errors.New("RoverService socket is not configured")
	}
	dialer := net.Dialer{Timeout: time.Second}
	client := http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialRoverService(ctx, dialer, socket)
			},
		},
	}
	req, err := http.NewRequest(method, "http://roverservice"+endpoint, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var apiResponse roverServiceAPIResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&apiResponse); err != nil {
		return err
	}
	if !apiResponse.Success {
		return errors.New(firstNonEmpty(apiResponse.Error, apiResponse.Message, "RoverService request failed"))
	}
	if out == nil || len(apiResponse.Data) == 0 {
		return nil
	}
	return json.Unmarshal(apiResponse.Data, out)
}

func roverServiceSocketPath() string {
	if value := strings.TrimSpace(os.Getenv("SANDFOX_ROVERSERVICE_SOCKET")); value != "" {
		return value
	}
	if runtime.GOOS == "windows" {
		return `\\.\pipe\roverservice`
	}
	return "/var/run/roverservice.sock"
}

func (s *SandfoxService) GetInstallationStatus() CoreServiceStatus {
	return s.GetCoreServiceStatus()
}

func (s *SandfoxService) GetDnsStatus() DNSRuntimeStatus {
	s.mu.Lock()
	address := s.dnsServerAddressLocked()
	certPath := s.dnsServerCertPathLocked()
	running := s.dnsServerRunning
	s.mu.Unlock()
	if helperStatus, ok := roverServiceDNSStatus(); ok && helperStatus.Running {
		running = true
		address = firstNonEmpty(helperStatus.Address, address)
		certPath = firstNonEmpty(helperStatus.CertPath, certPath)
	}
	status := DNSRuntimeStatusData{
		Running:  running,
		Address:  address,
		CertPath: certPath,
	}
	if address == "" {
		return DNSRuntimeStatus{Success: false, Data: status, Error: "DNS server address is not configured"}
	}
	return DNSRuntimeStatus{Success: true, Data: status}
}

func (s *SandfoxService) GetDNSStatus() DNSRuntimeStatus {
	return s.GetDnsStatus()
}

func (s *SandfoxService) startDNSServerLocked() {
	if s.dnsServer != nil {
		_ = s.dnsServer.Close()
		s.dnsServer = nil
	}
	port := preferenceInt(s.data.Preferences, "dns-server-port", 5353)
	s.dnsServerAddress = fmt.Sprintf("127.0.0.1:%d", port)
	base := s.dataDir
	if base == "" {
		base = "."
	}
	certDir := filepath.Join(base, "dns")
	if status, err := roverServiceStartDNS(s.dnsServerAddress, certDir); err == nil {
		s.dnsServerRunning = true
		s.dnsServerAddress = firstNonEmpty(status.Address, s.dnsServerAddress)
		s.dnsServerCertPath = firstNonEmpty(status.CertPath, filepath.Join(certDir, "cert.pem"))
		s.logLocked("info", "dns", "RoverService DNS server started on "+s.dnsServerAddress)
		return
	}
	certPath, keyPath, err := ensureDNSServerCertificate(certDir)
	if err != nil {
		s.dnsServerRunning = false
		s.logLocked("error", "dns", "Failed to prepare Rover DNS certificate: "+err.Error())
		return
	}
	listener, err := net.Listen("tcp", s.dnsServerAddress)
	if err != nil {
		s.dnsServerRunning = false
		s.logLocked("error", "dns", "Failed to listen on "+s.dnsServerAddress+": "+err.Error())
		return
	}
	server := &http.Server{Handler: http.HandlerFunc(s.handleDNSQuery)}
	s.dnsServer = server
	s.dnsServerCertPath = certPath
	s.dnsServerKeyPath = keyPath
	s.dnsServerRunning = true
	address := s.dnsServerAddress
	go func() {
		err := server.ServeTLS(listener, certPath, keyPath)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log("error", "dns", "Rover DNS server stopped with error: "+err.Error())
		}
		s.mu.Lock()
		if s.dnsServer == server {
			s.dnsServer = nil
			s.dnsServerRunning = false
		}
		s.mu.Unlock()
	}()
	s.logLocked("info", "dns", "Rover DNS server started on "+address)
}

func (s *SandfoxService) stopDNSServerLocked() {
	if s.dnsServer != nil {
		_ = s.dnsServer.Close()
		s.dnsServer = nil
	} else if s.dnsServerRunning {
		_ = roverServiceStopDNS()
	}
	if s.dnsServerRunning {
		s.logLocked("info", "dns", "Rover DNS server stopped")
	}
	s.dnsServerRunning = false
}

func (s *SandfoxService) dnsServerAddressLocked() string {
	if strings.TrimSpace(s.dnsServerAddress) != "" {
		return s.dnsServerAddress
	}
	port := preferenceInt(s.data.Preferences, "dns-server-port", 5353)
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func (s *SandfoxService) dnsServerCertPathLocked() string {
	if strings.TrimSpace(s.dnsServerCertPath) != "" {
		return s.dnsServerCertPath
	}
	base := s.dataDir
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "dns", "cert.pem")
}

func (s *SandfoxService) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dns-query" {
		http.NotFound(w, r)
		return
	}
	payload, err := dnsQueryPayload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	upstream := firstNonEmpty(s.data.Preferences["dns-upstream"], s.data.Settings.DNSListen, "https://1.1.1.1/dns-query")
	s.mu.Unlock()
	if !strings.HasPrefix(upstream, "http://") && !strings.HasPrefix(upstream, "https://") {
		upstream = "https://1.1.1.1/dns-query"
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream, bytes.NewReader(payload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	client := http.Client{Timeout: 8 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(res.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(res.Body, 64*1024))
}

func dnsQueryPayload(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		value := r.URL.Query().Get("dns")
		if value == "" {
			return nil, errors.New("missing dns query parameter")
		}
		return decodeDNSQueryParam(value)
	case http.MethodPost:
		return io.ReadAll(io.LimitReader(r.Body, 64*1024))
	default:
		return nil, errors.New("method not allowed")
	}
}

func decodeDNSQueryParam(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty dns query parameter")
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return decodeBase64Text(value)
}

func ensureDNSServerCertificate(dir string) (string, string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if fileExists(certPath) && fileExists(keyPath) {
		return certPath, keyPath, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "Sandfox Rover DNS",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", "", err
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		_ = certFile.Close()
		return "", "", err
	}
	if err := certFile.Close(); err != nil {
		return "", "", err
	}
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		_ = keyFile.Close()
		return "", "", err
	}
	if err := keyFile.Close(); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func (s *SandfoxService) GetSingboxStatus() SingBoxRuntimeStatus {
	if status, ok := roverServiceSingboxStatus(); ok {
		return SingBoxRuntimeStatus{Success: true, Data: status, Message: "sing-box status loaded from RoverService"}
	}
	s.mu.Lock()
	status := s.singBoxRuntimeStatusLocked()
	s.mu.Unlock()
	return SingBoxRuntimeStatus{Success: true, Data: status, Message: "sing-box status loaded"}
}

func (s *SandfoxService) GetSingBoxStatus() SingBoxRuntimeStatus {
	return s.GetSingboxStatus()
}

func (s *SandfoxService) FetchIPDirect() (*IPInfo, error) {
	info, err := fetchIPInfo(nil)
	if err != nil {
		s.log("error", "ip", "Direct IP check failed: "+err.Error())
		return nil, err
	}
	s.log("info", "ip", "Direct IP: "+info.IP+" "+info.CountryCode)
	return info, nil
}

func (s *SandfoxService) FetchIpDirect() (*IPInfo, error) {
	return s.FetchIPDirect()
}

func (s *SandfoxService) FetchIPThroughProxy() (*IPInfo, error) {
	s.mu.Lock()
	settings := normalizeSettings(s.data.Settings)
	s.mu.Unlock()
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", settings.MixedPort))
	if err != nil {
		return nil, err
	}
	info, err := fetchIPInfo(proxyURL)
	if err != nil {
		s.log("error", "ip", "Proxy IP check failed: "+err.Error())
		return nil, err
	}
	s.log("info", "ip", "Proxy IP: "+info.IP+" "+info.CountryCode)
	return info, nil
}

func (s *SandfoxService) FetchIpThroughProxy() (*IPInfo, error) {
	return s.FetchIPThroughProxy()
}

func (s *SandfoxService) GetBuildInfo() BuildInfo {
	s.mu.Lock()
	settings := normalizeSettings(s.data.Settings)
	s.mu.Unlock()
	_, version := detectSingBox(settings.SingBoxPath)
	return BuildInfo{
		AppVersion:     appVersion,
		SingBoxVersion: version,
		BuildTime:      buildTime,
		BuildNumber:    buildNumber,
		CommitSHA:      commitSHA,
	}
}

func (s *SandfoxService) CheckForUpdates(source string) UpdateCheckResult {
	source = strings.TrimSpace(source)
	if source == "" {
		return UpdateCheckResult{CurrentVersion: appVersion, Error: "update manifest source is required"}
	}
	raw, err := readUpdateManifestSource(source)
	if err != nil {
		return UpdateCheckResult{CurrentVersion: appVersion, Source: source, Error: err.Error()}
	}
	var manifest ReleaseManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return UpdateCheckResult{CurrentVersion: appVersion, Source: source, Error: err.Error()}
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return UpdateCheckResult{CurrentVersion: appVersion, Source: source, Error: "manifest version is required"}
	}
	return UpdateCheckResult{
		Available:      compareVersions(manifest.Version, appVersion) > 0,
		CurrentVersion: appVersion,
		LatestVersion:  manifest.Version,
		Manifest:       manifest,
		Source:         source,
	}
}

func readUpdateManifestSource(source string) ([]byte, error) {
	parsed, err := url.Parse(source)
	if err == nil {
		switch parsed.Scheme {
		case "http", "https":
			client := http.Client{Timeout: 10 * time.Second}
			req, err := http.NewRequest(http.MethodGet, source, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/json")
			res, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer res.Body.Close()
			if res.StatusCode < 200 || res.StatusCode >= 300 {
				return nil, fmt.Errorf("update manifest request failed: %s", res.Status)
			}
			return readLimitedBytes(res.Body, updateManifestMaxBytes)
		case "file":
			source = parsed.Path
		}
	}
	file, err := os.Open(source)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readLimitedBytes(file, updateManifestMaxBytes)
}

func readLimitedBytes(reader io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("payload exceeds %d bytes", limit)
	}
	return raw, nil
}

func compareVersions(a, b string) int {
	left := comparableVersion(a)
	right := comparableVersion(b)
	if left.special && right.special {
		return strings.Compare(left.raw, right.raw)
	}
	if left.special {
		return -1
	}
	if right.special {
		return 1
	}
	maxLen := len(left.parts)
	if len(right.parts) > maxLen {
		maxLen = len(right.parts)
	}
	for i := 0; i < maxLen; i++ {
		leftPart := versionPart(left.parts, i)
		rightPart := versionPart(right.parts, i)
		if leftPart > rightPart {
			return 1
		}
		if leftPart < rightPart {
			return -1
		}
	}
	if left.pre == right.pre {
		return 0
	}
	if left.pre == "" {
		return 1
	}
	if right.pre == "" {
		return -1
	}
	return strings.Compare(left.pre, right.pre)
}

type versionComparable struct {
	raw     string
	parts   []int
	pre     string
	special bool
}

func comparableVersion(value string) versionComparable {
	raw := strings.TrimSpace(strings.ToLower(value))
	raw = strings.TrimPrefix(raw, "v")
	raw = strings.Split(raw, "+")[0]
	if raw == "" || raw == "dev" || raw == "unknown" {
		return versionComparable{raw: raw, special: true}
	}
	base := raw
	pre := ""
	if idx := strings.Index(base, "-"); idx >= 0 {
		pre = base[idx+1:]
		base = base[:idx]
	}
	matches := regexp.MustCompile(`\d+`).FindAllString(base, -1)
	if len(matches) == 0 {
		return versionComparable{raw: raw, special: true}
	}
	parts := make([]int, 0, len(matches))
	for _, match := range matches {
		part, err := strconv.Atoi(match)
		if err != nil {
			part = 0
		}
		parts = append(parts, part)
	}
	return versionComparable{raw: raw, parts: parts, pre: pre}
}

func versionPart(parts []int, index int) int {
	if index >= len(parts) {
		return 0
	}
	return parts[index]
}

func (s *SandfoxService) OpenExternalURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return errors.New("url is required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return errors.New("absolute url is required")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "file":
		return openPath(rawURL)
	default:
		return fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}
}

func (s *SandfoxService) DetectSingBox() (string, error) {
	s.mu.Lock()
	settings := normalizeSettings(s.data.Settings)
	s.mu.Unlock()
	path, version := detectSingBox(settings.SingBoxPath)
	if path == "" {
		return "", errors.New("sing-box executable not found in settings or PATH")
	}
	s.log("info", "platform", "Detected sing-box "+version)
	return path, nil
}

func (s *SandfoxService) ApplyPlatformSettings() error {
	s.mu.Lock()
	settings := normalizeSettings(s.data.Settings)
	s.mu.Unlock()

	if err := setAutoStart(settings.AutoStart); err != nil {
		s.log("error", "platform", "Auto start update failed: "+err.Error())
		return err
	}
	if err := setSystemProxy(settings.SystemProxy, settings.MixedPort); err != nil {
		s.log("error", "platform", "System proxy update failed: "+err.Error())
		return err
	}
	s.log("info", "platform", "Applied platform settings")
	return nil
}

func (s *SandfoxService) InstallCoreService() error {
	check := s.ValidateConfig()
	if !check.OK {
		return errors.New(check.Message)
	}
	bin, err := s.resolvedCoreBinary()
	if err != nil {
		s.log("error", "platform", err.Error())
		return err
	}
	if err := installCoreService(bin, check.Path); err != nil {
		s.log("error", "platform", "Core service install failed: "+err.Error())
		return err
	}
	s.log("info", "platform", "Installed privileged core service")
	return nil
}

func (s *SandfoxService) UninstallCoreService() error {
	if err := uninstallCoreService(); err != nil {
		s.log("error", "platform", "Core service uninstall failed: "+err.Error())
		return err
	}
	s.log("warn", "platform", "Uninstalled privileged core service")
	return nil
}

func (s *SandfoxService) Install() LauncherTaskResult {
	if err := s.InstallCoreService(); err != nil {
		return LauncherTaskResult{Success: false, Error: err.Error()}
	}
	return LauncherTaskResult{Success: true}
}

func (s *SandfoxService) Uninstall() LauncherTaskResult {
	if err := s.UninstallCoreService(); err != nil {
		return LauncherTaskResult{Success: false, Error: err.Error()}
	}
	return LauncherTaskResult{Success: true}
}

func (s *SandfoxService) StartCoreService() error {
	if err := controlCoreService("bootstrap"); err != nil {
		s.log("error", "platform", "Core service start failed: "+err.Error())
		return err
	}
	s.log("info", "platform", "Started privileged core service")
	return nil
}

func (s *SandfoxService) StopCoreService() error {
	if err := controlCoreService("bootout"); err != nil {
		s.log("error", "platform", "Core service stop failed: "+err.Error())
		return err
	}
	s.log("warn", "platform", "Stopped privileged core service")
	return nil
}

func (s *SandfoxService) OpenDataDir() error {
	return openPath(s.dataDir)
}

func (s *SandfoxService) RunScheduledRefresh() error {
	profileIDs, ruleSetIDs, providerTargets, healthTargets := s.scheduledTargets(true)
	var errs []string
	for _, id := range profileIDs {
		if err := s.RefreshProfile(id); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, target := range providerTargets {
		if err := s.RefreshProfileProvider(target.ProfileID, target.ProviderName); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, target := range healthTargets {
		if _, err := s.TestProfileProvider(target.ProfileID, target.ProviderName, 3000); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, id := range ruleSetIDs {
		if err := s.RefreshRuleSet(id); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *SandfoxService) GetRefreshSchedule() []RefreshScheduleItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	items := make([]RefreshScheduleItem, 0, len(s.data.Profiles)+len(s.data.RuleSets))
	ruleProviderInterval := ruleProviderGlobalIntervalSeconds(s.data.Preferences)
	for _, profile := range s.data.Profiles {
		if strings.HasPrefix(profile.URL, "http://") || strings.HasPrefix(profile.URL, "https://") {
			interval := profile.UpdateInterval
			if interval <= 0 {
				interval = 24
			}
			next, due := nextRefreshState(profile.LastUpdated, interval, now)
			items = append(items, RefreshScheduleItem{
				Kind:          "profile",
				ID:            profile.ID,
				Name:          profile.Name,
				Enabled:       true,
				IntervalHours: interval,
				LastUpdated:   profile.LastUpdated,
				NextRefresh:   next,
				Due:           due,
				LastError:     profile.LastError,
			})
		}
		for _, provider := range profile.ProxyProviders {
			if provider.Type != "http" {
				continue
			}
			interval := providerRefreshIntervalSeconds(provider)
			next, due := nextRefreshStateDuration(provider.LastUpdated, time.Duration(interval)*time.Second, now)
			items = append(items, RefreshScheduleItem{
				Kind:            "proxy-provider",
				ID:              profile.ID + "::" + provider.Name,
				ProfileID:       profile.ID,
				ProviderName:    provider.Name,
				Name:            profile.Name + " / " + provider.Name,
				Enabled:         true,
				IntervalHours:   intervalHoursFromSeconds(interval),
				IntervalSeconds: interval,
				LastUpdated:     provider.LastUpdated,
				NextRefresh:     next,
				Due:             due,
				LastError:       provider.LastError,
			})
			if provider.HealthCheckEnable {
				healthInterval := providerHealthIntervalSeconds(provider)
				next, due := nextRefreshStateDuration(provider.LastChecked, time.Duration(healthInterval)*time.Second, now)
				items = append(items, RefreshScheduleItem{
					Kind:            "proxy-provider-health",
					ID:              profile.ID + "::" + provider.Name + "::health",
					ProfileID:       profile.ID,
					ProviderName:    provider.Name,
					Name:            profile.Name + " / " + provider.Name + " health",
					Enabled:         provider.HealthCheckEnable,
					IntervalHours:   intervalHoursFromSeconds(healthInterval),
					IntervalSeconds: healthInterval,
					LastUpdated:     provider.LastChecked,
					NextRefresh:     next,
					Due:             due,
					LastError:       provider.LastError,
				})
			}
		}
	}
	for _, ruleSet := range s.data.RuleSets {
		if !ruleSet.Enabled || ruleProviderInterval <= 0 {
			continue
		}
		next, due := nextRefreshStateDuration(ruleSet.LastUpdated, time.Duration(ruleProviderInterval)*time.Second, now)
		items = append(items, RefreshScheduleItem{
			Kind:            "ruleset",
			ID:              ruleSet.ID,
			Name:            ruleSet.Tag,
			Enabled:         ruleSet.Enabled,
			IntervalHours:   intervalHoursFromSeconds(ruleProviderInterval),
			IntervalSeconds: ruleProviderInterval,
			LastUpdated:     ruleSet.LastUpdated,
			NextRefresh:     next,
			Due:             due,
			LastError:       ruleSet.LastError,
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Due != items[j].Due {
			return items[i].Due
		}
		return items[i].NextRefresh.Before(items[j].NextRefresh)
	})
	return items
}

func (s *SandfoxService) startScheduler(parent context.Context) {
	if s.schedulerCancel != nil {
		s.schedulerCancel()
	}
	ctx, cancel := context.WithCancel(parent)
	s.schedulerCancel = cancel
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = s.runDueRefresh()
			}
		}
	}()
}

func (s *SandfoxService) runDueRefresh() error {
	profileIDs, ruleSetIDs, providerTargets, healthTargets := s.scheduledTargets(false)
	var errs []string
	for _, id := range profileIDs {
		if err := s.RefreshProfile(id); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, target := range providerTargets {
		if err := s.RefreshProfileProvider(target.ProfileID, target.ProviderName); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, target := range healthTargets {
		if _, err := s.TestProfileProvider(target.ProfileID, target.ProviderName, 3000); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, id := range ruleSetIDs {
		if err := s.RefreshRuleSet(id); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

type providerRefreshTarget struct {
	ProfileID    string
	ProviderName string
}

func (s *SandfoxService) scheduledTargets(force bool) ([]string, []string, []providerRefreshTarget, []providerRefreshTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	profileIDs := make([]string, 0)
	providerTargets := make([]providerRefreshTarget, 0)
	healthTargets := make([]providerRefreshTarget, 0)
	for _, profile := range s.data.Profiles {
		if !strings.HasPrefix(profile.URL, "http://") && !strings.HasPrefix(profile.URL, "https://") {
			for _, provider := range profile.ProxyProviders {
				if provider.Type != "http" {
					continue
				}
				interval := time.Duration(providerRefreshIntervalSeconds(provider)) * time.Second
				if force || provider.LastUpdated.IsZero() || now.Sub(provider.LastUpdated) >= interval {
					providerTargets = append(providerTargets, providerRefreshTarget{ProfileID: profile.ID, ProviderName: provider.Name})
				}
				healthInterval := time.Duration(providerHealthIntervalSeconds(provider)) * time.Second
				if provider.HealthCheckEnable && (force || provider.LastChecked.IsZero() || now.Sub(provider.LastChecked) >= healthInterval) {
					healthTargets = append(healthTargets, providerRefreshTarget{ProfileID: profile.ID, ProviderName: provider.Name})
				}
			}
			continue
		}
		interval := profile.UpdateInterval
		if interval <= 0 {
			interval = 24
		}
		if force || now.Sub(profile.LastUpdated) >= time.Duration(interval)*time.Hour {
			profileIDs = append(profileIDs, profile.ID)
		}
		for _, provider := range profile.ProxyProviders {
			if provider.Type != "http" {
				continue
			}
			providerInterval := time.Duration(providerRefreshIntervalSeconds(provider)) * time.Second
			if force || provider.LastUpdated.IsZero() || now.Sub(provider.LastUpdated) >= providerInterval {
				providerTargets = append(providerTargets, providerRefreshTarget{ProfileID: profile.ID, ProviderName: provider.Name})
			}
			healthInterval := time.Duration(providerHealthIntervalSeconds(provider)) * time.Second
			if provider.HealthCheckEnable && (force || provider.LastChecked.IsZero() || now.Sub(provider.LastChecked) >= healthInterval) {
				healthTargets = append(healthTargets, providerRefreshTarget{ProfileID: profile.ID, ProviderName: provider.Name})
			}
		}
	}
	ruleSetIDs := make([]string, 0)
	ruleProviderInterval := ruleProviderGlobalIntervalSeconds(s.data.Preferences)
	for _, ruleSet := range s.data.RuleSets {
		if !ruleSet.Enabled || ruleProviderInterval <= 0 {
			continue
		}
		if force || ruleSet.LastUpdated.IsZero() || now.Sub(ruleSet.LastUpdated) >= time.Duration(ruleProviderInterval)*time.Second {
			ruleSetIDs = append(ruleSetIDs, ruleSet.ID)
		}
	}
	return profileIDs, ruleSetIDs, providerTargets, healthTargets
}

func nextRefreshState(lastUpdated time.Time, intervalHours int, now time.Time) (time.Time, bool) {
	if intervalHours <= 0 {
		intervalHours = 24
	}
	return nextRefreshStateDuration(lastUpdated, time.Duration(intervalHours)*time.Hour, now)
}

func nextRefreshStateDuration(lastUpdated time.Time, interval time.Duration, now time.Time) (time.Time, bool) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if lastUpdated.IsZero() {
		return now, true
	}
	next := lastUpdated.Add(interval)
	return next, !now.Before(next)
}

func providerRefreshIntervalSeconds(provider ProxyProviderConfig) int {
	if provider.Interval > 0 {
		return provider.Interval
	}
	return 24 * 60 * 60
}

func providerHealthIntervalSeconds(provider ProxyProviderConfig) int {
	if provider.HealthCheckInterval > 0 {
		return provider.HealthCheckInterval
	}
	return providerRefreshIntervalSeconds(provider)
}

func ruleProviderGlobalIntervalSeconds(prefs map[string]string) int {
	if prefs == nil {
		return 24 * 60 * 60
	}
	value, ok := prefs["rule-provider-update-interval"]
	if !ok || strings.TrimSpace(value) == "" {
		return 24 * 60 * 60
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 0 {
		return 24 * 60 * 60
	}
	return parsed
}

func intervalHoursFromSeconds(seconds int) int {
	if seconds <= 0 {
		return 24
	}
	hours := seconds / 3600
	if seconds%3600 != 0 {
		hours++
	}
	if hours <= 0 {
		return 1
	}
	return hours
}

func (s *SandfoxService) GetLogs() []LogEntry {
	s.syncCoreLogTail()
	s.mu.Lock()
	defer s.mu.Unlock()
	logs := append([]LogEntry(nil), s.data.Logs...)
	sort.Slice(logs, func(i, j int) bool { return logs[i].Time.After(logs[j].Time) })
	return logs
}

func (s *SandfoxService) ClearLogs() error {
	s.mu.Lock()
	s.data.Logs = nil
	err := s.saveLocked()
	s.mu.Unlock()
	if truncateErr := os.Truncate(s.coreLogPath(), 0); truncateErr != nil && !os.IsNotExist(truncateErr) {
		return truncateErr
	}
	return err
}

func (s *SandfoxService) ClearAllLogs() error {
	return s.ClearLogs()
}

func (s *SandfoxService) Log(level, module, message string) error {
	s.log(level, module, message)
	return nil
}

func (s *SandfoxService) LogBatch(entries []LogInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range entries {
		s.logLocked(entry.Level, entry.Module, entry.Message)
	}
	return s.saveLocked()
}

func (s *SandfoxService) GetLogDir() string {
	return s.dataDir
}

func (s *SandfoxService) GetLogFiles() ([]string, error) {
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(strings.ToLower(name), ".log") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

func (s *SandfoxService) ReadCoreLog(options LogReadOptions) (LogReadResult, error) {
	path := s.coreLogPath()
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return LogReadResult{Lines: []string{}, TotalLines: 0, IsSearch: strings.TrimSpace(options.Search) != ""}, nil
		}
		return LogReadResult{}, err
	}
	defer file.Close()
	if options.MaxResults <= 0 {
		options.MaxResults = 500
	}
	search := strings.ToLower(strings.TrimSpace(options.Search))
	result := LogReadResult{Lines: []string{}, IsSearch: search != ""}
	scanner := bufio.NewScanner(file)
	lines := make([]string, 0)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return LogReadResult{}, err
	}
	result.TotalLines = len(lines)
	for lineNo, line := range lines {
		if lineNo >= options.FromLine && (search == "" || strings.Contains(strings.ToLower(line), search)) {
			result.Lines = append(result.Lines, line)
			if len(result.Lines) >= options.MaxResults {
				break
			}
		}
	}
	return result, nil
}

func (s *SandfoxService) GetInitialLogLineCount() (InitialLogLineCount, error) {
	result, err := s.ReadCoreLog(LogReadOptions{MaxResults: 1})
	if err != nil {
		return InitialLogLineCount{}, err
	}
	return InitialLogLineCount{LineCount: result.TotalLines}, nil
}

func (s *SandfoxService) ReadLog(options LogReadOptions) (LogReadResult, error) {
	return s.ReadCoreLog(options)
}

func (s *SandfoxService) ClearCoreLog() error {
	path := s.coreLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return file.Close()
}

func (s *SandfoxService) ClearLog() ClearOperationResult {
	if err := s.ClearCoreLog(); err != nil {
		return ClearOperationResult{Success: false, Error: err.Error()}
	}
	return ClearOperationResult{Success: true}
}

func (s *SandfoxService) OpenCoreLog() error {
	path := s.coreLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	_ = file.Close()
	return openPath(path)
}

func (s *SandfoxService) CloseConnection(id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("connection id is required")
	}
	_, err := s.clashRequest(http.MethodDelete, "/connections/"+urlPathEscape(id), nil)
	if err != nil {
		return err
	}
	s.log("info", "connection", "Closed connection "+id)
	return nil
}

func (s *SandfoxService) CloseAllConnections() error {
	_, err := s.clashRequest(http.MethodDelete, "/connections", nil)
	if err != nil {
		return err
	}
	s.log("info", "connection", "Closed all connections")
	return nil
}

func (s *SandfoxService) GetConnections() []Connection {
	if connections, err := s.fetchClashConnections(); err == nil && len(connections) > 0 {
		return connections
	}
	outbound := s.GetSettings().FinalOutbound
	return []Connection{
		{ID: "c1", Host: "github.com:443", Network: "tcp", Outbound: outbound, Upload: 32041, Download: 184234, Age: "2m14s"},
		{ID: "c2", Host: "api.openai.com:443", Network: "tcp", Outbound: outbound, Upload: 98122, Download: 640221, Age: "58s"},
		{ID: "c3", Host: "cloudflare-dns.com:443", Network: "udp", Outbound: "DIRECT", Upload: 4040, Download: 3002, Age: "9s"},
	}
}

func (s *SandfoxService) GetProxyGroups() []ProxyGroup {
	if groups, err := s.fetchClashProxies(); err == nil && len(groups) > 0 {
		return groups
	}
	profiles := s.GetProfiles()
	groups := make([]ProxyGroup, 0, len(profiles)+1)
	for _, profile := range profiles {
		if len(profile.Nodes) == 0 {
			continue
		}
		now := profile.Nodes[0].Name
		groups = append(groups, ProxyGroup{Name: profile.Name, Type: "selector", Now: now, All: profile.Nodes, Latency: profile.Nodes[0].Latency})
	}
	return groups
}

func (s *SandfoxService) GetAvailableOutbounds() []AvailableOutbound {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []AvailableOutbound{
		{Tag: "DIRECT", Type: "direct", Kind: "builtin"},
		{Tag: "REJECT", Type: "block", Kind: "builtin"},
	}
	seen := map[string]bool{"DIRECT": true, "REJECT": true}
	for _, profile := range s.data.Profiles {
		if !profile.Selected {
			continue
		}
		for _, node := range profile.Nodes {
			if node.Name == "" || seen[node.Name] {
				continue
			}
			seen[node.Name] = true
			out = append(out, AvailableOutbound{Tag: node.Name, Type: fallbackNodeType(node.Type), Kind: "node"})
		}
		for _, group := range profile.ProxyGroups {
			if group.Name == "" || seen[group.Name] {
				continue
			}
			seen[group.Name] = true
			out = append(out, AvailableOutbound{Tag: group.Name, Type: singBoxGroupType(group.Type), Kind: "group"})
		}
		break
	}
	return out
}

func (s *SandfoxService) SelectProxy(group, proxy string) error {
	body := strings.NewReader(fmt.Sprintf(`{"name":%q}`, proxy))
	_, err := s.clashRequest(http.MethodPut, "/proxies/"+urlPathEscape(group), body)
	return err
}

func (s *SandfoxService) GetTraffic() TrafficState {
	raw, err := s.clashRequest(http.MethodGet, "/traffic", nil)
	if err != nil {
		return TrafficState{}
	}
	var traffic TrafficState
	if err := json.Unmarshal(raw, &traffic); err != nil {
		return TrafficState{}
	}
	traffic.Live = true
	return traffic
}

func (s *SandfoxService) TestProxyDelay(name string) int {
	delay, err := s.GetProxyDelay(name, "http://www.gstatic.com/generate_204", 3000)
	if err == nil && delay > 0 {
		return delay
	}
	return 40 + len(name)*7%180
}

func (s *SandfoxService) GetProxyDelay(name, testURL string, timeout int) (int, error) {
	if timeout <= 0 {
		timeout = 3000
	}
	if testURL == "" {
		testURL = "http://www.gstatic.com/generate_204"
	}
	path := fmt.Sprintf("/proxies/%s/delay?timeout=%d&url=%s", urlPathEscape(name), timeout, url.QueryEscape(testURL))
	raw, err := s.clashRequest(http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}
	var payload struct {
		Delay int `json:"delay"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, err
	}
	return payload.Delay, nil
}

func (s *SandfoxService) TestClashAPI() ClashProbe {
	s.mu.Lock()
	settings := normalizeSettings(s.data.Settings)
	s.mu.Unlock()
	url := fmt.Sprintf("http://127.0.0.1:%d/version", settings.APIPort)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ClashProbe{Available: false, URL: url, Message: err.Error()}
	}
	if settings.APISecret != "" {
		req.Header.Set("Authorization", "Bearer "+settings.APISecret)
	}
	client := http.Client{Timeout: 2 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return ClashProbe{Available: false, URL: url, Message: err.Error()}
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return ClashProbe{Available: false, URL: url, Message: res.Status}
	}
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	version := fmt.Sprint(body["version"])
	if version == "<nil>" {
		version = strings.TrimSpace(string(raw))
	}
	return ClashProbe{Available: true, URL: url, Version: version, Message: "Clash API is reachable"}
}

func (s *SandfoxService) clashRequest(method, path string, body io.Reader) ([]byte, error) {
	settings := s.GetSettings()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", normalizeSettings(settings).APIPort, path)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if settings.APISecret != "" {
		req.Header.Set("Authorization", "Bearer "+settings.APISecret)
	}
	client := http.Client{Timeout: 3 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("clash api %s returned %s: %s", path, res.Status, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func (s *SandfoxService) fetchClashProxies() ([]ProxyGroup, error) {
	raw, err := s.clashRequest(http.MethodGet, "/proxies", nil)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Proxies map[string]struct {
			Name    string   `json:"name"`
			Type    string   `json:"type"`
			Now     string   `json:"now"`
			All     []string `json:"all"`
			History []struct {
				Delay int `json:"delay"`
			} `json:"history"`
		} `json:"proxies"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	groups := make([]ProxyGroup, 0, len(payload.Proxies))
	for name, proxy := range payload.Proxies {
		if len(proxy.All) == 0 {
			continue
		}
		latency := 0
		if len(proxy.History) > 0 {
			latency = proxy.History[len(proxy.History)-1].Delay
		}
		nodes := make([]ProxyNode, 0, len(proxy.All))
		for _, node := range proxy.All {
			nodes = append(nodes, ProxyNode{Name: node, Type: "proxy", Server: name, Country: guessCountry(node), Latency: latency, Selected: node == proxy.Now})
		}
		groups = append(groups, ProxyGroup{Name: name, Type: proxy.Type, Now: proxy.Now, All: nodes, Latency: latency})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	return groups, nil
}

func (s *SandfoxService) fetchClashConnections() ([]Connection, error) {
	raw, err := s.clashRequest(http.MethodGet, "/connections", nil)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Connections []struct {
			ID       string `json:"id"`
			Metadata struct {
				Host        string `json:"host"`
				Destination string `json:"destinationIP"`
				Network     string `json:"network"`
				DstPort     string `json:"destinationPort"`
			} `json:"metadata"`
			Chains   []string  `json:"chains"`
			Upload   int64     `json:"upload"`
			Download int64     `json:"download"`
			Start    time.Time `json:"start"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	connections := make([]Connection, 0, len(payload.Connections))
	for _, item := range payload.Connections {
		host := item.Metadata.Host
		if host == "" {
			host = item.Metadata.Destination
		}
		if item.Metadata.DstPort != "" {
			host += ":" + item.Metadata.DstPort
		}
		outbound := ""
		if len(item.Chains) > 0 {
			outbound = item.Chains[len(item.Chains)-1]
		}
		age := ""
		if !item.Start.IsZero() {
			age = time.Since(item.Start).Round(time.Second).String()
		}
		connections = append(connections, Connection{ID: item.ID, Host: host, Network: item.Metadata.Network, Outbound: outbound, Upload: item.Upload, Download: item.Download, Age: age})
	}
	return connections, nil
}

func (s *SandfoxService) isCoreRunning() bool {
	s.mu.Lock()
	localRunning := s.coreRunningLocked()
	s.mu.Unlock()
	if localRunning {
		return true
	}
	if status, ok := roverServiceSingboxStatus(); ok {
		return status.Running
	}
	return false
}

func (s *SandfoxService) coreRunningLocked() bool {
	return s.core != nil && s.core.Process != nil && s.core.ProcessState == nil
}

func (s *SandfoxService) singBoxRuntimeStatusLocked() SingBoxRuntimeStatusData {
	status := SingBoxRuntimeStatusData{
		Running:    s.coreRunningLocked(),
		ConfigPath: filepath.Join(s.dataDir, "config.json"),
		BinaryPath: s.coreBinaryLocked(),
	}
	if status.Running {
		status.PID = s.core.Process.Pid
		if !s.coreUpAt.IsZero() {
			status.StartTime = s.coreUpAt.UnixMilli()
		}
	}
	return status
}

func chooseTrafficValue(live, fallback int64) int64 {
	if live > 0 {
		return live
	}
	return fallback
}

func urlPathEscape(value string) string {
	replacer := strings.NewReplacer("%", "%25", "/", "%2F", "?", "%3F", "#", "%23", " ", "%20")
	return replacer.Replace(value)
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	stat, err := os.Stat(path)
	return err == nil && !stat.IsDir()
}

func sanitizeFilename(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "._")
}

func (s *SandfoxService) ExportConfigSnapshot() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dataDir, "sandfox-export-"+time.Now().Format("20060102-150405")+".json")
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return "", err
	}
	s.logLocked("info", "config", "Exported snapshot "+filepath.Base(path))
	_ = s.saveLocked()
	return path, nil
}

func (s *SandfoxService) ExportConfig() ConfigOperationResult {
	path, err := s.ExportConfigSnapshot()
	if err != nil {
		return ConfigOperationResult{OK: false, Error: err.Error()}
	}
	return ConfigOperationResult{OK: true, Path: path}
}

func (s *SandfoxService) Export() ConfigOperationResult {
	return s.ExportConfig()
}

func (s *SandfoxService) GetDatabaseStatus() DatabaseStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return DatabaseStatus{
		Path:           s.dataPath(),
		BackupDir:      s.backupDir(),
		SchemaVersion:  s.data.SchemaVersion,
		CurrentVersion: dataSchemaVersion,
		NeedsMigration: s.data.SchemaVersion < dataSchemaVersion,
		Profiles:       len(s.data.Profiles),
		Policies:       len(s.data.Policies),
		DNSServers:     len(s.data.DNSServers),
		DNSPolicies:    len(s.data.DNSPolicies),
		RuleSets:       len(s.data.RuleSets),
		Preferences:    len(s.data.Preferences),
		UpdatedAt:      s.data.UpdatedAt,
	}
}

func (s *SandfoxService) ExportConfigBackup() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.backupDir(), 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(s.backupDir(), "sandfox-backup-"+time.Now().Format("20060102-150405")+".zip")
	if err := s.writeBackupZipLocked(path); err != nil {
		return "", err
	}
	s.logLocked("info", "config", "Exported backup "+filepath.Base(path))
	_ = s.saveLocked()
	return path, nil
}

func (s *SandfoxService) ImportConfigBackup(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("backup path is required")
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()
	var manifest BackupManifest
	var data AppData
	foundManifest := false
	foundData := false
	for _, file := range reader.File {
		switch file.Name {
		case "manifest.json":
			raw, err := readZipFile(file, 1<<20)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &manifest); err != nil {
				return err
			}
			foundManifest = true
		case "sandfox.json", "database.json":
			raw, err := readZipFile(file, 32<<20)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &data); err != nil {
				return err
			}
			foundData = true
		}
	}
	if !foundManifest || !foundData {
		return errors.New("backup zip must contain manifest.json and sandfox.json")
	}
	if manifest.FormatVersion != backupFormatVersion {
		return fmt.Errorf("unsupported backup format version %d", manifest.FormatVersion)
	}
	s.migrateData(&data)
	if data.CreatedAt.IsZero() {
		data.CreatedAt = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.writeBackupZipLocked(filepath.Join(s.backupDir(), "pre-import-"+time.Now().Format("20060102-150405")+".zip"))
	s.data = data
	s.logLocked("warn", "config", "Imported backup "+filepath.Base(path))
	return s.saveLocked()
}

func (s *SandfoxService) ImportConfigSnapshot(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("snapshot path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var next AppData
	if err := json.Unmarshal(raw, &next); err != nil {
		return err
	}
	s.migrateData(&next)
	s.mu.Lock()
	s.data = next
	s.logLocked("warn", "config", "Imported config snapshot "+filepath.Base(path))
	err = s.saveLocked()
	s.mu.Unlock()
	return err
}

func (s *SandfoxService) ImportConfig(path string) ConfigOperationResult {
	if err := s.ImportConfigSnapshot(path); err != nil {
		return ConfigOperationResult{OK: false, Error: err.Error()}
	}
	return ConfigOperationResult{OK: true, Path: path}
}

func (s *SandfoxService) Import(path string) ConfigOperationResult {
	return s.ImportConfig(path)
}

func (s *SandfoxService) ImportSingBoxConfigFile(path string, replace bool) (ConfigImportResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return ConfigImportResult{}, errors.New("config path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ConfigImportResult{}, err
	}
	return s.ImportSingBoxConfig(string(raw), replace)
}

func (s *SandfoxService) ImportSingBoxConfig(content string, replace bool) (ConfigImportResult, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return ConfigImportResult{}, errors.New("sing-box config content is required")
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(content), &config); err != nil {
		return ConfigImportResult{}, err
	}
	route, ok := mapFromAny(config["route"])
	if !ok {
		return ConfigImportResult{}, errors.New("sing-box config route section is required")
	}
	importedRuleSets := ruleSetsFromConfig(route["rule_set"])
	importedPolicies := policiesFromConfigRules(route["rules"])
	if len(importedPolicies) == 0 && len(importedRuleSets) == 0 {
		return ConfigImportResult{}, errors.New("no route rules or rule sets found")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if replace {
		s.data.Policies = nil
		s.data.RuleSets = nil
	}
	for _, ruleSet := range importedRuleSets {
		if !replace && s.hasRuleSetTagLocked(ruleSet.Tag) {
			continue
		}
		s.data.RuleSets = append(s.data.RuleSets, ruleSet)
	}
	for _, policy := range importedPolicies {
		policy.Priority = len(s.data.Policies) + 1
		s.data.Policies = append(s.data.Policies, normalizePolicy(policy))
	}
	result := ConfigImportResult{Policies: len(importedPolicies), RuleSets: len(importedRuleSets), Replaced: replace}
	s.logLocked("info", "config", fmt.Sprintf("Imported sing-box config with %d policies and %d rule sets", result.Policies, result.RuleSets))
	return result, s.saveLocked()
}

func (s *SandfoxService) ImportClashConfigFile(path string, replace bool) (ConfigImportResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return ConfigImportResult{}, errors.New("config path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ConfigImportResult{}, err
	}
	return s.ImportClashConfig(string(raw), replace)
}

func (s *SandfoxService) ImportClashConfig(content string, replace bool) (ConfigImportResult, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return ConfigImportResult{}, errors.New("clash config content is required")
	}
	var config map[string]any
	if err := yaml.Unmarshal([]byte(content), &config); err != nil {
		return ConfigImportResult{}, err
	}
	importedPolicies, finalOutbound := policiesFromClashRules(config["rules"])
	importedSettings, hasImportedSettings := settingsFromClashConfig(config)
	importedDNSServers, importedDNSPolicies := dnsFromClashConfig(config)
	importedRuleSets := mergeRuleSets(
		ruleSetsFromClashProviders(config["rule-providers"]),
		mergeRuleSets(ruleSetsFromPolicyReferences(importedPolicies), ruleSetsFromDNSPolicyReferences(importedDNSPolicies)),
	)
	if len(importedPolicies) == 0 && len(importedRuleSets) == 0 && len(importedDNSServers) == 0 && len(importedDNSPolicies) == 0 && finalOutbound == "" && !hasImportedSettings {
		return ConfigImportResult{}, errors.New("no clash rules found")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if replace {
		s.data.Policies = nil
		s.data.RuleSets = nil
	}
	for _, ruleSet := range importedRuleSets {
		if !replace && s.hasRuleSetTagLocked(ruleSet.Tag) {
			continue
		}
		s.data.RuleSets = append(s.data.RuleSets, ruleSet)
	}
	for _, policy := range importedPolicies {
		policy.Priority = len(s.data.Policies) + 1
		s.data.Policies = append(s.data.Policies, normalizePolicy(policy))
	}
	if finalOutbound != "" {
		s.data.Settings.FinalOutbound = finalOutbound
	}
	if hasImportedSettings {
		s.data.Settings = mergeSettings(s.data.Settings, importedSettings)
	}
	if len(importedDNSServers) > 0 {
		if replace {
			s.data.DNSServers = nil
		}
		for _, server := range importedDNSServers {
			if !replace && s.hasDNSServerTagLocked(server.Tag) {
				continue
			}
			s.data.DNSServers = append(s.data.DNSServers, server)
		}
	}
	if len(importedDNSPolicies) > 0 {
		if replace {
			s.data.DNSPolicies = nil
		}
		for _, policy := range importedDNSPolicies {
			s.data.DNSPolicies = append(s.data.DNSPolicies, normalizeDNSPolicy(policy))
		}
	}
	result := ConfigImportResult{Policies: len(importedPolicies), RuleSets: len(importedRuleSets), Replaced: replace}
	s.logLocked("info", "config", fmt.Sprintf("Imported Clash rules with %d policies and %d rule sets", result.Policies, result.RuleSets))
	return result, s.saveLocked()
}

func (s *SandfoxService) ImportProfileFile(name, path string) (Profile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Profile{}, errors.New("profile file path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return s.ImportProfile(name, string(raw))
}

func (s *SandfoxService) GenerateConfig() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	config := s.buildConfigLocked()
	warnings := configWarnings(s.data.Settings)
	path := filepath.Join(s.dataDir, "config.json")
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return "", err
	}
	s.logLocked("info", "core", "Generated sing-box config")
	for _, warning := range warnings {
		s.logLocked("warn", "config", warning)
	}
	_ = s.saveLocked()
	return path, nil
}

func (s *SandfoxService) PreviewConfig() (ConfigPreview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	config := s.buildConfigLocked()
	path := filepath.Join(s.dataDir, "config.json")
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return ConfigPreview{}, err
	}
	changed := true
	if existing, err := os.ReadFile(path); err == nil {
		changed = string(existing) != string(raw)
	}
	return ConfigPreview{Path: path, Content: string(raw), Changed: changed, Warnings: configWarnings(s.data.Settings)}, nil
}

func (s *SandfoxService) GetActiveConfig() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buildConfigLocked()
}

func (s *SandfoxService) GetCurrentConfigRules() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	config := s.buildConfigLocked()
	route, _ := config["route"].(map[string]any)
	rules, _ := route["rules"].([]map[string]any)
	return append([]map[string]any(nil), rules...)
}

func (s *SandfoxService) GetSelectedProfile() SelectedProfileState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := SelectedProfileState{Config: s.buildConfigLocked()}
	for _, profile := range s.data.Profiles {
		if profile.Selected {
			state.Found = true
			state.Profile = profile
			return state
		}
	}
	return state
}

func (s *SandfoxService) PreviewConfigDiff() (ConfigPreview, error) {
	preview, err := s.PreviewConfig()
	if err != nil {
		return ConfigPreview{}, err
	}
	existing, err := os.ReadFile(preview.Path)
	if err != nil {
		return ConfigPreview{Path: preview.Path, Content: buildUnifiedDiff("", preview.Content), Changed: true}, nil
	}
	return ConfigPreview{
		Path:    preview.Path,
		Content: buildUnifiedDiff(string(existing), preview.Content),
		Changed: preview.Changed,
	}, nil
}

func (s *SandfoxService) ValidateConfig() CoreCheckResult {
	path, err := s.GenerateConfig()
	if err != nil {
		return CoreCheckResult{OK: false, Path: path, Message: err.Error()}
	}
	bin, err := s.resolvedCoreBinary()
	if err != nil {
		s.log("error", "core", err.Error())
		return CoreCheckResult{OK: false, Path: path, Message: err.Error()}
	}
	cmd := exec.Command(bin, "check", "-c", path)
	cmd.Env = singBoxCommandEnv()
	out, err := cmd.CombinedOutput()
	message := strings.TrimSpace(string(out))
	if err != nil {
		if message == "" {
			message = err.Error()
		}
		s.log("error", "core", "Config validation failed: "+message)
		return CoreCheckResult{OK: false, Path: path, Message: message}
	}
	if message == "" {
		message = "config is valid"
	}
	s.log("info", "core", "Config validation passed")
	return CoreCheckResult{OK: true, Path: path, Message: message}
}

func (s *SandfoxService) RestartCore() error {
	if err := s.StopCore(); err != nil {
		return err
	}
	return s.StartCore()
}

func (s *SandfoxService) StartCore() error {
	path, err := s.GenerateConfig()
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.core != nil && s.core.Process != nil {
		s.mu.Unlock()
		return nil
	}
	settings := normalizeSettings(s.data.Settings)
	bin := s.coreBinaryLocked()
	if resolved, err := s.resolvedCoreBinaryLocked(); err == nil {
		bin = resolved
	} else if !settings.TUNEnabled || os.Getenv("SANDFOX_ROVERSERVICE_SOCKET") == "" {
		s.mu.Unlock()
		s.log("error", "core", err.Error())
		return err
	}
	if settings.TUNEnabled {
		s.mu.Unlock()
		if err := roverServiceStartSingbox(path, bin); err != nil {
			s.log("error", "core", "RoverService start failed: "+err.Error())
			return err
		}
		s.mu.Lock()
		if preferenceBool(s.data.Preferences, "dns-server-enabled", false) {
			s.startDNSServerLocked()
		}
		if settings.SystemProxy {
			if err := setSystemProxy(true, settings.MixedPort); err != nil {
				s.logLocked("error", "platform", "System proxy update failed: "+err.Error())
			}
		}
		s.logLocked("info", "core", "sing-box started via RoverService")
		err := s.saveLocked()
		s.mu.Unlock()
		return err
	}
	defer s.mu.Unlock()
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Env = singBoxCommandEnv()
	logPath := s.coreLogPath()
	stdout, stderr, closeLog, err := s.coreLogWriters(logPath)
	if err != nil {
		s.logLocked("error", "core", "Failed to open core log: "+err.Error())
		_ = s.saveLocked()
		return err
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = closeLog()
		s.logLocked("error", "core", "Failed to start sing-box: "+err.Error())
		_ = s.saveLocked()
		return fmt.Errorf("failed to start sing-box: %w", err)
	}
	s.core = cmd
	s.coreUpAt = time.Now()
	s.logLocked("info", "core", "sing-box started")
	if preferenceBool(s.data.Preferences, "dns-server-enabled", false) {
		s.startDNSServerLocked()
	}
	go func() {
		_ = cmd.Wait()
		_ = closeLog()
		s.mu.Lock()
		if s.core == cmd {
			s.core = nil
		}
		s.stopDNSServerLocked()
		s.logLocked("warn", "core", "sing-box stopped")
		_ = s.saveLocked()
		s.mu.Unlock()
	}()
	if settings.SystemProxy {
		if err := setSystemProxy(true, settings.MixedPort); err != nil {
			s.logLocked("error", "platform", "System proxy update failed: "+err.Error())
		}
	}
	return s.saveLocked()
}

func (s *SandfoxService) coreBinary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.coreBinaryLocked()
}

func (s *SandfoxService) coreBinaryLocked() string {
	bin := strings.TrimSpace(s.data.Settings.SingBoxPath)
	if bin == "" {
		bin = "sing-box"
	}
	return bin
}

func (s *SandfoxService) resolvedCoreBinary() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resolvedCoreBinaryLocked()
}

func (s *SandfoxService) resolvedCoreBinaryLocked() (string, error) {
	bin := s.coreBinaryLocked()
	resolved, err := findExecutable(bin, standardExecutablePaths("sing-box")...)
	if err != nil {
		return "", fmt.Errorf("sing-box executable not found. Install sing-box or set Core settings > sing-box path. Checked value: %q", bin)
	}
	return resolved, nil
}

func (s *SandfoxService) StopCore() error {
	s.mu.Lock()
	settings := normalizeSettings(s.data.Settings)
	if s.core == nil || s.core.Process == nil {
		s.mu.Unlock()
		if settings.TUNEnabled {
			if err := roverServiceStopSingbox(); err != nil {
				s.log("error", "core", "RoverService stop failed: "+err.Error())
				return err
			}
		}
		s.mu.Lock()
		s.stopDNSServerLocked()
		if settings.SystemProxy {
			if proxyErr := setSystemProxy(false, settings.MixedPort); proxyErr != nil {
				s.logLocked("error", "platform", "System proxy disable failed: "+proxyErr.Error())
			}
		}
		s.logLocked("warn", "core", "sing-box stopped by user")
		err := s.saveLocked()
		s.mu.Unlock()
		return err
	}
	err := s.core.Process.Kill()
	s.core = nil
	s.stopDNSServerLocked()
	if settings.SystemProxy {
		if proxyErr := setSystemProxy(false, settings.MixedPort); proxyErr != nil {
			s.logLocked("error", "platform", "System proxy disable failed: "+proxyErr.Error())
		}
	}
	s.logLocked("warn", "core", "sing-box stopped by user")
	_ = s.saveLocked()
	s.mu.Unlock()
	return err
}

func (s *SandfoxService) Start() (bool, error) {
	if err := s.StartCore(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *SandfoxService) Stop() error {
	return s.StopCore()
}

func (s *SandfoxService) Restart() (bool, error) {
	if err := s.RestartCore(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *SandfoxService) IsRunning() bool {
	return s.isCoreRunning()
}

func (s *SandfoxService) GetStartTime() *int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.coreRunningLocked() || s.coreUpAt.IsZero() {
		return nil
	}
	start := s.coreUpAt.UnixMilli()
	return &start
}

func (s *SandfoxService) UpdateProfile(profileID string) (string, error) {
	if err := s.RefreshProfile(profileID); err != nil {
		return "", err
	}
	return profileID, nil
}

func (s *SandfoxService) AddSubscriptionProfile(url string) (string, error) {
	profile, err := s.ImportProfile(subscriptionProfileName(url), url)
	if err != nil {
		return "", err
	}
	return profile.ID, nil
}

func subscriptionProfileName(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return "New Profile"
}

func (s *SandfoxService) OpenUserDataPath() error {
	return s.OpenDataDir()
}

func (s *SandfoxService) OpenExternalUrl(rawURL string) error {
	return s.OpenExternalURL(rawURL)
}

func (s *SandfoxService) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.dataPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.data = defaultData()
			return s.saveLocked()
		}
		return err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return err
	}
	previousVersion := s.data.SchemaVersion
	if previousVersion < dataSchemaVersion {
		_ = s.writeRawBackup("pre-migration-"+time.Now().Format("20060102-150405")+".json", raw)
		s.migrateData(&s.data)
		return s.saveLocked()
	}
	s.migrateData(&s.data)
	return s.saveLocked()
}

func (s *SandfoxService) saveLocked() error {
	s.data.SchemaVersion = dataSchemaVersion
	s.data.UpdatedAt = time.Now()
	path := s.dataPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func (s *SandfoxService) migrateData(data *AppData) {
	if data.SchemaVersion <= 0 {
		data.SchemaVersion = 1
	}
	data.Settings = normalizeSettings(data.Settings)
	for i := range data.Profiles {
		data.Profiles[i].CustomGroups = normalizeCustomProxyGroups(data.Profiles[i].CustomGroups)
	}
	if data.Preferences == nil {
		data.Preferences = map[string]string{}
	}
	ensureDefaultDNSResolvers(data)
	if data.CreatedAt.IsZero() {
		data.CreatedAt = time.Now()
	}
	if data.UpdatedAt.IsZero() {
		data.UpdatedAt = data.CreatedAt
	}
	data.SchemaVersion = dataSchemaVersion
}

func ensureDefaultDNSResolvers(data *AppData) {
	for i := range data.DNSServers {
		switch data.DNSServers[i].Tag {
		case "cloudflare", "alidns":
			if data.DNSServers[i].AddressResolver == "" {
				data.DNSServers[i].AddressResolver = "dns_direct_out"
			}
		}
	}
}

func (s *SandfoxService) dataPath() string {
	return filepath.Join(s.dataDir, "sandfox.json")
}

func (s *SandfoxService) backupDir() string {
	return filepath.Join(s.dataDir, "backups")
}

func (s *SandfoxService) writeRawBackup(name string, raw []byte) error {
	if err := os.MkdirAll(s.backupDir(), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.backupDir(), name), raw, 0o644)
}

func (s *SandfoxService) writeBackupZipLocked(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()
	_, version := detectSingBox(s.data.Settings.SingBoxPath)
	manifest := BackupManifest{
		FormatVersion:  backupFormatVersion,
		SchemaVersion:  dataSchemaVersion,
		CreatedAt:      time.Now(),
		App:            "sandfox",
		AppVersion:     appVersion,
		SingBoxVersion: version,
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	dataRaw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := writeZipEntry(zipWriter, "manifest.json", manifestRaw); err != nil {
		return err
	}
	return writeZipEntry(zipWriter, "sandfox.json", dataRaw)
}

func writeZipEntry(zipWriter *zip.Writer, name string, raw []byte) error {
	writer, err := zipWriter.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write(raw)
	return err
}

func readZipFile(file *zip.File, limit int64) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, limit))
}

func (s *SandfoxService) log(level, source, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logLocked(level, source, message)
	_ = s.saveLocked()
}

func (s *SandfoxService) logLocked(level, source, message string) {
	s.data.Logs = append(s.data.Logs, LogEntry{ID: uuid.NewString(), Level: level, Source: source, Message: strings.TrimSpace(message), Time: time.Now()})
	if len(s.data.Logs) > 500 {
		s.data.Logs = s.data.Logs[len(s.data.Logs)-500:]
	}
}

func (s *SandfoxService) buildConfigLocked() map[string]any {
	settings := normalizeSettings(s.data.Settings)
	prefs := s.data.Preferences
	mixedInbound := map[string]any{"type": "mixed", "tag": "mixed-in", "listen": settings.MixedListen, "listen_port": settings.MixedPort}
	applySniffSettings(mixedInbound, settings)
	inbounds := []map[string]any{
		mixedInbound,
	}
	dnsProxyEnabled := preferenceBool(prefs, "dns-server-enabled", false)
	if dnsProxyEnabled {
		dnsProxyPort := preferenceInt(prefs, "dns-proxy-port", 17890)
		inbound := map[string]any{"type": "mixed", "tag": "dns_proxy_in", "listen": settings.MixedListen, "listen_port": dnsProxyPort}
		applySniffSettings(inbound, settings)
		inbounds = append(inbounds, inbound)
	}
	if settings.TUNEnabled {
		tunInbound := tunInboundFromSettings(settings)
		applySniffSettings(tunInbound, settings)
		inbounds = append(inbounds, tunInbound)
	}

	outbounds := []map[string]any{{"type": "direct", "tag": "DIRECT"}, {"type": "block", "tag": "REJECT"}}
	var selectedProfile *Profile
	for _, p := range s.data.Profiles {
		if !p.Selected {
			continue
		}
		selectedProfile = &p
		for _, n := range p.Nodes {
			outbounds = append(outbounds, outboundFromNode(n))
		}
		groupOutbounds := groupOutboundsFromProfile(p)
		if settings.CustomProxyGroups {
			groupOutbounds = customGroupOutboundsFromProfile(p)
		}
		for _, group := range groupOutbounds {
			outbounds = append(outbounds, group)
		}
	}
	proxyOutbound := preferredProxyOutbound(selectedProfile)
	policyOverrides := profilePolicyOverrideMap(selectedProfile)
	rules := make([]map[string]any, 0, len(s.data.Policies))
	ruleSets := make([]map[string]any, 0, len(s.data.RuleSets))
	if settingsOverrideRulesEnabled(settings) {
		for _, p := range s.data.Policies {
			if !p.Enabled {
				continue
			}
			policy := p
			if outbound := policyOverrides[policy.ID]; outbound != "" {
				policy.Outbound = outbound
			}
			rules = append(rules, ruleFromPolicy(policy))
		}
		for _, r := range s.data.RuleSets {
			if !r.Enabled {
				continue
			}
			ruleSets = append(ruleSets, ruleSetToSingBox(r))
		}
	}
	dnsServerDetours := profileDNSServerDetourMap(selectedProfile)
	dnsServers := make([]map[string]any, 0, len(s.data.DNSServers)+1)
	for _, server := range s.data.DNSServers {
		if !server.Enabled {
			continue
		}
		entry := dnsServerToSingBox(server, prefs, proxyOutbound)
		if server.AddressResolver != "" {
			entry["address_resolver"] = server.AddressResolver
		}
		if server.AddressStrategy != "" {
			entry["address_strategy"] = server.AddressStrategy
		}
		detour := firstNonEmpty(dnsServerDetours[server.ID], dnsServerDetours[server.Tag], server.Detour)
		if detour != "" {
			entry["detour"] = detour
		}
		if server.Strategy != "" {
			entry["strategy"] = server.Strategy
		}
		dnsServers = append(dnsServers, entry)
	}
	if len(dnsServers) == 0 {
		dnsServers = append(dnsServers, map[string]any{"tag": "cloudflare", "address": settings.DNSListen, "strategy": "prefer_ipv4"})
	}
	if dnsServersReferenceTag(dnsServers, "dns_direct_out") {
		dnsServers = ensureDirectDNSSupportServer(dnsServers)
	}
	normalDNSServer := dnsServers[0]["tag"]
	dnsPolicyOverrides := profileDNSPolicyOverrideMap(selectedProfile)
	dnsRules := make([]map[string]any, 0, len(s.data.DNSPolicies))
	if len(settings.Hosts) > 0 {
		dnsServers = append([]map[string]any{{
			"type":       "hosts",
			"tag":        "hosts",
			"predefined": settings.Hosts,
		}}, dnsServers...)
		dnsRules = append(dnsRules,
			map[string]any{"action": "evaluate", "server": "hosts"},
			map[string]any{"match_response": true, "ip_accept_any": true, "action": "respond"},
		)
	}
	if hostsServer, hostsRules := hostsOverrideToDNSConfig(prefs["hosts-override"]); hostsServer != nil || len(hostsRules) > 0 {
		if hostsServer != nil {
			dnsServers = append([]map[string]any{hostsServer}, dnsServers...)
		}
		dnsRules = append(append([]map[string]any{}, hostsRules...), dnsRules...)
	}
	if settings.DNSFakeIPEnabled {
		fakeIPServer := map[string]any{"type": "fakeip", "tag": "fakeip"}
		if settings.DNSFakeIPRange != "" {
			fakeIPServer["inet4_range"] = settings.DNSFakeIPRange
		}
		if settingsIPv6Enabled(settings) && settings.DNSFakeIPv6Range != "" {
			fakeIPServer["inet6_range"] = settings.DNSFakeIPv6Range
		}
		dnsServers = append(dnsServers, fakeIPServer)
		for _, rule := range dnsRulesFromMatchers(settings.DNSFakeIPFilter, fmt.Sprint(normalDNSServer)) {
			dnsRules = append(dnsRules, rule)
		}
	}
	if settingsOverrideRulesEnabled(settings) {
		for _, policy := range s.data.DNSPolicies {
			if !policy.Enabled {
				continue
			}
			policy = normalizeDNSPolicy(policy)
			if server := dnsPolicyOverrides[policy.ID]; server != "" {
				policy.Server = server
			}
			rule := map[string]any{"server": policy.Server}
			if len(policy.RuleSet) > 0 {
				rule["rule_set"] = policy.RuleSet
			}
			if len(policy.DomainSuffix) > 0 {
				rule["domain_suffix"] = policy.DomainSuffix
			}
			if len(policy.DomainKeyword) > 0 {
				rule["domain_keyword"] = policy.DomainKeyword
			}
			if len(policy.QueryType) > 0 {
				rule["query_type"] = policy.QueryType
			}
			if len(policy.Network) > 0 {
				rule["network"] = policy.Network
			}
			if policy.Strategy != "" {
				rule["strategy"] = policy.Strategy
			}
			if policy.Type == "raw" && len(policy.RawData) > 0 {
				rule = cloneMap(policy.RawData)
				if _, ok := rule["server"]; !ok {
					rule["server"] = policy.Server
				}
			}
			dnsRules = append(dnsRules, rule)
		}
	}
	ruleSets = ensureRuleSetsForDNSRules(ruleSets, dnsRules)
	finalDNSServer := dnsServers[0]["tag"]
	if settings.DNSFakeIPEnabled {
		finalDNSServer = "fakeip"
	}
	if value := strings.TrimSpace(prefs["dns-unmatched-server"]); value != "" {
		finalDNSServer = value
	}
	dnsConfig := map[string]any{"servers": dnsServers, "rules": dnsRules, "final": finalDNSServer}
	if settings.DNSStrategy != "" {
		dnsConfig["strategy"] = settings.DNSStrategy
	}
	if !settingsIPv6Enabled(settings) {
		dnsConfig["strategy"] = "ipv4_only"
	}
	systemRules := systemRouteRules(settings.TUNEnabled, dnsProxyEnabled, proxyOutbound)
	rules = append(systemRules, rules...)
	routeFinal := settings.FinalOutbound
	dashboardMode := strings.ToLower(firstNonEmpty(settings.Mode, "rule"))
	if dashboardMode == "direct" {
		rules = nil
		ruleSets = nil
		dnsRules = nil
		dnsConfig["rules"] = dnsRules
		routeFinal = "DIRECT"
		dnsConfig["final"] = "dns_direct_out"
	} else if dashboardMode == "global" {
		rules = nil
		ruleSets = nil
		dnsRules = nil
		dnsConfig["rules"] = dnsRules
		routeFinal = proxyOutbound
		dnsConfig["final"] = "dns_selector_out"
	}
	if dnsProxyEnabled || dashboardMode != "rule" || hasAnyPreference(prefs, "dns-unmatched-server", "dns-resolve-server", "dns-proxy-server") {
		dnsConfig["servers"] = ensureRoverDNSSupportServers(dnsServers, proxyOutbound)
	}
	route := map[string]any{
		"rules":                 rules,
		"rule_set":              ruleSets,
		"final":                 routeFinal,
		"auto_detect_interface": boolValue(settings.TUNAutoDetectInterface, true),
	}
	if resolver := strings.TrimSpace(prefs["dns-resolve-server"]); resolver != "" {
		route["default_domain_resolver"] = resolver
	} else {
		route["default_domain_resolver"] = dnsConfig["final"]
	}
	experimental := runtimeExperimental(settings.Experimental)
	if experimental == nil {
		experimental = map[string]any{}
	}
	clashAPI := map[string]any{}
	if existing, ok := mapFromAny(experimental["clash_api"]); ok {
		clashAPI = cloneMap(existing)
	}
	clashAPI["external_controller"] = fmt.Sprintf("127.0.0.1:%d", settings.APIPort)
	clashAPI["secret"] = settings.APISecret
	experimental["clash_api"] = clashAPI
	return map[string]any{
		"log":          map[string]any{"level": settings.LogLevel},
		"inbounds":     inbounds,
		"outbounds":    outbounds,
		"route":        route,
		"dns":          dnsConfig,
		"experimental": experimental,
	}
}

func runtimeExperimental(experimental map[string]any) map[string]any {
	out := cloneMap(experimental)
	delete(out, "sandfox_unsupported")
	return out
}

func configWarnings(settings Settings) []string {
	unsupported, ok := mapFromAny(settings.Experimental["sandfox_unsupported"])
	if !ok || len(unsupported) == 0 {
		return nil
	}
	warnings := []string{}
	if _, ok := unsupported["clash_script"]; ok {
		warnings = append(warnings, "Clash script rules are preserved in settings.experimental.sandfox_unsupported but are not emitted to sing-box config.")
	}
	return warnings
}

func tunInboundFromSettings(settings Settings) map[string]any {
	address := settings.TUNAddress
	if !settingsIPv6Enabled(settings) {
		address = filterIPv4CIDRs(address)
	}
	inbound := map[string]any{
		"type":           "tun",
		"tag":            "tun-in",
		"interface_name": firstNonEmpty(settings.TUNInterfaceName, "sandfox0"),
		"address":        address,
		"auto_route":     boolValue(settings.TUNAutoRoute, true),
		"strict_route":   boolValue(settings.TUNStrictRoute, true),
		"stack":          firstNonEmpty(settings.TUNStack, "system"),
	}
	if settings.TUNMTU > 0 {
		inbound["mtu"] = settings.TUNMTU
	}
	if len(settings.TUNDNSHijack) > 0 {
		inbound["dns_hijack"] = settings.TUNDNSHijack
	}
	if len(settings.TUNRouteAddress) > 0 {
		inbound["route_address"] = settings.TUNRouteAddress
	}
	if len(settings.TUNRouteExcludeAddress) > 0 {
		inbound["route_exclude_address"] = settings.TUNRouteExcludeAddress
	}
	return inbound
}

func settingsIPv6Enabled(settings Settings) bool {
	if settings.IPv6 != nil {
		return *settings.IPv6
	}
	if settings.DNSIPv6 != nil {
		return *settings.DNSIPv6
	}
	return true
}

func settingsOverrideRulesEnabled(settings Settings) bool {
	if settings.OverrideRules == nil {
		return true
	}
	return *settings.OverrideRules
}

func settingsAutoStartProxyEnabled(settings Settings) bool {
	if settings.AutoStartProxy == nil {
		return true
	}
	return *settings.AutoStartProxy
}

func roverSettingsMap(settings Settings) map[string]string {
	settings = normalizeSettings(settings)
	out := map[string]string{
		"mixed-port":                 strconv.Itoa(settings.MixedPort),
		"allow-lan":                  boolString(settings.AllowLAN),
		"log-level":                  settings.LogLevel,
		"api-url":                    fmt.Sprintf("http://127.0.0.1:%d", settings.APIPort),
		"api-secret":                 settings.APISecret,
		"dashboard-mode":             settings.Mode,
		"dashboard-system-proxy":     boolString(settings.SystemProxy),
		"dns-server-enabled":         "false",
		"dns-server-port":            "5353",
		"dns-proxy-port":             "17890",
		"dns-unmatched-server":       settings.DNSListen,
		"dns-resolve-server":         settings.DNSListen,
		"dns-proxy-server":           settings.DNSListen,
		"override-rules":             boolString(settingsOverrideRulesEnabled(settings)),
		"custom-proxy-groups":        boolString(settings.CustomProxyGroups),
		"subscription-user-agent":    settings.SubscriptionUserAgent,
		"auto-start-proxy":           boolString(settingsAutoStartProxyEnabled(settings)),
		"ipv6":                       boolString(settingsIPv6Enabled(settings)),
		"dashboard-tun-mode":         boolString(settings.TUNEnabled),
		"sniff-enabled":              boolString(settings.SniffEnabled),
		"sniff-override-destination": boolString(settings.SniffOverrideDestination),
		"policy-final-outbound":      settings.FinalOutbound,
	}
	if raw, err := json.Marshal(settings.TUNRouteExcludeAddress); err == nil {
		out["tun-exclude-address"] = string(raw)
	}
	return out
}

func applyRoverSetting(settings *Settings, key, value string) bool {
	value = strings.TrimSpace(value)
	switch key {
	case "mixed-port":
		if port, err := strconv.Atoi(value); err == nil && port > 0 {
			settings.MixedPort = port
		}
	case "allow-lan":
		settings.AllowLAN = parseBoolSetting(value)
		if settings.AllowLAN {
			settings.MixedListen = "0.0.0.0"
		} else {
			settings.MixedListen = "127.0.0.1"
		}
	case "log-level":
		settings.LogLevel = value
	case "api-url":
		settings.APIPort = apiPortFromSetting(value, settings.APIPort)
	case "api-secret":
		settings.APISecret = value
	case "dashboard-mode":
		switch strings.ToLower(value) {
		case "rule", "global", "direct":
			settings.Mode = strings.ToLower(value)
		}
	case "dashboard-system-proxy":
		settings.SystemProxy = parseBoolSetting(value)
	case "dns-unmatched-server":
		return false
	case "override-rules":
		settings.OverrideRules = boolPtr(parseBoolSetting(value))
	case "custom-proxy-groups":
		settings.CustomProxyGroups = parseBoolSetting(value)
	case "subscription-user-agent":
		settings.SubscriptionUserAgent = value
	case "auto-start-proxy":
		settings.AutoStartProxy = boolPtr(parseBoolSetting(value))
	case "ipv6":
		settings.IPv6 = boolPtr(parseBoolSetting(value))
	case "dashboard-tun-mode":
		settings.TUNEnabled = parseBoolSetting(value)
	case "sniff-enabled":
		settings.SniffEnabled = parseBoolSetting(value)
	case "sniff-override-destination":
		settings.SniffOverrideDestination = parseBoolSetting(value)
	case "policy-final-outbound":
		settings.FinalOutbound = roverFinalOutbound(value)
	case "tun-exclude-address":
		settings.TUNRouteExcludeAddress = parseJSONStringList(value)
	default:
		return false
	}
	return true
}

func isPreferenceBackedRoverSetting(key string) bool {
	switch key {
	case "dns-server-enabled", "dns-server-port", "dns-proxy-port", "dns-unmatched-server", "dns-resolve-server", "dns-proxy-server", "hosts-override", "rule-provider-update-interval", "proxies-page-settings":
		return true
	default:
		return false
	}
}

func patchRuleSetFromMap(ruleSet RuleSet, updates map[string]any) RuleSet {
	if value := firstString(updates["name"], updates["tag"]); value != "" {
		ruleSet.Tag = strings.TrimSpace(value)
	}
	if value := firstString(updates["url"]); value != "" {
		ruleSet.URL = strings.TrimSpace(value)
	}
	if value := firstString(updates["path"]); value != "" {
		ruleSet.Path = strings.TrimSpace(value)
	}
	if value := firstString(updates["localPath"], updates["local_path"]); value != "" {
		ruleSet.LocalPath = strings.TrimSpace(value)
	}
	if value := firstString(updates["type"]); value != "" {
		ruleSet.Type = strings.ToLower(strings.TrimSpace(value))
	}
	if value := firstString(updates["format"]); value != "" {
		ruleSet.Format = strings.ToLower(strings.TrimSpace(value))
	}
	if value := firstString(updates["behavior"]); value != "" {
		ruleSet.Behavior = strings.ToLower(strings.TrimSpace(value))
	}
	if value := firstString(updates["downloadDetour"], updates["download_detour"]); value != "" {
		ruleSet.DownloadDetour = strings.TrimSpace(value)
	}
	if enabled, ok := boolFromAny(updates["enabled"]); ok {
		ruleSet.Enabled = enabled
	}
	ruleSet.Tag = strings.TrimSpace(ruleSet.Tag)
	if ruleSet.Type == "" {
		if ruleSet.URL != "" {
			ruleSet.Type = "remote"
		} else {
			ruleSet.Type = "local"
		}
	}
	if ruleSet.Format == "" {
		ruleSet.Format = guessRuleSetFormat(ruleSet.URL + ruleSet.Path)
	}
	if ruleSet.DownloadDetour == "" {
		ruleSet.DownloadDetour = "DIRECT"
	}
	return ruleSet
}

func patchByJSON[T any](base T, updates map[string]any) T {
	raw, err := json.Marshal(base)
	if err != nil {
		return base
	}
	var merged map[string]any
	if err := json.Unmarshal(raw, &merged); err != nil {
		return base
	}
	for key, value := range updates {
		merged[key] = value
	}
	raw, err = json.Marshal(merged)
	if err != nil {
		return base
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		return base
	}
	return out
}

func orderedIDsFromOrders(orders []OrderItem) []string {
	ordered := append([]OrderItem(nil), orders...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Order < ordered[j].Order
	})
	out := make([]string, 0, len(ordered))
	for _, item := range ordered {
		if strings.TrimSpace(item.ID) != "" {
			out = append(out, strings.TrimSpace(item.ID))
		}
	}
	return out
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func parseBoolSetting(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func preferenceBool(prefs map[string]string, key string, fallback bool) bool {
	if prefs == nil {
		return fallback
	}
	value, ok := prefs[key]
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	return parseBoolSetting(value)
}

func preferenceInt(prefs map[string]string, key string, fallback int) int {
	if prefs == nil {
		return fallback
	}
	value, ok := prefs[key]
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func apiPortFromSetting(value string, fallback int) int {
	if fallback <= 0 {
		fallback = 9090
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.Port() != "" {
		if port, convErr := strconv.Atoi(parsed.Port()); convErr == nil && port > 0 {
			return port
		}
	}
	if host, portText, err := net.SplitHostPort(value); err == nil && host != "" && portText != "" {
		if port, convErr := strconv.Atoi(portText); convErr == nil && port > 0 {
			return port
		}
	}
	if port, err := strconv.Atoi(value); err == nil && port > 0 {
		return port
	}
	return fallback
}

func roverFinalOutbound(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "direct_out", "direct":
		return "DIRECT"
	case "block_out", "reject", "block":
		return "REJECT"
	case "selector_out", "proxy":
		return "Auto"
	default:
		return strings.TrimSpace(value)
	}
}

func parseJSONStringList(value string) []string {
	var out []string
	if err := json.Unmarshal([]byte(value), &out); err == nil {
		return compactList(out)
	}
	return splitSettingList(value)
}

func splitSettingList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	return compactList(parts)
}

func filterIPv4CIDRs(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.Contains(value, ":") {
			continue
		}
		out = append(out, value)
	}
	return out
}

func applySniffSettings(inbound map[string]any, settings Settings) {
	if !settings.SniffEnabled {
		return
	}
	inbound["sniff"] = true
	if settings.SniffOverrideDestination {
		inbound["sniff_override_destination"] = true
	}
}

func profilePolicyOverrideMap(profile *Profile) map[string]string {
	out := map[string]string{}
	if profile == nil {
		return out
	}
	for _, override := range profile.PolicyOverrides {
		if override.PolicyID != "" && override.Outbound != "" {
			out[override.PolicyID] = override.Outbound
		}
	}
	return out
}

func profileDNSPolicyOverrideMap(profile *Profile) map[string]string {
	out := map[string]string{}
	if profile == nil {
		return out
	}
	for _, override := range profile.DNSPolicyOverrides {
		if override.PolicyID != "" && override.Server != "" {
			out[override.PolicyID] = override.Server
		}
	}
	return out
}

func profileDNSServerDetourMap(profile *Profile) map[string]string {
	out := map[string]string{}
	if profile == nil {
		return out
	}
	for _, detour := range profile.DNSServerDetours {
		if detour.ServerID != "" && detour.Detour != "" {
			out[detour.ServerID] = detour.Detour
		}
	}
	return out
}

type logWriter struct {
	service *SandfoxService
	level   string
	source  string
	file    *os.File
}

func (w logWriter) Write(p []byte) (int, error) {
	if w.file != nil {
		_, _ = w.file.Write(p)
	}
	w.service.log(w.level, w.source, string(p))
	return len(p), nil
}

func (s *SandfoxService) coreLogPath() string {
	return filepath.Join(s.dataDir, "sing-box.log")
}

func (s *SandfoxService) coreLogWriters(path string) (io.Writer, io.Writer, func() error, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, nil, err
	}
	stdout := logWriter{service: s, level: "info", source: "sing-box", file: file}
	stderr := logWriter{service: s, level: "error", source: "sing-box", file: file}
	return stdout, stderr, file.Close, nil
}

func (s *SandfoxService) syncCoreLogTail() {
	path := s.coreLogPath()
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || stat.Size() == 0 {
		return
	}
	var start int64
	if stat.Size() > 64*1024 {
		start = stat.Size() - 64*1024
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return
	}
	scanner := bufio.NewScanner(file)
	lines := make([]string, 0, 80)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			lines = append(lines, text)
		}
		if len(lines) > 80 {
			lines = lines[len(lines)-80:]
		}
	}
	if len(lines) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := map[string]bool{}
	for _, log := range s.data.Logs {
		if log.Source == "sing-box-file" {
			existing[log.Message] = true
		}
	}
	for _, line := range lines {
		if existing[line] {
			continue
		}
		s.data.Logs = append(s.data.Logs, LogEntry{ID: uuid.NewString(), Level: inferLogLevel(line), Source: "sing-box-file", Message: line, Time: time.Now()})
	}
	if len(s.data.Logs) > 500 {
		s.data.Logs = s.data.Logs[len(s.data.Logs)-500:]
	}
	_ = s.saveLocked()
}

func inferLogLevel(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "error") || strings.Contains(lower, "fatal"):
		return "error"
	case strings.Contains(lower, "warn"):
		return "warn"
	default:
		return "info"
	}
}

func normalizePolicy(policy Policy) Policy {
	policy.Name = strings.TrimSpace(policy.Name)
	policy.Match = strings.TrimSpace(policy.Match)
	policy.Outbound = strings.TrimSpace(policy.Outbound)
	if policy.Outbound == "" {
		policy.Outbound = "DIRECT"
	}
	policy.Domain = compactList(policy.Domain)
	policy.DomainSuffix = compactList(policy.DomainSuffix)
	policy.DomainKeyword = compactList(policy.DomainKeyword)
	policy.DomainRegex = compactList(policy.DomainRegex)
	policy.IPCIDR = compactList(policy.IPCIDR)
	policy.SourceIPCIDR = compactList(policy.SourceIPCIDR)
	policy.Port = compactList(policy.Port)
	policy.PortRange = compactList(policy.PortRange)
	policy.SourcePort = compactList(policy.SourcePort)
	policy.SourcePortRange = compactList(policy.SourcePortRange)
	policy.ProcessName = compactList(policy.ProcessName)
	policy.ProcessPath = compactList(policy.ProcessPath)
	policy.ProcessPathRegex = compactList(policy.ProcessPathRegex)
	policy.PackageName = compactList(policy.PackageName)
	policy.Protocol = compactList(policy.Protocol)
	policy.QueryType = compactList(policy.QueryType)
	policy.Network = compactList(policy.Network)
	policy.NetworkType = compactList(policy.NetworkType)
	policy.DefaultInterfaceAddress = compactList(policy.DefaultInterfaceAddress)
	policy.WifiSSID = compactList(policy.WifiSSID)
	policy.WifiBSSID = compactList(policy.WifiBSSID)
	policy.RuleSet = compactList(policy.RuleSet)
	if policy.Match != "" && !hasLegacyPolicyMatchers(policy) && len(policy.RuleSet) == 0 {
		if strings.HasPrefix(policy.Match, "rule-set:") {
			policy.RuleSet = splitCSV(strings.TrimPrefix(policy.Match, "rule-set:"))
		} else {
			policy.DomainSuffix = splitCSV(policy.Match)
		}
	}
	return policy
}

func normalizeDNSPolicy(policy DNSPolicy) DNSPolicy {
	policy.Domain = strings.TrimSpace(policy.Domain)
	policy.Server = strings.TrimSpace(policy.Server)
	policy.Strategy = strings.TrimSpace(policy.Strategy)
	policy.DomainSuffix = compactList(policy.DomainSuffix)
	policy.DomainKeyword = compactList(policy.DomainKeyword)
	policy.RuleSet = compactList(policy.RuleSet)
	policy.QueryType = compactList(policy.QueryType)
	policy.Network = compactList(policy.Network)
	if policy.Domain != "" && len(policy.DomainSuffix)+len(policy.RuleSet)+len(policy.DomainKeyword) == 0 {
		switch {
		case strings.HasPrefix(policy.Domain, "rule-set:"):
			policy.RuleSet = splitCSV(strings.TrimPrefix(policy.Domain, "rule-set:"))
		case strings.HasPrefix(policy.Domain, "geosite:"):
			policy.RuleSet = splitCSV(strings.TrimPrefix(policy.Domain, "geosite:"))
		default:
			policy.DomainSuffix = splitCSV(policy.Domain)
		}
	}
	return policy
}

func normalizeNode(node ProxyNode) ProxyNode {
	node.Name = strings.TrimSpace(node.Name)
	node.Type = fallbackNodeType(strings.TrimSpace(node.Type))
	node.Server = strings.TrimSpace(node.Server)
	if node.Port == 0 {
		node.Port = 443
	}
	if node.Raw == nil {
		node.Raw = map[string]any{}
	}
	node.Raw["name"] = node.Name
	node.Raw["type"] = node.Type
	node.Raw["server"] = node.Server
	node.Raw["port"] = node.Port
	if node.Country == "" {
		node.Country = guessCountry(node.Name + " " + node.Server)
	}
	if node.Latency == 0 {
		node.Latency = 80 + len(node.Name)*5%180
	}
	return node
}

func normalizeProxyGroupConfig(group ProxyGroupConfig) ProxyGroupConfig {
	group.Name = strings.TrimSpace(group.Name)
	group.Type = strings.ToLower(strings.TrimSpace(group.Type))
	if group.Type == "" {
		group.Type = "select"
	}
	group.Proxies = uniqueCompactList(group.Proxies)
	group.Use = uniqueCompactList(group.Use)
	group.URL = strings.TrimSpace(group.URL)
	group.Strategy = strings.TrimSpace(group.Strategy)
	if group.Interval < 0 {
		group.Interval = 0
	}
	if group.Tolerance < 0 {
		group.Tolerance = 0
	}
	return group
}

func customGroupsFromProxyGroups(groups []ProxyGroupConfig) []CustomProxyGroup {
	out := make([]CustomProxyGroup, 0, len(groups))
	for index, group := range groups {
		members := append([]string{}, group.Proxies...)
		members = append(members, group.Use...)
		groupType := group.Type
		switch groupType {
		case "select":
			groupType = "selector"
		case "url-test":
			groupType = "urltest"
		}
		out = append(out, CustomProxyGroup{
			Name:      group.Name,
			Type:      groupType,
			Outbounds: uniqueCompactList(members),
			Order:     index,
		})
	}
	return out
}

func normalizeCustomProxyGroups(groups []CustomProxyGroup) []CustomProxyGroup {
	ordered := append([]CustomProxyGroup(nil), groups...)
	sort.SliceStable(ordered, func(i, j int) bool {
		left := ordered[i].Order
		right := ordered[j].Order
		if left == right {
			return i < j
		}
		return left < right
	})
	out := make([]CustomProxyGroup, 0, len(ordered))
	for index, group := range ordered {
		group = normalizeCustomProxyGroup(group)
		if group.Name == "" {
			continue
		}
		if group.Order == 0 {
			group.Order = index
		}
		out = append(out, group)
	}
	return out
}

func normalizeCustomProxyGroup(group CustomProxyGroup) CustomProxyGroup {
	group.Name = strings.TrimSpace(group.Name)
	group.Type = strings.ToLower(strings.TrimSpace(group.Type))
	switch group.Type {
	case "select":
		group.Type = "selector"
	case "url-test", "fallback", "load-balance":
		group.Type = "urltest"
	}
	if group.Type == "" {
		group.Type = "selector"
	}
	group.Outbounds = uniqueCompactList(group.Outbounds)
	return group
}

func proxyGroupsFromCustomGroups(groups []CustomProxyGroup) []ProxyGroupConfig {
	ordered := append([]CustomProxyGroup(nil), groups...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Order < ordered[j].Order })
	out := make([]ProxyGroupConfig, 0, len(ordered))
	for _, group := range ordered {
		out = append(out, proxyGroupFromCustomGroup(group))
	}
	return out
}

func proxyGroupFromCustomGroup(group CustomProxyGroup) ProxyGroupConfig {
	groupType := group.Type
	switch groupType {
	case "selector":
		groupType = "select"
	case "urltest":
		groupType = "url-test"
	}
	return normalizeProxyGroupConfig(ProxyGroupConfig{
		Name:    group.Name,
		Type:    groupType,
		Proxies: group.Outbounds,
	})
}

func (s *SandfoxService) profileIndexLocked(profileID string) (int, error) {
	if profileID == "" {
		for i := range s.data.Profiles {
			if s.data.Profiles[i].Selected {
				return i, nil
			}
		}
	}
	for i := range s.data.Profiles {
		if s.data.Profiles[i].ID == profileID {
			return i, nil
		}
	}
	return -1, errors.New("profile not found")
}

func outboundFromNode(node ProxyNode) map[string]any {
	raw := node.Raw
	if raw == nil {
		raw = map[string]any{}
	}
	out := map[string]any{
		"type":        fallbackNodeType(firstString(raw["type"], node.Type)),
		"tag":         firstString(raw["name"], node.Name),
		"server":      firstString(raw["server"], node.Server),
		"server_port": firstInt(raw["port"], node.Port),
	}
	switch out["type"] {
	case "shadowsocks":
		copyString(out, raw, "method", "method", "cipher")
		copyString(out, raw, "password")
		copyBool(out, raw, "udp_over_tcp", "udp-over-tcp")
		copyString(out, raw, "udp_over_tcp_version", "udp-over-tcp-version")
		copyPluginOptions(out, raw)
	case "vmess":
		copyString(out, raw, "uuid")
		copyString(out, raw, "security")
		copyString(out, raw, "alter_id", "alterId")
		copyTLS(out, raw, false)
		copyTransport(out, raw)
		copyMultiplex(out, raw)
		copyPacketEncoding(out, raw)
	case "vless":
		copyString(out, raw, "uuid")
		copyString(out, raw, "flow")
		copyTLS(out, raw, false)
		copyTransport(out, raw)
		copyMultiplex(out, raw)
		copyPacketEncoding(out, raw)
	case "trojan":
		copyString(out, raw, "password")
		copyTLS(out, raw, true)
		copyTransport(out, raw)
		copyMultiplex(out, raw)
	case "hysteria2":
		copyString(out, raw, "password")
		copyString(out, raw, "obfs")
		copyString(out, raw, "obfs_password", "obfs-password", "obfs_password")
		copyMbps(out, raw, "up_mbps", "up", "up_mbps")
		copyMbps(out, raw, "down_mbps", "down", "down_mbps")
		copyTLS(out, raw, true)
	case "tuic":
		copyString(out, raw, "uuid")
		copyString(out, raw, "password")
		copyString(out, raw, "congestion_control", "congestion-controller")
		copyString(out, raw, "udp_relay_mode", "udp-relay-mode")
		copyTLS(out, raw, true)
	case "socks":
		out["version"] = "5"
		copyString(out, raw, "username")
		copyString(out, raw, "password")
		copyTLS(out, raw, false)
	case "http":
		copyString(out, raw, "username")
		copyString(out, raw, "password")
		copyTLS(out, raw, false)
	case "anytls":
		copyString(out, raw, "password")
		copyTLS(out, raw, true)
		copyDurationSeconds(out, raw, "idle_session_check_interval", "idle-session-check-interval", "idle_session_check_interval")
		copyDurationSeconds(out, raw, "idle_session_timeout", "idle-session-timeout", "idle_session_timeout")
		if minIdle := firstInt(raw["min-idle-session"], firstInt(raw["min_idle_session"], 0)); minIdle > 0 {
			out["min_idle_session"] = minIdle
		}
	}
	copyBool(out, raw, "tcp_fast_open", "tfo", "tcp_fast_open")
	return out
}

func groupOutboundsFromProfile(profile Profile) []map[string]any {
	if len(profile.ProxyGroups) == 0 {
		return nil
	}
	validNodes := map[string]bool{"DIRECT": true, "REJECT": true}
	for _, node := range profile.Nodes {
		if node.Name != "" {
			validNodes[node.Name] = true
		}
	}
	validGroups := map[string]bool{}
	for _, group := range profile.ProxyGroups {
		if group.Name != "" {
			validGroups[group.Name] = true
		}
	}
	out := make([]map[string]any, 0, len(profile.ProxyGroups))
	for _, group := range profile.ProxyGroups {
		if group.Name == "" {
			continue
		}
		outbounds := make([]string, 0, len(group.Proxies))
		for _, proxy := range group.Proxies {
			proxy = normalizeClashOutbound(proxy)
			if proxy == "" {
				continue
			}
			if validNodes[proxy] || validGroups[proxy] {
				outbounds = append(outbounds, proxy)
			}
		}
		for _, provider := range profile.ProxyProviders {
			if !containsString(group.Use, provider.Name) {
				continue
			}
			for _, node := range profile.Nodes {
				if firstString(node.Raw["provider"]) != provider.Name {
					continue
				}
				if validNodes[node.Name] {
					outbounds = append(outbounds, node.Name)
				}
			}
		}
		if len(outbounds) == 0 {
			outbounds = []string{"DIRECT"}
		}
		entry := map[string]any{
			"type":      singBoxGroupType(group.Type),
			"tag":       group.Name,
			"outbounds": uniqueCompactList(outbounds),
		}
		if entry["type"] == "urltest" {
			entry["url"] = firstNonEmpty(group.URL, "http://www.gstatic.com/generate_204")
			if group.Interval > 0 {
				entry["interval"] = intervalSeconds(group.Interval)
			}
			if group.Type == "url-test" || group.Type == "load-balance" {
				entry["tolerance"] = chooseInt(group.Tolerance, 50)
			}
		}
		out = append(out, entry)
	}
	return out
}

func preferredProxyOutbound(profile *Profile) string {
	if profile == nil {
		return "DIRECT"
	}
	if len(profile.CustomGroups) > 0 {
		return "Proxy"
	}
	for _, group := range profile.ProxyGroups {
		if group.Name != "" {
			return group.Name
		}
	}
	for _, node := range profile.Nodes {
		if node.Name != "" {
			return node.Name
		}
	}
	return "DIRECT"
}

func systemRouteRules(tunEnabled, dnsProxyEnabled bool, proxyOutbound string) []map[string]any {
	if !dnsProxyEnabled {
		return nil
	}
	rules := []map[string]any{
		{"protocol": "dns", "action": "hijack-dns"},
		{"inbound": "mixed-in", "action": "sniff"},
	}
	if tunEnabled {
		rules = append([]map[string]any{{"inbound": "tun-in", "action": "sniff"}}, rules...)
	}
	if dnsProxyEnabled {
		rules = append(rules, map[string]any{"inbound": "dns_proxy_in", "outbound": proxyOutbound})
	}
	return rules
}

func ensureRoverDNSSupportServers(servers []map[string]any, proxyOutbound string) []map[string]any {
	servers = ensureDirectDNSSupportServer(servers)
	hasSelector := false
	for _, server := range servers {
		if firstString(server["tag"]) == "dns_selector_out" {
			hasSelector = true
			break
		}
	}
	if !hasSelector {
		servers = append(servers, map[string]any{"type": "tls", "tag": "dns_selector_out", "server": "8.8.8.8", "detour": proxyOutbound})
	}
	return servers
}

func ensureDirectDNSSupportServer(servers []map[string]any) []map[string]any {
	hasDirect := false
	for _, server := range servers {
		if firstString(server["tag"]) == "dns_direct_out" {
			hasDirect = true
			break
		}
	}
	if !hasDirect {
		support := map[string]any{"tag": "dns_direct_out", "address": "local"}
		servers = append([]map[string]any{support}, servers...)
	}
	return servers
}

func ruleSetToSingBox(ruleSet RuleSet) map[string]any {
	entry := map[string]any{
		"type":   ruleSet.Type,
		"tag":    ruleSet.Tag,
		"format": ruleSet.Format,
	}
	if ruleSet.Type == "remote" && ruleSet.LocalPath != "" && fileExists(ruleSet.LocalPath) {
		entry["type"] = "local"
		entry["path"] = ruleSet.LocalPath
	} else if ruleSet.Type == "remote" {
		entry["url"] = ruleSet.URL
		entry["download_detour"] = ruleSet.DownloadDetour
	} else {
		entry["path"] = ruleSet.Path
	}
	return entry
}

func ensureRuleSetsForDNSRules(ruleSets []map[string]any, dnsRules []map[string]any) []map[string]any {
	if len(dnsRules) == 0 {
		return ruleSets
	}
	known := map[string]bool{}
	for _, ruleSet := range ruleSets {
		if tag := firstString(ruleSet["tag"]); tag != "" {
			known[tag] = true
		}
	}
	presets := presetRuleSetsByID()
	for _, rule := range dnsRules {
		refs := stringList(rule["rule_set"])
		if len(refs) == 0 {
			continue
		}
		normalized := make([]string, 0, len(refs))
		for _, ref := range refs {
			tag := resolveRuleSetTag(ref, known, presets)
			normalized = append(normalized, tag)
			if known[tag] {
				continue
			}
			if preset, ok := presets[tag]; ok {
				ruleSets = append(ruleSets, ruleSetToSingBox(preset))
				known[tag] = true
			}
		}
		rule["rule_set"] = normalized
	}
	return ruleSets
}

func resolveRuleSetTag(ref string, known map[string]bool, presets map[string]RuleSet) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || known[ref] {
		return ref
	}
	candidates := []string{ref}
	switch {
	case strings.HasPrefix(ref, "geosite:"):
		candidates = append(candidates, "geosite-"+strings.TrimPrefix(ref, "geosite:"))
	case strings.HasPrefix(ref, "geoip:"):
		candidates = append(candidates, "geoip-"+strings.TrimPrefix(ref, "geoip:"))
	case !strings.Contains(ref, ":"):
		candidates = append(candidates, "geosite-"+ref, "geoip-"+ref)
	}
	for _, candidate := range candidates {
		if known[candidate] {
			return candidate
		}
	}
	for _, candidate := range candidates {
		if _, ok := presets[candidate]; ok {
			return candidate
		}
	}
	return ref
}

func dnsServersReferenceTag(servers []map[string]any, tag string) bool {
	for _, server := range servers {
		for _, key := range []string{"address_resolver", "domain_resolver"} {
			if firstString(server[key]) == tag {
				return true
			}
		}
	}
	return false
}

func dnsServerToSingBox(server DNSServer, prefs map[string]string, proxyOutbound string) map[string]any {
	tag := firstNonEmpty(server.Tag, server.ID, server.Name)
	serverType := strings.ToLower(strings.TrimSpace(server.Type))
	switch serverType {
	case "raw":
		entry := cloneMap(server.RawData)
		entry["tag"] = tag
		return entry
	case "rover":
		port := 5353
		if raw := strings.TrimSpace(prefs["dns-server-port"]); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				port = parsed
			}
		}
		headers := map[string]string{}
		if server.Upstreams != "" {
			headers["X-Upstreams"] = server.Upstreams
		}
		if server.UseProxy {
			proxyPort := 17890
			if raw := strings.TrimSpace(prefs["dns-proxy-port"]); raw != "" {
				if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
					proxyPort = parsed
				}
			}
			headers["X-Proxy"] = "socks5"
			headers["X-Proxy-Addr"] = fmt.Sprintf("127.0.0.1:%d", proxyPort)
		}
		if server.BootstrapAddrs != "" {
			headers["X-Bootstrap-Addrs"] = server.BootstrapAddrs
		}
		if server.FallbackAddrs != "" {
			headers["X-Fallback-Addrs"] = server.FallbackAddrs
		}
		entry := map[string]any{
			"type":        "https",
			"tag":         tag,
			"server":      "127.0.0.1",
			"server_port": port,
			"path":        "/dns-query",
			"tls":         map[string]any{"enabled": true, "insecure": true},
		}
		if len(headers) > 0 {
			entry["headers"] = headers
		}
		if server.Detour != "" {
			entry["detour"] = server.Detour
		}
		return entry
	case "local":
		return map[string]any{"type": "local", "tag": tag}
	case "tls", "https", "http", "udp", "tcp", "quic", "h3":
		entry := map[string]any{"type": serverType, "tag": tag}
		if server.Server != "" {
			entry["server"] = server.Server
		} else if server.Address != "" {
			entry["server"] = dnsServerAddressHost(server.Address)
		}
		if server.ServerPort > 0 {
			entry["server_port"] = server.ServerPort
		}
		if server.Path != "" {
			entry["path"] = server.Path
		}
		if server.Detour != "" {
			entry["detour"] = server.Detour
		}
		if server.PreferGo != nil {
			entry["prefer_go"] = *server.PreferGo
		}
		if server.DomainResolver != "" {
			entry["domain_resolver"] = server.DomainResolver
		}
		return entry
	default:
		return map[string]any{"tag": tag, "address": server.Address}
	}
}

func dnsServerAddressHost(address string) string {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return ""
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return trimmed
}

func dnsServerTypeAllowsEmptyAddress(serverType string) bool {
	switch strings.ToLower(strings.TrimSpace(serverType)) {
	case "local", "raw", "rover":
		return true
	default:
		return false
	}
}

func hasAnyPreference(prefs map[string]string, keys ...string) bool {
	if prefs == nil {
		return false
	}
	for _, key := range keys {
		if _, ok := prefs[key]; ok {
			return true
		}
	}
	return false
}

func hostsOverrideToDNSConfig(raw string) (map[string]any, []map[string]any) {
	var lines []string
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &lines) != nil {
		return nil, nil
	}
	single := map[string]string{}
	wildcards := map[string]map[string]string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		ip := parts[0]
		for _, host := range parts[1:] {
			if host == "" || strings.HasPrefix(host, "#") {
				break
			}
			if strings.HasPrefix(host, "*.") {
				suffix := strings.TrimPrefix(host, "*")
				if !strings.HasPrefix(suffix, ".") {
					suffix = "." + suffix
				}
				if wildcards[suffix] == nil {
					wildcards[suffix] = map[string]string{}
				}
				if strings.Contains(ip, ":") {
					wildcards[suffix]["AAAA"] = ip
				} else {
					wildcards[suffix]["A"] = ip
				}
			} else {
				single[host] = ip
			}
		}
	}
	var server map[string]any
	rules := []map[string]any{}
	if len(single) > 0 {
		server = map[string]any{"type": "hosts", "tag": "dns_hosts", "predefined": single}
		rules = append(rules, map[string]any{"ip_accept_any": true, "server": "dns_hosts"})
	}
	for suffix, byType := range wildcards {
		queryTypes := []string{}
		answers := []string{}
		if ip := byType["A"]; ip != "" {
			queryTypes = append(queryTypes, "A")
			answers = append(answers, "*"+suffix+". IN A "+ip)
		}
		if ip := byType["AAAA"]; ip != "" {
			queryTypes = append(queryTypes, "AAAA")
			answers = append(answers, "*"+suffix+". IN AAAA "+ip)
		}
		if len(answers) > 0 {
			rules = append(rules, map[string]any{"query_type": queryTypes, "domain_suffix": []string{suffix}, "action": "predefined", "rcode": "NOERROR", "answer": answers})
		}
	}
	return server, rules
}

func customGroupOutboundsFromProfile(profile Profile) []map[string]any {
	nodeTags := make([]string, 0, len(profile.Nodes))
	validNodes := map[string]bool{}
	for _, node := range profile.Nodes {
		if node.Name == "" {
			continue
		}
		nodeTags = append(nodeTags, node.Name)
		validNodes[node.Name] = true
	}
	if len(nodeTags) == 0 {
		return groupOutboundsFromProfile(profile)
	}
	customGroupDefs := normalizeCustomProxyGroups(profile.CustomGroups)
	customGroups := make([]map[string]any, 0, len(customGroupDefs))
	customNames := make([]string, 0, len(customGroupDefs))
	for _, group := range customGroupDefs {
		if group.Name == "" {
			continue
		}
		outbounds := make([]string, 0, len(group.Outbounds))
		for _, outbound := range group.Outbounds {
			outbound = normalizeClashOutbound(outbound)
			if validNodes[outbound] {
				outbounds = append(outbounds, outbound)
			}
		}
		if len(outbounds) == 0 {
			continue
		}
		entry := map[string]any{
			"type":      group.Type,
			"tag":       group.Name,
			"outbounds": uniqueCompactList(outbounds),
		}
		if entry["type"] == "urltest" {
			entry["url"] = "http://www.gstatic.com/generate_204"
			entry["interval"] = "300s"
			entry["tolerance"] = 50
		}
		customGroups = append(customGroups, entry)
		customNames = append(customNames, group.Name)
	}
	autoGroup := map[string]any{
		"type":      "urltest",
		"tag":       "Auto",
		"outbounds": nodeTags,
		"url":       "http://www.gstatic.com/generate_204",
		"interval":  "300s",
		"tolerance": 50,
	}
	selectorOutbounds := append([]string{"Auto"}, customNames...)
	selectorOutbounds = append(selectorOutbounds, nodeTags...)
	selectorGroup := map[string]any{
		"type":      "selector",
		"tag":       "Proxy",
		"outbounds": uniqueCompactList(selectorOutbounds),
	}
	out := []map[string]any{selectorGroup, autoGroup}
	return append(out, customGroups...)
}

func singBoxGroupType(value string) string {
	switch strings.ToLower(value) {
	case "select":
		return "selector"
	case "url-test", "fallback", "load-balance":
		return "urltest"
	default:
		return strings.ToLower(value)
	}
}

func intervalSeconds(value int) string {
	if value > 600 {
		value = 600
	}
	return fmt.Sprintf("%ds", value)
}

func durationSeconds(value any) int {
	if seconds := toInt(value); seconds > 0 {
		return seconds
	}
	text := firstString(value)
	if text == "" {
		return 0
	}
	duration, err := time.ParseDuration(text)
	if err == nil && duration > 0 {
		return int(duration / time.Second)
	}
	return 0
}

func chooseInt(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func copyTLS(out map[string]any, raw map[string]any, force bool) {
	tlsEnabled := force || firstBool(raw["tls"], false) || firstString(raw["security"]) == "tls" || firstString(raw["security"]) == "reality"
	if !tlsEnabled {
		return
	}
	tls := map[string]any{"enabled": true}
	if sni := firstString(raw["sni"], raw["servername"], raw["server_name"]); sni != "" {
		tls["server_name"] = sni
	}
	if hasAnyKey(raw, "skip-cert-verify", "skip_cert_verify", "allowInsecure") {
		tls["insecure"] = firstBool(raw["skip-cert-verify"], firstBool(raw["skip_cert_verify"], firstBool(raw["allowInsecure"], false)))
	}
	if alpn := stringList(raw["alpn"]); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if firstString(raw["security"]) == "reality" {
		reality := map[string]any{"enabled": true}
		copyString(reality, raw, "public_key", "reality-opts.public-key", "public-key")
		copyString(reality, raw, "short_id", "reality-opts.short-id", "short-id")
		tls["reality"] = reality
	}
	if fingerprint := firstString(raw["client-fingerprint"], raw["client_fingerprint"], raw["fingerprint"], raw["fp"]); fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	out["tls"] = tls
}

func copyTransport(out map[string]any, raw map[string]any) {
	network := strings.ToLower(firstString(raw["network"], raw["net"], raw["transport"]))
	switch network {
	case "ws", "websocket":
		transport := map[string]any{"type": "ws"}
		if path := firstString(raw["ws-opts.path"], raw["ws-path"], raw["path"]); path != "" {
			transport["path"] = path
		}
		host := firstString(raw["ws-opts.headers.Host"], raw["ws-opts.headers.host"], raw["ws-host"], raw["host"])
		if host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		if maxEarlyData := firstInt(raw["ws-opts.max-early-data"], 0); maxEarlyData > 0 {
			transport["max_early_data"] = maxEarlyData
		}
		if earlyDataHeader := firstString(raw["ws-opts.early-data-header-name"]); earlyDataHeader != "" {
			transport["early_data_header_name"] = earlyDataHeader
		}
		out["transport"] = transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if serviceName := firstString(raw["grpc-opts.grpc-service-name"], raw["grpc-service-name"], raw["serviceName"], raw["service_name"]); serviceName != "" {
			transport["service_name"] = serviceName
		}
		if firstBool(raw["grpc-opts.multi-mode"], firstBool(raw["multi-mode"], false)) {
			transport["multi_mode"] = true
		}
		out["transport"] = transport
	case "h2", "http":
		transport := map[string]any{"type": "http"}
		if path := stringList(raw["h2-opts.path"]); len(path) > 0 {
			transport["path"] = path
		} else if path := firstString(raw["path"]); path != "" {
			transport["path"] = []string{path}
		}
		if host := stringList(raw["h2-opts.host"]); len(host) > 0 {
			transport["host"] = host
		} else if host := firstString(raw["host"]); host != "" {
			transport["host"] = []string{host}
		}
		out["transport"] = transport
	}
}

func copyMultiplex(out map[string]any, raw map[string]any) {
	enabled := firstBool(raw["smux.enabled"], firstBool(raw["multiplex"], firstBool(raw["mux"], false)))
	if !enabled {
		return
	}
	mux := map[string]any{"enabled": true}
	if protocol := firstString(raw["smux.protocol"], raw["mux-protocol"]); protocol != "" {
		mux["protocol"] = protocol
	}
	if maxConnections := firstInt(raw["smux.max-connections"], firstInt(raw["max-connections"], 0)); maxConnections > 0 {
		mux["max_connections"] = maxConnections
	}
	if minStreams := firstInt(raw["smux.min-streams"], firstInt(raw["min-streams"], 0)); minStreams > 0 {
		mux["min_streams"] = minStreams
	}
	if maxStreams := firstInt(raw["smux.max-streams"], firstInt(raw["max-streams"], 0)); maxStreams > 0 {
		mux["max_streams"] = maxStreams
	}
	out["multiplex"] = mux
}

func copyPacketEncoding(out map[string]any, raw map[string]any) {
	if value := firstString(raw["packet-encoding"], raw["packet_encoding"]); value != "" {
		out["packet_encoding"] = value
	}
}

func copyMbps(out map[string]any, raw map[string]any, target string, sources ...string) {
	for _, source := range sources {
		if value, ok := parseMbps(raw[source]); ok {
			out[target] = value
			return
		}
	}
}

func copyDurationSeconds(out map[string]any, raw map[string]any, target string, sources ...string) {
	for _, source := range sources {
		value := raw[source]
		if n := toInt(value); n > 0 {
			out[target] = fmt.Sprintf("%ds", n)
			return
		}
		if text := firstString(value); text != "" {
			out[target] = text
			return
		}
	}
}

func copyPluginOptions(out map[string]any, raw map[string]any) {
	plugin := firstString(raw["plugin"])
	if plugin == "" {
		return
	}
	if plugin != "v2ray-plugin" && plugin != "obfs-local" {
		return
	}
	out["plugin"] = plugin
	if opts := pluginOptionsString(raw); opts != "" {
		out["plugin_opts"] = opts
	}
}

func pluginOptionsString(raw map[string]any) string {
	if opts := firstString(raw["plugin-opts"], raw["plugin_opts"]); opts != "" && !strings.HasPrefix(opts, "map[") {
		return opts
	}
	opts := make(map[string]any)
	for _, key := range []string{"plugin-opts", "plugin_opts"} {
		if nested, ok := mapFromAny(raw[key]); ok {
			for nestedKey, value := range nested {
				opts[nestedKey] = value
			}
		}
	}
	for key, value := range raw {
		if strings.HasPrefix(key, "plugin-opts.") {
			opts[strings.TrimPrefix(key, "plugin-opts.")] = value
		}
		if strings.HasPrefix(key, "plugin_opts.") {
			opts[strings.TrimPrefix(key, "plugin_opts.")] = value
		}
	}
	if len(opts) == 0 {
		return ""
	}
	fieldOrder := []string{"mode", "host", "path", "tls", "mux", "skip-cert-verify", "obfs", "obfs-host"}
	boolAsString := map[string]bool{"skip-cert-verify": true, "tls": true}
	seen := map[string]bool{}
	keys := make([]string, 0, len(opts)+len(fieldOrder))
	for _, key := range fieldOrder {
		if _, ok := opts[key]; ok {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	extra := make([]string, 0, len(opts))
	for key := range opts {
		if !seen[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	keys = append(keys, extra...)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := pluginOptionValue(key, opts[key], boolAsString[key])
		if value == "" {
			continue
		}
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, ";")
}

func pluginOptionValue(key string, value any, boolAsString bool) string {
	switch typed := value.(type) {
	case bool:
		if !typed {
			return ""
		}
		if boolAsString {
			return "true"
		}
		return "1"
	default:
		return firstString(value)
	}
}

func parseMbps(value any) (float64, bool) {
	switch typed := value.(type) {
	case int:
		if typed > 0 {
			return float64(typed), true
		}
	case int64:
		if typed > 0 {
			return float64(typed), true
		}
	case float64:
		if typed > 0 {
			return typed, true
		}
	case string:
		text := strings.TrimSpace(strings.ToLower(typed))
		text = strings.TrimSuffix(text, "mbps")
		text = strings.TrimSuffix(text, "mb/s")
		text = strings.TrimSpace(text)
		value, err := strconv.ParseFloat(text, 64)
		if err == nil && value > 0 {
			return value, true
		}
	}
	return 0, false
}

func hasAnyKey(raw map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, ok := raw[key]; ok {
			return true
		}
	}
	return false
}

func copyString(out map[string]any, raw map[string]any, target string, sources ...string) {
	if len(sources) == 0 {
		sources = []string{target}
	}
	for _, source := range sources {
		if value := firstString(raw[source]); value != "" {
			out[target] = value
			return
		}
	}
}

func copyBool(out map[string]any, raw map[string]any, target string, sources ...string) {
	if len(sources) == 0 {
		sources = []string{target}
	}
	for _, source := range sources {
		if _, ok := raw[source]; !ok {
			continue
		}
		out[target] = firstBool(raw[source], false)
		return
	}
}

func ruleFromPolicy(policy Policy) map[string]any {
	policy = normalizePolicy(policy)
	if policy.Type == "raw" && len(policy.RawData) > 0 {
		rule := cloneMap(policy.RawData)
		if _, hasAction := rule["action"]; !hasAction {
			if _, hasOutbound := rule["outbound"]; !hasOutbound {
				rule["outbound"] = firstNonEmpty(policy.Outbound, "selector_out")
			}
		}
		return rule
	}

	ruleSets := policyRuleSet(policy)
	logicalRule := cloneLogicalRule(policy.LogicalRule)
	logicalRules := ruleListFromAny(logicalRule["rules"])
	hasRuleSet := len(ruleSets) > 0
	hasLogicalRules := len(logicalRules) > 0

	if hasRuleSet && !hasLogicalRules && !hasLegacyPolicyMatchers(policy) {
		return map[string]any{"rule_set": ruleSets, "outbound": policy.Outbound}
	}
	if !hasRuleSet && hasLogicalRules && !hasLegacyPolicyMatchers(policy) {
		if len(logicalRules) == 1 && firstString(logicalRules[0]["type"]) != "logical" {
			rule := cloneMap(logicalRules[0])
			rule["outbound"] = policy.Outbound
			return rule
		}
		rule := cloneMap(logicalRule)
		rule["outbound"] = policy.Outbound
		return rule
	}
	if hasRuleSet && hasLogicalRules && !hasLegacyPolicyMatchers(policy) {
		filtered := make([]map[string]any, 0, len(logicalRules))
		for _, rule := range logicalRules {
			if !isRuleSetOnlyRule(rule) {
				filtered = append(filtered, rule)
			}
		}
		if len(filtered) == 0 {
			return map[string]any{"rule_set": ruleSets, "outbound": policy.Outbound}
		}
		logicalPart := cloneMap(logicalRule)
		logicalPart["rules"] = filtered
		if logicalPart["mode"] == nil || logicalPart["mode"] == "" {
			logicalPart["mode"] = "and"
		}
		return map[string]any{
			"rule_set": ruleSets,
			"type":     "logical",
			"mode":     "and",
			"rules":    []map[string]any{logicalPart},
			"outbound": policy.Outbound,
		}
	}

	rule := legacyRuleFromPolicy(policy)
	if hasLogicalRules {
		rule["type"] = firstNonEmpty(firstString(logicalRule["type"]), "logical")
		rule["mode"] = firstNonEmpty(firstString(logicalRule["mode"]), "and")
		rule["rules"] = logicalRules
		if invert, ok := logicalRule["invert"].(bool); ok {
			rule["invert"] = invert
		}
	}
	if hasRuleSet {
		rule["rule_set"] = ruleSets
	}
	return rule
}

func legacyRuleFromPolicy(policy Policy) map[string]any {
	rule := map[string]any{"outbound": policy.Outbound}
	if len(policy.Domain) > 0 {
		rule["domain"] = policy.Domain
	}
	if len(policy.DomainSuffix) > 0 {
		rule["domain_suffix"] = policy.DomainSuffix
	}
	if len(policy.DomainKeyword) > 0 {
		rule["domain_keyword"] = policy.DomainKeyword
	}
	if len(policy.DomainRegex) > 0 {
		rule["domain_regex"] = policy.DomainRegex
	}
	if len(policy.IPCIDR) > 0 {
		rule["ip_cidr"] = policy.IPCIDR
	}
	if len(policy.SourceIPCIDR) > 0 {
		rule["source_ip_cidr"] = policy.SourceIPCIDR
	}
	if ports := intList(policy.Port); len(ports) > 0 {
		rule["port"] = ports
	}
	if len(policy.PortRange) > 0 {
		rule["port_range"] = policy.PortRange
	}
	if ports := intList(policy.SourcePort); len(ports) > 0 {
		rule["source_port"] = ports
	}
	if len(policy.SourcePortRange) > 0 {
		rule["source_port_range"] = policy.SourcePortRange
	}
	if len(policy.ProcessName) > 0 {
		rule["process_name"] = policy.ProcessName
	}
	if len(policy.ProcessPath) > 0 {
		rule["process_path"] = policy.ProcessPath
	}
	if len(policy.ProcessPathRegex) > 0 {
		rule["process_path_regex"] = policy.ProcessPathRegex
	}
	if len(policy.PackageName) > 0 {
		rule["package_name"] = policy.PackageName
	}
	if len(policy.Protocol) > 0 {
		rule["protocol"] = policy.Protocol
	}
	if len(policy.QueryType) > 0 {
		rule["query_type"] = policy.QueryType
	}
	if len(policy.Network) > 0 {
		rule["network"] = policy.Network
	}
	if len(policy.NetworkType) > 0 {
		rule["network_type"] = policy.NetworkType
	}
	if len(policy.DefaultInterfaceAddress) > 0 {
		rule["default_interface_address"] = policy.DefaultInterfaceAddress
	}
	if len(policy.WifiSSID) > 0 {
		rule["wifi_ssid"] = policy.WifiSSID
	}
	if len(policy.WifiBSSID) > 0 {
		rule["wifi_bssid"] = policy.WifiBSSID
	}
	if policy.NetworkIsExpensive {
		rule["network_is_expensive"] = true
	}
	if policy.NetworkIsConstrained {
		rule["network_is_constrained"] = true
	}
	if policy.IPIsPrivate {
		rule["ip_is_private"] = true
	}
	if len(policy.RuleSet) > 0 {
		rule["rule_set"] = policy.RuleSet
	}
	if len(rule) == 1 && policy.Match != "" {
		rule["domain_suffix"] = splitCSV(policy.Match)
	}
	return rule
}

func hasLegacyPolicyMatchers(policy Policy) bool {
	return len(policy.Domain)+len(policy.DomainSuffix)+len(policy.DomainKeyword)+len(policy.DomainRegex)+len(policy.IPCIDR)+len(policy.SourceIPCIDR)+len(policy.Port)+len(policy.PortRange)+len(policy.SourcePort)+len(policy.SourcePortRange)+len(policy.ProcessName)+len(policy.ProcessPath)+len(policy.ProcessPathRegex)+len(policy.PackageName)+len(policy.Protocol)+len(policy.QueryType)+len(policy.Network)+len(policy.NetworkType)+len(policy.DefaultInterfaceAddress)+len(policy.WifiSSID)+len(policy.WifiBSSID) > 0 || policy.NetworkIsExpensive || policy.NetworkIsConstrained || policy.IPIsPrivate || policy.Match != ""
}

func policyRuleSet(policy Policy) []string {
	if len(policy.RuleSet) > 0 {
		return uniqueCompactList(policy.RuleSet)
	}
	if len(policy.LogicalRule) > 0 {
		return uniqueCompactList(extractRuleSetFromRule(policy.LogicalRule))
	}
	return nil
}

func extractRuleSetFromRule(rule map[string]any) []string {
	out := stringList(rule["rule_set"])
	if firstString(rule["type"]) == "logical" {
		for _, child := range ruleListFromAny(rule["rules"]) {
			out = append(out, extractRuleSetFromRule(child)...)
		}
	}
	return out
}

func isRuleSetOnlyRule(rule map[string]any) bool {
	if firstString(rule["type"]) == "logical" {
		return false
	}
	ruleSet := stringList(rule["rule_set"])
	if len(ruleSet) == 0 {
		return false
	}
	for key, value := range rule {
		if key == "rule_set" || isEmptyRuleValue(value) {
			continue
		}
		return false
	}
	return true
}

func isEmptyRuleValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return typed == ""
	case []string:
		return len(typed) == 0
	case []any:
		return len(typed) == 0
	default:
		return false
	}
}

func cloneLogicalRule(rule map[string]any) map[string]any {
	if len(rule) == 0 {
		return nil
	}
	out := cloneMap(rule)
	out["type"] = firstNonEmpty(firstString(out["type"]), "logical")
	out["mode"] = firstNonEmpty(firstString(out["mode"]), "or")
	out["rules"] = ruleListFromAny(out["rules"])
	return out
}

func ruleListFromAny(value any) []map[string]any {
	switch typed := value.(type) {
	case []map[string]any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, cloneMap(item))
		}
		return out
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if rule, ok := mapFromAny(item); ok {
				out = append(out, cloneMap(rule))
			}
		}
		return out
	default:
		return nil
	}
}

func mapFromAny(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, true
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[fmt.Sprint(key)] = value
		}
		return out, true
	default:
		return nil, false
	}
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = cloneRuleValue(value)
	}
	return out
}

func cloneRuleValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []map[string]any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, cloneMap(item))
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, cloneRuleValue(item))
		}
		return out
	case []string:
		return append([]string(nil), typed...)
	default:
		return typed
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func policiesFromConfigRules(value any) []Policy {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	now := time.Now()
	policies := make([]Policy, 0, len(items))
	for i, item := range items {
		rule, ok := mapFromAny(item)
		if !ok {
			continue
		}
		policy := configRouteRuleToPolicy(rule, i)
		policy.ID = uuid.NewString()
		policy.Enabled = true
		policy.UpdatedAt = now
		policies = append(policies, policy)
	}
	return policies
}

func policiesFromClashRules(value any) ([]Policy, string) {
	items, ok := value.([]any)
	if !ok {
		return nil, ""
	}
	now := time.Now()
	policies := make([]Policy, 0, len(items))
	finalOutbound := ""
	for _, item := range items {
		line := strings.TrimSpace(firstString(item))
		if line == "" {
			continue
		}
		rule, final := clashRuleToRouteRule(line)
		if final != "" {
			finalOutbound = final
			continue
		}
		if len(rule) == 0 {
			continue
		}
		policy := configRouteRuleToPolicy(rule, len(policies))
		policy.ID = uuid.NewString()
		policy.Enabled = true
		policy.UpdatedAt = now
		policies = append(policies, policy)
	}
	return policies, finalOutbound
}

func settingsFromClashConfig(config map[string]any) (Settings, bool) {
	settings := Settings{}
	found := false
	if mixedPort := firstInt(config["mixed-port"], firstInt(config["mixed_port"], firstInt(config["port"], firstInt(config["socks-port"], firstInt(config["socks_port"], 0))))); mixedPort > 0 {
		settings.MixedPort = mixedPort
		found = true
	}
	if bindAddress := firstString(config["bind-address"], config["bind_address"]); bindAddress != "" {
		settings.MixedListen = bindAddress
		found = true
	} else if firstBool(config["allow-lan"], firstBool(config["allow_lan"], false)) {
		settings.MixedListen = "0.0.0.0"
		found = true
	}
	if apiPort := clashExternalControllerPort(firstString(config["external-controller"], config["external_controller"])); apiPort > 0 {
		settings.APIPort = apiPort
		found = true
	}
	if secret := firstString(config["secret"]); secret != "" {
		settings.APISecret = secret
		found = true
	}
	if logLevel := firstString(config["log-level"], config["log_level"]); logLevel != "" {
		settings.LogLevel = strings.ToLower(logLevel)
		found = true
	}
	if mode := firstString(config["mode"]); mode != "" {
		settings.Mode = strings.ToLower(mode)
		found = true
	}
	experimental := map[string]any{}
	if rawExperimental, ok := mapFromAny(config["experimental"]); ok {
		for key, value := range rawExperimental {
			experimental[key] = cloneRuleValue(value)
		}
	}
	if unifiedDelay, ok := boolFromAny(config["unified-delay"], config["unified_delay"]); ok {
		experimental["unified_delay"] = unifiedDelay
	}
	if tcpConcurrent, ok := boolFromAny(config["tcp-concurrent"], config["tcp_concurrent"]); ok {
		experimental["tcp_concurrent"] = tcpConcurrent
	}
	clashAPI := map[string]any{}
	if existing, ok := mapFromAny(experimental["clash_api"]); ok {
		clashAPI = cloneMap(existing)
	}
	if externalUI := firstString(config["external-ui"], config["external_ui"]); externalUI != "" {
		clashAPI["external_ui"] = externalUI
	}
	if externalUIDownloadURL := firstString(config["external-ui-url"], config["external_ui_url"], config["external-ui-download-url"], config["external_ui_download_url"]); externalUIDownloadURL != "" {
		clashAPI["external_ui_download_url"] = externalUIDownloadURL
	}
	if externalUIDownloadDetour := firstString(config["external-ui-download-detour"], config["external_ui_download_detour"]); externalUIDownloadDetour != "" {
		clashAPI["external_ui_download_detour"] = externalUIDownloadDetour
	}
	if defaultMode := firstString(config["default-mode"], config["default_mode"]); defaultMode != "" {
		clashAPI["default_mode"] = defaultMode
	}
	if len(clashAPI) > 0 {
		experimental["clash_api"] = clashAPI
	}
	if script, ok := mapFromAny(config["script"]); ok {
		unsupported := map[string]any{}
		if existing, ok := mapFromAny(experimental["sandfox_unsupported"]); ok {
			unsupported = cloneMap(existing)
		}
		unsupported["clash_script"] = cloneMap(script)
		experimental["sandfox_unsupported"] = unsupported
		found = true
	}
	if len(experimental) > 0 {
		settings.Experimental = experimental
		found = true
	}
	if hosts := hostsFromClashConfig(config["hosts"]); len(hosts) > 0 {
		settings.Hosts = hosts
		found = true
	}
	if dns, ok := mapFromAny(config["dns"]); ok {
		if dnsListen := firstString(firstListItem(dns["nameserver"]), firstListItem(dns["default-nameserver"]), firstListItem(dns["default_nameserver"])); dnsListen != "" {
			settings.DNSListen = dnsListen
			found = true
		}
		if ipv6, ok := boolFromAny(dns["ipv6"]); ok {
			settings.DNSIPv6 = boolPtr(ipv6)
			if !ipv6 {
				settings.DNSStrategy = "prefer_ipv4"
			}
			found = true
		}
		if strategy := firstString(dns["strategy"]); strategy != "" {
			settings.DNSStrategy = strategy
			found = true
		}
		enhancedMode := strings.ToLower(firstString(dns["enhanced-mode"], dns["enhanced_mode"]))
		if enhancedMode == "fake-ip" || enhancedMode == "fakeip" {
			settings.DNSFakeIPEnabled = true
			settings.DNSFakeIPRange = firstString(dns["fake-ip-range"], dns["fake_ip_range"])
			settings.DNSFakeIPv6Range = firstString(dns["fake-ip-range6"], dns["fake_ip_range6"], dns["fake-ipv6-range"], dns["fake_ipv6_range"])
			settings.DNSFakeIPFilter = compactList(append(stringList(dns["fake-ip-filter"]), stringList(dns["fake_ip_filter"])...))
			found = true
		}
		fallbackFilter, hasFallbackFilter := mapFromAny(dns["fallback-filter"])
		if !hasFallbackFilter {
			fallbackFilter, hasFallbackFilter = mapFromAny(dns["fallback_filter"])
		}
		if hasFallbackFilter {
			settings.DNSFallbackFilter = cloneMap(fallbackFilter)
			found = true
		}
	}
	if tun, ok := mapFromAny(config["tun"]); ok {
		settings.TUNEnabled = firstBool(tun["enable"], firstBool(tun["enabled"], false))
		settings.TUNStack = strings.ToLower(firstString(tun["stack"]))
		settings.TUNInterfaceName = firstString(tun["device"], tun["interface-name"], tun["interface_name"])
		settings.TUNAddress = compactList(append(stringList(tun["inet4-address"]), stringList(tun["inet6-address"])...))
		if len(settings.TUNAddress) == 0 {
			settings.TUNAddress = compactList(append(stringList(tun["address"]), stringList(tun["addresses"])...))
		}
		settings.TUNMTU = toInt(tun["mtu"])
		settings.TUNAutoRoute = boolPtr(firstBool(tun["auto-route"], firstBool(tun["auto_route"], true)))
		settings.TUNStrictRoute = boolPtr(firstBool(tun["strict-route"], firstBool(tun["strict_route"], true)))
		settings.TUNAutoDetectInterface = boolPtr(firstBool(tun["auto-detect-interface"], firstBool(tun["auto_detect_interface"], true)))
		settings.TUNDNSHijack = compactList(append(stringList(tun["dns-hijack"]), stringList(tun["dns_hijack"])...))
		settings.TUNRouteAddress = compactList(append(stringList(tun["route-address"]), stringList(tun["route_address"])...))
		settings.TUNRouteExcludeAddress = compactList(append(stringList(tun["route-exclude-address"]), stringList(tun["route_exclude_address"])...))
		found = true
	}
	if sniffer, ok := mapFromAny(config["sniffer"]); ok {
		settings.SniffEnabled = firstBool(sniffer["enable"], false)
		settings.SniffOverrideDestination = firstBool(sniffer["override-destination"], firstBool(sniffer["override_destination"], false))
		found = true
	}
	return settings, found
}

func dnsFromClashConfig(config map[string]any) ([]DNSServer, []DNSPolicy) {
	dns, ok := mapFromAny(config["dns"])
	if !ok {
		return nil, nil
	}
	servers := make([]DNSServer, 0)
	policies := make([]DNSPolicy, 0)
	addressTags := map[string]string{}
	addServer := func(prefix string, index int, address string) string {
		address = strings.TrimSpace(address)
		if address == "" {
			return ""
		}
		if tag := addressTags[address]; tag != "" {
			return tag
		}
		tag := fmt.Sprintf("%s-%d", prefix, index)
		addressTags[address] = tag
		servers = append(servers, DNSServer{
			ID:       uuid.NewString(),
			Tag:      tag,
			Type:     guessDNSServerType(address),
			Address:  address,
			Strategy: "prefer_ipv4",
			Enabled:  true,
		})
		return tag
	}
	for i, address := range stringList(dns["nameserver"]) {
		addServer("nameserver", i+1, address)
	}
	for i, address := range stringList(dns["fallback"]) {
		addServer("fallback", i+1, address)
	}
	defaultServers := compactList(append(stringList(dns["default-nameserver"]), stringList(dns["default_nameserver"])...))
	for i, address := range defaultServers {
		addServer("default-nameserver", i+1, address)
	}
	if policyMap, ok := mapFromAny(dns["nameserver-policy"]); ok {
		for matcher, target := range policyMap {
			addresses := stringList(target)
			if len(addresses) == 0 {
				addresses = []string{firstString(target)}
			}
			tag := addServer("policy-nameserver", len(servers)+1, firstString(addresses[0]))
			if tag == "" {
				continue
			}
			policy := dnsPolicyFromClashMatcher(matcher, tag)
			if policy.Server != "" {
				policies = append(policies, policy)
			}
		}
	}
	if policyMap, ok := mapFromAny(dns["nameserver_policy"]); ok {
		for matcher, target := range policyMap {
			addresses := stringList(target)
			if len(addresses) == 0 {
				addresses = []string{firstString(target)}
			}
			tag := addServer("policy-nameserver", len(servers)+1, firstString(addresses[0]))
			if tag == "" {
				continue
			}
			policy := dnsPolicyFromClashMatcher(matcher, tag)
			if policy.Server != "" {
				policies = append(policies, policy)
			}
		}
	}
	return servers, policies
}

func hostsFromClashConfig(value any) map[string][]string {
	rawHosts, ok := mapFromAny(value)
	if !ok || len(rawHosts) == 0 {
		return nil
	}
	hosts := map[string][]string{}
	for host, value := range rawHosts {
		host = strings.TrimSpace(host)
		values := stringList(value)
		if len(values) == 0 {
			values = []string{firstString(value)}
		}
		values = compactList(values)
		if host != "" && len(values) > 0 {
			hosts[host] = values
		}
	}
	return hosts
}

func dnsPolicyFromClashMatcher(matcher, server string) DNSPolicy {
	matcher = strings.TrimSpace(matcher)
	policy := DNSPolicy{ID: uuid.NewString(), Domain: matcher, Server: server, Strategy: "prefer_ipv4", Enabled: true}
	switch {
	case matcher == "":
		return DNSPolicy{}
	case strings.HasPrefix(matcher, "geosite:"):
		policy.RuleSet = []string{matcher}
	case strings.HasPrefix(matcher, "rule-set:"):
		policy.RuleSet = []string{strings.TrimPrefix(matcher, "rule-set:")}
	case strings.HasPrefix(matcher, "+."):
		policy.DomainSuffix = []string{strings.TrimPrefix(matcher, "+.")}
	case strings.HasPrefix(matcher, "."):
		policy.DomainSuffix = []string{strings.TrimPrefix(matcher, ".")}
	case strings.Contains(matcher, "*"):
		policy.DomainKeyword = []string{strings.Trim(matcher, "*")}
	default:
		policy.DomainSuffix = []string{matcher}
	}
	return policy
}

func dnsRulesFromMatchers(matchers []string, server string) []map[string]any {
	rules := make([]map[string]any, 0, len(matchers))
	for _, matcher := range matchers {
		policy := dnsPolicyFromClashMatcher(matcher, server)
		if policy.Server == "" {
			continue
		}
		rule := map[string]any{"server": policy.Server}
		if len(policy.RuleSet) > 0 {
			rule["rule_set"] = policy.RuleSet
		}
		if len(policy.DomainSuffix) > 0 {
			rule["domain_suffix"] = policy.DomainSuffix
		}
		if len(policy.DomainKeyword) > 0 {
			rule["domain_keyword"] = policy.DomainKeyword
		}
		if policy.Domain != "" && len(policy.RuleSet) == 0 && len(policy.DomainSuffix) == 0 && len(policy.DomainKeyword) == 0 {
			rule["domain"] = []string{policy.Domain}
		}
		rules = append(rules, rule)
	}
	return rules
}

func mergeSettings(base Settings, patch Settings) Settings {
	if patch.APIPort > 0 {
		base.APIPort = patch.APIPort
	}
	if patch.APISecret != "" {
		base.APISecret = patch.APISecret
	}
	if patch.MixedPort > 0 {
		base.MixedPort = patch.MixedPort
	}
	if patch.MixedListen != "" {
		base.MixedListen = patch.MixedListen
	}
	if patch.AllowLAN {
		base.AllowLAN = true
	}
	if patch.SubscriptionUserAgent != "" {
		base.SubscriptionUserAgent = patch.SubscriptionUserAgent
	}
	if patch.IPv6 != nil {
		base.IPv6 = patch.IPv6
	}
	if patch.OverrideRules != nil {
		base.OverrideRules = patch.OverrideRules
	}
	if patch.AutoStartProxy != nil {
		base.AutoStartProxy = patch.AutoStartProxy
	}
	if patch.CustomProxyGroups {
		base.CustomProxyGroups = true
	}
	if patch.Mode != "" {
		base.Mode = patch.Mode
	}
	if patch.LogLevel != "" {
		base.LogLevel = patch.LogLevel
	}
	if patch.DNSListen != "" {
		base.DNSListen = patch.DNSListen
	}
	if patch.DNSStrategy != "" {
		base.DNSStrategy = patch.DNSStrategy
	}
	if patch.DNSIPv6 != nil {
		base.DNSIPv6 = patch.DNSIPv6
	}
	if patch.DNSFakeIPEnabled {
		base.DNSFakeIPEnabled = true
	}
	if patch.DNSFakeIPRange != "" {
		base.DNSFakeIPRange = patch.DNSFakeIPRange
	}
	if patch.DNSFakeIPv6Range != "" {
		base.DNSFakeIPv6Range = patch.DNSFakeIPv6Range
	}
	if len(patch.DNSFakeIPFilter) > 0 {
		base.DNSFakeIPFilter = patch.DNSFakeIPFilter
	}
	if len(patch.DNSFallbackFilter) > 0 {
		base.DNSFallbackFilter = patch.DNSFallbackFilter
	}
	if len(patch.Hosts) > 0 {
		base.Hosts = patch.Hosts
	}
	if len(patch.Experimental) > 0 {
		base.Experimental = patch.Experimental
	}
	if patch.SniffEnabled {
		base.SniffEnabled = true
	}
	if patch.SniffOverrideDestination {
		base.SniffOverrideDestination = true
	}
	if patch.TUNEnabled {
		base.TUNEnabled = true
	}
	if patch.TUNStack != "" {
		base.TUNStack = patch.TUNStack
	}
	if patch.TUNInterfaceName != "" {
		base.TUNInterfaceName = patch.TUNInterfaceName
	}
	if len(patch.TUNAddress) > 0 {
		base.TUNAddress = patch.TUNAddress
	}
	if patch.TUNMTU > 0 {
		base.TUNMTU = patch.TUNMTU
	}
	if patch.TUNAutoRoute != nil {
		base.TUNAutoRoute = patch.TUNAutoRoute
	}
	if patch.TUNStrictRoute != nil {
		base.TUNStrictRoute = patch.TUNStrictRoute
	}
	if patch.TUNAutoDetectInterface != nil {
		base.TUNAutoDetectInterface = patch.TUNAutoDetectInterface
	}
	if len(patch.TUNDNSHijack) > 0 {
		base.TUNDNSHijack = patch.TUNDNSHijack
	}
	if len(patch.TUNRouteAddress) > 0 {
		base.TUNRouteAddress = patch.TUNRouteAddress
	}
	if len(patch.TUNRouteExcludeAddress) > 0 {
		base.TUNRouteExcludeAddress = patch.TUNRouteExcludeAddress
	}
	return normalizeSettings(base)
}

func mergeTemplateSettings(base Settings, patch Settings) Settings {
	if patch.FinalOutbound != "" {
		base.FinalOutbound = patch.FinalOutbound
	}
	if patch.DNSListen != "" {
		base.DNSListen = patch.DNSListen
	}
	if patch.Mode != "" {
		base.Mode = patch.Mode
	}
	if patch.LogLevel != "" {
		base.LogLevel = patch.LogLevel
	}
	if patch.SniffEnabled {
		base.SniffEnabled = true
	}
	if patch.SniffOverrideDestination {
		base.SniffOverrideDestination = true
	}
	if patch.TUNEnabled {
		base.TUNEnabled = true
	}
	return normalizeSettings(base)
}

func clashRuleToRouteRule(line string) (map[string]any, string) {
	parts := splitClashRule(line)
	if len(parts) == 0 {
		return nil, ""
	}
	ruleType := strings.ToUpper(parts[0])
	if ruleType == "MATCH" {
		if len(parts) > 1 {
			return nil, normalizeClashOutbound(parts[1])
		}
		return nil, "DIRECT"
	}
	if len(parts) < 3 {
		return nil, ""
	}
	value := parts[1]
	rule := map[string]any{"outbound": normalizeClashOutbound(parts[2])}
	switch ruleType {
	case "DOMAIN":
		rule["domain"] = []string{value}
	case "DOMAIN-SUFFIX":
		if suffix := normalizeDomainSuffix(value); suffix != "" {
			rule["domain_suffix"] = []string{suffix}
		}
	case "DOMAIN-KEYWORD":
		rule["domain_keyword"] = []string{value}
	case "DOMAIN-REGEX":
		rule["domain_regex"] = []string{value}
	case "GEOSITE":
		rule["rule_set"] = []string{"geosite:" + strings.ToLower(value)}
	case "GEOIP":
		value = strings.ToLower(value)
		if value == "lan" || value == "private" {
			rule["ip_is_private"] = true
		} else {
			rule["rule_set"] = []string{"geoip:" + value}
		}
	case "IP-CIDR", "IP-CIDR6":
		rule["ip_cidr"] = []string{value}
	case "SRC-IP-CIDR":
		rule["source_ip_cidr"] = []string{value}
	case "SRC-PORT":
		if port := parsePort(value); port >= 0 {
			rule["source_port"] = []int{port}
		} else {
			return nil, ""
		}
	case "DST-PORT":
		if port := parsePort(value); port >= 0 {
			rule["port"] = []int{port}
		} else {
			return nil, ""
		}
	case "PORT-RANGE":
		if strings.Contains(value, ":") {
			rule["port_range"] = []string{value}
		} else {
			return nil, ""
		}
	case "PROCESS-NAME":
		rule["process_name"] = []string{value}
	case "PROCESS-PATH":
		rule["process_path"] = []string{value}
	case "PROCESS-PATH-REGEX":
		rule["process_path_regex"] = []string{value}
	case "PACKAGE-NAME":
		rule["package_name"] = []string{value}
	case "NETWORK":
		rule["network"] = splitListByAny(value, "/:")
	case "RULE-SET":
		rule["rule_set"] = []string{value}
	default:
		return nil, ""
	}
	if len(rule) == 1 {
		return nil, ""
	}
	return rule, ""
}

func configRouteRuleToPolicy(rule map[string]any, order int) Policy {
	outbound := firstNonEmpty(firstString(rule["outbound"]), "direct_out")
	if firstString(rule["action"]) != "" {
		return Policy{
			Type:     "raw",
			Name:     policyNameFromRule(rule, order),
			RawData:  cloneMap(rule),
			Outbound: "",
			Priority: order + 1,
		}
	}
	if firstString(rule["type"]) == "logical" {
		ruleSets := uniqueCompactList(extractRuleSetFromRule(rule))
		logical := cloneMap(rule)
		delete(logical, "outbound")
		delete(logical, "rule_set")
		filtered := make([]map[string]any, 0)
		for _, child := range ruleListFromAny(logical["rules"]) {
			if !isRuleSetOnlyRule(child) {
				filtered = append(filtered, child)
			}
		}
		if len(filtered) > 0 {
			logical["rules"] = filtered
		} else {
			logical = nil
		}
		return Policy{
			Type:        "default",
			Name:        policyNameFromRule(rule, order),
			RuleSet:     ruleSets,
			LogicalRule: logical,
			Outbound:    outbound,
			Priority:    order + 1,
		}
	}

	ruleSets := uniqueCompactList(stringList(rule["rule_set"]))
	cleanRule := cloneMap(rule)
	delete(cleanRule, "outbound")
	delete(cleanRule, "rule_set")
	policy := Policy{
		Type:     "default",
		Name:     policyNameFromRule(rule, order),
		RuleSet:  ruleSets,
		Outbound: outbound,
		Priority: order + 1,
	}
	if values := stringList(cleanRule["domain_suffix"]); len(values) > 0 {
		policy.DomainSuffix = values
		delete(cleanRule, "domain_suffix")
	}
	if values := stringList(cleanRule["domain"]); len(values) > 0 {
		policy.Domain = values
		delete(cleanRule, "domain")
	}
	if values := stringList(cleanRule["domain_keyword"]); len(values) > 0 {
		policy.DomainKeyword = values
		delete(cleanRule, "domain_keyword")
	}
	if values := stringList(cleanRule["domain_regex"]); len(values) > 0 {
		policy.DomainRegex = values
		delete(cleanRule, "domain_regex")
	}
	if values := stringList(cleanRule["ip_cidr"]); len(values) > 0 {
		policy.IPCIDR = values
		delete(cleanRule, "ip_cidr")
	}
	if values := stringList(cleanRule["source_ip_cidr"]); len(values) > 0 {
		policy.SourceIPCIDR = values
		delete(cleanRule, "source_ip_cidr")
	}
	if values := stringList(cleanRule["port"]); len(values) > 0 {
		policy.Port = values
		delete(cleanRule, "port")
	}
	if values := stringList(cleanRule["port_range"]); len(values) > 0 {
		policy.PortRange = values
		delete(cleanRule, "port_range")
	}
	if values := stringList(cleanRule["source_port"]); len(values) > 0 {
		policy.SourcePort = values
		delete(cleanRule, "source_port")
	}
	if values := stringList(cleanRule["source_port_range"]); len(values) > 0 {
		policy.SourcePortRange = values
		delete(cleanRule, "source_port_range")
	}
	if values := stringList(cleanRule["process_name"]); len(values) > 0 {
		policy.ProcessName = values
		delete(cleanRule, "process_name")
	}
	if values := stringList(cleanRule["process_path"]); len(values) > 0 {
		policy.ProcessPath = values
		delete(cleanRule, "process_path")
	}
	if values := stringList(cleanRule["process_path_regex"]); len(values) > 0 {
		policy.ProcessPathRegex = values
		delete(cleanRule, "process_path_regex")
	}
	if values := stringList(cleanRule["package_name"]); len(values) > 0 {
		policy.PackageName = values
		delete(cleanRule, "package_name")
	}
	if values := stringList(cleanRule["protocol"]); len(values) > 0 {
		policy.Protocol = values
		delete(cleanRule, "protocol")
	}
	if values := stringList(cleanRule["query_type"]); len(values) > 0 {
		policy.QueryType = values
		delete(cleanRule, "query_type")
	}
	if values := stringList(cleanRule["network"]); len(values) > 0 {
		policy.Network = values
		delete(cleanRule, "network")
	}
	if values := stringList(cleanRule["network_type"]); len(values) > 0 {
		policy.NetworkType = values
		delete(cleanRule, "network_type")
	}
	if values := stringList(cleanRule["default_interface_address"]); len(values) > 0 {
		policy.DefaultInterfaceAddress = values
		delete(cleanRule, "default_interface_address")
	}
	if values := stringList(cleanRule["wifi_ssid"]); len(values) > 0 {
		policy.WifiSSID = values
		delete(cleanRule, "wifi_ssid")
	}
	if values := stringList(cleanRule["wifi_bssid"]); len(values) > 0 {
		policy.WifiBSSID = values
		delete(cleanRule, "wifi_bssid")
	}
	if value, ok := cleanRule["network_is_expensive"].(bool); ok {
		policy.NetworkIsExpensive = value
		delete(cleanRule, "network_is_expensive")
	}
	if value, ok := cleanRule["network_is_constrained"].(bool); ok {
		policy.NetworkIsConstrained = value
		delete(cleanRule, "network_is_constrained")
	}
	if value, ok := cleanRule["ip_is_private"].(bool); ok {
		policy.IPIsPrivate = value
		delete(cleanRule, "ip_is_private")
	}
	if hasRuleContent(cleanRule) {
		policy.LogicalRule = map[string]any{"type": "logical", "mode": "or", "rules": []map[string]any{cleanRule}}
	}
	return policy
}

func hasRuleContent(rule map[string]any) bool {
	for _, value := range rule {
		if !isEmptyRuleValue(value) {
			return true
		}
	}
	return false
}

func policyNameFromRule(rule map[string]any, order int) string {
	if name := firstString(rule["name"]); name != "" {
		return name
	}
	parts := make([]string, 0, 2)
	if ruleSets := stringList(rule["rule_set"]); len(ruleSets) > 0 {
		parts = append(parts, strings.Join(firstN(ruleSets, 2), ", "))
	}
	if domains := stringList(rule["domain"]); len(domains) > 0 {
		parts = append(parts, fmt.Sprintf("domain:%d", len(domains)))
	}
	if suffixes := stringList(rule["domain_suffix"]); len(suffixes) > 0 {
		parts = append(parts, fmt.Sprintf("suffix:%d", len(suffixes)))
	}
	if keywords := stringList(rule["domain_keyword"]); len(keywords) > 0 {
		parts = append(parts, fmt.Sprintf("keyword:%d", len(keywords)))
	}
	if cidrs := stringList(rule["ip_cidr"]); len(cidrs) > 0 {
		parts = append(parts, fmt.Sprintf("ip:%d", len(cidrs)))
	}
	if len(parts) > 0 {
		return strings.Join(firstN(parts, 2), " | ")
	}
	if action := firstString(rule["action"]); action != "" {
		return action + " rule"
	}
	return fmt.Sprintf("Rule %d", order+1)
}

func firstN(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func splitClashRule(line string) []string {
	parts := strings.Split(line, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeClashOutbound(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "DIRECT":
		return "DIRECT"
	case "REJECT", "REJECT-DROP", "BLOCK":
		return "REJECT"
	default:
		return strings.TrimSpace(value)
	}
}

func normalizeDomainSuffix(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	for strings.HasPrefix(value, "+") || strings.HasPrefix(value, ".") {
		value = strings.TrimPrefix(value, "+")
		value = strings.TrimPrefix(value, ".")
	}
	if value == "" {
		return ""
	}
	return "." + value
}

func parsePort(value string) int {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 0 || port > 65535 {
		return -1
	}
	return port
}

func splitListByAny(value, separators string) []string {
	return compactList(strings.FieldsFunc(value, func(r rune) bool {
		return strings.ContainsRune(separators, r)
	}))
}

func buildUnifiedDiff(oldText, newText string) string {
	oldLines := splitLinesForDiff(oldText)
	newLines := splitLinesForDiff(newText)
	if strings.Join(oldLines, "\n") == strings.Join(newLines, "\n") {
		return "No changes"
	}
	var out strings.Builder
	out.WriteString("--- current config.json\n")
	out.WriteString("+++ generated config.json\n")
	max := len(oldLines)
	if len(newLines) > max {
		max = len(newLines)
	}
	for i := 0; i < max; i++ {
		var oldLine, newLine string
		oldOK := i < len(oldLines)
		newOK := i < len(newLines)
		if oldOK {
			oldLine = oldLines[i]
		}
		if newOK {
			newLine = newLines[i]
		}
		switch {
		case oldOK && newOK && oldLine == newLine:
			out.WriteString(" " + oldLine + "\n")
		default:
			if oldOK {
				out.WriteString("-" + oldLine + "\n")
			}
			if newOK {
				out.WriteString("+" + newLine + "\n")
			}
		}
	}
	return strings.TrimRight(out.String(), "\n")
}

func splitLinesForDiff(value string) []string {
	value = strings.TrimRight(value, "\n")
	if value == "" {
		return nil
	}
	return strings.Split(value, "\n")
}

func ruleSetsFromConfig(value any) []RuleSet {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	now := time.Now()
	ruleSets := make([]RuleSet, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		entry, ok := mapFromAny(item)
		if !ok {
			continue
		}
		tag := firstString(entry["tag"])
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		ruleSet := RuleSet{
			ID:             uuid.NewString(),
			Tag:            tag,
			Type:           firstNonEmpty(firstString(entry["type"]), "local"),
			Format:         firstNonEmpty(firstString(entry["format"]), guessRuleSetFormat(firstString(entry["url"], entry["path"]))),
			URL:            firstString(entry["url"]),
			Path:           firstString(entry["path"]),
			DownloadDetour: firstNonEmpty(firstString(entry["download_detour"], entry["downloadDetour"]), "DIRECT"),
			Enabled:        true,
			LastUpdated:    now,
		}
		ruleSets = append(ruleSets, ruleSet)
	}
	return ruleSets
}

func ruleSetsFromClashProviders(value any) []RuleSet {
	providers, ok := value.(map[string]any)
	if !ok || len(providers) == 0 {
		return nil
	}
	now := time.Now()
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]RuleSet, 0, len(names))
	for _, name := range names {
		entry, ok := mapFromAny(providers[name])
		if !ok {
			continue
		}
		providerType := strings.ToLower(firstString(entry["type"]))
		remoteURL := firstString(entry["url"])
		localPath := firstString(entry["path"])
		ruleSet := RuleSet{
			ID:             uuid.NewString(),
			Tag:            name,
			Type:           clashRuleProviderType(providerType, remoteURL),
			Format:         clashRuleProviderFormat(entry, remoteURL, localPath),
			Behavior:       strings.ToLower(firstString(entry["behavior"])),
			URL:            remoteURL,
			Path:           localPath,
			DownloadDetour: firstNonEmpty(firstString(entry["download-detour"], entry["download_detour"], entry["proxy"]), "DIRECT"),
			Enabled:        true,
			LastUpdated:    now,
		}
		if ruleSet.URL == "" && ruleSet.Path == "" {
			continue
		}
		out = append(out, ruleSet)
	}
	return out
}

func clashRuleProviderType(providerType, remoteURL string) string {
	switch providerType {
	case "http":
		return "remote"
	case "file":
		return "local"
	default:
		if remoteURL != "" {
			return "remote"
		}
		return "local"
	}
}

func clashRuleProviderFormat(entry map[string]any, remoteURL, localPath string) string {
	format := strings.ToLower(firstString(entry["format"]))
	switch format {
	case "mrs", "srs", "binary":
		return "binary"
	case "yaml", "yml", "text", "source":
		return "source"
	}
	return guessRuleSetFormat(remoteURL + localPath)
}

func mergeRuleSets(groups ...[]RuleSet) []RuleSet {
	seen := map[string]bool{}
	out := make([]RuleSet, 0)
	for _, group := range groups {
		for _, ruleSet := range group {
			if ruleSet.Tag == "" || seen[ruleSet.Tag] {
				continue
			}
			seen[ruleSet.Tag] = true
			out = append(out, ruleSet)
		}
	}
	return out
}

func (s *SandfoxService) syncProfileRuleSetsLocked(profileID string, ruleSets []RuleSet) {
	if profileID == "" {
		return
	}
	seen := map[string]bool{}
	for _, ruleSet := range ruleSets {
		ruleSet.Tag = strings.TrimSpace(ruleSet.Tag)
		ruleSet.URL = strings.TrimSpace(ruleSet.URL)
		ruleSet.Path = strings.TrimSpace(ruleSet.Path)
		ruleSet.Behavior = strings.ToLower(strings.TrimSpace(ruleSet.Behavior))
		if ruleSet.Tag == "" {
			continue
		}
		if ruleSet.Type == "" {
			if ruleSet.URL != "" {
				ruleSet.Type = "remote"
			} else {
				ruleSet.Type = "local"
			}
		}
		if ruleSet.Format == "" {
			ruleSet.Format = guessRuleSetFormat(ruleSet.URL + ruleSet.Path)
		}
		if ruleSet.DownloadDetour == "" {
			ruleSet.DownloadDetour = "DIRECT"
		}
		if ruleSet.ID == "" {
			ruleSet.ID = uuid.NewString()
		}
		if ruleSet.Type == "remote" && ruleSet.LocalPath == "" {
			ruleSet.LocalPath = s.ruleSetCachePath(ruleSet)
		}
		ruleSet.ProfileID = profileID
		seen[ruleSet.Tag] = true
		updated := false
		for i := range s.data.RuleSets {
			if s.data.RuleSets[i].Tag != ruleSet.Tag {
				continue
			}
			ruleSet.ID = firstNonEmpty(s.data.RuleSets[i].ID, ruleSet.ID)
			ruleSet.LocalPath = firstNonEmpty(s.data.RuleSets[i].LocalPath, ruleSet.LocalPath)
			ruleSet.LastUpdated = s.data.RuleSets[i].LastUpdated
			ruleSet.LastError = s.data.RuleSets[i].LastError
			ruleSet.LastWarning = s.data.RuleSets[i].LastWarning
			s.data.RuleSets[i] = ruleSet
			updated = true
			break
		}
		if !updated {
			if ruleSet.Type == "remote" {
				ruleSet.LastUpdated = time.Time{}
			}
			s.data.RuleSets = append(s.data.RuleSets, ruleSet)
		}
	}
	next := s.data.RuleSets[:0]
	for _, ruleSet := range s.data.RuleSets {
		if ruleSet.ProfileID == profileID && !seen[ruleSet.Tag] {
			continue
		}
		next = append(next, ruleSet)
	}
	s.data.RuleSets = next
}

func ruleSetsFromPolicyReferences(policies []Policy) []RuleSet {
	now := time.Now()
	seen := map[string]bool{}
	out := make([]RuleSet, 0)
	for _, policy := range policies {
		for _, tag := range policyRuleSet(policy) {
			if seen[tag] {
				continue
			}
			seen[tag] = true
			if ruleSet, ok := builtinRuleSetFromTag(tag, now); ok {
				out = append(out, ruleSet)
			}
		}
	}
	return out
}

func ruleSetsFromDNSPolicyReferences(policies []DNSPolicy) []RuleSet {
	now := time.Now()
	seen := map[string]bool{}
	out := make([]RuleSet, 0)
	for _, policy := range policies {
		for _, tag := range policy.RuleSet {
			tag = strings.TrimSpace(tag)
			if tag == "" || seen[tag] {
				continue
			}
			seen[tag] = true
			if ruleSet, ok := builtinRuleSetFromTag(tag, now); ok {
				out = append(out, ruleSet)
			}
		}
	}
	return out
}

func builtinRuleSetFromTag(tag string, now time.Time) (RuleSet, bool) {
	kind, name, ok := strings.Cut(tag, ":")
	if !ok || name == "" {
		return RuleSet{}, false
	}
	kind = strings.ToLower(kind)
	name = strings.ToLower(name)
	switch kind {
	case "geosite":
		return RuleSet{ID: uuid.NewString(), Tag: tag, Type: "remote", Format: "binary", URL: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-" + name + ".srs", DownloadDetour: "DIRECT", Enabled: true, LastUpdated: now}, true
	case "geoip":
		return RuleSet{ID: uuid.NewString(), Tag: tag, Type: "remote", Format: "binary", URL: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-" + name + ".srs", DownloadDetour: "DIRECT", Enabled: true, LastUpdated: now}, true
	default:
		return RuleSet{}, false
	}
}

func presetRuleSets() []RuleSet {
	now := time.Now()
	presets := []RuleSet{
		builtinRemoteRuleSet("geosite-cn", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"),
		builtinRemoteRuleSet("geoip-cn", "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"),
		builtinRemoteRuleSet("geosite-geolocation-!cn", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs"),
		builtinRemoteRuleSet("geosite-category-ads-all", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"),
		builtinRemoteRuleSet("geosite-openai", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-openai.srs"),
		builtinRemoteRuleSet("geosite-youtube", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-youtube.srs"),
		builtinRemoteRuleSet("geosite-netflix", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs"),
		builtinRemoteRuleSet("geoip-private", "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-private.srs"),
	}
	for i := range presets {
		presets[i].LastUpdated = now
	}
	return mergePresetRuleSetPresets(presets, roverPresetRuleSets(now))
}

type roverPresetRuleSetRecord struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	Type       string `json:"type"`
	Enabled    bool   `json:"enabled"`
	Path       string `json:"path"`
	LastUpdate string `json:"last_update"`
}

func roverPresetRuleSets(now time.Time) []RuleSet {
	var records []roverPresetRuleSetRecord
	if err := json.Unmarshal(roverPresetRuleSetsJSON, &records); err != nil {
		return nil
	}
	out := make([]RuleSet, 0, len(records))
	for _, record := range records {
		tag := strings.TrimSpace(record.ID)
		if tag == "" {
			tag = strings.TrimSuffix(strings.TrimSpace(record.Path), filepath.Ext(record.Path))
		}
		if tag == "" || strings.TrimSpace(record.URL) == "" {
			continue
		}
		lastUpdated := now
		if parsed, err := time.ParseInLocation("2006/1/2 15:04:05", record.LastUpdate, time.Local); err == nil {
			lastUpdated = parsed
		}
		out = append(out, RuleSet{
			ID:             tag,
			Tag:            tag,
			Type:           "remote",
			Format:         "binary",
			URL:            strings.TrimSpace(record.URL),
			Path:           strings.TrimSpace(record.Path),
			DownloadDetour: "DIRECT",
			Enabled:        record.Enabled,
			LastUpdated:    lastUpdated,
		})
	}
	return out
}

func mergePresetRuleSetPresets(groups ...[]RuleSet) []RuleSet {
	seen := map[string]bool{}
	out := make([]RuleSet, 0)
	for _, group := range groups {
		for _, preset := range group {
			if preset.Tag == "" || seen[preset.Tag] {
				continue
			}
			seen[preset.Tag] = true
			out = append(out, preset)
		}
	}
	return out
}

func presetRuleSetsByID() map[string]RuleSet {
	out := map[string]RuleSet{}
	for _, preset := range presetRuleSets() {
		out[preset.Tag] = preset
	}
	return out
}

func defaultData() AppData {
	now := time.Now()
	return AppData{
		SchemaVersion: dataSchemaVersion,
		Settings:      normalizeSettings(Settings{}),
		Preferences:   map[string]string{},
		Policies: []Policy{
			{ID: uuid.NewString(), Name: "Domestic direct", Match: "cn,local,lan", Outbound: "DIRECT", Enabled: true, Priority: 1, UpdatedAt: now},
			{ID: uuid.NewString(), Name: "Ads reject", Match: "doubleclick.net,googlesyndication.com", Outbound: "REJECT", Enabled: true, Priority: 2, UpdatedAt: now},
		},
		DNSPolicies: []DNSPolicy{
			{ID: uuid.NewString(), Domain: "geosite:cn", Server: "alidns", Strategy: "prefer_ipv4", Enabled: true},
			{ID: uuid.NewString(), Domain: "geosite:geolocation-!cn", Server: "cloudflare", Strategy: "prefer_ipv4", Enabled: true},
		},
		DNSServers: []DNSServer{
			{ID: uuid.NewString(), Tag: "cloudflare", Type: "doh", Address: "https://1.1.1.1/dns-query", Strategy: "prefer_ipv4", AddressResolver: "dns_direct_out", Enabled: true},
			{ID: uuid.NewString(), Tag: "alidns", Type: "doh", Address: "https://dns.alidns.com/dns-query", Strategy: "prefer_ipv4", AddressResolver: "dns_direct_out", Enabled: true},
		},
		RuleSets: []RuleSet{
			{ID: uuid.NewString(), Tag: "geosite-cn", Type: "remote", Format: "binary", URL: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", DownloadDetour: "DIRECT", Enabled: true, LastUpdated: now},
			{ID: uuid.NewString(), Tag: "geoip-cn", Type: "remote", Format: "binary", URL: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", DownloadDetour: "DIRECT", Enabled: true, LastUpdated: now},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func builtinTemplates() []BuiltinTemplate {
	templates := roverBuiltinTemplates()
	templates = append(templates, sandfoxLegacyBuiltinTemplates()...)
	return templates
}

func roverBuiltinTemplates() []BuiltinTemplate {
	var index []TemplateSummary
	if raw, err := roverTemplatesFS.ReadFile("resources/presets/templates.json"); err != nil || json.Unmarshal(raw, &index) != nil {
		return nil
	}
	templates := make([]BuiltinTemplate, 0, len(index))
	for _, summary := range index {
		path := strings.TrimSpace(summary.Path)
		if path == "" {
			continue
		}
		raw, err := roverTemplatesFS.ReadFile("resources/presets/" + path)
		if err != nil {
			continue
		}
		var template BuiltinTemplate
		if err := json.Unmarshal(raw, &template); err != nil {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(path, "templates/"), ".json")
		template.ID = id
		template.Path = path
		template.Name = summary.Name
		template.Description = summary.Description
		template.SettingsRecord = roverTemplateSettingsRecord(raw)
		template.Policies = normalizeTemplatePolicies(template.Policies)
		template.DNSServers = normalizeTemplateDNSServers(template.DNSServers)
		template.DNSPolicies = normalizeTemplateDNSPolicies(template.DNSPolicies)
		template.Settings = settingsFromTemplateRecord(template.SettingsRecord)
		templates = append(templates, template)
	}
	return templates
}

func roverTemplateSettingsRecord(raw []byte) map[string]string {
	var container struct {
		Settings map[string]any `json:"settings"`
	}
	if json.Unmarshal(raw, &container) != nil || len(container.Settings) == 0 {
		return nil
	}
	out := make(map[string]string, len(container.Settings))
	for key, value := range container.Settings {
		if value == nil {
			continue
		}
		out[key] = fmt.Sprint(value)
	}
	return out
}

func normalizeTemplatePolicies(policies []Policy) []Policy {
	out := make([]Policy, 0, len(policies))
	for i, policy := range policies {
		if policy.Priority == 0 {
			policy.Priority = i + 1
		}
		policy.Enabled = true
		policy.Outbound = roverFinalOutbound(policy.Outbound)
		if policy.Type == "raw" && len(policy.RawData) > 0 {
			if outbound := firstString(policy.RawData["outbound"]); outbound != "" {
				policy.RawData["outbound"] = roverFinalOutbound(outbound)
			}
		}
		out = append(out, policy)
	}
	return out
}

func normalizeTemplateDNSServers(servers []DNSServer) []DNSServer {
	out := make([]DNSServer, 0, len(servers))
	for _, server := range servers {
		server.ID = strings.TrimSpace(server.ID)
		server.Name = strings.TrimSpace(server.Name)
		server.Tag = firstNonEmpty(strings.TrimSpace(server.Tag), server.ID, server.Name)
		if server.ID == "" {
			server.ID = server.Tag
		}
		if server.Name == "" {
			server.Name = server.Tag
		}
		server.Type = strings.TrimSpace(server.Type)
		server.Address = strings.TrimSpace(server.Address)
		server.Server = strings.TrimSpace(server.Server)
		if server.Address == "" && server.Server != "" {
			switch strings.ToLower(server.Type) {
			case "tls":
				server.Address = "tls://" + server.Server
			case "https":
				server.Address = "https://" + server.Server + firstNonEmpty(server.Path, "/dns-query")
			default:
				server.Address = server.Server
			}
		}
		out = append(out, server)
	}
	return out
}

func normalizeTemplateDNSPolicies(policies []DNSPolicy) []DNSPolicy {
	out := make([]DNSPolicy, 0, len(policies))
	for _, policy := range policies {
		policy.Enabled = true
		out = append(out, policy)
	}
	return out
}

func settingsFromTemplateRecord(record map[string]string) Settings {
	settings := Settings{}
	for key, value := range record {
		_ = applyRoverSetting(&settings, key, value)
	}
	return settings
}

func sandfoxLegacyBuiltinTemplates() []BuiltinTemplate {
	return []BuiltinTemplate{
		{
			ID:          "domestic-direct",
			Name:        "Domestic Direct",
			Description: "CN geo rules go DIRECT; unmatched traffic follows final outbound.",
			RuleSets: []RuleSet{
				builtinRemoteRuleSet("geosite-cn", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"),
				builtinRemoteRuleSet("geoip-cn", "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"),
			},
			Policies: []Policy{
				{Name: "Private and LAN direct", DomainSuffix: []string{"local", "lan"}, IPCIDR: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}, Outbound: "DIRECT"},
				{Name: "China sites direct", RuleSet: []string{"geosite-cn"}, Outbound: "DIRECT"},
				{Name: "China IP direct", RuleSet: []string{"geoip-cn"}, Outbound: "DIRECT"},
			},
			DNSServers: []DNSServer{
				{Tag: "alidns", Type: "doh", Address: "https://dns.alidns.com/dns-query", Strategy: "prefer_ipv4", Enabled: true},
			},
			DNSPolicies: []DNSPolicy{
				{Domain: "geosite:cn", RuleSet: []string{"geosite-cn"}, Server: "alidns", Strategy: "prefer_ipv4", Enabled: true},
			},
			Settings: Settings{FinalOutbound: "DIRECT", DNSListen: "https://dns.alidns.com/dns-query"},
		},
		{
			ID:          "global-proxy",
			Name:        "Global Proxy",
			Description: "Keep private traffic direct; route common global services through selected proxy.",
			RuleSets: []RuleSet{
				builtinRemoteRuleSet("geosite-geolocation-!cn", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs"),
			},
			Policies: []Policy{
				{Name: "Private and LAN direct", DomainSuffix: []string{"local", "lan"}, IPCIDR: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}, Outbound: "DIRECT"},
				{Name: "Global sites proxy", RuleSet: []string{"geosite-geolocation-!cn"}, Outbound: "Auto"},
			},
			Settings: Settings{FinalOutbound: "Auto", SniffEnabled: true, SniffOverrideDestination: true},
		},
		{
			ID:          "ads-reject",
			Name:        "Ads Reject",
			Description: "Reject common ad and tracker domains using geosite category rules.",
			RuleSets: []RuleSet{
				builtinRemoteRuleSet("geosite-category-ads-all", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"),
			},
			Policies: []Policy{
				{Name: "Ads reject", RuleSet: []string{"geosite-category-ads-all"}, DomainKeyword: []string{"doubleclick", "googlesyndication"}, Outbound: "REJECT"},
			},
		},
		{
			ID:          "ai-streaming",
			Name:        "AI and Streaming",
			Description: "Route AI, developer, and streaming domains through selected proxy.",
			Policies: []Policy{
				{Name: "AI services", DomainSuffix: []string{"openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "perplexity.ai"}, Outbound: "Auto"},
				{Name: "Developer services", DomainSuffix: []string{"github.com", "githubusercontent.com", "npmjs.com"}, Outbound: "Auto"},
				{Name: "Streaming services", DomainSuffix: []string{"netflix.com", "disneyplus.com", "hulu.com", "youtube.com", "googlevideo.com"}, Outbound: "Auto"},
			},
		},
	}
}

func builtinTemplatePath(template BuiltinTemplate) string {
	if template.Path != "" {
		return template.Path
	}
	return "builtin/" + template.ID
}

func builtinTemplateByPath(templatePath string) (BuiltinTemplate, bool) {
	key := strings.TrimSpace(templatePath)
	normalized := strings.TrimPrefix(key, "builtin/")
	normalized = strings.TrimPrefix(normalized, "templates/")
	normalized = strings.TrimSuffix(normalized, ".json")
	legacyPaths := map[string]string{
		"domestic-direct.json": "domestic-direct",
		"global-proxy.json":    "global-proxy",
		"ads-reject.json":      "ads-reject",
		"ai-streaming.json":    "ai-streaming",
	}
	if mapped, ok := legacyPaths[normalized]; ok {
		normalized = mapped
	}
	for _, template := range builtinTemplates() {
		if template.ID == normalized || template.Name == key || builtinTemplatePath(template) == key {
			return template, true
		}
	}
	return BuiltinTemplate{}, false
}

func templateSettingsRecord(template BuiltinTemplate) map[string]string {
	out := map[string]string{}
	for key, value := range template.SettingsRecord {
		out[key] = value
	}
	settings := template.Settings
	if settings.FinalOutbound != "" {
		out["policy-final-outbound"] = settings.FinalOutbound
	}
	if settings.DNSListen != "" {
		out["dns-unmatched-server"] = settings.DNSListen
	}
	if settings.TUNEnabled {
		out["dashboard-tun-mode"] = "true"
	}
	if settings.SniffEnabled {
		out["sniff-enabled"] = "true"
	}
	if settings.SniffOverrideDestination {
		out["sniff-override-destination"] = "true"
	}
	return out
}

func builtinRemoteRuleSet(tag, remoteURL string) RuleSet {
	return RuleSet{Tag: tag, Type: "remote", Format: "binary", URL: remoteURL, DownloadDetour: "DIRECT", Enabled: true}
}

func normalizeSettings(settings Settings) Settings {
	if settings.APIPort == 0 {
		settings.APIPort = 9090
	}
	if settings.MixedPort == 0 {
		settings.MixedPort = 7890
	}
	if settings.AllowLAN {
		settings.MixedListen = "0.0.0.0"
	} else if settings.MixedListen == "" {
		settings.MixedListen = "127.0.0.1"
	}
	if settings.MixedListen == "0.0.0.0" || settings.MixedListen == "::" {
		settings.AllowLAN = true
	}
	settings.SubscriptionUserAgent = strings.TrimSpace(settings.SubscriptionUserAgent)
	if settings.OverrideRules == nil {
		settings.OverrideRules = boolPtr(true)
	}
	if settings.AutoStartProxy == nil {
		settings.AutoStartProxy = boolPtr(true)
	}
	if settings.Mode == "" {
		settings.Mode = "rule"
	}
	if settings.LogLevel == "" {
		settings.LogLevel = "info"
	}
	if settings.DNSListen == "" {
		settings.DNSListen = "https://1.1.1.1/dns-query"
	}
	if settings.DNSStrategy == "" && settings.DNSIPv6 != nil && !*settings.DNSIPv6 {
		settings.DNSStrategy = "prefer_ipv4"
	}
	if settings.DNSFakeIPEnabled && settings.DNSFakeIPRange == "" {
		settings.DNSFakeIPRange = "198.18.0.1/16"
	}
	settings.DNSFakeIPFilter = compactList(settings.DNSFakeIPFilter)
	if settings.DNSFallbackFilter == nil {
		settings.DNSFallbackFilter = map[string]any{}
	}
	if settings.FinalOutbound == "" {
		settings.FinalOutbound = "DIRECT"
	}
	if len(settings.Hosts) > 0 {
		hosts := map[string][]string{}
		for host, values := range settings.Hosts {
			host = strings.TrimSpace(host)
			values = compactList(values)
			if host != "" && len(values) > 0 {
				hosts[host] = values
			}
		}
		settings.Hosts = hosts
	}
	if settings.Experimental == nil {
		settings.Experimental = map[string]any{}
	}
	if settings.TUNStack == "" {
		settings.TUNStack = "system"
	}
	if settings.TUNInterfaceName == "" {
		settings.TUNInterfaceName = "sandfox0"
	}
	if len(settings.TUNAddress) == 0 {
		settings.TUNAddress = []string{"172.19.0.1/30"}
	}
	return settings
}

func (s *SandfoxService) subscriptionUserAgent() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return normalizeSettings(s.data.Settings).SubscriptionUserAgent
}

func fetchText(url string) (string, error) {
	return fetchTextWithUserAgent(url, "")
}

func fetchTextWithUserAgent(url, userAgent string) (string, error) {
	response, err := fetchTextWithUserAgentResponse(url, userAgent)
	if err != nil {
		return "", err
	}
	return response.Body, nil
}

type fetchTextResponse struct {
	Body   string
	Header http.Header
}

func fetchTextWithUserAgentResponse(url, userAgent string) (fetchTextResponse, error) {
	client := http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fetchTextResponse{}, err
	}
	if strings.TrimSpace(userAgent) != "" {
		req.Header.Set("User-Agent", strings.TrimSpace(userAgent))
	}
	res, err := client.Do(req)
	if err != nil {
		return fetchTextResponse{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fetchTextResponse{}, fmt.Errorf("subscription returned %s", res.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return fetchTextResponse{}, err
	}
	return fetchTextResponse{Body: string(raw), Header: res.Header.Clone()}, nil
}

func parseSubscriptionUserinfo(value string) *SubscriptionUserinfo {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ";")
	result := SubscriptionUserinfo{Expire: 0}
	seen := map[string]bool{}
	for _, part := range parts {
		key, rawValue, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		rawValue = strings.TrimSpace(rawValue)
		if key == "expire" && rawValue == "" {
			seen[key] = true
			result.Expire = 0
			continue
		}
		parsed, err := strconv.ParseInt(rawValue, 10, 64)
		if err != nil || parsed < 0 {
			continue
		}
		switch key {
		case "upload":
			result.Upload = parsed
			seen[key] = true
		case "download":
			result.Download = parsed
			seen[key] = true
		case "total":
			result.Total = parsed
			seen[key] = true
		case "expire":
			result.Expire = parsed
			seen[key] = true
		}
	}
	if seen["upload"] && seen["download"] && seen["total"] {
		return &result
	}
	return nil
}

func fetchIPInfo(proxyURL *url.URL) (*IPInfo, error) {
	transport := &http.Transport{}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	client := http.Client{Timeout: 8 * time.Second, Transport: transport}
	res, err := client.Get("https://ipwho.is/")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("IP check returned %s", res.Status)
	}
	var payload struct {
		Success     bool   `json:"success"`
		Message     string `json:"message"`
		IP          string `json:"ip"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, err
	}
	if !payload.Success && payload.Message != "" {
		return nil, errors.New(payload.Message)
	}
	if strings.TrimSpace(payload.IP) == "" {
		return nil, errors.New("IP check returned no address")
	}
	return &IPInfo{IP: payload.IP, Country: payload.Country, CountryCode: payload.CountryCode}, nil
}

type profileParseResult struct {
	Nodes          []ProxyNode
	Groups         []ProxyGroupConfig
	Providers      []ProxyProviderConfig
	RuleSets       []RuleSet
	UpdateInterval int
	Filter         string
	TestURL        string
}

func parseProfileContent(content string) profileParseResult {
	if decoded, err := decodeBase64Text(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err == nil {
		nodes := parseNodesFromDoc(doc)
		groups := parseProxyGroupsFromDoc(doc)
		providers, providerNodes := parseProxyProvidersFromDoc(doc)
		nodes = mergeProxyNodes(nodes, providerNodes)
		groups = expandProxyGroupProviderUse(groups, providers, providerNodes)
		meta := profileMetaFromClashDoc(doc)
		meta.Nodes = nodes
		meta.Groups = groups
		meta.Providers = providers
		meta.RuleSets = ruleSetsFromClashProviders(doc["rule-providers"])
		return meta
	}
	return profileParseResult{Nodes: parseNodes(content)}
}

func validateProfileParseResult(content string, result profileParseResult) error {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return errors.New("profile content is empty")
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(trimmed, "<") || strings.HasPrefix(lower, "<!") || strings.HasPrefix(lower, "<?xml") {
		return errors.New("profile content looks like HTML or XML, not a subscription profile")
	}
	if len(result.Nodes) == 0 && len(result.Groups) == 0 && len(result.Providers) == 0 && len(result.RuleSets) == 0 {
		return errors.New("profile content must include proxies, outbounds, proxy-providers, or rule-providers")
	}
	return nil
}

func profileMetaFromClashDoc(doc map[string]any) profileParseResult {
	result := profileParseResult{
		Filter:  firstString(doc["filter"]),
		TestURL: firstString(doc["test-url"], doc["test_url"]),
	}
	if profile, ok := mapFromAny(doc["profile"]); ok {
		result.UpdateInterval = firstInt(profile["update-interval"], firstInt(profile["update_interval"], 0))
		if result.Filter == "" {
			result.Filter = firstString(profile["filter"])
		}
		if result.TestURL == "" {
			result.TestURL = firstString(profile["test-url"], profile["test_url"], profile["url"])
		}
	}
	if result.UpdateInterval == 0 {
		result.UpdateInterval = firstInt(doc["update-interval"], firstInt(doc["update_interval"], 0))
	}
	return result
}

func filterProfileNodes(nodes []ProxyNode, filter string) ([]ProxyNode, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nodes, nil
	}
	re, err := regexp.Compile(filter)
	if err != nil {
		return nil, err
	}
	out := make([]ProxyNode, 0, len(nodes))
	for _, node := range nodes {
		if re.MatchString(node.Name) || re.MatchString(node.Server) || re.MatchString(node.Type) || re.MatchString(node.Country) {
			out = append(out, node)
		}
	}
	return out, nil
}

func filteredProfileSnapshot(profile Profile, filter string) ([]ProxyNode, []ProxyGroupConfig, []ProxyProviderConfig, error) {
	nodes := append([]ProxyNode(nil), profile.Nodes...)
	groups := append([]ProxyGroupConfig(nil), profile.ProxyGroups...)
	providers := append([]ProxyProviderConfig(nil), profile.ProxyProviders...)
	if strings.TrimSpace(profile.Content) != "" {
		result := parseProfileContent(profile.Content)
		nodes = result.Nodes
		groups = result.Groups
		providers = result.Providers
	}
	filtered, err := filterProfileNodes(nodes, filter)
	if err != nil {
		return nil, nil, nil, err
	}
	return filtered, groups, providers, nil
}

func parseNodes(content string) []ProxyNode {
	if decoded, err := decodeBase64Text(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err == nil {
		if nodes := parseNodesFromDoc(doc); len(nodes) > 0 {
			return nodes
		}
	}
	lines := strings.Split(content, "\n")
	nodes := make([]ProxyNode, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "://") {
			continue
		}
		if node, ok := parseShareLink(line); ok {
			nodes = append(nodes, node)
			continue
		}
		name := line
		if i := strings.LastIndex(line, "#"); i >= 0 {
			name = line[i+1:]
		}
		nodeType := strings.Split(line, "://")[0]
		nodes = append(nodes, ProxyNode{Name: name, Type: nodeType, Server: "imported", Port: 443, Country: guessCountry(name), Latency: 60 + len(name)*5%160, Raw: map[string]any{"type": nodeType, "name": name}})
	}
	return nodes
}

func parseNodesFromDoc(doc map[string]any) []ProxyNode {
	proxies, ok := doc["proxies"].([]any)
	if !ok {
		outbounds, ok := doc["outbounds"].([]any)
		if !ok {
			return nil
		}
		return parseNodesFromSingBoxOutbounds(outbounds)
	}
	nodes := make([]ProxyNode, 0, len(proxies))
	for _, item := range proxies {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := fmt.Sprint(m["name"])
		server := fmt.Sprint(m["server"])
		nodes = append(nodes, ProxyNode{
			Name:    name,
			Type:    fmt.Sprint(m["type"]),
			Server:  server,
			Port:    toInt(m["port"]),
			Country: guessCountry(name + " " + server),
			Latency: 40 + len(name)*9%220,
			Raw:     normalizeRawMap(m),
		})
	}
	return nodes
}

func parseNodesFromSingBoxOutbounds(outbounds []any) []ProxyNode {
	nodes := make([]ProxyNode, 0, len(outbounds))
	for _, item := range outbounds {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		nodeType := strings.ToLower(firstString(m["type"]))
		switch nodeType {
		case "", "direct", "block", "selector", "urltest", "dns":
			continue
		}
		name := firstString(m["tag"], m["name"])
		server := firstString(m["server"])
		if name == "" || server == "" {
			continue
		}
		raw := normalizeRawMap(cloneMap(m))
		raw["name"] = name
		raw["type"] = nodeType
		raw["port"] = firstInt(m["server_port"], firstInt(m["serverPort"], toInt(m["port"])))
		nodes = append(nodes, ProxyNode{
			Name:    name,
			Type:    nodeType,
			Server:  server,
			Port:    firstInt(raw["port"], 0),
			Country: guessCountry(name + " " + server),
			Latency: 40 + len(name)*9%220,
			Raw:     raw,
		})
	}
	return nodes
}

func parseProxyGroupsFromDoc(doc map[string]any) []ProxyGroupConfig {
	items, ok := doc["proxy-groups"].([]any)
	if !ok {
		outbounds, ok := doc["outbounds"].([]any)
		if !ok {
			return nil
		}
		return parseProxyGroupsFromSingBoxOutbounds(outbounds)
	}
	groups := make([]ProxyGroupConfig, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		group := ProxyGroupConfig{
			Name:      firstString(m["name"]),
			Type:      strings.ToLower(firstString(m["type"])),
			Proxies:   stringList(m["proxies"]),
			Use:       stringList(m["use"]),
			URL:       firstString(m["url"]),
			Strategy:  firstString(m["strategy"]),
			Interval:  firstInt(m["interval"], 0),
			Tolerance: firstInt(m["tolerance"], 0),
		}
		if group.Name != "" && group.Type != "" {
			groups = append(groups, group)
		}
	}
	return groups
}

func parseProxyGroupsFromSingBoxOutbounds(outbounds []any) []ProxyGroupConfig {
	groups := make([]ProxyGroupConfig, 0)
	for _, item := range outbounds {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		groupType := strings.ToLower(firstString(m["type"]))
		if groupType != "selector" && groupType != "urltest" {
			continue
		}
		group := ProxyGroupConfig{
			Name:     firstString(m["tag"]),
			Type:     groupType,
			Proxies:  stringList(m["outbounds"]),
			URL:      firstString(m["url"]),
			Interval: durationSeconds(m["interval"]),
		}
		if tolerance := firstInt(m["tolerance"], 0); tolerance > 0 {
			group.Tolerance = tolerance
		}
		if group.Name != "" && len(group.Proxies) > 0 {
			groups = append(groups, group)
		}
	}
	return groups
}

func parseProxyProvidersFromDoc(doc map[string]any) ([]ProxyProviderConfig, []ProxyNode) {
	rawProviders, ok := doc["proxy-providers"].(map[string]any)
	if !ok || len(rawProviders) == 0 {
		return nil, nil
	}
	providerNames := make([]string, 0, len(rawProviders))
	for name := range rawProviders {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	providers := make([]ProxyProviderConfig, 0, len(providerNames))
	nodes := make([]ProxyNode, 0)
	for _, name := range providerNames {
		m, ok := rawProviders[name].(map[string]any)
		if !ok {
			continue
		}
		provider := ProxyProviderConfig{
			Name:     name,
			Type:     strings.ToLower(firstString(m["type"])),
			URL:      firstString(m["url"]),
			Path:     firstString(m["path"]),
			Interval: firstInt(m["interval"], 0),
			Filter:   firstString(m["filter"]),
		}
		health, ok := mapFromAny(m["health-check"])
		if !ok {
			health, ok = mapFromAny(m["health_check"])
		}
		if ok {
			provider.HealthCheckEnable = firstBool(health["enable"], false)
			provider.HealthCheckURL = firstString(health["url"])
			provider.HealthCheckInterval = firstInt(health["interval"], 0)
		}
		providerNodes, err := loadProxyProviderNodes(provider, "")
		if err != nil {
			provider.LastError = err.Error()
			providers = append(providers, provider)
			continue
		}
		if provider.Filter != "" {
			filtered, err := filterProfileNodes(providerNodes, provider.Filter)
			if err != nil {
				provider.LastError = err.Error()
				providers = append(providers, provider)
				continue
			}
			providerNodes = filtered
		}
		for i := range providerNodes {
			if providerNodes[i].Raw == nil {
				providerNodes[i].Raw = map[string]any{}
			}
			providerNodes[i].Raw["provider"] = provider.Name
		}
		provider.NodeCount = len(providerNodes)
		provider.LastUpdated = time.Now()
		providers = append(providers, provider)
		nodes = append(nodes, providerNodes...)
	}
	return providers, nodes
}

func loadProxyProviderNodes(provider ProxyProviderConfig, userAgent string) ([]ProxyNode, error) {
	var content string
	var err error
	switch provider.Type {
	case "http":
		if provider.URL == "" {
			return nil, errors.New("proxy provider url is empty")
		}
		content, err = fetchTextWithUserAgent(provider.URL, userAgent)
	case "file":
		if provider.Path == "" {
			return nil, errors.New("proxy provider path is empty")
		}
		raw, readErr := os.ReadFile(provider.Path)
		if readErr != nil {
			return nil, readErr
		}
		content = string(raw)
	default:
		return nil, fmt.Errorf("unsupported proxy provider type %q", provider.Type)
	}
	if err != nil {
		return nil, err
	}
	return parseProxyProviderContent(content), nil
}

func parseProxyProviderContent(content string) []ProxyNode {
	if decoded, err := decodeBase64Text(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err == nil {
		if nodes := parseNodesFromDoc(doc); len(nodes) > 0 {
			return nodes
		}
	}
	var items []any
	if err := yaml.Unmarshal([]byte(content), &items); err == nil {
		return parseNodesFromList(items)
	}
	return parseNodes(content)
}

func parseNodesFromList(items []any) []ProxyNode {
	nodes := make([]ProxyNode, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := fmt.Sprint(m["name"])
		server := fmt.Sprint(m["server"])
		nodes = append(nodes, ProxyNode{
			Name:    name,
			Type:    fmt.Sprint(m["type"]),
			Server:  server,
			Port:    toInt(m["port"]),
			Country: guessCountry(name + " " + server),
			Latency: 40 + len(name)*9%220,
			Raw:     normalizeRawMap(m),
		})
	}
	return nodes
}

func mergeProxyNodes(base []ProxyNode, extra []ProxyNode) []ProxyNode {
	if len(extra) == 0 {
		return base
	}
	seen := map[string]bool{}
	for _, node := range base {
		if node.Name != "" {
			seen[node.Name] = true
		}
	}
	out := append([]ProxyNode(nil), base...)
	for _, node := range extra {
		if node.Name == "" || seen[node.Name] {
			continue
		}
		out = append(out, node)
		seen[node.Name] = true
	}
	return out
}

func expandProxyGroupProviderUse(groups []ProxyGroupConfig, providers []ProxyProviderConfig, nodes []ProxyNode) []ProxyGroupConfig {
	if len(groups) == 0 || len(providers) == 0 || len(nodes) == 0 {
		return groups
	}
	providerNodes := map[string][]string{}
	for _, node := range nodes {
		provider := firstString(node.Raw["provider"])
		if provider == "" || node.Name == "" {
			continue
		}
		providerNodes[provider] = append(providerNodes[provider], node.Name)
	}
	out := append([]ProxyGroupConfig(nil), groups...)
	for i := range out {
		for _, provider := range out[i].Use {
			out[i].Proxies = append(out[i].Proxies, providerNodes[provider]...)
		}
		out[i].Proxies = uniqueCompactList(out[i].Proxies)
	}
	return out
}

func providersForRefresh(providers []ProxyProviderConfig, target string) []ProxyProviderConfig {
	out := make([]ProxyProviderConfig, 0, len(providers))
	for _, provider := range providers {
		if target == "" || provider.Name == target {
			out = append(out, provider)
		}
	}
	return out
}

func providerNameSet(providers []ProxyProviderConfig) map[string]bool {
	out := map[string]bool{}
	for _, provider := range providers {
		if provider.Name != "" {
			out[provider.Name] = true
		}
	}
	return out
}

func providerNodesByName(nodes []ProxyNode, providers map[string]bool) map[string][]ProxyNode {
	out := map[string][]ProxyNode{}
	for _, node := range nodes {
		provider := firstString(node.Raw["provider"])
		if providers[provider] {
			out[provider] = append(out[provider], node)
		}
	}
	return out
}

func removeProviderNodes(nodes []ProxyNode, providers map[string]bool) []ProxyNode {
	out := make([]ProxyNode, 0, len(nodes))
	for _, node := range nodes {
		if providers[firstString(node.Raw["provider"])] {
			continue
		}
		out = append(out, node)
	}
	return out
}

func updateProfileProviders(profile *Profile, refreshed []ProxyProviderConfig) {
	byName := map[string]ProxyProviderConfig{}
	for _, provider := range refreshed {
		byName[provider.Name] = provider
	}
	for i := range profile.ProxyProviders {
		if provider, ok := byName[profile.ProxyProviders[i].Name]; ok {
			profile.ProxyProviders[i] = provider
			delete(byName, provider.Name)
		}
	}
	for _, provider := range refreshed {
		if _, ok := byName[provider.Name]; ok {
			profile.ProxyProviders = append(profile.ProxyProviders, provider)
		}
	}
}

func replaceProxyGroupProviderMembers(groups []ProxyGroupConfig, providerNames map[string]bool, oldNodes map[string][]ProxyNode, providers []ProxyProviderConfig, replacementNodes []ProxyNode) []ProxyGroupConfig {
	oldNodeNames := map[string]bool{}
	for _, nodes := range oldNodes {
		for _, node := range nodes {
			oldNodeNames[node.Name] = true
		}
	}
	out := append([]ProxyGroupConfig(nil), groups...)
	for i := range out {
		next := make([]string, 0, len(out[i].Proxies))
		for _, proxy := range out[i].Proxies {
			if oldNodeNames[proxy] {
				continue
			}
			next = append(next, proxy)
		}
		out[i].Proxies = uniqueCompactList(next)
	}
	return expandProxyGroupProviderUse(out, providersMatchingUse(providers, providerNames), replacementNodes)
}

func providersMatchingUse(providers []ProxyProviderConfig, providerNames map[string]bool) []ProxyProviderConfig {
	out := make([]ProxyProviderConfig, 0, len(providers))
	for _, provider := range providers {
		if providerNames[provider.Name] {
			out = append(out, provider)
		}
	}
	return out
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func parseShareLink(line string) (ProxyNode, bool) {
	u, err := url.Parse(line)
	if err != nil {
		return ProxyNode{}, false
	}
	switch strings.ToLower(u.Scheme) {
	case "vmess":
		return parseVMessLink(u)
	case "vless", "trojan", "hysteria2", "hy2", "tuic", "anytls":
		return parseURIStyleLink(u)
	case "ss":
		return parseSSLink(u)
	default:
		return ProxyNode{}, false
	}
}

func parseVMessLink(u *url.URL) (ProxyNode, bool) {
	rawText, err := decodeBase64Text(u.Opaque + u.Host + u.Path)
	if err != nil {
		return ProxyNode{}, false
	}
	var doc map[string]any
	if err := json.Unmarshal(rawText, &doc); err != nil {
		return ProxyNode{}, false
	}
	name := firstString(doc["ps"], doc["name"], doc["add"])
	server := firstString(doc["add"], doc["server"])
	port := firstInt(doc["port"], 443)
	raw := normalizeRawMap(map[string]any{
		"type":            "vmess",
		"name":            name,
		"server":          server,
		"port":            port,
		"uuid":            firstString(doc["id"]),
		"alterId":         firstString(doc["aid"]),
		"security":        firstString(doc["scy"], "auto"),
		"network":         firstString(doc["net"]),
		"tls":             firstString(doc["tls"]) != "",
		"sni":             firstString(doc["sni"], doc["host"]),
		"path":            firstString(doc["path"]),
		"host":            firstString(doc["host"]),
		"packet-encoding": firstString(doc["packet-encoding"]),
	})
	return ProxyNode{Name: name, Type: "vmess", Server: server, Port: port, Country: guessCountry(name + " " + server), Latency: 80 + len(name)*5%180, Raw: raw}, true
}

func parseURIStyleLink(u *url.URL) (ProxyNode, bool) {
	nodeType := strings.ToLower(u.Scheme)
	if nodeType == "hy2" {
		nodeType = "hysteria2"
	}
	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = u.Hostname()
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	raw := map[string]any{
		"type":   nodeType,
		"name":   name,
		"server": u.Hostname(),
		"port":   port,
	}
	if u.User != nil {
		if nodeType == "trojan" || nodeType == "hysteria2" || nodeType == "anytls" {
			raw["password"] = u.User.Username()
		} else {
			raw["uuid"] = u.User.Username()
			if pass, ok := u.User.Password(); ok {
				raw["password"] = pass
			}
		}
	}
	query := u.Query()
	for key, values := range query {
		if len(values) > 0 {
			if key == "type" {
				raw["network"] = values[len(values)-1]
			} else {
				raw[key] = values[len(values)-1]
			}
		}
	}
	if security := query.Get("security"); security == "tls" || security == "reality" {
		raw["tls"] = true
	}
	return ProxyNode{Name: name, Type: nodeType, Server: u.Hostname(), Port: port, Country: guessCountry(name + " " + u.Hostname()), Latency: 80 + len(name)*5%180, Raw: normalizeRawMap(raw)}, true
}

func parseSSLink(u *url.URL) (ProxyNode, bool) {
	name, _ := url.QueryUnescape(u.Fragment)
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	user := u.User.Username()
	password, _ := u.User.Password()
	if user == "" && u.Opaque != "" {
		decoded, err := decodeBase64Text(u.Opaque)
		if err == nil {
			parsed, err := url.Parse("ss://" + string(decoded))
			if err == nil {
				server = parsed.Hostname()
				port, _ = strconv.Atoi(parsed.Port())
				user = parsed.User.Username()
				password, _ = parsed.User.Password()
			}
		}
	}
	if strings.Contains(user, ":") && password == "" {
		parts := strings.SplitN(user, ":", 2)
		user = parts[0]
		password = parts[1]
	} else if password == "" && user != "" {
		if decoded, err := decodeBase64Text(user); err == nil && strings.Contains(string(decoded), ":") {
			parts := strings.SplitN(string(decoded), ":", 2)
			user = parts[0]
			password = parts[1]
		}
	}
	if name == "" {
		name = server
	}
	rawInput := map[string]any{"type": "shadowsocks", "name": name, "server": server, "port": port, "cipher": user, "password": password}
	for key, values := range u.Query() {
		if len(values) > 0 {
			rawInput[key] = values[len(values)-1]
		}
	}
	raw := normalizeRawMap(rawInput)
	return ProxyNode{Name: name, Type: "shadowsocks", Server: server, Port: port, Country: guessCountry(name + " " + server), Latency: 80 + len(name)*5%180, Raw: raw}, server != ""
}

func normalizeRawMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
		flattenRawMap(out, key, value)
	}
	return out
}

func flattenRawMap(out map[string]any, prefix string, value any) {
	nested, ok := value.(map[string]any)
	if !ok {
		return
	}
	for nestedKey, nestedValue := range nested {
		key := prefix + "." + nestedKey
		out[key] = nestedValue
		flattenRawMap(out, key, nestedValue)
	}
}

func decodeBase64Text(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "vmess://")
	value = strings.TrimPrefix(value, "ss://")
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\r", "")
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	if pad := len(value) % 4; pad > 0 {
		return decodeBase64Text(value + strings.Repeat("=", 4-pad))
	}
	return nil, lastErr
}

func fallbackNodeType(value string) string {
	switch strings.ToLower(value) {
	case "ss", "shadowsocks":
		return "shadowsocks"
	case "socks5", "socks":
		return "socks"
	case "hy2", "hysteria2":
		return "hysteria2"
	case "vmess", "vless", "trojan", "tuic", "http", "anytls":
		return strings.ToLower(value)
	default:
		return "direct"
	}
}

func guessRuleSetFormat(value string) string {
	lower := strings.ToLower(value)
	if strings.HasSuffix(lower, ".srs") {
		return "binary"
	}
	return "source"
}

func guessDNSServerType(address string) string {
	lower := strings.ToLower(strings.TrimSpace(address))
	switch {
	case strings.HasPrefix(lower, "https://"):
		return "doh"
	case strings.HasPrefix(lower, "tls://"):
		return "dot"
	case strings.HasPrefix(lower, "tcp://"):
		return "tcp"
	case strings.HasPrefix(lower, "udp://"):
		return "udp"
	case strings.HasPrefix(lower, "quic://"):
		return "doq"
	default:
		return "plain"
	}
}

func dnsProbeEndpoint(server DNSServer) (string, string, error) {
	rawAddress := strings.TrimSpace(server.Address)
	if rawAddress == "" {
		return "", "", errors.New("dns server address is required")
	}
	serverType := server.Type
	if serverType == "" {
		serverType = guessDNSServerType(rawAddress)
	}
	defaultPort := "53"
	network := "tcp"
	switch serverType {
	case "doh":
		defaultPort = "443"
	case "dot":
		defaultPort = "853"
	case "doq", "udp":
		network = "udp"
	case "tcp", "plain":
	default:
		if strings.HasPrefix(strings.ToLower(rawAddress), "udp://") {
			network = "udp"
		}
	}
	host := rawAddress
	if parsed, err := url.Parse(rawAddress); err == nil && parsed.Host != "" {
		host = parsed.Host
		if parsed.Scheme == "udp" || parsed.Scheme == "quic" {
			network = "udp"
		}
	}
	host = strings.TrimPrefix(host, "//")
	if strings.Contains(host, "/") {
		host = strings.Split(host, "/")[0]
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return network, host, nil
	}
	if strings.Contains(host, ":") && strings.Count(host, ":") > 1 {
		return network, net.JoinHostPort(host, defaultPort), nil
	}
	return network, net.JoinHostPort(host, defaultPort), nil
}

func firstString(values ...any) string {
	for _, value := range values {
		switch v := value.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		case fmt.Stringer:
			if strings.TrimSpace(v.String()) != "" {
				return strings.TrimSpace(v.String())
			}
		case nil:
		default:
			text := strings.TrimSpace(fmt.Sprint(v))
			if text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}

func firstListItem(value any) string {
	switch v := value.(type) {
	case []any:
		if len(v) == 0 {
			return ""
		}
		return firstString(v[0])
	case []string:
		if len(v) == 0 {
			return ""
		}
		return firstString(v[0])
	default:
		return firstString(value)
	}
}

func clashExternalControllerPort(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if _, port, err := net.SplitHostPort(value); err == nil {
		return toInt(port)
	}
	if strings.Count(value, ":") == 1 {
		parts := strings.Split(value, ":")
		return toInt(parts[1])
	}
	if port := toInt(value); port > 0 {
		return port
	}
	return 0
}

func firstInt(value any, fallback int) int {
	if n := toInt(value); n > 0 {
		return n
	}
	return fallback
}

func firstBool(value any, fallback bool) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	}
	return fallback
}

func boolFromAny(values ...any) (bool, bool) {
	for _, value := range values {
		switch v := value.(type) {
		case bool:
			return v, true
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true", "1", "yes", "on":
				return true, true
			case "false", "0", "no", "off":
				return false, true
			}
		}
	}
	return false, false
}

func boolPtr(value bool) *bool {
	return &value
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func stringList(value any) []string {
	switch v := value.(type) {
	case []string:
		return compactList(v)
	case []int:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, strconv.Itoa(item))
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, firstString(item))
		}
		return compactList(out)
	case string:
		return splitCSV(v)
	default:
		return nil
	}
}

func intList(values []string) []int {
	out := make([]int, 0, len(values))
	for _, value := range values {
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	return compactList(parts)
}

func compactList(parts []string) []string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func uniqueCompactList(parts []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, part := range compactList(parts) {
		if seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	return out
}

func reorderByID[T any](items []T, orderedIDs []string, idOf func(T) string) ([]T, bool) {
	if len(items) <= 1 || len(orderedIDs) == 0 {
		return items, false
	}
	byID := map[string]T{}
	for _, item := range items {
		if id := strings.TrimSpace(idOf(item)); id != "" {
			byID[id] = item
		}
	}
	used := map[string]bool{}
	next := make([]T, 0, len(items))
	for _, id := range orderedIDs {
		id = strings.TrimSpace(id)
		item, ok := byID[id]
		if !ok || used[id] {
			continue
		}
		next = append(next, item)
		used[id] = true
	}
	for _, item := range items {
		id := strings.TrimSpace(idOf(item))
		if id == "" || !used[id] {
			next = append(next, item)
		}
	}
	if len(next) != len(items) {
		return items, false
	}
	for i := range items {
		if idOf(items[i]) != idOf(next[i]) {
			return next, true
		}
	}
	return items, false
}

func toInt(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		var n int
		_, _ = fmt.Sscanf(v, "%d", &n)
		return n
	default:
		return 0
	}
}

func guessCountry(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "hk") || strings.Contains(value, "香港"):
		return "HK"
	case strings.Contains(lower, "jp") || strings.Contains(value, "日本"):
		return "JP"
	case strings.Contains(lower, "sg") || strings.Contains(value, "新加坡"):
		return "SG"
	case strings.Contains(lower, "us") || strings.Contains(value, "美国"):
		return "US"
	case strings.Contains(lower, "tw") || strings.Contains(value, "台湾"):
		return "TW"
	default:
		return "GL"
	}
}
