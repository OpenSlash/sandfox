package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseClashYAMLAndOutboundTransports(t *testing.T) {
	content := `
proxies:
  - name: vmess-ws
    type: vmess
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example.com
    smux:
      enabled: true
      protocol: h2mux
      max-streams: 16
  - name: vless-reality
    type: vless
    server: reality.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000002
    flow: xtls-rprx-vision
    security: reality
    network: grpc
    grpc-opts:
      grpc-service-name: svc
    reality-opts:
      public-key: pubkey
      short-id: abcd
`
	nodes := parseNodes(content)
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	vmess := outboundFromNode(nodes[0])
	if vmess["type"] != "vmess" || vmess["server"] != "example.com" {
		t.Fatalf("unexpected vmess outbound: %#v", vmess)
	}
	transport, ok := vmess["transport"].(map[string]any)
	if !ok || transport["type"] != "ws" || transport["path"] != "/ray" {
		t.Fatalf("expected ws transport, got %#v", vmess["transport"])
	}
	headers, ok := transport["headers"].(map[string]any)
	if !ok || headers["Host"] != "cdn.example.com" {
		t.Fatalf("expected ws Host header, got %#v", transport["headers"])
	}
	mux, ok := vmess["multiplex"].(map[string]any)
	if !ok || mux["enabled"] != true || mux["protocol"] != "h2mux" || mux["max_streams"] != 16 {
		t.Fatalf("expected multiplex config, got %#v", vmess["multiplex"])
	}

	vless := outboundFromNode(nodes[1])
	if vless["type"] != "vless" || vless["flow"] != "xtls-rprx-vision" {
		t.Fatalf("unexpected vless outbound: %#v", vless)
	}
	grpc, ok := vless["transport"].(map[string]any)
	if !ok || grpc["type"] != "grpc" || grpc["service_name"] != "svc" {
		t.Fatalf("expected grpc transport, got %#v", vless["transport"])
	}
	tls, ok := vless["tls"].(map[string]any)
	if !ok || tls["enabled"] != true {
		t.Fatalf("expected tls config, got %#v", vless["tls"])
	}
	reality, ok := tls["reality"].(map[string]any)
	if !ok || reality["public_key"] != "pubkey" || reality["short_id"] != "abcd" {
		t.Fatalf("expected reality config, got %#v", tls["reality"])
	}
}

func TestRoverProxyNodeTypesConvertToSingBoxOutbounds(t *testing.T) {
	cases := []struct {
		name   string
		node   ProxyNode
		assert func(t *testing.T, outbound map[string]any)
	}{
		{
			name: "shadowsocks",
			node: ProxyNode{Type: "ss", Name: "ss-node", Server: "ss.example.com", Port: 8388, Raw: map[string]any{
				"type": "ss", "name": "ss-node", "server": "ss.example.com", "port": 8388,
				"cipher": "aes-128-gcm", "password": "secret", "plugin": "v2ray-plugin",
				"plugin-opts": map[string]any{"mode": "websocket", "path": "/ray", "mux": true},
			}},
			assert: func(t *testing.T, outbound map[string]any) {
				if outbound["type"] != "shadowsocks" || outbound["method"] != "aes-128-gcm" || outbound["plugin"] != "v2ray-plugin" {
					t.Fatalf("unexpected shadowsocks outbound: %#v", outbound)
				}
				if !strings.Contains(fmt.Sprint(outbound["plugin_opts"]), "mode=websocket") || !strings.Contains(fmt.Sprint(outbound["plugin_opts"]), "path=/ray") {
					t.Fatalf("expected SIP003 plugin opts, got %#v", outbound["plugin_opts"])
				}
			},
		},
		{
			name: "socks5",
			node: ProxyNode{Type: "socks5", Name: "socks-node", Server: "socks.example.com", Port: 1080, Raw: map[string]any{
				"type": "socks5", "name": "socks-node", "server": "socks.example.com", "port": 1080,
				"username": "user", "password": "pass",
			}},
			assert: func(t *testing.T, outbound map[string]any) {
				if outbound["type"] != "socks" || outbound["version"] != "5" || outbound["username"] != "user" || outbound["password"] != "pass" {
					t.Fatalf("unexpected socks outbound: %#v", outbound)
				}
			},
		},
		{
			name: "http",
			node: ProxyNode{Type: "http", Name: "http-node", Server: "http.example.com", Port: 8080, Raw: map[string]any{
				"type": "http", "name": "http-node", "server": "http.example.com", "port": 8080,
				"username": "user", "password": "pass", "tls": true, "sni": "edge.example.com",
			}},
			assert: func(t *testing.T, outbound map[string]any) {
				tls := outbound["tls"].(map[string]any)
				if outbound["type"] != "http" || tls["enabled"] != true || tls["server_name"] != "edge.example.com" {
					t.Fatalf("unexpected http outbound: %#v", outbound)
				}
			},
		},
		{
			name: "vmess",
			node: ProxyNode{Type: "vmess", Name: "vmess-node", Server: "vmess.example.com", Port: 443, Raw: map[string]any{
				"type": "vmess", "name": "vmess-node", "server": "vmess.example.com", "port": 443,
				"uuid": "00000000-0000-0000-0000-000000000001", "alterId": 0, "security": "auto",
				"network": "ws", "ws-opts.path": "/ray", "ws-opts.headers.Host": "cdn.example.com",
				"tls": true, "packet-encoding": "xudp",
			}},
			assert: func(t *testing.T, outbound map[string]any) {
				transport := outbound["transport"].(map[string]any)
				headers := transport["headers"].(map[string]any)
				if outbound["type"] != "vmess" || outbound["uuid"] == "" || outbound["packet_encoding"] != "xudp" || transport["type"] != "ws" || headers["Host"] != "cdn.example.com" {
					t.Fatalf("unexpected vmess outbound: %#v", outbound)
				}
			},
		},
		{
			name: "vless",
			node: ProxyNode{Type: "vless", Name: "vless-node", Server: "vless.example.com", Port: 443, Raw: map[string]any{
				"type": "vless", "name": "vless-node", "server": "vless.example.com", "port": 443,
				"uuid": "00000000-0000-0000-0000-000000000002", "flow": "xtls-rprx-vision",
				"security": "reality", "reality-opts.public-key": "pubkey", "reality-opts.short-id": "abcd",
				"network": "grpc", "grpc-opts.grpc-service-name": "svc",
			}},
			assert: func(t *testing.T, outbound map[string]any) {
				tls := outbound["tls"].(map[string]any)
				reality := tls["reality"].(map[string]any)
				if outbound["type"] != "vless" || outbound["flow"] != "xtls-rprx-vision" || reality["public_key"] != "pubkey" || reality["short_id"] != "abcd" {
					t.Fatalf("unexpected vless outbound: %#v", outbound)
				}
			},
		},
		{
			name: "trojan",
			node: ProxyNode{Type: "trojan", Name: "trojan-node", Server: "trojan.example.com", Port: 443, Raw: map[string]any{
				"type": "trojan", "name": "trojan-node", "server": "trojan.example.com", "port": 443,
				"password": "secret", "network": "grpc", "grpc-opts.grpc-service-name": "svc", "skip-cert-verify": true,
			}},
			assert: func(t *testing.T, outbound map[string]any) {
				tls := outbound["tls"].(map[string]any)
				transport := outbound["transport"].(map[string]any)
				if outbound["type"] != "trojan" || outbound["password"] != "secret" || tls["insecure"] != true || transport["type"] != "grpc" {
					t.Fatalf("unexpected trojan outbound: %#v", outbound)
				}
			},
		},
		{
			name: "hysteria2",
			node: ProxyNode{Type: "hysteria2", Name: "hy2-node", Server: "hy2.example.com", Port: 443, Raw: map[string]any{
				"type": "hysteria2", "name": "hy2-node", "server": "hy2.example.com", "port": 443,
				"password": "secret", "up": "50 Mbps", "down": "100 Mbps", "obfs": "salamander", "obfs-password": "obfs-secret",
			}},
			assert: func(t *testing.T, outbound map[string]any) {
				if outbound["type"] != "hysteria2" || outbound["password"] != "secret" || outbound["up_mbps"] != float64(50) || outbound["down_mbps"] != float64(100) || outbound["obfs_password"] != "obfs-secret" {
					t.Fatalf("unexpected hysteria2 outbound: %#v", outbound)
				}
			},
		},
		{
			name: "tuic",
			node: ProxyNode{Type: "tuic", Name: "tuic-node", Server: "tuic.example.com", Port: 443, Raw: map[string]any{
				"type": "tuic", "name": "tuic-node", "server": "tuic.example.com", "port": 443,
				"uuid": "00000000-0000-0000-0000-000000000003", "password": "secret",
				"congestion-controller": "bbr", "udp-relay-mode": "native", "skip-cert-verify": true,
			}},
			assert: func(t *testing.T, outbound map[string]any) {
				tls := outbound["tls"].(map[string]any)
				if outbound["type"] != "tuic" || outbound["congestion_control"] != "bbr" || outbound["udp_relay_mode"] != "native" || tls["insecure"] != true {
					t.Fatalf("unexpected tuic outbound: %#v", outbound)
				}
			},
		},
		{
			name: "anytls",
			node: ProxyNode{Type: "anytls", Name: "anytls-node", Server: "anytls.example.com", Port: 443, Raw: map[string]any{
				"type": "anytls", "name": "anytls-node", "server": "anytls.example.com", "port": 443,
				"password": "secret", "sni": "edge.example.com", "client-fingerprint": "chrome",
				"alpn": []any{"h2", "http/1.1"}, "idle-session-check-interval": 30, "idle-session-timeout": 60, "min-idle-session": 2,
			}},
			assert: func(t *testing.T, outbound map[string]any) {
				tls := outbound["tls"].(map[string]any)
				utls := tls["utls"].(map[string]any)
				if outbound["type"] != "anytls" || outbound["password"] != "secret" || tls["server_name"] != "edge.example.com" || utls["fingerprint"] != "chrome" || outbound["idle_session_timeout"] != "60s" || outbound["min_idle_session"] != 2 {
					t.Fatalf("unexpected anytls outbound: %#v", outbound)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outbound := outboundFromNode(tc.node)
			if outbound["tag"] != tc.node.Name || outbound["server"] != tc.node.Server || outbound["server_port"] != tc.node.Port {
				t.Fatalf("unexpected common outbound fields: %#v", outbound)
			}
			tc.assert(t, outbound)
		})
	}
}

func TestImportProfileParsesProxyGroups(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = nil
	content := `
proxies:
  - name: node-a
    type: ss
    server: a.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
  - name: node-b
    type: vmess
    server: b.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000006
    alterId: 0
    cipher: auto
proxy-groups:
  - name: Auto
    type: url-test
    proxies: [node-a, node-b, missing]
    interval: 900
    tolerance: 75
  - name: Proxy
    type: select
    proxies: [Auto, DIRECT, REJECT]
  - name: Balance
    type: load-balance
    proxies: [node-a, node-b]
    strategy: round-robin
`
	profile, err := service.ImportProfile("clash", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.ProxyGroups) != 3 {
		t.Fatalf("expected proxy groups parsed, got %#v", profile.ProxyGroups)
	}
	if profile.ProxyGroups[2].Type != "load-balance" || profile.ProxyGroups[2].Strategy != "round-robin" {
		t.Fatalf("expected load-balance metadata parsed, got %#v", profile.ProxyGroups[2])
	}
	config := service.buildConfigLocked()
	outbounds := config["outbounds"].([]map[string]any)
	byTag := map[string]map[string]any{}
	for _, outbound := range outbounds {
		byTag[firstString(outbound["tag"])] = outbound
	}
	auto := byTag["Auto"]
	if auto["type"] != "urltest" || auto["interval"] != "600s" || auto["tolerance"] != 75 {
		t.Fatalf("expected url-test group outbound, got %#v", auto)
	}
	if got := stringList(auto["outbounds"]); len(got) != 2 || got[0] != "node-a" || got[1] != "node-b" {
		t.Fatalf("expected invalid references filtered, got %#v", auto["outbounds"])
	}
	proxy := byTag["Proxy"]
	if proxy["type"] != "selector" {
		t.Fatalf("expected selector group outbound, got %#v", proxy)
	}
	if got := stringList(proxy["outbounds"]); len(got) != 3 || got[0] != "Auto" || got[1] != "DIRECT" || got[2] != "REJECT" {
		t.Fatalf("expected nested group and builtins preserved, got %#v", proxy["outbounds"])
	}
	balance := byTag["Balance"]
	if balance["type"] != "urltest" || balance["interval"] != nil {
		t.Fatalf("expected load-balance group converted to urltest, got %#v", balance)
	}
	if got := stringList(balance["outbounds"]); len(got) != 2 || got[0] != "node-a" || got[1] != "node-b" {
		t.Fatalf("expected load-balance members preserved, got %#v", balance["outbounds"])
	}
}

func TestCustomProxyGroupsSettingBuildsRoverStyleGroups(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.CustomProxyGroups = true
	service.data.Profiles = []Profile{{
		ID:       "profile-1",
		Name:     "Custom",
		Selected: true,
		Nodes: []ProxyNode{
			{Name: "node-a", Type: "ss", Server: "a.example.com", Port: 8388, Raw: map[string]any{"cipher": "aes-128-gcm", "password": "secret"}},
			{Name: "node-b", Type: "ss", Server: "b.example.com", Port: 8389, Raw: map[string]any{"cipher": "aes-128-gcm", "password": "secret"}},
		},
		ProxyGroups: []ProxyGroupConfig{
			{Name: "Subscription", Type: "select", Proxies: []string{"node-b"}},
		},
		CustomGroups: []CustomProxyGroup{
			{Name: "Media", Type: "selector", Outbounds: []string{"node-a", "missing"}},
		},
	}}
	config := service.buildConfigLocked()
	outbounds := config["outbounds"].([]map[string]any)
	byTag := map[string]map[string]any{}
	for _, outbound := range outbounds {
		byTag[firstString(outbound["tag"])] = outbound
	}
	if got := stringList(byTag["Auto"]["outbounds"]); len(got) != 2 || got[0] != "node-a" || got[1] != "node-b" {
		t.Fatalf("expected Auto group with all nodes, got %#v", byTag["Auto"])
	}
	if got := stringList(byTag["Proxy"]["outbounds"]); len(got) != 4 || got[0] != "Auto" || got[1] != "Media" || got[2] != "node-a" || got[3] != "node-b" {
		t.Fatalf("expected Proxy selector with custom group and nodes, got %#v", byTag["Proxy"])
	}
	if got := stringList(byTag["Media"]["outbounds"]); len(got) != 1 || got[0] != "node-a" {
		t.Fatalf("expected custom group to keep only valid nodes, got %#v", byTag["Media"])
	}
	if _, ok := byTag["Subscription"]; ok {
		t.Fatalf("expected subscription groups replaced while customProxyGroups is enabled, got %#v", byTag["Subscription"])
	}
}

func TestImportProfileParsesProxyProvidersAndUse(t *testing.T) {
	providerYAML := `
proxies:
  - name: provider-node
    type: ss
    server: provider.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
  - name: other-node
    type: ss
    server: other.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(providerYAML))
	}))
	defer server.Close()

	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = nil
	content := `
proxy-providers:
  remote:
    type: http
    url: ` + server.URL + `
    filter: provider
    health_check:
      enable: true
      url: http://www.gstatic.com/generate_204
      interval: 300
proxy-groups:
  - name: Provider Auto
    type: url-test
    use: [remote]
    interval: 300
`
	profile, err := service.ImportProfile("providers", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.ProxyProviders) != 1 || profile.ProxyProviders[0].Name != "remote" || profile.ProxyProviders[0].NodeCount != 1 {
		t.Fatalf("expected provider metadata with one filtered node, got %#v", profile.ProxyProviders)
	}
	if !profile.ProxyProviders[0].HealthCheckEnable || profile.ProxyProviders[0].HealthCheckURL != "http://www.gstatic.com/generate_204" || profile.ProxyProviders[0].HealthCheckInterval != 300 {
		t.Fatalf("expected provider health_check imported, got %#v", profile.ProxyProviders[0])
	}
	if profile.NodeCount != 1 || profile.Nodes[0].Name != "provider-node" || firstString(profile.Nodes[0].Raw["provider"]) != "remote" {
		t.Fatalf("expected provider node merged into profile, got %#v", profile.Nodes)
	}
	if len(profile.ProxyGroups) != 1 || !containsString(profile.ProxyGroups[0].Use, "remote") || !containsString(profile.ProxyGroups[0].Proxies, "provider-node") {
		t.Fatalf("expected provider use expanded into group, got %#v", profile.ProxyGroups)
	}
	config := service.buildConfigLocked()
	outbounds := config["outbounds"].([]map[string]any)
	byTag := map[string]map[string]any{}
	for _, outbound := range outbounds {
		byTag[firstString(outbound["tag"])] = outbound
	}
	auto := byTag["Provider Auto"]
	if auto["type"] != "urltest" {
		t.Fatalf("expected provider group converted to urltest, got %#v", auto)
	}
	if got := stringList(auto["outbounds"]); len(got) != 1 || got[0] != "provider-node" {
		t.Fatalf("expected provider node in group outbound, got %#v", auto["outbounds"])
	}
}

func TestImportProfileWithSingBoxOutbounds(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = nil
	content := `
outbounds:
  - type: direct
    tag: DIRECT
  - type: shadowsocks
    tag: sb-node
    server: sb.example.com
    server_port: 443
    method: aes-128-gcm
    password: secret
  - type: selector
    tag: Proxy
    outbounds:
      - sb-node
  - type: urltest
    tag: Auto
    outbounds:
      - sb-node
    url: http://www.gstatic.com/generate_204
    interval: 300s
    tolerance: 50
`
	profile, err := service.ImportProfile("singbox", content)
	if err != nil {
		t.Fatal(err)
	}
	if profile.NodeCount != 1 || profile.Nodes[0].Name != "sb-node" || profile.Nodes[0].Type != "shadowsocks" || profile.Nodes[0].Port != 443 {
		t.Fatalf("expected sing-box outbound node imported, got %#v", profile.Nodes)
	}
	if len(profile.ProxyGroups) != 2 || profile.ProxyGroups[0].Name != "Proxy" || profile.ProxyGroups[1].Interval != 300 {
		t.Fatalf("expected sing-box selector/urltest groups imported, got %#v", profile.ProxyGroups)
	}
	config := service.buildConfigLocked()
	outbounds := config["outbounds"].([]map[string]any)
	byTag := map[string]map[string]any{}
	for _, outbound := range outbounds {
		byTag[firstString(outbound["tag"])] = outbound
	}
	if byTag["sb-node"]["type"] != "shadowsocks" || byTag["Proxy"]["type"] != "selector" {
		t.Fatalf("expected sing-box profile outbounds emitted, got %#v", byTag)
	}
}

func TestImportProfileParsesProfileMetadata(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = nil
	content := `
profile:
  update-interval: 6
  test-url: https://example.com/generate_204
filter: node-a
proxies:
  - name: node-a
    type: ss
    server: a.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
  - name: node-b
    type: ss
    server: b.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
`
	profile, err := service.ImportProfile("metadata", content)
	if err != nil {
		t.Fatal(err)
	}
	if profile.UpdateInterval != 6 || profile.TestURL != "https://example.com/generate_204" || profile.Filter != "node-a" {
		t.Fatalf("profile metadata not imported: %#v", profile)
	}
	if profile.NodeCount != 1 || len(profile.Nodes) != 1 || profile.Nodes[0].Name != "node-a" {
		t.Fatalf("profile filter not applied on import: %#v", profile.Nodes)
	}
}

func TestGetProfileContent(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{{ID: "profile-1", Name: "Profile", Content: "proxies: []"}}
	content, err := service.GetProfileContent("profile-1")
	if err != nil {
		t.Fatal(err)
	}
	if content != "proxies: []" {
		t.Fatalf("unexpected profile content: %q", content)
	}
	if _, err := service.GetProfileContent("missing"); err == nil {
		t.Fatal("expected missing profile error")
	}
}

func TestUpdateProfileContentReparsesProfile(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{{
		ID:             "profile-1",
		Name:           "Local",
		Filter:         "US",
		UpdateInterval: 24,
		Selected:       true,
	}}
	content := `
profile:
  update-interval: 6
  test-url: http://test.local/204
proxies:
  - name: HK node
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
  - name: US node
    type: ss
    server: us.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
proxy-groups:
  - name: Auto
    type: url-test
    proxies: [US node]
`
	profile, err := service.UpdateProfileContent("profile-1", content)
	if err != nil {
		t.Fatal(err)
	}
	if profile.NodeCount != 1 || profile.Nodes[0].Name != "US node" || profile.Content == "" {
		t.Fatalf("expected profile content reparsed with existing filter, got %#v", profile)
	}
	if profile.UpdateInterval != 6 || profile.TestURL != "http://test.local/204" || len(profile.ProxyGroups) != 1 {
		t.Fatalf("expected profile metadata and groups updated, got %#v", profile)
	}
}

func TestGetProxyProviderContent(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	path := filepath.Join(t.TempDir(), "provider.yaml")
	if err := os.WriteFile(path, []byte("proxies: []"), 0o644); err != nil {
		t.Fatal(err)
	}
	service.data.Profiles = []Profile{{
		ID: "profile-1", Name: "Profile", Selected: true,
		ProxyProviders: []ProxyProviderConfig{{Name: "local", Type: "file", Path: path}},
	}}
	content, err := service.GetProxyProviderContent("profile-1", "local")
	if err != nil {
		t.Fatal(err)
	}
	if content != "proxies: []" {
		t.Fatalf("unexpected provider content: %q", content)
	}
	if _, err := service.GetProxyProviderContent("profile-1", "missing"); err == nil {
		t.Fatal("expected missing provider error")
	}
}

func TestRefreshProfileProvidersReplacesProviderNodes(t *testing.T) {
	current := `
proxies:
  - name: old-provider-node
    type: ss
    server: old.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
`
	next := `
proxies:
  - name: new-provider-node
    type: ss
    server: new.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
`
	served := current
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(served))
	}))
	defer server.Close()

	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = nil
	content := `
proxy-providers:
  remote:
    type: http
    url: ` + server.URL + `
    interval: 60
proxy-groups:
  - name: Provider Auto
    type: url-test
    use: [remote]
`
	profile, err := service.ImportProfile("providers", content)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Nodes[0].Name != "old-provider-node" {
		t.Fatalf("expected initial provider node, got %#v", profile.Nodes)
	}
	served = next
	if err := service.RefreshProfileProviders(profile.ID); err != nil {
		t.Fatal(err)
	}
	updated := service.data.Profiles[0]
	if updated.NodeCount != 1 || updated.Nodes[0].Name != "new-provider-node" || firstString(updated.Nodes[0].Raw["provider"]) != "remote" {
		t.Fatalf("provider nodes not replaced: %#v", updated.Nodes)
	}
	if len(updated.ProxyGroups) != 1 || containsString(updated.ProxyGroups[0].Proxies, "old-provider-node") || !containsString(updated.ProxyGroups[0].Proxies, "new-provider-node") {
		t.Fatalf("provider group members not refreshed: %#v", updated.ProxyGroups)
	}
	schedule := service.GetRefreshSchedule()
	foundProvider := false
	for _, item := range schedule {
		if item.Kind == "proxy-provider" && item.ProfileID == profile.ID && item.ProviderName == "remote" && item.IntervalSeconds == 60 {
			foundProvider = true
		}
	}
	if !foundProvider {
		t.Fatalf("provider missing from refresh schedule: %#v", schedule)
	}
}

func TestProfileProviderHealthCheckUpdatesProviderAndNode(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{{
		ID:       "profile-1",
		Name:     "Provider profile",
		Selected: true,
		Nodes: []ProxyNode{{
			Name:    "provider-node",
			Type:    "ss",
			Server:  "provider.example.com",
			Port:    8388,
			Raw:     map[string]any{"provider": "remote", "type": "ss", "name": "provider-node", "server": "provider.example.com", "port": 8388},
			Latency: 0,
		}},
		ProxyProviders: []ProxyProviderConfig{{
			Name:           "remote",
			Type:           "http",
			URL:            "https://example.com/provider.yaml",
			HealthCheckURL: "http://www.gstatic.com/generate_204",
			NodeCount:      1,
		}},
	}}
	results, err := service.TestProfileProvider("profile-1", "remote", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Target != "provider-node" || results[0].Delay <= 0 {
		t.Fatalf("expected provider test result, got %#v", results)
	}
	profile := service.data.Profiles[0]
	if profile.Nodes[0].Latency <= 0 || len(profile.ProxyProviders[0].Health) != 1 || profile.ProxyProviders[0].LastChecked.IsZero() {
		t.Fatalf("provider health state not saved: %#v", profile)
	}
}

func TestScheduledTargetsIncludesProviderHealth(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	now := time.Now()
	service.data = defaultData()
	service.data.Profiles = []Profile{{
		ID: "profile-1", Name: "Provider profile",
		ProxyProviders: []ProxyProviderConfig{{
			Name:                "remote",
			Type:                "http",
			URL:                 "https://example.com/provider.yaml",
			Interval:            3600,
			LastUpdated:         now.Add(-30 * time.Minute),
			HealthCheckEnable:   true,
			HealthCheckInterval: 60,
			LastChecked:         now.Add(-2 * time.Minute),
		}},
	}}
	_, _, providerTargets, healthTargets := service.scheduledTargets(false)
	if len(providerTargets) != 0 {
		t.Fatalf("provider content refresh should not be due: %#v", providerTargets)
	}
	if len(healthTargets) != 1 || healthTargets[0].ProfileID != "profile-1" || healthTargets[0].ProviderName != "remote" {
		t.Fatalf("provider health target missing: %#v", healthTargets)
	}
}

func TestParseShareLinks(t *testing.T) {
	vmessPayload := map[string]any{
		"v":    "2",
		"ps":   "vmess-share",
		"add":  "vm.example.com",
		"port": "443",
		"id":   "00000000-0000-0000-0000-000000000003",
		"aid":  "0",
		"scy":  "auto",
		"net":  "ws",
		"type": "none",
		"host": "edge.example.com",
		"path": "/ws",
		"tls":  "tls",
		"sni":  "sni.example.com",
	}
	raw, _ := json.Marshal(vmessPayload)
	links := []string{
		"vmess://" + base64.RawStdEncoding.EncodeToString(raw),
		"vless://00000000-0000-0000-0000-000000000004@vl.example.com:443?security=reality&sni=vl.example.com&flow=xtls-rprx-vision&type=grpc&serviceName=svc&public-key=pk&short-id=sid#vless-share",
		"trojan://secret@trojan.example.com:443?security=tls&sni=trojan.example.com&type=ws&path=%2Ftrojan#trojan-share",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:password")) + "@ss.example.com:8388#ss-share",
		"anytls://secret@anytls.example.com:443?sni=anytls.example.com&alpn=h2,http/1.1&client-fingerprint=chrome&idle-session-timeout=60#anytls-share",
	}
	nodes := parseNodes(joinLines(links))
	if len(nodes) != len(links) {
		t.Fatalf("expected %d nodes, got %d: %#v", len(links), len(nodes), nodes)
	}
	if got := outboundFromNode(nodes[0]); got["type"] != "vmess" || got["tag"] != "vmess-share" {
		t.Fatalf("unexpected vmess share outbound: %#v", got)
	}
	vless := outboundFromNode(nodes[1])
	if vless["type"] != "vless" || vless["flow"] != "xtls-rprx-vision" {
		t.Fatalf("unexpected vless share outbound: %#v", vless)
	}
	trojan := outboundFromNode(nodes[2])
	if trojan["type"] != "trojan" || trojan["password"] != "secret" {
		t.Fatalf("unexpected trojan share outbound: %#v", trojan)
	}
	ss := outboundFromNode(nodes[3])
	if ss["type"] != "shadowsocks" || ss["method"] != "aes-128-gcm" || ss["password"] != "password" {
		t.Fatalf("unexpected ss share outbound: %#v", ss)
	}
	anytls := outboundFromNode(nodes[4])
	if anytls["type"] != "anytls" || anytls["password"] != "secret" || anytls["idle_session_timeout"] != "60s" {
		t.Fatalf("unexpected anytls share outbound: %#v", anytls)
	}
}

func TestOutboundAdvancedNodeFields(t *testing.T) {
	ss := outboundFromNode(ProxyNode{
		Name:   "ss-plugin",
		Type:   "ss",
		Server: "ss.example.com",
		Port:   8388,
		Raw: normalizeRawMap(map[string]any{
			"name":     "ss-plugin",
			"type":     "ss",
			"server":   "ss.example.com",
			"port":     8388,
			"cipher":   "2022-blake3-aes-128-gcm",
			"password": "secret",
			"plugin":   "v2ray-plugin",
			"plugin-opts": map[string]any{
				"mode":             "websocket",
				"host":             "cdn.example.com",
				"path":             "/ws",
				"tls":              true,
				"mux":              true,
				"skip-cert-verify": true,
				"disabled":         false,
			},
			"tfo": true,
		}),
	})
	if ss["plugin"] != "v2ray-plugin" || ss["plugin_opts"] != "mode=websocket;host=cdn.example.com;path=/ws;tls=true;mux=1;skip-cert-verify=true" || ss["tcp_fast_open"] != true {
		t.Fatalf("expected shadowsocks plugin/tfo fields, got %#v", ss)
	}

	hy2 := outboundFromNode(ProxyNode{
		Name:   "hy2",
		Type:   "hysteria2",
		Server: "hy2.example.com",
		Port:   443,
		Raw: map[string]any{
			"name":             "hy2",
			"type":             "hysteria2",
			"server":           "hy2.example.com",
			"port":             443,
			"password":         "secret",
			"sni":              "hy2.example.com",
			"skip-cert-verify": false,
			"up":               "20 Mbps",
			"down":             "100 mb/s",
			"obfs-password":    "obfs-secret",
		},
	})
	if hy2["up_mbps"] != float64(20) || hy2["down_mbps"] != float64(100) || hy2["obfs_password"] != "obfs-secret" {
		t.Fatalf("expected hysteria2 bandwidth/obfs fields, got %#v", hy2)
	}
	if tls, ok := hy2["tls"].(map[string]any); !ok || tls["enabled"] != true || tls["insecure"] != false || tls["server_name"] != "hy2.example.com" {
		t.Fatalf("expected forced hysteria2 tls, got %#v", hy2["tls"])
	}

	tuic := outboundFromNode(ProxyNode{
		Name:   "tuic",
		Type:   "tuic",
		Server: "tuic.example.com",
		Port:   443,
		Raw: map[string]any{
			"name":                  "tuic",
			"type":                  "tuic",
			"server":                "tuic.example.com",
			"port":                  443,
			"uuid":                  "00000000-0000-0000-0000-000000000005",
			"password":              "secret",
			"congestion-controller": "bbr",
			"client-fingerprint":    "chrome",
		},
	})
	tls := tuic["tls"].(map[string]any)
	utls := tls["utls"].(map[string]any)
	if tuic["congestion_control"] != "bbr" || utls["fingerprint"] != "chrome" {
		t.Fatalf("expected tuic congestion/utls fields, got %#v", tuic)
	}
}

func TestRuleSetCacheFallbackInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.RuleSets = []RuleSet{
		{ID: "remote", Tag: "remote-rules", Type: "remote", Format: "binary", URL: "https://example.com/remote.srs", LocalPath: "/missing/remote.srs", DownloadDetour: "DIRECT", Enabled: true},
		{ID: "local", Tag: "local-rules", Type: "remote", Format: "binary", URL: "https://example.com/local.srs", LocalPath: mustTempFile(t, service.dataDir), DownloadDetour: "DIRECT", Enabled: true},
	}
	config := service.buildConfigLocked()
	route := config["route"].(map[string]any)
	ruleSets := route["rule_set"].([]map[string]any)
	if ruleSets[0]["type"] != "remote" || ruleSets[0]["url"] == "" {
		t.Fatalf("missing cache should stay remote, got %#v", ruleSets[0])
	}
	if ruleSets[1]["type"] != "local" || ruleSets[1]["path"] == "" {
		t.Fatalf("existing cache should become local, got %#v", ruleSets[1])
	}
}

func TestSniffSettingsInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.SniffEnabled = true
	service.data.Settings.SniffOverrideDestination = true
	service.data.Settings.TUNEnabled = true
	config := service.buildConfigLocked()
	inbounds := config["inbounds"].([]map[string]any)
	if len(inbounds) != 2 {
		t.Fatalf("expected mixed and tun inbounds, got %#v", inbounds)
	}
	for _, inbound := range inbounds {
		if inbound["sniff"] != true || inbound["sniff_override_destination"] != true {
			t.Fatalf("expected sniff fields on inbound, got %#v", inbound)
		}
	}
}

func TestMixedListenInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.MixedListen = "0.0.0.0"
	config := service.buildConfigLocked()
	inbounds := config["inbounds"].([]map[string]any)
	if inbounds[0]["listen"] != "0.0.0.0" {
		t.Fatalf("expected mixed listen from settings, got %#v", inbounds[0])
	}
}

func TestAllowLANSettingControlsMixedListen(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.AllowLAN = true
	config := service.buildConfigLocked()
	inbounds := config["inbounds"].([]map[string]any)
	if inbounds[0]["listen"] != "0.0.0.0" {
		t.Fatalf("expected allowLan to listen on all interfaces, got %#v", inbounds[0])
	}
}

func TestHostsInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.Hosts = map[string][]string{"router.lan": []string{"192.168.1.1"}}
	config := service.buildConfigLocked()
	dns := config["dns"].(map[string]any)
	servers := dns["servers"].([]map[string]any)
	if len(servers) == 0 || servers[0]["type"] != "hosts" || servers[0]["tag"] != "hosts" {
		t.Fatalf("expected hosts DNS server first, got %#v", servers)
	}
	predefined := servers[0]["predefined"].(map[string][]string)
	if predefined["router.lan"][0] != "192.168.1.1" {
		t.Fatalf("expected predefined hosts, got %#v", predefined)
	}
	rules := dns["rules"].([]map[string]any)
	if len(rules) < 2 || rules[0]["action"] != "evaluate" || rules[0]["server"] != "hosts" || rules[1]["action"] != "respond" || rules[1]["match_response"] != true {
		t.Fatalf("expected hosts DNS rule first, got %#v", rules)
	}
}

func TestExperimentalSettingsInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.Experimental = map[string]any{
		"cache_file": map[string]any{"enabled": true},
		"clash_api":  map[string]any{"external_ui": "ui", "external_ui_download_url": "https://example.com/ui.zip"},
	}
	config := service.buildConfigLocked()
	experimental := config["experimental"].(map[string]any)
	if _, ok := experimental["clash_api"]; !ok {
		t.Fatalf("expected clash_api preserved, got %#v", experimental)
	}
	clashAPI := experimental["clash_api"].(map[string]any)
	if clashAPI["external_ui"] != "ui" || clashAPI["external_ui_download_url"] != "https://example.com/ui.zip" || clashAPI["external_controller"] == "" {
		t.Fatalf("expected clash_api fields merged, got %#v", clashAPI)
	}
	cacheFile := experimental["cache_file"].(map[string]any)
	if cacheFile["enabled"] != true {
		t.Fatalf("expected custom experimental settings, got %#v", experimental)
	}
}

func TestFakeIPDNSSettingsInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.DNSFakeIPEnabled = true
	service.data.Settings.DNSFakeIPRange = "198.18.0.1/16"
	service.data.Settings.DNSFakeIPv6Range = "fc00::/18"
	service.data.Settings.DNSFakeIPFilter = []string{"+.lan", "geosite:private"}
	config := service.buildConfigLocked()
	dns := config["dns"].(map[string]any)
	if dns["final"] != "fakeip" {
		t.Fatalf("expected fakeip final DNS server, got %#v", dns)
	}
	servers := dns["servers"].([]map[string]any)
	fakeIPServer := servers[len(servers)-1]
	if fakeIPServer["type"] != "fakeip" || fakeIPServer["inet4_range"] != "198.18.0.1/16" || fakeIPServer["inet6_range"] != "fc00::/18" {
		t.Fatalf("expected fakeip DNS server, got %#v", fakeIPServer)
	}
	rules := dns["rules"].([]map[string]any)
	if len(rules) < 2 || rules[0]["domain_suffix"].([]string)[0] != "lan" || rules[1]["rule_set"].([]string)[0] != "geosite:private" {
		t.Fatalf("expected fake-ip filter DNS rules, got %#v", rules)
	}
}

func TestIPv6DisabledRemovesGeneratedIPv6Config(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.IPv6 = boolPtr(false)
	service.data.Settings.DNSFakeIPEnabled = true
	service.data.Settings.DNSFakeIPRange = "198.18.0.1/16"
	service.data.Settings.DNSFakeIPv6Range = "fc00::/18"
	service.data.Settings.TUNEnabled = true
	service.data.Settings.TUNAddress = []string{"198.18.0.1/30", "fdfe:dcba:9876::1/126"}

	config := service.buildConfigLocked()
	dns := config["dns"].(map[string]any)
	if dns["strategy"] != "ipv4_only" {
		t.Fatalf("expected ipv4_only DNS strategy, got %#v", dns)
	}
	servers := dns["servers"].([]map[string]any)
	fakeIPServer := servers[len(servers)-1]
	if _, ok := fakeIPServer["inet6_range"]; ok {
		t.Fatalf("expected fake-ip IPv6 range removed, got %#v", fakeIPServer)
	}
	inbounds := config["inbounds"].([]map[string]any)
	tun := inbounds[1]
	if got := stringList(tun["address"]); len(got) != 1 || got[0] != "198.18.0.1/30" {
		t.Fatalf("expected IPv4-only tun address, got %#v", tun["address"])
	}
}

func TestTUNSettingsInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.TUNEnabled = true
	service.data.Settings.TUNStack = "gvisor"
	service.data.Settings.TUNInterfaceName = "utun9"
	service.data.Settings.TUNAddress = []string{"198.18.0.1/30", "fdfe:dcba:9876::1/126"}
	service.data.Settings.TUNMTU = 9000
	service.data.Settings.TUNAutoRoute = boolPtr(false)
	service.data.Settings.TUNStrictRoute = boolPtr(false)
	service.data.Settings.TUNAutoDetectInterface = boolPtr(false)
	service.data.Settings.TUNDNSHijack = []string{"any:53"}
	service.data.Settings.TUNRouteAddress = []string{"0.0.0.0/1"}
	service.data.Settings.TUNRouteExcludeAddress = []string{"192.168.0.0/16"}

	config := service.buildConfigLocked()
	inbounds := config["inbounds"].([]map[string]any)
	if len(inbounds) != 2 {
		t.Fatalf("expected mixed and tun inbounds, got %#v", inbounds)
	}
	tun := inbounds[1]
	if tun["stack"] != "gvisor" || tun["interface_name"] != "utun9" || tun["mtu"] != 9000 || tun["auto_route"] != false || tun["strict_route"] != false {
		t.Fatalf("expected advanced tun fields, got %#v", tun)
	}
	if got := stringList(tun["address"]); len(got) != 2 || got[0] != "198.18.0.1/30" || got[1] != "fdfe:dcba:9876::1/126" {
		t.Fatalf("expected tun addresses, got %#v", tun["address"])
	}
	if got := stringList(tun["dns_hijack"]); len(got) != 1 || got[0] != "any:53" {
		t.Fatalf("expected dns hijack, got %#v", tun["dns_hijack"])
	}
	if route := config["route"].(map[string]any); route["auto_detect_interface"] != false {
		t.Fatalf("expected route auto_detect_interface false, got %#v", route)
	}
}

func TestSubscriptionUserAgentUsedForProfileImport(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.SubscriptionUserAgent = "SandfoxTest/1.0"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "SandfoxTest/1.0" {
			t.Fatalf("expected custom user agent, got %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("subscription-userinfo", "upload=100; download=200; total=1000; expire=4102329600")
		_, _ = w.Write([]byte(`
proxies:
  - name: ua-node
    type: ss
    server: example.com
    port: 443
    cipher: aes-128-gcm
    password: secret
`))
	}))
	defer server.Close()

	profile, err := service.ImportProfile("UA", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if profile.NodeCount != 1 || profile.Nodes[0].Name != "ua-node" {
		t.Fatalf("expected imported node, got %#v", profile)
	}
	if profile.SubscriptionUserinfo == nil || profile.SubscriptionUserinfo.Upload != 100 || profile.SubscriptionUserinfo.Download != 200 || profile.SubscriptionUserinfo.Total != 1000 || profile.SubscriptionUserinfo.Expire != 4102329600 {
		t.Fatalf("expected subscription userinfo imported, got %#v", profile.SubscriptionUserinfo)
	}
}

func TestProfileContentValidationRejectsInvalidSubscription(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	if _, err := service.ImportProfile("bad", "<html>not a subscription</html>"); err == nil {
		t.Fatal("expected html profile import to fail")
	}
	if _, err := service.ImportProfile("empty", "rules:\n  - MATCH,DIRECT\n"); err == nil {
		t.Fatal("expected profile without nodes or providers to fail")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<!doctype html><title>login</title>"))
	}))
	defer server.Close()
	service.data.Profiles = []Profile{{ID: "profile-1", Name: "Remote", URL: server.URL, Selected: true, UpdateInterval: 24}}
	if err := service.RefreshProfile("profile-1"); err == nil {
		t.Fatal("expected invalid remote refresh to fail")
	}
	if service.data.Profiles[0].LastError == "" {
		t.Fatalf("expected refresh error recorded, got %#v", service.data.Profiles[0])
	}
}

func TestProfileImportSyncsRuleProviders(t *testing.T) {
	ruleProviderServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload:\n  - DOMAIN,example.com\n"))
	}))
	defer ruleProviderServer.Close()
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	content := fmt.Sprintf(`
proxies:
  - name: node-a
    type: ss
    server: example.com
    port: 443
    cipher: aes-128-gcm
    password: secret
rule-providers:
  custom:rules:
    type: http
    behavior: classical
    format: yaml
    url: %s
    path: ./rules/custom.yaml
    proxy: Auto
`, ruleProviderServer.URL)
	profile, err := service.ImportProfile("Rules", content)
	if err != nil {
		t.Fatal(err)
	}
	profileRuleSets := ruleSetsForProfile(service.data.RuleSets, profile.ID)
	if len(profileRuleSets) != 1 {
		t.Fatalf("expected profile rule provider synced, got %#v", service.data.RuleSets)
	}
	ruleSet := profileRuleSets[0]
	if ruleSet.Tag != "custom:rules" || ruleSet.ProfileID != profile.ID || ruleSet.Type != "remote" || ruleSet.Format != "source" || ruleSet.Behavior != "classical" || ruleSet.DownloadDetour != "Auto" || ruleSet.LocalPath == "" {
		t.Fatalf("unexpected profile rule provider: %#v", ruleSet)
	}
	if ruleSet.LastUpdated.IsZero() || ruleSet.LastError != "" {
		t.Fatalf("new profile rule provider should be downloaded during import, got %#v", ruleSet)
	}
	if _, err := os.Stat(ruleSet.LocalPath); err != nil {
		t.Fatalf("expected downloaded profile rule provider cache at %s: %v", ruleSet.LocalPath, err)
	}
	_, dueRuleSets, _, _ := service.scheduledTargets(false)
	if containsString(dueRuleSets, ruleSet.ID) {
		t.Fatalf("fresh profile rule provider should skip scheduled download, got %#v", dueRuleSets)
	}
	service.data.RuleSets[len(service.data.RuleSets)-1].LastUpdated = time.Now()
	service.data.RuleSets[len(service.data.RuleSets)-1].LastWarning = "cached"
	refreshed := fmt.Sprintf(`
proxies:
  - name: node-a
    type: ss
    server: example.com
    port: 443
    cipher: aes-128-gcm
    password: secret
rule-providers:
  custom:rules:
    type: http
    behavior: classical
    format: yaml
    url: %s/new
    proxy: Auto
`, ruleProviderServer.URL)
	service.data.Profiles[0].URL = "inline"
	if _, err := service.UpdateProfileContent(profile.ID, refreshed); err != nil {
		t.Fatal(err)
	}
	profileRuleSets = ruleSetsForProfile(service.data.RuleSets, profile.ID)
	if len(profileRuleSets) != 1 || profileRuleSets[0].LastWarning != "cached" || profileRuleSets[0].URL != ruleProviderServer.URL+"/new" {
		t.Fatalf("expected profile rule provider metadata preserved on refresh, got %#v", profileRuleSets)
	}
	refreshed = `
proxies:
  - name: node-a
    type: ss
    server: example.com
    port: 443
    cipher: aes-128-gcm
    password: secret
`
	if _, err := service.UpdateProfileContent(profile.ID, refreshed); err != nil {
		t.Fatal(err)
	}
	if remaining := ruleSetsForProfile(service.data.RuleSets, profile.ID); len(remaining) != 0 {
		t.Fatalf("expected removed profile rule providers to be pruned, got %#v", service.data.RuleSets)
	}
}

func ruleSetsForProfile(ruleSets []RuleSet, profileID string) []RuleSet {
	out := make([]RuleSet, 0)
	for _, ruleSet := range ruleSets {
		if ruleSet.ProfileID == profileID {
			out = append(out, ruleSet)
		}
	}
	return out
}

func TestSelectedProfilePolicyOverrideInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Policies = []Policy{{
		ID:        "policy-1",
		Name:      "Example",
		Domain:    []string{"example.com"},
		Outbound:  "DIRECT",
		Enabled:   true,
		Priority:  1,
		UpdatedAt: time.Now(),
	}}
	service.data.Profiles = []Profile{{
		ID:       "profile-1",
		Name:     "Selected",
		Selected: true,
		PolicyOverrides: []ProfilePolicyOverride{{
			PolicyID: "policy-1",
			Outbound: "Proxy",
		}},
	}}
	config := service.buildConfigLocked()
	route := config["route"].(map[string]any)
	rules := route["rules"].([]map[string]any)
	if len(rules) != 1 || rules[0]["outbound"] != "Proxy" {
		t.Fatalf("expected selected profile policy override, got %#v", rules)
	}
	if err := service.ClearProfilePolicyOverride("profile-1", "policy-1"); err != nil {
		t.Fatal(err)
	}
	config = service.buildConfigLocked()
	route = config["route"].(map[string]any)
	rules = route["rules"].([]map[string]any)
	if rules[0]["outbound"] != "DIRECT" {
		t.Fatalf("expected global policy outbound after clearing override, got %#v", rules)
	}
}

func TestSelectedProfileDNSPolicyOverrideInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.DNSServers = []DNSServer{
		{ID: "dns-1", Tag: "cloudflare", Address: "https://1.1.1.1/dns-query", Strategy: "prefer_ipv4", Enabled: true},
		{ID: "dns-2", Tag: "alidns", Address: "https://dns.alidns.com/dns-query", Strategy: "prefer_ipv4", Enabled: true},
	}
	service.data.DNSPolicies = []DNSPolicy{{
		ID:           "dns-policy-1",
		DomainSuffix: []string{"example.com"},
		Server:       "cloudflare",
		Strategy:     "prefer_ipv4",
		Enabled:      true,
	}}
	service.data.Profiles = []Profile{{
		ID:       "profile-1",
		Name:     "Selected",
		Selected: true,
		DNSPolicyOverrides: []ProfileDNSPolicyOverride{{
			PolicyID: "dns-policy-1",
			Server:   "alidns",
		}},
	}}
	config := service.buildConfigLocked()
	dns := config["dns"].(map[string]any)
	rules := dns["rules"].([]map[string]any)
	if len(rules) != 1 || rules[0]["server"] != "alidns" {
		t.Fatalf("expected selected profile DNS override, got %#v", rules)
	}
	if err := service.ClearProfileDNSPolicyOverride("profile-1", "dns-policy-1"); err != nil {
		t.Fatal(err)
	}
	config = service.buildConfigLocked()
	dns = config["dns"].(map[string]any)
	rules = dns["rules"].([]map[string]any)
	if rules[0]["server"] != "cloudflare" {
		t.Fatalf("expected global DNS policy server after clearing override, got %#v", rules)
	}
}

func TestSelectedProfileDNSServerDetourInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.DNSServers = []DNSServer{{
		ID:       "dns-1",
		Tag:      "cloudflare",
		Address:  "https://1.1.1.1/dns-query",
		Detour:   "DIRECT",
		Strategy: "prefer_ipv4",
		Enabled:  true,
	}}
	service.data.Profiles = []Profile{{
		ID:       "profile-1",
		Name:     "Selected",
		Selected: true,
		DNSServerDetours: []ProfileDNSServerDetour{{
			ServerID: "dns-1",
			Detour:   "Proxy",
		}},
	}}
	config := service.buildConfigLocked()
	dns := config["dns"].(map[string]any)
	servers := dns["servers"].([]map[string]any)
	if len(servers) != 1 || servers[0]["detour"] != "Proxy" {
		t.Fatalf("expected selected profile DNS server detour, got %#v", servers)
	}
	if err := service.ClearProfileDNSServerDetour("profile-1", "dns-1"); err != nil {
		t.Fatal(err)
	}
	config = service.buildConfigLocked()
	dns = config["dns"].(map[string]any)
	servers = dns["servers"].([]map[string]any)
	if servers[0]["detour"] != "DIRECT" {
		t.Fatalf("expected global DNS server detour after clearing override, got %#v", servers)
	}
}

func TestBuiltinTemplateAppliesDNSAndSettings(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.DNSPolicies = nil
	service.data.DNSServers = nil
	if err := service.ApplyBuiltinTemplate("domestic-direct", true); err != nil {
		t.Fatal(err)
	}
	if len(service.data.DNSServers) == 0 || service.data.DNSServers[0].Tag != "alidns" {
		t.Fatalf("expected template DNS server, got %#v", service.data.DNSServers)
	}
	if len(service.data.DNSPolicies) == 0 || service.data.DNSPolicies[0].Server != "alidns" {
		t.Fatalf("expected template DNS policy, got %#v", service.data.DNSPolicies)
	}
	if service.data.Settings.FinalOutbound != "DIRECT" || service.data.Settings.DNSListen != "https://dns.alidns.com/dns-query" {
		t.Fatalf("expected template settings, got %#v", service.data.Settings)
	}
}

func TestRefreshRuleSetConvertsClashProviderPayload(t *testing.T) {
	content := `
payload:
  - DOMAIN,example.com
  - DOMAIN-SUFFIX,+.google.com
  - IP-CIDR,8.8.8.0/24
  - 1.1.1.0/24
  - '+.github.com'
  - GEOSITE,youtube
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(content))
	}))
	defer server.Close()

	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.RuleSets = []RuleSet{{
		ID:             "rules",
		Tag:            "custom",
		Type:           "remote",
		Format:         "source",
		URL:            server.URL,
		DownloadDetour: "DIRECT",
		Enabled:        true,
	}}
	if err := service.RefreshRuleSet("rules"); err != nil {
		t.Fatal(err)
	}
	localPath := service.data.RuleSets[0].LocalPath
	raw, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	var converted map[string]any
	if err := json.Unmarshal(raw, &converted); err != nil {
		t.Fatalf("expected converted source rule set json, got %s: %v", string(raw), err)
	}
	if toInt(converted["version"]) != 3 {
		t.Fatalf("expected source rule set version, got %#v", converted)
	}
	rules, ok := converted["rules"].([]any)
	if !ok || len(rules) != 6 {
		t.Fatalf("expected six converted rules, got %#v", converted["rules"])
	}
	geosite := rules[5].(map[string]any)
	if stringList(geosite["rule_set"])[0] != "geosite:youtube" {
		t.Fatalf("expected GEOSITE payload converted, got %#v", geosite)
	}
	if service.data.RuleSets[0].LastError != "" || !strings.Contains(service.data.RuleSets[0].LastWarning, "Converted 6 rules") || !strings.HasSuffix(localPath, ".json") {
		t.Fatalf("rule set refresh metadata not updated: %#v", service.data.RuleSets[0])
	}
}

func TestSaveRuleSetUpdate(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.RuleSets = nil
	ruleSet, err := service.SaveRuleSet(RuleSet{
		Tag:            "remote",
		Type:           "remote",
		Format:         "binary",
		URL:            "https://example.com/old.srs",
		DownloadDetour: "DIRECT",
		Enabled:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ruleSet.URL = "https://example.com/new.srs"
	ruleSet.DownloadDetour = "Auto"
	ruleSet.Enabled = false
	updated, err := service.SaveRuleSet(ruleSet)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != ruleSet.ID || len(service.data.RuleSets) != 1 {
		t.Fatalf("rule set should update in place, got %#v", service.data.RuleSets)
	}
	if service.data.RuleSets[0].URL != "https://example.com/new.srs" || service.data.RuleSets[0].DownloadDetour != "Auto" || service.data.RuleSets[0].Enabled {
		t.Fatalf("rule set fields not updated: %#v", service.data.RuleSets[0])
	}
}

func TestPresetRuleSets(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	presets := service.GetPresetRuleSets()
	if len(presets) < 2200 || presets[0].Tag != "geosite-cn" {
		t.Fatalf("expected preset rule sets, got %#v", presets)
	}
	foundRoverPreset := false
	for _, preset := range presets {
		if preset.Tag == "acl:360" && preset.URL != "" && preset.Format == "binary" {
			foundRoverPreset = true
			break
		}
	}
	if !foundRoverPreset {
		limit := len(presets)
		if limit > 8 {
			limit = 8
		}
		t.Fatalf("expected embedded Rover preset rule sets, got first presets %#v", presets[:limit])
	}
	service.data.RuleSets = []RuleSet{{ID: "existing", Tag: "geosite-cn", Type: "remote", Format: "source", URL: "old", LocalPath: "/tmp/geosite-cn.srs", Enabled: true}}
	result, err := service.AddRuleSetsFromPreset([]string{"geosite-cn", "geosite-openai", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 1 || result.Updated != 1 || len(service.data.RuleSets) != 2 {
		t.Fatalf("unexpected preset apply result: %#v ruleSets=%#v", result, service.data.RuleSets)
	}
	if service.data.RuleSets[0].ID != "existing" || service.data.RuleSets[0].Format != "binary" || service.data.RuleSets[0].LocalPath != "/tmp/geosite-cn.srs" {
		t.Fatalf("existing preset not updated in place: %#v", service.data.RuleSets[0])
	}
	if service.data.RuleSets[1].Tag != "geosite-openai" || !service.data.RuleSets[1].Enabled {
		t.Fatalf("new preset not added: %#v", service.data.RuleSets[1])
	}
}

func TestGetRuleSetContent(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	path := mustTempFileWithContent(t, service.dataDir, `{"version":3,"rules":[{"domain":["example.com"]}]}`)
	service.data.RuleSets = []RuleSet{{
		ID:      "rules",
		Tag:     "custom",
		Type:    "local",
		Format:  "source",
		Path:    path,
		Enabled: true,
	}}
	preview, err := service.GetRuleSetContent("rules")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Path != path || !strings.Contains(preview.Content, "example.com") || preview.Changed {
		t.Fatalf("unexpected rule set preview: %#v", preview)
	}
}

func TestOverrideRulesSettingCanDisableLocalRules(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.OverrideRules = boolPtr(false)
	config := service.buildConfigLocked()
	route := config["route"].(map[string]any)
	if rules := route["rules"].([]map[string]any); len(rules) != 0 {
		t.Fatalf("expected local route rules disabled, got %#v", rules)
	}
	if ruleSets := route["rule_set"].([]map[string]any); len(ruleSets) != 0 {
		t.Fatalf("expected local rule sets disabled, got %#v", ruleSets)
	}
	dns := config["dns"].(map[string]any)
	if rules := dns["rules"].([]map[string]any); len(rules) != 0 {
		t.Fatalf("expected local DNS rules disabled, got %#v", rules)
	}
}

func TestAutoStartProxySettingDefaultsAndCanBeDisabled(t *testing.T) {
	settings := normalizeSettings(Settings{})
	if settings.AutoStartProxy == nil || !*settings.AutoStartProxy {
		t.Fatalf("expected autoStartProxy enabled by default, got %#v", settings.AutoStartProxy)
	}
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.AutoStartProxy = boolPtr(false)
	service.data.Profiles = []Profile{{ID: "profile-1", Name: "Profile", Selected: true}}
	service.autoStartCoreIfEnabled()
	if service.core != nil {
		t.Fatalf("expected disabled autoStartProxy to skip core start")
	}
}

func TestDNSServerAdvancedFieldsInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	server, err := service.SaveDNSServer(DNSServer{
		Tag:             "dot-upstream",
		Address:         "tls://1.1.1.1",
		AddressResolver: "bootstrap",
		AddressStrategy: "prefer_ipv4",
		Detour:          "DIRECT",
		Strategy:        "ipv4_only",
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.Type != "dot" {
		t.Fatalf("expected dot type, got %#v", server)
	}
	config := service.buildConfigLocked()
	dns := config["dns"].(map[string]any)
	servers := dns["servers"].([]map[string]any)
	found := false
	for _, entry := range servers {
		if entry["tag"] != "dot-upstream" {
			continue
		}
		found = entry["address_resolver"] == "bootstrap" && entry["address_strategy"] == "prefer_ipv4" && entry["detour"] == "DIRECT"
	}
	if !found {
		t.Fatalf("advanced DNS fields missing: %#v", servers)
	}
}

func TestDefaultDNSResolverSupportServerPrecedesReferences(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()

	config := service.buildConfigLocked()
	dns := config["dns"].(map[string]any)
	servers := dns["servers"].([]map[string]any)
	if len(servers) < 3 {
		t.Fatalf("expected DNS support and upstream servers, got %#v", servers)
	}
	if servers[0]["tag"] != "dns_direct_out" || servers[0]["address"] != "local" {
		t.Fatalf("expected legacy local support server first, got %#v", servers[0])
	}
	if servers[1]["address_resolver"] != "dns_direct_out" || servers[2]["address_resolver"] != "dns_direct_out" {
		t.Fatalf("expected default upstreams to reference support server, got %#v", servers)
	}
	route := config["route"].(map[string]any)
	routeRuleSets := route["rule_set"].([]map[string]any)
	routeRuleSetTags := map[string]bool{}
	for _, ruleSet := range routeRuleSets {
		routeRuleSetTags[firstString(ruleSet["tag"])] = true
	}
	for _, tag := range []string{"geosite-cn", "geosite-geolocation-!cn"} {
		if !routeRuleSetTags[tag] {
			t.Fatalf("expected DNS-referenced rule set %s in route rule_set, got %#v", tag, routeRuleSets)
		}
	}
	rules := dns["rules"].([]map[string]any)
	if len(rules) < 2 || stringList(rules[0]["rule_set"])[0] != "geosite-cn" || stringList(rules[1]["rule_set"])[0] != "geosite-geolocation-!cn" {
		t.Fatalf("expected default DNS rule sets normalized, got %#v", rules)
	}
}

func TestDNSServerAndPolicyUpdate(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	server, err := service.SaveDNSServer(DNSServer{Tag: "test", Address: "https://1.1.1.1/dns-query", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	server.Address = "tls://1.0.0.1"
	server.Type = "dot"
	server.Detour = "Auto"
	updatedServer, err := service.SaveDNSServer(server)
	if err != nil {
		t.Fatal(err)
	}
	if updatedServer.ID != server.ID || len(service.data.DNSServers) != 3 || service.data.DNSServers[2].Address != "tls://1.0.0.1" || service.data.DNSServers[2].Detour != "Auto" {
		t.Fatalf("dns server not updated in place: %#v", service.data.DNSServers)
	}

	policy, err := service.SaveDNSPolicy(DNSPolicy{DomainSuffix: []string{"example.com"}, Server: "test", Strategy: "prefer_ipv4", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	policy.DomainSuffix = []string{"example.org"}
	policy.QueryType = []string{"A"}
	updatedPolicy, err := service.SaveDNSPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if updatedPolicy.ID != policy.ID || len(service.data.DNSPolicies) != 3 || service.data.DNSPolicies[2].DomainSuffix[0] != "example.org" || service.data.DNSPolicies[2].QueryType[0] != "A" {
		t.Fatalf("dns policy not updated in place: %#v", service.data.DNSPolicies)
	}
}

func TestDNSServerRefsAndToggle(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.DNSListen = "bootstrap"
	service.data.DNSServers = []DNSServer{
		{ID: "dns-1", Tag: "bootstrap", Address: "1.1.1.1", Enabled: true},
		{ID: "dns-2", Tag: "main", Address: "https://dns.example/dns-query", AddressResolver: "bootstrap", Detour: "Proxy", Enabled: true},
	}
	service.data.DNSPolicies = []DNSPolicy{{ID: "policy-1", DomainSuffix: []string{"example.com"}, Server: "main", Enabled: true}}
	service.data.Profiles = []Profile{{
		ID:                 "profile-1",
		Name:               "Profile",
		DNSPolicyOverrides: []ProfileDNSPolicyOverride{{PolicyID: "policy-1", Server: "main"}},
		DNSServerDetours:   []ProfileDNSServerDetour{{ServerID: "dns-2", Detour: "Proxy"}},
	}}
	refs := service.GetDNSServerRefs("main")
	if len(refs) != 2 || refs[0].Source != "dns" || refs[1].Source != "profile_dns" {
		t.Fatalf("expected dns policy refs for main, got %#v", refs)
	}
	refs = service.GetDNSServerRefs("bootstrap")
	if len(refs) != 2 || refs[0].Source != "dns_server" || refs[1].Source != "setting" {
		t.Fatalf("expected resolver and setting refs for bootstrap, got %#v", refs)
	}
	enabled, err := service.ToggleDNSServerEnabled("main", false)
	if err != nil {
		t.Fatal(err)
	}
	if enabled || service.data.DNSServers[1].Enabled {
		t.Fatalf("dns server not toggled off: %#v", service.data.DNSServers[1])
	}
}

func TestDNSServerProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.DNSServers = []DNSServer{{ID: "local", Tag: "local", Type: "tcp", Address: "tcp://" + listener.Addr().String(), Enabled: true}}
	probe, err := service.TestDNSServer("local")
	if err != nil {
		t.Fatal(err)
	}
	if probe.Status != "ok" || probe.Delay <= 0 {
		t.Fatalf("unexpected dns probe: %#v", probe)
	}
}

func TestDNSPolicyAdvancedFieldsInConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.DNSPolicies = []DNSPolicy{
		{
			ID:            "advanced",
			Server:        "cloudflare",
			RuleSet:       []string{"geosite-openai"},
			DomainSuffix:  []string{"example.com"},
			DomainKeyword: []string{"ai"},
			QueryType:     []string{"A", "AAAA"},
			Network:       []string{"tcp"},
			Strategy:      "prefer_ipv4",
			Enabled:       true,
		},
	}
	config := service.buildConfigLocked()
	dns := config["dns"].(map[string]any)
	rules := dns["rules"].([]map[string]any)
	if len(rules) != 1 || len(stringList(rules[0]["rule_set"])) != 1 || len(stringList(rules[0]["query_type"])) != 2 || len(stringList(rules[0]["network"])) != 1 {
		t.Fatalf("advanced DNS policy fields missing: %#v", rules)
	}
}

func TestPolicyRawActionRulesDoNotForceOutbound(t *testing.T) {
	rule := ruleFromPolicy(Policy{
		Type: "raw",
		Name: "sniff",
		RawData: map[string]any{
			"action":   "sniff",
			"protocol": []string{"tls", "http"},
		},
		Outbound: "Auto",
		Enabled:  true,
	})
	if rule["action"] != "sniff" {
		t.Fatalf("expected raw action rule, got %#v", rule)
	}
	if _, ok := rule["outbound"]; ok {
		t.Fatalf("action rule should not force outbound, got %#v", rule)
	}

	route := ruleFromPolicy(Policy{
		Type:    "raw",
		Name:    "custom",
		RawData: map[string]any{"domain_suffix": []string{"example.com"}},
		Enabled: true,
	})
	if route["outbound"] != "DIRECT" {
		t.Fatalf("raw route without action should keep normalized outbound fallback, got %#v", route)
	}
}

func TestSavePoliciesBatch(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Policies = []Policy{{ID: "existing", Name: "Existing", Enabled: true, Priority: 1}}
	added, err := service.SavePoliciesBatch([]Policy{
		{Name: "One", DomainSuffix: []string{"one.example"}, Outbound: "DIRECT"},
		{Name: "Two", DomainSuffix: []string{"two.example"}, Outbound: "REJECT"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 || len(service.data.Policies) != 3 || service.data.Policies[1].Priority != 2 || service.data.Policies[2].Priority != 3 {
		t.Fatalf("batch append failed: added=%d policies=%#v", added, service.data.Policies)
	}
	added, err = service.SavePoliciesBatch([]Policy{{Name: "Only", DomainSuffix: []string{"only.example"}, Outbound: "DIRECT"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || len(service.data.Policies) != 1 || service.data.Policies[0].Name != "Only" || service.data.Policies[0].Priority != 1 {
		t.Fatalf("batch replace failed: added=%d policies=%#v", added, service.data.Policies)
	}
}

func TestPolicyLogicalRuleConversion(t *testing.T) {
	rule := ruleFromPolicy(Policy{
		Type:     "default",
		Name:     "rule-set plus process",
		RuleSet:  []string{"geosite:openai"},
		Outbound: "Auto",
		Enabled:  true,
		LogicalRule: map[string]any{
			"type": "logical",
			"mode": "and",
			"rules": []map[string]any{
				{"rule_set": []string{"geosite:openai"}},
				{"process_name": []string{"ChatGPT"}},
			},
		},
	})
	if rule["type"] != "logical" || rule["mode"] != "and" || rule["outbound"] != "Auto" {
		t.Fatalf("expected logical wrapper, got %#v", rule)
	}
	if got := stringList(rule["rule_set"]); len(got) != 1 || got[0] != "geosite:openai" {
		t.Fatalf("expected top-level rule set, got %#v", rule["rule_set"])
	}
	rules, ok := rule["rules"].([]map[string]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected one nested logical part, got %#v", rule["rules"])
	}
	nestedRules := ruleListFromAny(rules[0]["rules"])
	if len(nestedRules) != 1 || len(stringList(nestedRules[0]["process_name"])) != 1 {
		t.Fatalf("expected rule-set-only child to be removed, got %#v", nestedRules)
	}
}

func TestPolicySingleLogicalRuleFlattens(t *testing.T) {
	rule := ruleFromPolicy(Policy{
		Type:     "default",
		Name:     "single logical",
		Outbound: "Auto",
		Enabled:  true,
		LogicalRule: map[string]any{
			"type":  "logical",
			"mode":  "or",
			"rules": []any{map[string]any{"domain_keyword": []any{"github"}}},
		},
	})
	if _, ok := rule["rules"]; ok {
		t.Fatalf("single simple logical rule should flatten, got %#v", rule)
	}
	if got := stringList(rule["domain_keyword"]); len(got) != 1 || got[0] != "github" {
		t.Fatalf("expected flattened domain keyword, got %#v", rule)
	}
	if rule["outbound"] != "Auto" {
		t.Fatalf("expected outbound to be preserved, got %#v", rule)
	}
}

func TestPolicyAdvancedRouteFieldsInConfig(t *testing.T) {
	rule := ruleFromPolicy(Policy{
		Type:                    "default",
		Name:                    "advanced matchers",
		Domain:                  []string{"example.com"},
		DomainRegex:             []string{".*\\.internal$"},
		SourceIPCIDR:            []string{"10.0.0.0/8"},
		Port:                    []string{"443", "8443"},
		PortRange:               []string{"1000:2000"},
		SourcePort:              []string{"5353"},
		SourcePortRange:         []string{"3000:4000"},
		ProcessPath:             []string{"/Applications/ChatGPT.app"},
		ProcessPathRegex:        []string{".*ChatGPT.*"},
		PackageName:             []string{"com.openai.chatgpt"},
		QueryType:               []string{"A", "AAAA"},
		Network:                 []string{"tcp"},
		NetworkType:             []string{"wifi"},
		DefaultInterfaceAddress: []string{"192.168.1.2"},
		WifiSSID:                []string{"Office"},
		WifiBSSID:               []string{"00:11:22:33:44:55"},
		NetworkIsExpensive:      true,
		NetworkIsConstrained:    true,
		IPIsPrivate:             true,
		Outbound:                "Auto",
		Enabled:                 true,
	})
	if got := stringList(rule["domain"]); len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("expected domain matcher, got %#v", rule)
	}
	if ports, ok := rule["port"].([]int); !ok || len(ports) != 2 || ports[0] != 443 {
		t.Fatalf("expected numeric ports, got %#v", rule["port"])
	}
	for _, key := range []string{"domain_regex", "source_ip_cidr", "port_range", "source_port", "source_port_range", "process_path", "process_path_regex", "package_name", "query_type", "network", "network_type", "default_interface_address", "wifi_ssid", "wifi_bssid"} {
		if len(stringList(rule[key])) == 0 {
			t.Fatalf("expected %s matcher in %#v", key, rule)
		}
	}
	for _, key := range []string{"network_is_expensive", "network_is_constrained", "ip_is_private"} {
		if rule[key] != true {
			t.Fatalf("expected %s boolean matcher in %#v", key, rule)
		}
	}
}

func TestImportSingBoxConfigPreservesAdvancedRouteFields(t *testing.T) {
	policy := configRouteRuleToPolicy(map[string]any{
		"domain":                    []any{"example.com"},
		"domain_regex":              []any{".*\\.internal$"},
		"source_ip_cidr":            []any{"10.0.0.0/8"},
		"port":                      []any{float64(443), float64(8443)},
		"port_range":                []any{"1000:2000"},
		"source_port":               []any{float64(5353)},
		"source_port_range":         []any{"3000:4000"},
		"process_path":              []any{"/Applications/ChatGPT.app"},
		"process_path_regex":        []any{".*ChatGPT.*"},
		"package_name":              []any{"com.openai.chatgpt"},
		"query_type":                []any{"A"},
		"network":                   []any{"tcp"},
		"network_type":              []any{"wifi"},
		"default_interface_address": []any{"192.168.1.2"},
		"wifi_ssid":                 []any{"Office"},
		"wifi_bssid":                []any{"00:11:22:33:44:55"},
		"network_is_expensive":      true,
		"network_is_constrained":    true,
		"ip_is_private":             true,
		"outbound":                  "Auto",
	}, 0)
	if len(policy.Domain) != 1 || len(policy.DomainRegex) != 1 || len(policy.SourceIPCIDR) != 1 || len(policy.Port) != 2 || len(policy.SourcePort) != 1 {
		t.Fatalf("expected advanced fields imported, got %#v", policy)
	}
	if len(policy.ProcessPath) != 1 || len(policy.PackageName) != 1 || len(policy.QueryType) != 1 || len(policy.NetworkType) != 1 {
		t.Fatalf("expected process/network fields imported, got %#v", policy)
	}
	if !policy.NetworkIsExpensive || !policy.NetworkIsConstrained || !policy.IPIsPrivate {
		t.Fatalf("expected boolean matchers imported, got %#v", policy)
	}
	if len(policy.LogicalRule) != 0 {
		t.Fatalf("known fields should not fall back to logical rule, got %#v", policy.LogicalRule)
	}
}

func TestImportSingBoxConfigRoutesAndRuleSets(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	content := `{
	  "route": {
	    "rule_set": [
	      {"tag": "geosite:openai", "type": "local", "format": "binary", "path": "rulesets/geosite/openai.srs"}
	    ],
	    "rules": [
	      {
	        "type": "logical",
	        "mode": "and",
	        "rule_set": ["geosite:openai"],
	        "rules": [
	          {"rule_set": ["geosite:openai"]},
	          {"process_name": ["ChatGPT"]}
	        ],
	        "outbound": "Auto"
	      },
	      {"action": "sniff", "protocol": ["tls", "http"]}
	    ]
	  }
	}`
	result, err := service.ImportSingBoxConfig(content, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Policies != 2 || result.RuleSets != 1 || !result.Replaced {
		t.Fatalf("unexpected import result: %#v", result)
	}
	if len(service.data.RuleSets) != 1 || service.data.RuleSets[0].Tag != "geosite:openai" {
		t.Fatalf("expected imported rule set, got %#v", service.data.RuleSets)
	}
	if len(service.data.Policies) != 2 {
		t.Fatalf("expected imported policies, got %#v", service.data.Policies)
	}
	logical := service.data.Policies[0]
	if logical.Outbound != "Auto" || len(logical.RuleSet) != 1 || logical.RuleSet[0] != "geosite:openai" {
		t.Fatalf("expected logical policy with rule set, got %#v", logical)
	}
	nested := ruleListFromAny(logical.LogicalRule["rules"])
	if len(nested) != 1 || len(stringList(nested[0]["process_name"])) != 1 {
		t.Fatalf("expected rule-set-only child to be removed on import, got %#v", logical.LogicalRule)
	}
	raw := service.data.Policies[1]
	if raw.Type != "raw" || raw.RawData["action"] != "sniff" || raw.Outbound != "DIRECT" {
		t.Fatalf("expected action rule as raw policy, got %#v", raw)
	}
}

func TestImportClashConfigRules(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	content := `
mode: rule
mixed-port: 7899
allow-lan: true
bind-address: 0.0.0.0
external-controller: 127.0.0.1:9099
secret: imported-secret
log-level: debug
external-ui: ui
external-ui-url: https://example.com/ui.zip
external-ui-download-detour: DIRECT
default-mode: rule
unified-delay: true
tcp-concurrent: true
experimental:
  ignore-resolve-fail: true
script:
  code: |
    function main(ctx) { return "DIRECT"; }
  shortcuts:
    private: geoip:private
hosts:
  router.lan: 192.168.1.1
  multi.lan:
    - 192.168.1.2
    - 192.168.1.3
dns:
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - +.lan
    - geosite:private
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
  nameserver:
    - https://dns.alidns.com/dns-query
  fallback:
    - tls://1.1.1.1
  default-nameserver:
    - 223.5.5.5
  nameserver-policy:
    geosite:cn: https://dns.alidns.com/dns-query
    +.example.com: https://8.8.8.8/dns-query
sniffer:
  enable: true
  override-destination: true
tun:
  enable: true
  stack: gvisor
  device: utun8
  inet4-address:
    - 198.18.0.1/30
  inet6-address:
    - fdfe:dcba:9876::1/126
  auto-route: false
  strict-route: false
  auto-detect-interface: false
  dns-hijack:
    - any:53
  route-exclude-address:
    - 192.168.0.0/16
  mtu: 9000
rules:
  - DOMAIN,example.com,Proxy
  - DOMAIN-SUFFIX,+.google.com,Proxy
  - DOMAIN-KEYWORD,openai,Proxy
  - DOMAIN-REGEX,.*\.internal$,DIRECT
  - GEOSITE,youtube,Proxy
  - GEOIP,private,DIRECT
  - IP-CIDR,8.8.8.0/24,Proxy
  - SRC-IP-CIDR,10.0.0.0/8,DIRECT
  - SRC-PORT,5353,DIRECT
  - DST-PORT,443,Proxy
  - PORT-RANGE,1000:2000,Proxy
  - PROCESS-NAME,ChatGPT,Proxy
  - PROCESS-PATH,/Applications/ChatGPT.app,Proxy
  - PROCESS-PATH-REGEX,.*ChatGPT.*,Proxy
  - PACKAGE-NAME,com.openai.chatgpt,Proxy
  - NETWORK,tcp/udp,Proxy
  - RULE-SET,custom-rules,Proxy
  - MATCH,DIRECT
`
	result, err := service.ImportClashConfig(content, true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Replaced || result.Policies != 17 || result.RuleSets != 2 {
		t.Fatalf("unexpected import result: %#v", result)
	}
	if service.data.Settings.FinalOutbound != "DIRECT" {
		t.Fatalf("expected MATCH final outbound, got %q", service.data.Settings.FinalOutbound)
	}
	if service.data.Settings.MixedPort != 7899 || service.data.Settings.MixedListen != "0.0.0.0" || service.data.Settings.APIPort != 9099 || service.data.Settings.APISecret != "imported-secret" || service.data.Settings.LogLevel != "debug" || service.data.Settings.DNSListen != "https://dns.alidns.com/dns-query" {
		t.Fatalf("expected Clash base settings imported, got %#v", service.data.Settings)
	}
	if len(service.data.Settings.Hosts["router.lan"]) != 1 || len(service.data.Settings.Hosts["multi.lan"]) != 2 {
		t.Fatalf("expected Clash hosts imported, got %#v", service.data.Settings.Hosts)
	}
	if service.data.Settings.Experimental["unified_delay"] != true || service.data.Settings.Experimental["tcp_concurrent"] != true || service.data.Settings.Experimental["ignore-resolve-fail"] != true {
		t.Fatalf("expected Clash experimental settings imported, got %#v", service.data.Settings.Experimental)
	}
	unsupported := service.data.Settings.Experimental["sandfox_unsupported"].(map[string]any)
	if _, ok := unsupported["clash_script"]; !ok {
		t.Fatalf("expected Clash script preserved as unsupported metadata, got %#v", unsupported)
	}
	clashAPI := service.data.Settings.Experimental["clash_api"].(map[string]any)
	if clashAPI["external_ui"] != "ui" || clashAPI["external_ui_download_url"] != "https://example.com/ui.zip" || clashAPI["external_ui_download_detour"] != "DIRECT" || clashAPI["default_mode"] != "rule" {
		t.Fatalf("expected Clash API UI settings imported, got %#v", clashAPI)
	}
	if !service.data.Settings.DNSFakeIPEnabled || service.data.Settings.DNSFakeIPRange != "198.18.0.1/16" || len(service.data.Settings.DNSFakeIPFilter) != 2 || service.data.Settings.DNSStrategy != "prefer_ipv4" {
		t.Fatalf("expected Clash fake-ip DNS settings imported, got %#v", service.data.Settings)
	}
	if len(service.data.Settings.DNSFallbackFilter) == 0 || service.data.Settings.DNSFallbackFilter["geoip-code"] != "CN" {
		t.Fatalf("expected Clash DNS fallback filter preserved, got %#v", service.data.Settings.DNSFallbackFilter)
	}
	if len(service.data.DNSServers) != 4 {
		t.Fatalf("expected Clash DNS servers imported, got %#v", service.data.DNSServers)
	}
	preview, err := service.PreviewConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(preview.Warnings, "\n"), "Clash script rules are preserved") {
		t.Fatalf("expected Clash script warning, got %#v", preview.Warnings)
	}
	if strings.Contains(preview.Content, "sandfox_unsupported") || strings.Contains(preview.Content, "function main") {
		t.Fatalf("unsupported Clash script metadata should not be emitted to sing-box config: %s", preview.Content)
	}
	dnsServerTags := map[string]bool{}
	for _, server := range service.data.DNSServers {
		dnsServerTags[server.Tag] = true
	}
	for _, tag := range []string{"nameserver-1", "fallback-1", "default-nameserver-1", "policy-nameserver-4"} {
		if !dnsServerTags[tag] {
			t.Fatalf("expected DNS server tag %s, got %#v", tag, service.data.DNSServers)
		}
	}
	if len(service.data.DNSPolicies) != 2 {
		t.Fatalf("expected Clash DNS policies imported, got %#v", service.data.DNSPolicies)
	}
	if !service.data.Settings.SniffEnabled || !service.data.Settings.SniffOverrideDestination {
		t.Fatalf("expected Clash sniffer settings imported, got %#v", service.data.Settings)
	}
	if !service.data.Settings.TUNEnabled || service.data.Settings.TUNStack != "gvisor" || service.data.Settings.TUNInterfaceName != "utun8" || service.data.Settings.TUNMTU != 9000 {
		t.Fatalf("expected Clash tun settings imported, got %#v", service.data.Settings)
	}
	if boolValue(service.data.Settings.TUNAutoRoute, true) || boolValue(service.data.Settings.TUNStrictRoute, true) || boolValue(service.data.Settings.TUNAutoDetectInterface, true) {
		t.Fatalf("expected Clash tun booleans imported as false, got %#v", service.data.Settings)
	}
	if len(service.data.Settings.TUNAddress) != 2 || service.data.Settings.TUNAddress[0] != "198.18.0.1/30" || len(service.data.Settings.TUNDNSHijack) != 1 || len(service.data.Settings.TUNRouteExcludeAddress) != 1 {
		t.Fatalf("expected Clash tun lists imported, got %#v", service.data.Settings)
	}
	ruleSetTags := map[string]bool{}
	for _, ruleSet := range service.data.RuleSets {
		ruleSetTags[ruleSet.Tag] = true
	}
	if !ruleSetTags["geosite:youtube"] || !ruleSetTags["geosite:cn"] {
		t.Fatalf("expected route and DNS geosite rule sets, got %#v", service.data.RuleSets)
	}
	rules := make([]map[string]any, 0, len(service.data.Policies))
	for _, policy := range service.data.Policies {
		rules = append(rules, ruleFromPolicy(policy))
	}
	if len(stringList(rules[0]["domain"])) != 1 || rules[1]["domain_suffix"].([]string)[0] != ".google.com" || len(stringList(rules[2]["domain_keyword"])) != 1 || len(stringList(rules[3]["domain_regex"])) != 1 {
		t.Fatalf("expected domain clash rules, got %#v", rules[:4])
	}
	if got := stringList(rules[4]["rule_set"]); len(got) != 1 || got[0] != "geosite:youtube" {
		t.Fatalf("expected geosite rule set route, got %#v", rules[4])
	}
	if rules[5]["ip_is_private"] != true || len(stringList(rules[6]["ip_cidr"])) != 1 || len(stringList(rules[7]["source_ip_cidr"])) != 1 {
		t.Fatalf("expected ip clash rules, got %#v", rules[5:8])
	}
	if rules[8]["source_port"].([]int)[0] != 5353 || rules[9]["port"].([]int)[0] != 443 || len(stringList(rules[10]["port_range"])) != 1 {
		t.Fatalf("expected port clash rules, got %#v", rules[8:11])
	}
	if len(stringList(rules[11]["process_name"])) != 1 || len(stringList(rules[12]["process_path"])) != 1 || len(stringList(rules[13]["process_path_regex"])) != 1 || len(stringList(rules[14]["package_name"])) != 1 || len(stringList(rules[15]["network"])) != 2 {
		t.Fatalf("expected process/package/network clash rules, got %#v", rules[11:16])
	}
	if got := stringList(rules[16]["rule_set"]); len(got) != 1 || got[0] != "custom-rules" {
		t.Fatalf("expected custom rule-set route, got %#v", rules[16])
	}
}

func TestImportClashConfigUsesPortFallbacks(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	content := `
port: 7891
socks-port: 7892
rules:
  - DOMAIN,example.com,DIRECT
`
	if _, err := service.ImportClashConfig(content, true); err != nil {
		t.Fatal(err)
	}
	if service.data.Settings.MixedPort != 7891 {
		t.Fatalf("expected http port fallback imported as mixed port, got %#v", service.data.Settings)
	}
	content = `
socks-port: 7892
rules:
  - DOMAIN,example.org,DIRECT
`
	if _, err := service.ImportClashConfig(content, true); err != nil {
		t.Fatal(err)
	}
	if service.data.Settings.MixedPort != 7892 {
		t.Fatalf("expected socks port fallback imported as mixed port, got %#v", service.data.Settings)
	}
}

func TestSaveProfileAndAddNode(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{
		{ID: "profile-1", Name: "Old", URL: "https://old.example/sub", Selected: true, UpdateInterval: 24},
	}
	updated, err := service.SaveProfile(Profile{ID: "profile-1", Name: "New", URL: "https://new.example/sub", Selected: true, UpdateInterval: 12, Filter: "HK|US", TestURL: "http://test.local/204"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "New" || updated.URL != "https://new.example/sub" || updated.UpdateInterval != 12 || updated.Filter != "HK|US" || updated.TestURL != "http://test.local/204" {
		t.Fatalf("profile settings not updated: %#v", updated)
	}
	node, err := service.AddNodeToProfile("profile-1", ProxyNode{
		Name:   "manual-vless",
		Type:   "vless",
		Server: "node.example.com",
		Port:   443,
		Raw:    map[string]any{"uuid": "00000000-0000-0000-0000-000000000005"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.Raw["type"] != "vless" || node.Raw["server"] != "node.example.com" {
		t.Fatalf("node raw fields were not normalized: %#v", node)
	}
	if service.data.Profiles[0].NodeCount != 1 || len(service.data.Profiles[0].Nodes) != 1 {
		t.Fatalf("node not added to profile: %#v", service.data.Profiles[0])
	}
}

func TestReorderCollectionsByID(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{{ID: "p1", Name: "one"}, {ID: "p2", Name: "two"}, {ID: "p3", Name: "three"}}
	service.data.Policies = []Policy{{ID: "r1", Name: "one"}, {ID: "r2", Name: "two"}, {ID: "r3", Name: "three"}}
	service.data.DNSPolicies = []DNSPolicy{{ID: "d1", Server: "a"}, {ID: "d2", Server: "b"}, {ID: "d3", Server: "c"}}
	service.data.DNSServers = []DNSServer{{ID: "s1", Tag: "a"}, {ID: "s2", Tag: "b"}, {ID: "s3", Tag: "c"}}
	service.data.RuleSets = []RuleSet{{ID: "rs1", Tag: "a"}, {ID: "rs2", Tag: "b"}, {ID: "rs3", Tag: "c"}}
	if err := service.ReorderProfiles([]string{"p3", "p1"}); err != nil {
		t.Fatal(err)
	}
	if err := service.ReorderPolicies([]string{"r3", "r1"}); err != nil {
		t.Fatal(err)
	}
	if err := service.ReorderDNSPolicies([]string{"d3", "d1"}); err != nil {
		t.Fatal(err)
	}
	if err := service.ReorderDNSServers([]string{"s3", "s1"}); err != nil {
		t.Fatal(err)
	}
	if err := service.ReorderRuleSets([]string{"rs3", "rs1"}); err != nil {
		t.Fatal(err)
	}
	if service.data.Profiles[0].ID != "p3" || service.data.Profiles[1].ID != "p1" || service.data.Profiles[2].ID != "p2" {
		t.Fatalf("profiles not reordered: %#v", service.data.Profiles)
	}
	if service.data.Policies[0].ID != "r3" || service.data.Policies[0].Priority != 1 || service.data.Policies[2].ID != "r2" || service.data.Policies[2].Priority != 3 {
		t.Fatalf("policies not reordered with priorities: %#v", service.data.Policies)
	}
	if service.data.DNSPolicies[0].ID != "d3" || service.data.DNSPolicies[2].ID != "d2" {
		t.Fatalf("dns policies not reordered: %#v", service.data.DNSPolicies)
	}
	if service.data.DNSServers[0].ID != "s3" || service.data.DNSServers[2].ID != "s2" {
		t.Fatalf("dns servers not reordered: %#v", service.data.DNSServers)
	}
	if service.data.RuleSets[0].ID != "rs3" || service.data.RuleSets[2].ID != "rs2" {
		t.Fatalf("rule sets not reordered: %#v", service.data.RuleSets)
	}
}

func TestBuildInfoAndExternalURLValidation(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	info := service.GetBuildInfo()
	if info.AppVersion == "" || info.BuildNumber == "" || info.CommitSHA == "" {
		t.Fatalf("expected build info defaults, got %#v", info)
	}
	if err := service.OpenExternalURL(""); err == nil {
		t.Fatal("expected empty url error")
	}
	if err := service.OpenExternalURL("example.com"); err == nil {
		t.Fatal("expected relative url error")
	}
	if err := service.OpenExternalURL("javascript:alert(1)"); err == nil {
		t.Fatal("expected unsupported scheme error")
	}
}

func TestSaveProfileReappliesFilterFromContent(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	content := `
proxies:
  - name: HK One
    type: ss
    server: hk.example.com
    port: 443
  - name: US One
    type: ss
    server: us.example.com
    port: 443
`
	result := parseProfileContent(content)
	service.data.Profiles = []Profile{
		{ID: "profile-1", Name: "Sub", Selected: true, Filter: "HK", Content: content, Nodes: result.Nodes[:1], NodeCount: 1},
	}
	updated, err := service.SaveProfile(Profile{ID: "profile-1", Name: "Sub", Selected: true, UpdateInterval: 24, Filter: ""})
	if err != nil {
		t.Fatal(err)
	}
	if updated.NodeCount != 2 || len(updated.Nodes) != 2 {
		t.Fatalf("expected relaxed filter to restore content nodes, got %#v", updated.Nodes)
	}
	updated, err = service.SaveProfile(Profile{ID: "profile-1", Name: "Sub", Selected: true, UpdateInterval: 24, Filter: "US"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.NodeCount != 1 || updated.Nodes[0].Name != "US One" {
		t.Fatalf("expected tightened filter to keep US node, got %#v", updated.Nodes)
	}
}

func TestImportClashConfigRuleProviders(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	content := `
rule-providers:
  custom-rules:
    type: http
    behavior: classical
    format: yaml
    url: https://example.com/custom.yaml
    path: ./rules/custom.yaml
    proxy: Auto
  local-direct:
    type: file
    behavior: domain
    path: ./rules/direct.yaml
rules:
  - RULE-SET,custom-rules,Proxy
  - RULE-SET,local-direct,DIRECT
  - GEOSITE,youtube,Proxy
`
	result, err := service.ImportClashConfig(content, true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Replaced || result.Policies != 3 || result.RuleSets != 3 {
		t.Fatalf("unexpected import result: %#v", result)
	}
	byTag := map[string]RuleSet{}
	for _, ruleSet := range service.data.RuleSets {
		byTag[ruleSet.Tag] = ruleSet
	}
	custom := byTag["custom-rules"]
	if custom.Type != "remote" || custom.Format != "source" || custom.Behavior != "classical" || custom.URL != "https://example.com/custom.yaml" || custom.DownloadDetour != "Auto" {
		t.Fatalf("custom provider not converted: %#v", custom)
	}
	local := byTag["local-direct"]
	if local.Type != "local" || local.Path != "./rules/direct.yaml" || local.Format != "source" || local.Behavior != "domain" {
		t.Fatalf("local provider not converted: %#v", local)
	}
	if byTag["geosite:youtube"].Type != "remote" {
		t.Fatalf("builtin geosite rule set missing: %#v", byTag)
	}
}

func TestClashRuleProviderClassicalExtendedRules(t *testing.T) {
	cases := []struct {
		ruleType string
		value    string
		key      string
		expected string
	}{
		{"GEOSITE", "openai", "rule_set", "geosite:openai"},
		{"GEOIP", "telegram", "rule_set", "geoip:telegram"},
		{"RULE-SET", "custom", "rule_set", "custom"},
		{"PROCESS-PATH-REGEX", ".*ChatGPT.*", "process_path_regex", ".*ChatGPT.*"},
		{"PACKAGE-NAME", "com.openai.chatgpt", "package_name", "com.openai.chatgpt"},
	}
	for _, tc := range cases {
		rule := clashProviderClassicalRuleToSourceRule(tc.ruleType, tc.value)
		values := stringList(rule[tc.key])
		if len(values) != 1 || values[0] != tc.expected {
			t.Fatalf("expected %s to map to %s=%s, got %#v", tc.ruleType, tc.key, tc.expected, rule)
		}
	}
	private := clashProviderClassicalRuleToSourceRule("GEOIP", "private")
	if private["ip_is_private"] != true {
		t.Fatalf("expected GEOIP private to map to ip_is_private, got %#v", private)
	}
}

func TestRefreshProfileAppliesFilterAndRecordsErrors(t *testing.T) {
	content := `
proxies:
  - name: HK node
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
  - name: US node
    type: ss
    server: us.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=10; download=20; total=100; expire=")
		_, _ = w.Write([]byte(content))
	}))
	defer server.Close()
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{{ID: "profile-1", Name: "Remote", URL: server.URL, Filter: "HK", Selected: true, UpdateInterval: 24}}
	if err := service.RefreshProfile("profile-1"); err != nil {
		t.Fatal(err)
	}
	if service.data.Profiles[0].LastError != "" || service.data.Profiles[0].NodeCount != 1 || service.data.Profiles[0].Nodes[0].Name != "HK node" {
		t.Fatalf("profile filter not applied: %#v", service.data.Profiles[0])
	}
	if userinfo := service.data.Profiles[0].SubscriptionUserinfo; userinfo == nil || userinfo.Upload != 10 || userinfo.Download != 20 || userinfo.Total != 100 || userinfo.Expire != 0 {
		t.Fatalf("subscription userinfo not refreshed: %#v", userinfo)
	}
	service.data.Profiles[0].Filter = "["
	if err := service.RefreshProfile("profile-1"); err == nil {
		t.Fatal("expected invalid filter error")
	}
	if service.data.Profiles[0].LastError == "" {
		t.Fatalf("refresh error not recorded: %#v", service.data.Profiles[0])
	}
	schedule := service.GetRefreshSchedule()
	foundError := false
	for _, item := range schedule {
		if item.Kind == "profile" && item.ID == "profile-1" && item.LastError != "" {
			foundError = true
		}
	}
	if !foundError {
		t.Fatalf("profile last error missing from schedule: %#v", schedule)
	}
}

func TestUpdateDeleteAndMoveProfileNode(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{
		{
			ID: "profile-1", Name: "Profile", Selected: true, UpdateInterval: 24,
			Nodes: []ProxyNode{
				{Name: "a", Type: "vless", Server: "a.example.com", Port: 443, Raw: map[string]any{"uuid": "a"}},
				{Name: "b", Type: "trojan", Server: "b.example.com", Port: 443, Raw: map[string]any{"password": "b"}},
			},
			NodeCount: 2,
		},
	}
	if _, err := service.UpdateProfileNode("profile-1", 0, ProxyNode{Name: "a2", Type: "vmess", Server: "a2.example.com", Port: 8443, Raw: map[string]any{"uuid": "a2"}}); err != nil {
		t.Fatal(err)
	}
	if service.data.Profiles[0].Nodes[0].Name != "a2" || service.data.Profiles[0].Nodes[0].Raw["type"] != "vmess" {
		t.Fatalf("node not updated: %#v", service.data.Profiles[0].Nodes[0])
	}
	if err := service.MoveProfileNode("profile-1", 1, -1); err != nil {
		t.Fatal(err)
	}
	if service.data.Profiles[0].Nodes[0].Name != "b" {
		t.Fatalf("node not moved: %#v", service.data.Profiles[0].Nodes)
	}
	if err := service.DeleteProfileNode("profile-1", 1); err != nil {
		t.Fatal(err)
	}
	if service.data.Profiles[0].NodeCount != 1 || len(service.data.Profiles[0].Nodes) != 1 {
		t.Fatalf("node not deleted: %#v", service.data.Profiles[0])
	}
}

func TestAddUpdateDeleteAndMoveProfileGroup(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{
		{
			ID: "profile-1", Name: "Profile", Selected: true, UpdateInterval: 24,
			Nodes: []ProxyNode{
				{Name: "a", Type: "vless", Server: "a.example.com", Port: 443, Raw: map[string]any{"uuid": "a"}},
				{Name: "b", Type: "trojan", Server: "b.example.com", Port: 443, Raw: map[string]any{"password": "b"}},
			},
			NodeCount: 2,
		},
	}
	group, err := service.AddProfileGroup("profile-1", ProxyGroupConfig{Name: "Auto", Type: "url-test", Proxies: []string{"a", "b", "a"}, Interval: 900})
	if err != nil {
		t.Fatal(err)
	}
	if group.Type != "url-test" || len(group.Proxies) != 2 {
		t.Fatalf("group not normalized: %#v", group)
	}
	if _, err := service.AddProfileGroup("", ProxyGroupConfig{Name: "Proxy", Type: "select", Proxies: []string{"Auto", "DIRECT"}}); err != nil {
		t.Fatal(err)
	}
	if err := service.MoveProfileGroup("profile-1", 1, -1); err != nil {
		t.Fatal(err)
	}
	if service.data.Profiles[0].ProxyGroups[0].Name != "Proxy" {
		t.Fatalf("group not moved: %#v", service.data.Profiles[0].ProxyGroups)
	}
	if _, err := service.UpdateProfileGroup("profile-1", 1, ProxyGroupConfig{Name: "Fast", Type: "fallback", Proxies: []string{"b"}, Tolerance: 25}); err != nil {
		t.Fatal(err)
	}
	if service.data.Profiles[0].ProxyGroups[1].Name != "Fast" || service.data.Profiles[0].ProxyGroups[1].Type != "fallback" {
		t.Fatalf("group not updated: %#v", service.data.Profiles[0].ProxyGroups)
	}
	if err := service.DeleteProfileGroup("profile-1", 0); err != nil {
		t.Fatal(err)
	}
	if len(service.data.Profiles[0].ProxyGroups) != 1 || service.data.Profiles[0].ProxyGroups[0].Name != "Fast" {
		t.Fatalf("group not deleted: %#v", service.data.Profiles[0].ProxyGroups)
	}
}

func TestProfileCustomGroupCompatibilityAliases(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{{
		ID: "profile-1", Name: "Profile", Selected: true,
		Nodes: []ProxyNode{{Name: "a", Type: "vless"}, {Name: "b", Type: "trojan"}},
		ProxyGroups: []ProxyGroupConfig{
			{Name: "Subscription", Type: "select", Proxies: []string{"a", "b"}},
		},
	}}
	if err := service.SetProfileCustomGroups("profile-1", []CustomProxyGroup{
		{Name: "B", Type: "selector", Outbounds: []string{"b"}, Order: 2},
		{Name: "A", Type: "urltest", Outbounds: []string{"a"}, Order: 1},
	}); err != nil {
		t.Fatal(err)
	}
	groups, err := service.GetProfileCustomGroups("profile-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].Name != "A" || groups[1].Name != "B" {
		t.Fatalf("expected ordered custom groups, got %#v", groups)
	}
	if err := service.AddProfileCustomGroup("profile-1", CustomProxyGroup{Name: "C", Type: "selector", Outbounds: []string{"A"}}); err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateProfileCustomGroup("profile-1", "C", CustomProxyGroup{Type: "urltest", Outbounds: []string{"b"}}); err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateProfileCustomGroupsOrder("profile-1", []CustomProxyGroupOrder{{Name: "C", Order: 0}, {Name: "A", Order: 1}, {Name: "B", Order: 2}}); err != nil {
		t.Fatal(err)
	}
	groups, err = service.GetProfileCustomGroups("profile-1")
	if err != nil || groups[0].Name != "C" || groups[0].Type != "urltest" {
		t.Fatalf("expected updated/reordered custom groups, got %#v err %v", groups, err)
	}
	nodes, err := service.GetProfileNodes("profile-1")
	if err != nil || len(nodes) != 2 {
		t.Fatalf("expected profile nodes, got %#v err %v", nodes, err)
	}
	if err := service.DeleteProfileCustomGroup("profile-1", "C"); err != nil {
		t.Fatal(err)
	}
	if err := service.ClearProfileCustomGroups("profile-1"); err != nil {
		t.Fatal(err)
	}
	if len(service.data.Profiles[0].CustomGroups) != 0 {
		t.Fatalf("expected custom groups cleared, got %#v", service.data.Profiles[0].CustomGroups)
	}
	if len(service.data.Profiles[0].ProxyGroups) != 1 || service.data.Profiles[0].ProxyGroups[0].Name != "Subscription" {
		t.Fatalf("expected subscription groups preserved, got %#v", service.data.Profiles[0].ProxyGroups)
	}
}

func TestGetAvailableOutbounds(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{
		{
			ID: "profile-1", Name: "Selected", Selected: true,
			Nodes: []ProxyNode{
				{Name: "node-a", Type: "vless", Server: "a.example.com", Port: 443},
				{Name: "node-b", Type: "ss", Server: "b.example.com", Port: 8388},
			},
			ProxyGroups: []ProxyGroupConfig{
				{Name: "Auto", Type: "url-test", Proxies: []string{"node-a", "node-b"}},
				{Name: "Balance", Type: "load-balance", Proxies: []string{"node-a", "node-b"}},
			},
		},
		{
			ID: "profile-2", Name: "Other",
			Nodes: []ProxyNode{{Name: "node-c", Type: "trojan", Server: "c.example.com", Port: 443}},
		},
	}
	outbounds := service.GetAvailableOutbounds()
	tags := make([]string, 0, len(outbounds))
	kinds := map[string]string{}
	for _, outbound := range outbounds {
		tags = append(tags, outbound.Tag)
		kinds[outbound.Tag] = outbound.Kind
	}
	expected := []string{"DIRECT", "REJECT", "node-a", "node-b", "Auto", "Balance"}
	if strings.Join(tags, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected available outbounds: %#v", outbounds)
	}
	if kinds["Auto"] != "group" || kinds["Balance"] != "group" || kinds["node-a"] != "node" || kinds["DIRECT"] != "builtin" {
		t.Fatalf("unexpected outbound kinds: %#v", outbounds)
	}
}

func TestClearLogs(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Logs = []LogEntry{{ID: "log-1", Level: "info", Source: "test", Message: "hello", Time: time.Now()}}
	if err := os.WriteFile(service.coreLogPath(), []byte("core log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := service.ClearLogs(); err != nil {
		t.Fatal(err)
	}
	if len(service.data.Logs) != 0 {
		t.Fatalf("logs not cleared: %#v", service.data.Logs)
	}
	info, err := os.Stat(service.coreLogPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("core log not truncated: %d", info.Size())
	}
}

func TestCoreLogReadAndFiles(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	if err := os.WriteFile(service.coreLogPath(), []byte("first line\nerror line\nlast line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := service.GetLogFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != "sing-box.log" {
		t.Fatalf("expected core log file listed, got %#v", files)
	}
	result, err := service.ReadCoreLog(LogReadOptions{FromLine: 1, MaxResults: 5})
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalLines != 3 || len(result.Lines) != 2 || result.Lines[0] != "error line" {
		t.Fatalf("unexpected core log read: %#v", result)
	}
	result, err = service.ReadCoreLog(LogReadOptions{Search: "ERROR", MaxResults: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsSearch || len(result.Lines) != 1 || result.Lines[0] != "error line" {
		t.Fatalf("unexpected core log search: %#v", result)
	}
	if err := service.ClearCoreLog(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(service.coreLogPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("core log not cleared: %d", info.Size())
	}
}

func TestProfileNodeDelayAndSort(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.APIPort = 1
	service.data.Profiles = []Profile{
		{
			ID: "profile-1", Name: "Profile", Selected: true, UpdateInterval: 24,
			Nodes: []ProxyNode{
				{Name: "slow-node", Type: "vless", Server: "slow.example.com", Port: 443, Latency: 200, Raw: map[string]any{"uuid": "slow"}},
				{Name: "fast-node", Type: "vless", Server: "fast.example.com", Port: 443, Latency: 20, Raw: map[string]any{"uuid": "fast"}},
			},
			NodeCount: 2,
		},
	}
	results, err := service.TestProfileNodes("profile-1", "http://example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Delay <= 0 || service.data.Profiles[0].Nodes[0].Latency <= 0 {
		t.Fatalf("delay test did not update nodes: %#v %#v", results, service.data.Profiles[0].Nodes)
	}
	service.data.Profiles[0].Nodes[0].Latency = 200
	service.data.Profiles[0].Nodes[1].Latency = 20
	if err := service.SortProfileNodesByLatency("profile-1"); err != nil {
		t.Fatal(err)
	}
	if service.data.Profiles[0].Nodes[0].Name != "fast-node" {
		t.Fatalf("nodes not sorted by latency: %#v", service.data.Profiles[0].Nodes)
	}
}

func TestPreviewConfigChangedState(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	first, err := service.PreviewConfig()
	if err != nil {
		t.Fatal(err)
	}
	if first.Path == "" || first.Content == "" || !first.Changed {
		t.Fatalf("expected initial preview to be changed, got %#v", first)
	}
	if _, err := service.GenerateConfig(); err != nil {
		t.Fatal(err)
	}
	second, err := service.PreviewConfig()
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed {
		t.Fatalf("expected preview to match generated config, got %#v", second)
	}
}

func TestActiveConfigRulesAndSelectedProfile(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{{
		ID:        "profile-1",
		Name:      "Selected",
		Selected:  true,
		NodeCount: 1,
		Nodes:     []ProxyNode{{Name: "node-a", Type: "vless", Server: "a.example.com", Port: 443, Raw: map[string]any{"uuid": "00000000-0000-0000-0000-000000000001"}}},
	}}
	service.data.Policies = []Policy{{ID: "policy-1", Name: "Domain", DomainSuffix: []string{"example.com"}, Outbound: "node-a", Enabled: true}}
	config := service.GetActiveConfig()
	if _, ok := config["route"].(map[string]any); !ok {
		t.Fatalf("active config missing route: %#v", config)
	}
	rules := service.GetCurrentConfigRules()
	if len(rules) != 1 || rules[0]["outbound"] != "node-a" {
		t.Fatalf("current config rules not returned: %#v", rules)
	}
	selected := service.GetSelectedProfile()
	if !selected.Found || selected.Profile.ID != "profile-1" || selected.Config["route"] == nil {
		t.Fatalf("selected profile state not returned: %#v", selected)
	}
}

func TestPreviewConfigDiff(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	if err := os.WriteFile(service.dataDir+"/config.json", []byte("{\n  \"old\": true\n}"), 0o644); err != nil {
		t.Fatal(err)
	}
	diff, err := service.PreviewConfigDiff()
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Changed || !strings.Contains(diff.Content, "--- current config.json") || !strings.Contains(diff.Content, "-  \"old\": true") {
		t.Fatalf("unexpected diff: %#v", diff)
	}
}

func TestRefreshScheduleStatus(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	now := time.Now()
	service.data = defaultData()
	service.data.Profiles = []Profile{
		{ID: "remote-due", Name: "Remote Due", URL: "https://example.com/sub", UpdateInterval: 12, LastUpdated: now.Add(-13 * time.Hour)},
		{ID: "local", Name: "Local", URL: "inline", UpdateInterval: 12, LastUpdated: now.Add(-13 * time.Hour)},
		{
			ID: "provider-profile", Name: "Provider Profile", URL: "inline",
			ProxyProviders: []ProxyProviderConfig{{
				Name:                "remote",
				Type:                "http",
				URL:                 "https://example.com/provider.yaml",
				Interval:            3600,
				LastUpdated:         now.Add(-30 * time.Minute),
				HealthCheckEnable:   true,
				HealthCheckInterval: 60,
				LastChecked:         now.Add(-2 * time.Minute),
			}},
		},
	}
	service.data.RuleSets = []RuleSet{
		{ID: "fresh", Tag: "fresh", Enabled: true, LastUpdated: now.Add(-1 * time.Hour)},
		{ID: "due", Tag: "due", Enabled: true, LastUpdated: now.Add(-25 * time.Hour), LastError: "previous failure"},
	}
	items := service.GetRefreshSchedule()
	if len(items) != 5 {
		t.Fatalf("expected remote profile, provider, provider health, and two rule sets, got %#v", items)
	}
	if !items[0].Due {
		t.Fatalf("due items should be sorted first: %#v", items)
	}
	foundError := false
	foundProvider := false
	foundProviderHealth := false
	for _, item := range items {
		if item.Name == "due" && item.LastError == "previous failure" {
			foundError = true
		}
		if item.Kind == "proxy-provider" && item.ProfileID == "provider-profile" && item.ProviderName == "remote" && item.IntervalSeconds == 3600 && !item.Due {
			foundProvider = true
		}
		if item.Kind == "proxy-provider-health" && item.ProfileID == "provider-profile" && item.ProviderName == "remote" && item.IntervalSeconds == 60 && item.Due {
			foundProviderHealth = true
		}
		if item.Name == "Local" {
			t.Fatalf("local profile should not be scheduled: %#v", items)
		}
	}
	if !foundError {
		t.Fatalf("rule set last error missing from schedule: %#v", items)
	}
	if !foundProvider || !foundProviderHealth {
		t.Fatalf("provider refresh or health schedule missing: %#v", items)
	}
}

func TestRuleProviderGlobalUpdateIntervalSetting(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	now := time.Now()
	service.data = defaultData()
	service.data.RuleSets = []RuleSet{
		{ID: "fresh", Tag: "fresh", Enabled: true, LastUpdated: now.Add(-1 * time.Hour)},
		{ID: "due", Tag: "due", Enabled: true, LastUpdated: now.Add(-3 * time.Hour)},
	}
	if err := service.SetSetting("rule-provider-update-interval", "7200"); err != nil {
		t.Fatal(err)
	}
	items := service.GetRefreshSchedule()
	foundFresh := false
	foundDue := false
	for _, item := range items {
		if item.Kind != "ruleset" {
			continue
		}
		if item.ID == "fresh" && item.IntervalSeconds == 7200 && !item.Due {
			foundFresh = true
		}
		if item.ID == "due" && item.IntervalSeconds == 7200 && item.Due {
			foundDue = true
		}
	}
	if !foundFresh || !foundDue {
		t.Fatalf("expected rule provider global interval applied, got %#v", items)
	}
	_, ruleSetIDs, _, _ := service.scheduledTargets(false)
	if len(ruleSetIDs) != 1 || ruleSetIDs[0] != "due" {
		t.Fatalf("expected only due rule set target, got %#v", ruleSetIDs)
	}
	if err := service.SetSetting("rule-provider-update-interval", "0"); err != nil {
		t.Fatal(err)
	}
	items = service.GetRefreshSchedule()
	for _, item := range items {
		if item.Kind == "ruleset" {
			t.Fatalf("expected rule provider schedule disabled, got %#v", items)
		}
	}
}

func TestTemplateCompatibilityAPIs(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	templates := service.GetTemplates()
	if len(templates) == 0 {
		t.Fatal("expected builtin templates exposed through Rover-compatible API")
	}
	payload := service.GetTemplatePolicies(templates[0].Path)
	if len(payload.Policies) == 0 {
		t.Fatalf("expected template policies for %s", templates[0].Path)
	}
	result := service.ImportTemplateComplete(templates[0].Path)
	if !result.Success {
		t.Fatalf("expected complete import success: %#v", result)
	}
	if result.AddedCount != len(payload.Policies) {
		t.Fatalf("expected %d imported policies, got %d", len(payload.Policies), result.AddedCount)
	}
	if len(service.data.Policies) != len(payload.Policies) {
		t.Fatalf("expected policy data replaced by template, got %#v", service.data.Policies)
	}
	if service.GetTemplatePolicies("missing.json").Settings == nil {
		t.Fatal("missing template should return an empty settings map")
	}
}

func TestRoverPresetTemplatesAreImportedWithSettingsAndRawDNS(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	templates := service.GetTemplates()
	if len(templates) < 3 {
		t.Fatalf("expected Rover preset templates, got %#v", templates)
	}
	expectedPaths := map[string]bool{"templates/3.json": false, "templates/4.json": false, "templates/5.json": false}
	for _, template := range templates {
		if _, ok := expectedPaths[template.Path]; ok {
			expectedPaths[template.Path] = true
		}
	}
	for path, found := range expectedPaths {
		if !found {
			t.Fatalf("expected Rover template path %s in %#v", path, templates)
		}
	}

	payload := service.GetTemplatePolicies("templates/3.json")
	if payload.Settings["dns-unmatched-server"] != "Rover" || payload.Settings["dns-resolve-server"] != "local" || payload.Settings["dashboard-tun-mode"] != "true" {
		t.Fatalf("expected Rover template settings preserved, got %#v", payload.Settings)
	}
	if len(payload.DNSServers) != 3 || payload.DNSServers[0].Tag != "Rover" || payload.DNSServers[0].Type != "rover" || payload.DNSServers[2].Type != "raw" {
		t.Fatalf("expected Rover DNS servers mapped, got %#v", payload.DNSServers)
	}
	if len(payload.DNSPolicies) != 2 || payload.DNSPolicies[1].Type != "raw" || payload.DNSPolicies[1].RawData["server"] != "fakeip" {
		t.Fatalf("expected raw DNS policy preserved, got %#v", payload.DNSPolicies)
	}

	result := service.ImportTemplateComplete("templates/3.json")
	if !result.Success || !result.TUNSet || !result.TUNValue || !result.FinalOutboundSet || result.FinalOutbound != "Auto" || !result.DefaultDNSServerSet {
		t.Fatalf("expected Rover template import flags, got %#v", result)
	}
	if service.GetSetting("dns-unmatched-server", "") != "Rover" || service.GetSetting("dns-resolve-server", "") != "local" || service.GetSetting("dns-server-enabled", "") != "true" {
		t.Fatalf("expected Rover template settings stored, got %#v", service.GetAllSettings())
	}
	if len(service.data.Policies) != len(payload.Policies) || len(service.data.DNSServers) != 3 || len(service.data.DNSPolicies) != 2 {
		t.Fatalf("expected Rover template data imported, policies=%d dnsServers=%d dnsPolicies=%d", len(service.data.Policies), len(service.data.DNSServers), len(service.data.DNSPolicies))
	}

	config := service.buildConfigLocked()
	dns := config["dns"].(map[string]any)
	if dns["final"] != "Rover" {
		t.Fatalf("expected Rover unmatched DNS final, got %#v", dns)
	}
	servers := dns["servers"].([]map[string]any)
	foundRover := false
	foundFakeIP := false
	for _, server := range servers {
		if server["tag"] == "Rover" {
			foundRover = server["type"] == "https" && server["path"] == "/dns-query"
			headers, _ := server["headers"].(map[string]string)
			if headers["X-Upstreams"] == "" || headers["X-Proxy"] != "socks5" {
				t.Fatalf("expected Rover DNS headers, got %#v", server)
			}
		}
		if server["tag"] == "fakeip" {
			foundFakeIP = server["type"] == "fakeip" && server["inet4_range"] == "198.18.0.0/15"
		}
	}
	if !foundRover || !foundFakeIP {
		t.Fatalf("expected Rover and raw fakeip DNS servers in config, got %#v", servers)
	}
}

func TestRuntimeStatusAPIs(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	singbox := service.GetSingboxStatus()
	if !singbox.Success || singbox.Data.Running {
		t.Fatalf("expected stopped sing-box status success, got %#v", singbox)
	}
	if singbox.Data.ConfigPath == "" || singbox.Data.BinaryPath == "" {
		t.Fatalf("expected config and binary paths, got %#v", singbox.Data)
	}
	dns := service.GetDnsStatus()
	if !dns.Success || dns.Data.Address == "" {
		t.Fatalf("expected DNS status with configured address, got %#v", dns)
	}
}

func TestRoverDNSServerSettingUpdatesRuntimeStatus(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if r.Method != http.MethodPost || !bytes.Equal(body, []byte{0x01, 0x02}) {
			t.Errorf("unexpected DoH upstream request: method=%s body=%v", r.Method, body)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte{0x03, 0x04})
	}))
	defer upstream.Close()
	service.data.Settings.DNSListen = upstream.URL
	port := freeTCPPort(t)
	if err := service.SetSetting("dns-server-port", strconv.Itoa(port)); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSetting("dns-server-enabled", "true"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.SetSetting("dns-server-enabled", "false") }()
	status := service.GetDnsStatus()
	if !status.Success || !status.Data.Running || status.Data.Address != fmt.Sprintf("127.0.0.1:%d", port) || status.Data.CertPath == "" {
		t.Fatalf("expected running Rover DNS status, got %#v", status)
	}
	client := http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   2 * time.Second,
	}
	res, err := client.Post("https://"+status.Data.Address+"/dns-query", "application/dns-message", bytes.NewReader([]byte{0x01, 0x02}))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, []byte{0x03, 0x04}) {
		t.Fatalf("expected proxied DoH response, got %v", body)
	}
	nextPort := freeTCPPort(t)
	if err := service.SetSetting("dns-server-port", strconv.Itoa(nextPort)); err != nil {
		t.Fatal(err)
	}
	status = service.GetDnsStatus()
	if status.Data.Address != fmt.Sprintf("127.0.0.1:%d", nextPort) {
		t.Fatalf("expected DNS status address to follow port changes, got %#v", status)
	}
	if err := service.SetSetting("dns-server-enabled", "false"); err != nil {
		t.Fatal(err)
	}
	status = service.GetDnsStatus()
	if status.Data.Running {
		t.Fatalf("expected stopped Rover DNS status, got %#v", status)
	}
}

func TestRoverDNSServerUsesHelperWhenAvailable(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("sandfox-rs-dns-%d.sock", time.Now().UnixNano()))
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANDFOX_ROVERSERVICE_SOCKET", socketPath)
	var started bool
	var stopped bool
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/dns/start":
			started = true
			_, _ = w.Write([]byte(`{"success":true,"data":{"address":"127.0.0.1:15353","status":"running","cert_path":"/tmp/helper-cert.pem"}}`))
		case "/dns/status":
			running := "false"
			if started && !stopped {
				running = "true"
			}
			_, _ = w.Write([]byte(`{"success":true,"data":{"running":` + running + `,"address":"127.0.0.1:15353","cert_path":"/tmp/helper-cert.pem"}}`))
		case "/dns/stop":
			stopped = true
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = os.Remove(socketPath)
	})

	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	if err := service.SetSetting("dns-server-enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if !started || service.dnsServer != nil {
		t.Fatalf("expected helper DNS start without local server, started=%v server=%#v", started, service.dnsServer)
	}
	status := service.GetDnsStatus()
	if !status.Data.Running || status.Data.Address != "127.0.0.1:15353" || status.Data.CertPath != "/tmp/helper-cert.pem" {
		t.Fatalf("expected helper DNS status, got %#v", status)
	}
	if err := service.SetSetting("dns-server-enabled", "false"); err != nil {
		t.Fatal(err)
	}
	if !stopped {
		t.Fatal("expected helper DNS stop")
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestDatabaseBackupRoundTrip(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{{ID: "profile-a", Name: "Profile A"}}
	path, err := service.ExportConfigBackup()
	if err != nil {
		t.Fatal(err)
	}
	service.data.Profiles = nil
	if err := service.ImportConfigBackup(path); err != nil {
		t.Fatal(err)
	}
	if service.data.SchemaVersion != dataSchemaVersion {
		t.Fatalf("expected schema %d, got %d", dataSchemaVersion, service.data.SchemaVersion)
	}
	if len(service.data.Profiles) != 1 || service.data.Profiles[0].Name != "Profile A" {
		t.Fatalf("expected restored profile, got %#v", service.data.Profiles)
	}
	status := service.GetDatabaseStatus()
	if status.SchemaVersion != dataSchemaVersion || status.BackupDir == "" || status.Path == "" {
		t.Fatalf("unexpected database status: %#v", status)
	}
}

func TestPreferencesRoundTrip(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	if got := service.GetPreference("theme", "light"); got != "light" {
		t.Fatalf("expected default preference, got %q", got)
	}
	if err := service.SetPreference("theme", "dark"); err != nil {
		t.Fatal(err)
	}
	if got := service.GetPreference("theme", "light"); got != "dark" {
		t.Fatalf("expected saved preference, got %q", got)
	}
	if prefs := service.GetPreferences(); prefs["theme"] != "dark" {
		t.Fatalf("expected preference map, got %#v", prefs)
	}
	if err := service.DeletePreference("theme"); err != nil {
		t.Fatal(err)
	}
	if got := service.GetPreference("theme", "light"); got != "light" {
		t.Fatalf("expected deleted preference to fall back, got %q", got)
	}
}

func TestRoverSettingCompatibilityAliases(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	if got := service.GetSetting("mixed-port", "0"); got != "7890" {
		t.Fatalf("expected mixed-port setting, got %q", got)
	}
	if err := service.SetSetting("mixed-port", "7899"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSetting("allow-lan", "true"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSetting("api-url", "http://127.0.0.1:19090"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSetting("policy-final-outbound", "block_out"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSetting("tun-exclude-address", `["10.0.0.0/8","fd00::/8"]`); err != nil {
		t.Fatal(err)
	}
	settings := service.GetSettings()
	if settings.MixedPort != 7899 || !settings.AllowLAN || settings.MixedListen != "0.0.0.0" || settings.APIPort != 19090 || settings.FinalOutbound != "REJECT" {
		t.Fatalf("expected rover settings applied, got %#v", settings)
	}
	if got := strings.Join(settings.TUNRouteExcludeAddress, ","); got != "10.0.0.0/8,fd00::/8" {
		t.Fatalf("expected tun exclude list, got %#v", settings.TUNRouteExcludeAddress)
	}
	all := service.GetAllSettings()
	if all["mixed-port"] != "7899" || all["allow-lan"] != "true" || all["policy-final-outbound"] != "REJECT" {
		t.Fatalf("expected rover settings map, got %#v", all)
	}
}

func TestRoverPlatformSettingsAffectGeneratedConfig(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.FinalOutbound = "Proxy"
	service.data.Profiles = []Profile{{
		ID:       "p1",
		Name:     "Profile",
		Selected: true,
		Nodes:    []ProxyNode{{Name: "node-a", Type: "vmess", Server: "example.com", Port: 443, Raw: map[string]any{"type": "vmess", "name": "node-a", "server": "example.com", "port": 443, "uuid": "00000000-0000-0000-0000-000000000000"}}},
		ProxyGroups: []ProxyGroupConfig{{
			Name:    "Proxy",
			Type:    "select",
			Proxies: []string{"node-a"},
		}},
	}}
	if err := service.SetSetting("dns-proxy-port", "17891"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSetting("dns-server-enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSetting("dns-resolve-server", "dns_direct_out"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSetting("dns-unmatched-server", "dns_selector_out"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSetting("hosts-override", `["1.2.3.4 example.com","5.6.7.8 *.example.org"]`); err != nil {
		t.Fatal(err)
	}
	config := service.buildConfigLocked()
	inbounds := config["inbounds"].([]map[string]any)
	foundDNSProxyInbound := false
	for _, inbound := range inbounds {
		if inbound["tag"] == "dns_proxy_in" && inbound["listen_port"] == 17891 {
			foundDNSProxyInbound = true
		}
	}
	if !foundDNSProxyInbound {
		t.Fatalf("expected dns proxy inbound, got %#v", inbounds)
	}
	route := config["route"].(map[string]any)
	if route["default_domain_resolver"] != "dns_direct_out" {
		t.Fatalf("expected dns resolve server applied, got %#v", route)
	}
	dns := config["dns"].(map[string]any)
	if dns["final"] != "dns_selector_out" {
		t.Fatalf("expected unmatched DNS server applied, got %#v", dns)
	}
	servers := dns["servers"].([]map[string]any)
	foundHosts := false
	foundSelector := false
	for _, server := range servers {
		if server["tag"] == "dns_hosts" {
			foundHosts = true
		}
		if server["tag"] == "dns_selector_out" {
			foundSelector = true
		}
	}
	if !foundHosts || !foundSelector {
		t.Fatalf("expected Rover DNS support servers, got %#v", servers)
	}
	if err := service.SetSetting("dashboard-mode", "direct"); err != nil {
		t.Fatal(err)
	}
	directConfig := service.buildConfigLocked()
	directRoute := directConfig["route"].(map[string]any)
	if directRoute["final"] != "DIRECT" {
		t.Fatalf("expected direct dashboard mode route, got %#v", directRoute)
	}
}

func TestRoverProfileDetailCompatibilityAliases(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = nil
	id, err := service.AddProfile(Profile{ID: "profile-1", Name: "Old", URL: "https://old.example/sub", Selected: true, UpdateInterval: 24})
	if err != nil || id != "profile-1" {
		t.Fatalf("expected add profile alias, id %q err %v", id, err)
	}
	if err := service.UpdateProfileDetails("profile-1", "New", "https://new.example/sub", 12); err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateProfileInterval("profile-1", 6); err != nil {
		t.Fatal(err)
	}
	profile := service.GetProfiles()[0]
	if profile.Name != "New" || profile.URL != "https://new.example/sub" || profile.UpdateInterval != 6 {
		t.Fatalf("expected profile aliases to update details, got %#v", profile)
	}
	if err := service.UpdateProfilesOrder([]string{"profile-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ImportLocalProfile(); err == nil {
		t.Fatalf("expected import local profile alias to report missing file picker")
	}
}

func TestRoverProfileOverrideCompatibilityAliases(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Profiles = []Profile{{ID: "profile-1", Name: "Profile", Selected: true}}
	policyID := service.data.Policies[0].ID
	dnsPolicyID := service.data.DNSPolicies[0].ID
	dnsServerID := service.data.DNSServers[0].ID
	if err := service.SetProfilePolicy("profile-1", policyID, []string{"Auto"}); err != nil {
		t.Fatal(err)
	}
	policyOverride := service.GetProfilePolicyByPolicyId("profile-1", policyID)
	if policyOverride == nil || policyOverride.PolicyID != policyID || policyOverride.PreferredOutbound != "Auto" {
		t.Fatalf("expected rover policy override, got %#v", policyOverride)
	}
	if err := service.SetProfilePolicy("profile-1", policyID, nil); err != nil {
		t.Fatal(err)
	}
	if policyOverride = service.GetProfilePolicyByPolicyId("profile-1", policyID); policyOverride != nil {
		t.Fatalf("expected policy override cleared, got %#v", policyOverride)
	}
	if err := service.SetProfileDnsPolicy("profile-1", dnsPolicyID, "alidns"); err != nil {
		t.Fatal(err)
	}
	dnsOverride := service.GetProfileDnsPolicyByPolicyId("profile-1", dnsPolicyID)
	if dnsOverride == nil || dnsOverride.DNSPolicyID != dnsPolicyID || dnsOverride.PreferredServer != "alidns" {
		t.Fatalf("expected rover dns policy override, got %#v", dnsOverride)
	}
	if err := service.SetProfileDnsServerDetour("profile-1", dnsServerID, "DIRECT"); err != nil {
		t.Fatal(err)
	}
	if detour := service.GetProfileDnsServerDetour("profile-1", dnsServerID); detour != "DIRECT" {
		t.Fatalf("expected dns server detour, got %q", detour)
	}
	allDetours := service.GetAllProfileDnsServerDetours("profile-1")
	if len(allDetours) != 1 || allDetours[0].DNSServerID != dnsServerID || allDetours[0].PreferredDetour != "DIRECT" {
		t.Fatalf("expected all dns server detours, got %#v", allDetours)
	}
	if err := service.SetProfileDnsServerDetour("profile-1", dnsServerID, ""); err != nil {
		t.Fatal(err)
	}
	if detour := service.GetProfileDnsServerDetour("profile-1", dnsServerID); detour != "" {
		t.Fatalf("expected dns server detour cleared, got %q", detour)
	}
}

func TestRoverPolicyAndDNSCrudCompatibilityAliases(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Policies = nil
	policyA, err := service.AddPolicy(Policy{Name: "A", Domain: []string{"a.example"}, Outbound: "DIRECT"})
	if err != nil {
		t.Fatal(err)
	}
	policyB, err := service.AddPolicy(Policy{Name: "B", Domain: []string{"b.example"}, Outbound: "Auto"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.UpdatePolicy(policyA, map[string]any{"name": "A2", "outbound": "REJECT"}); err != nil {
		t.Fatal(err)
	}
	if service.GetPolicies()[0].Name != "A2" || service.GetPolicies()[0].Outbound != "REJECT" {
		t.Fatalf("expected policy updated, got %#v", service.GetPolicies())
	}
	if err := service.UpdatePoliciesOrder([]OrderItem{{ID: policyB, Order: 0}, {ID: policyA, Order: 1}}); err != nil {
		t.Fatal(err)
	}
	if service.GetPolicies()[0].ID != policyB {
		t.Fatalf("expected policies reordered, got %#v", service.GetPolicies())
	}
	if count, err := service.AddPoliciesBatch([]Policy{{Name: "C", Domain: []string{"c.example"}, Outbound: "DIRECT"}}, false); err != nil || count != 1 {
		t.Fatalf("expected policy batch added, count %d err %v", count, err)
	}
	serverID, err := service.AddDnsServer(DNSServer{Tag: "quad9", Address: "https://dns.quad9.net/dns-query"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateDnsServer(serverID, map[string]any{"strategy": "ipv4_only"}); err != nil {
		t.Fatal(err)
	}
	if service.GetDNSServers()[len(service.GetDNSServers())-1].Strategy != "ipv4_only" {
		t.Fatalf("expected dns server updated, got %#v", service.GetDNSServers())
	}
	dnsPolicyID, err := service.AddDnsPolicy(DNSPolicy{Domain: "example.com", Server: "quad9"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateDnsPolicy(dnsPolicyID, map[string]any{"strategy": "ipv4_only"}); err != nil {
		t.Fatal(err)
	}
	if service.GetDNSPolicies()[len(service.GetDNSPolicies())-1].Strategy != "ipv4_only" {
		t.Fatalf("expected dns policy updated, got %#v", service.GetDNSPolicies())
	}
	if err := service.UpdateDnsPoliciesOrder([]OrderItem{{ID: dnsPolicyID, Order: 0}}); err != nil {
		t.Fatal(err)
	}
	if service.GetDNSPolicies()[0].ID != dnsPolicyID {
		t.Fatalf("expected dns policies reordered, got %#v", service.GetDNSPolicies())
	}
	if _, err := service.ToggleDnsServerEnabled(serverID, false); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteDnsPolicy(dnsPolicyID); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteDnsServer(serverID); err != nil {
		t.Fatal(err)
	}
}

func TestLauncherStatusAliases(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	_ = service.IsServiceInstalled()
	_ = service.IsLauncherAvailable()
	_ = service.IsLauncherTaskInstalled()
	if err := service.UpdateTrayMenu(); err != nil {
		t.Fatal(err)
	}
	status := service.GetInstallationStatus()
	if status.Platform == "" {
		t.Fatalf("expected installation status platform, got %#v", status)
	}
}

func TestCoreServiceStatusUsesRoverServiceAPIVersion(t *testing.T) {
	status := applyCoreServiceRuntimeStatus(CoreServiceStatus{
		Platform: "darwin",
		Running:  true,
	}, SingBoxRuntimeStatusData{
		Running:   true,
		PID:       42,
		StartTime: 123,
	})
	if status.Version != roverServiceAPIVersion {
		t.Fatalf("expected RoverService API version %q, got %q", roverServiceAPIVersion, status.Version)
	}
	if status.NeedsUpgrade {
		t.Fatal("current API version should not need upgrade")
	}
	if !status.SocketAvailable || !status.SingboxRunning || status.SingboxPid != 42 || status.SingboxStartTime != 123 {
		t.Fatalf("runtime fields were not applied: %#v", status)
	}
}

func TestCoreServiceStatusReadsRoverServiceSocket(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("sandfox-rs-%d.sock", time.Now().UnixNano()))
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANDFOX_ROVERSERVICE_SOCKET", socketPath)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			_, _ = w.Write([]byte(`{"success":true,"data":{"version":"1.1.0","pid":99,"uptime":1,"socketPath":"` + socketPath + `","platform":"darwin"}}`))
		case "/singbox/status":
			_, _ = w.Write([]byte(`{"success":true,"data":{"running":true,"pid":100,"startTime":123,"configPath":"/tmp/config.json","binaryPath":"/tmp/sing-box"}}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = os.Remove(socketPath)
	})

	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	status := service.GetCoreServiceStatus()
	if !status.SocketAvailable || !status.Running || status.PID != 99 || status.Version != "1.1.0" || status.ServicePath != socketPath {
		t.Fatalf("expected RoverService daemon status, got %#v", status)
	}
	if !status.SingboxRunning || status.SingboxPid != 100 || status.SingboxStartTime != 123 {
		t.Fatalf("expected RoverService sing-box status, got %#v", status)
	}
	runtimeStatus := service.GetSingboxStatus()
	if !runtimeStatus.Success || !runtimeStatus.Data.Running || runtimeStatus.Data.PID != 100 || runtimeStatus.Data.BinaryPath != "/tmp/sing-box" {
		t.Fatalf("expected sing-box status from RoverService, got %#v", runtimeStatus)
	}
}

func TestStartStopCoreUsesRoverServiceForTun(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("sandfox-rs-core-%d.sock", time.Now().UnixNano()))
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANDFOX_ROVERSERVICE_SOCKET", socketPath)
	var startCalled bool
	var stopCalled bool
	var startPayload map[string]string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/singbox/start":
			startCalled = true
			if err := json.NewDecoder(r.Body).Decode(&startPayload); err != nil {
				t.Errorf("decode start payload: %v", err)
			}
			_, _ = w.Write([]byte(`{"success":true,"data":{"running":true,"pid":101,"startTime":123}}`))
		case "/singbox/stop":
			stopCalled = true
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = os.Remove(socketPath)
	})

	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.Settings.TUNEnabled = true
	if err := service.StartCore(); err != nil {
		t.Fatal(err)
	}
	if !startCalled || startPayload["configPath"] == "" || startPayload["binaryPath"] == "" {
		t.Fatalf("expected RoverService start payload, called=%v payload=%#v", startCalled, startPayload)
	}
	if service.core != nil {
		t.Fatalf("TUN mode should not start a local core process: %#v", service.core)
	}
	if err := service.StopCore(); err != nil {
		t.Fatal(err)
	}
	if !stopCalled {
		t.Fatal("expected RoverService stop to be called")
	}
}

func TestCoreCompatibilityAliases(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ss://YWVzLTEyOC1nY206cGFzc0BleGFtcGxlLmNvbTo4Mzg4#alias"))
	}))
	defer server.Close()
	if service.IsRunning() {
		t.Fatal("new service should not be running")
	}
	if service.GetStartTime() != nil {
		t.Fatal("stopped service should not have a start time")
	}
	id, err := service.AddSubscriptionProfile(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || len(service.data.Profiles) == 0 {
		t.Fatalf("expected profile id from compatibility alias, got %q", id)
	}
	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if service.data.Profiles[0].Name != parsedURL.Hostname() {
		t.Fatalf("expected subscription profile name from host, got %#v", service.data.Profiles[0])
	}
	if got, err := service.UpdateProfile(id); err != nil || got != id {
		t.Fatalf("expected update profile alias to return id, got %q err %v", got, err)
	}
}

func TestRuleProviderCompatibilityAliases(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	service.data.RuleSets = nil
	path := mustTempFileWithContent(t, service.dataDir, `{"version":1,"rules":[{"domain":["example.com"]}]}`)
	saved, err := service.SaveRuleSet(RuleSet{Tag: "local-json", Type: "local", Format: "source", Path: path, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if content := service.GetRuleProviderViewContent(saved.ID); content.Error != "" || !strings.Contains(content.Content, "example.com") {
		t.Fatalf("expected rule provider content, got %#v", content)
	}
	if result := service.DownloadRuleProvider(saved.Tag); !result.Success || result.Error != "" {
		t.Fatalf("expected local provider download/check success, got %#v", result)
	}
	if providers := service.GetRuleProviders(); len(providers) != 1 || providers[0].Tag != "local-json" {
		t.Fatalf("expected rule provider alias list, got %#v", providers)
	}
	if err := service.UpdateRuleProvider(saved.ID, map[string]any{"name": "local-updated", "enabled": false, "download_detour": "Auto"}); err != nil {
		t.Fatal(err)
	}
	providers := service.GetRuleProviders()
	if providers[0].Tag != "local-updated" || providers[0].Enabled || providers[0].DownloadDetour != "Auto" {
		t.Fatalf("expected rule provider update alias, got %#v", providers[0])
	}
	grouped := service.GetAllRuleSetsGrouped()
	if len(grouped) == 0 || grouped[0].GroupKey != "installed" || len(grouped[0].Items) != 1 {
		t.Fatalf("expected installed grouped rule sets, got %#v", grouped)
	}
	if result, err := service.AddRuleProvidersFromPreset([]string{"geosite-cn"}); err != nil || result.Added != 1 {
		t.Fatalf("expected preset provider added, result %#v err %v", result, err)
	}
	if err := service.UpdateRuleProvidersOrder([]string{service.data.RuleSets[1].ID, service.data.RuleSets[0].ID}); err != nil {
		t.Fatal(err)
	}
	if service.data.RuleSets[0].Tag != "geosite-cn" {
		t.Fatalf("expected rule providers reordered, got %#v", service.data.RuleSets)
	}
	if err := service.DeleteRuleProvider("local-updated"); err != nil {
		t.Fatal(err)
	}
	if providers := service.GetRuleProviders(); len(providers) != 1 || providers[0].Tag != "geosite-cn" {
		t.Fatalf("expected rule provider deleted by tag, got %#v", providers)
	}
}

func TestConfigLoggerAndSingboxCompatibilityAliases(t *testing.T) {
	service := NewSandfoxService()
	service.dataDir = t.TempDir()
	service.data = defaultData()
	if err := service.Log("info", "test", "one"); err != nil {
		t.Fatal(err)
	}
	if err := service.LogBatch([]LogInput{{Level: "warn", Module: "test", Message: "two"}}); err != nil {
		t.Fatal(err)
	}
	if logs := service.GetLogs(); len(logs) < 2 {
		t.Fatalf("expected logs from aliases, got %#v", logs)
	}
	exported := service.ExportConfig()
	if !exported.OK || exported.Path == "" {
		t.Fatalf("expected export config success, got %#v", exported)
	}
	if imported := service.ImportConfig(exported.Path); !imported.OK {
		t.Fatalf("expected import config success, got %#v", imported)
	}
	if err := os.WriteFile(service.coreLogPath(), []byte("alpha\nbeta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	count, err := service.GetInitialLogLineCount()
	if err != nil || count.LineCount != 2 {
		t.Fatalf("expected core log line count, got %#v err %v", count, err)
	}
	read, err := service.ReadLog(LogReadOptions{Search: "beta", MaxResults: 10})
	if err != nil || len(read.Lines) != 1 || read.Lines[0] != "beta" {
		t.Fatalf("expected searched core log, got %#v err %v", read, err)
	}
	if cleared := service.ClearLog(); !cleared.Success {
		t.Fatalf("expected core log clear success, got %#v", cleared)
	}
	if err := service.ClearAllLogs(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckForUpdatesFromLocalManifest(t *testing.T) {
	previous := appVersion
	appVersion = "1.2.3"
	t.Cleanup(func() { appVersion = previous })

	dir := t.TempDir()
	path := filepath.Join(dir, "release.json")
	if err := os.WriteFile(path, []byte(`{"version":"1.2.10","buildNumber":"42","downloadUrl":"https://example.com/sandfox.zip"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	service := NewSandfoxService()
	result := service.CheckForUpdates(path)
	if result.Error != "" || !result.Available || result.CurrentVersion != "1.2.3" || result.LatestVersion != "1.2.10" {
		t.Fatalf("expected update available from local manifest, got %#v", result)
	}
}

func TestCheckForUpdatesEqualAndMissingVersion(t *testing.T) {
	previous := appVersion
	appVersion = "2.0.0"
	t.Cleanup(func() { appVersion = previous })

	dir := t.TempDir()
	equalPath := filepath.Join(dir, "equal.json")
	if err := os.WriteFile(equalPath, []byte(`{"version":"2.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	service := NewSandfoxService()
	if result := service.CheckForUpdates(equalPath); result.Error != "" || result.Available {
		t.Fatalf("expected no update for equal manifest, got %#v", result)
	}

	missingPath := filepath.Join(dir, "missing.json")
	if err := os.WriteFile(missingPath, []byte(`{"notes":"no version"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if result := service.CheckForUpdates(missingPath); result.Error != "manifest version is required" {
		t.Fatalf("expected missing version error, got %#v", result)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		left  string
		right string
		want  int
	}{
		{left: "1.2.10", right: "1.2.3", want: 1},
		{left: "v2.0.0", right: "1.9.9", want: 1},
		{left: "1.0.0", right: "1.0.0-beta.1", want: 1},
		{left: "1.0.0-beta.1", right: "1.0.0", want: -1},
		{left: "1.0.0", right: "dev", want: 1},
		{left: "dev", right: "1.0.0", want: -1},
		{left: "dev", right: "dev", want: 0},
	}
	for _, tc := range cases {
		got := compareVersions(tc.left, tc.right)
		if got > 0 {
			got = 1
		}
		if got < 0 {
			got = -1
		}
		if got != tc.want {
			t.Fatalf("compareVersions(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}
}

func TestAdminShellEscaping(t *testing.T) {
	shell := shellQuote("/tmp/sandfox path/rover's helper")
	if shell != "'/tmp/sandfox path/rover'\\''s helper'" {
		t.Fatalf("unexpected shell quote: %s", shell)
	}
	appleScript := appleScriptStringEscape(`/bin/sh "/tmp/sandfox admin.sh"`)
	if appleScript != `/bin/sh \"/tmp/sandfox admin.sh\"` {
		t.Fatalf("unexpected AppleScript escape: %s", appleScript)
	}
}

func joinLines(lines []string) string {
	out := ""
	for _, line := range lines {
		out += line + "\n"
	}
	return out
}

func mustTempFile(t *testing.T, dir string) string {
	t.Helper()
	path := dir + "/rules.srs"
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustTempFileWithContent(t *testing.T, dir, content string) string {
	t.Helper()
	path := dir + "/rules.json"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
