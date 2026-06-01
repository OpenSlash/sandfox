package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestHelpTextIsPlatformNeutral(t *testing.T) {
	var out bytes.Buffer
	stdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	printHelp()
	_ = writer.Close()
	os.Stdout = stdout
	if _, err := io.Copy(&out, reader); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.Contains(text, "LaunchDaemon") {
		t.Fatalf("help text should be platform-neutral: %s", text)
	}
	if !strings.Contains(text, "platform service") {
		t.Fatalf("expected platform service wording: %s", text)
	}
}

func TestStatusEndpoint(t *testing.T) {
	server := createHTTPServer()
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success {
		t.Fatalf("expected success response, got %#v", body)
	}
	data, ok := body.Data.(map[string]any)
	if !ok || data["version"] != apiVersion {
		t.Fatalf("expected API version %q, got %#v", apiVersion, body.Data)
	}
}

func TestSingboxStartValidatesPaths(t *testing.T) {
	server := createHTTPServer()
	payload := []byte(`{"configPath":"/missing/config.json","binaryPath":"/missing/sing-box"}`)
	req := httptest.NewRequest(http.MethodPost, "/singbox/start", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var body response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Success || body.Message == "" {
		t.Fatalf("expected validation error response, got %#v", body)
	}
}

func TestParsePIDHelpers(t *testing.T) {
	pids := parseLinePIDs("123\nbad\n456\n")
	if len(pids) != 2 || pids[0] != 123 || pids[1] != 456 {
		t.Fatalf("unexpected line pids: %#v", pids)
	}
	pids = parseTasklistPIDs("\"sing-box.exe\",\"789\",\"Console\",\"1\",\"1,024 K\"\n")
	if len(pids) != 1 || pids[0] != 789 {
		t.Fatalf("unexpected tasklist pids: %#v", pids)
	}
}

func TestFileHelperEndpoints(t *testing.T) {
	server := createHTTPServer()
	path := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/check-path", bytes.NewReader([]byte(`{"path":"`+path+`"}`)))
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected check-path 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body.Data.(map[string]any)
	if data["exists"] != true || data["isDir"] != false {
		t.Fatalf("unexpected check-path response: %#v", body.Data)
	}

	req = httptest.NewRequest(http.MethodPost, "/read-file", bytes.NewReader([]byte(`{"path":"`+path+`","maxBytes":5}`)))
	rec = httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected read-file 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data = body.Data.(map[string]any)
	if data["content"] != "hello" {
		t.Fatalf("expected limited file content, got %#v", body.Data)
	}
}

func TestLaunchDaemonPlist(t *testing.T) {
	plist := launchDaemonPlist(`/Library/PrivilegedHelperTools/rover&service`)
	if !bytes.Contains([]byte(plist), []byte(`<string>RoverService</string>`)) {
		t.Fatalf("expected service label in plist: %s", plist)
	}
	if !bytes.Contains([]byte(plist), []byte(`/Library/PrivilegedHelperTools/rover&amp;service`)) {
		t.Fatalf("expected escaped binary path in plist: %s", plist)
	}
	if !bytes.Contains([]byte(plist), []byte(`<string>run</string>`)) {
		t.Fatalf("expected run argument in plist: %s", plist)
	}
}

func TestWindowsHelperTargetPath(t *testing.T) {
	t.Setenv("ProgramFiles", `C:\PF`)
	path := windowsHelperTargetPath()
	if !strings.Contains(path, "Rover") || !strings.Contains(path, "roverservice.exe") {
		t.Fatalf("unexpected Windows helper path: %s", path)
	}
}

func TestLinuxSystemdUnit(t *testing.T) {
	unit := linuxSystemdUnit(`/usr/local/bin/rover service`)
	if !strings.Contains(unit, "Description=RoverService privileged helper") {
		t.Fatalf("expected service description in unit: %s", unit)
	}
	if !strings.Contains(unit, `ExecStart="/usr/local/bin/rover service" run`) {
		t.Fatalf("expected quoted ExecStart in unit: %s", unit)
	}
	if !strings.Contains(unit, "WantedBy=multi-user.target") {
		t.Fatalf("expected system service install target in unit: %s", unit)
	}
}

func TestDNSLifecycleEndpoints(t *testing.T) {
	server := createHTTPServer()
	defer stopDNSServer()

	startBody := []byte(`{"address":"127.0.0.1:0","certDir":"` + t.TempDir() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/dns/start", bytes.NewReader(startBody))
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS start 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success {
		t.Fatalf("expected DNS start success, got %#v", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/dns/status", nil)
	rec = httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS status 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body.Data.(map[string]any)
	if data["running"] != true || data["address"] == "" || data["cert_path"] == "" {
		t.Fatalf("expected running DNS status, got %#v", body.Data)
	}

	req = httptest.NewRequest(http.MethodPost, "/dns/stop", nil)
	rec = httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS stop 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDNSJSONQueryEndpoint(t *testing.T) {
	server := createHTTPServer()
	req := httptest.NewRequest(http.MethodPost, "/dns/query", bytes.NewReader([]byte(`{"name":"localhost","type":"A","timeout":1000}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS JSON query 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success {
		t.Fatalf("expected DNS JSON success, got %#v", body)
	}
	data := body.Data.(map[string]any)
	if data["rcode"] != "NOERROR" {
		t.Fatalf("expected NOERROR response, got %#v", body.Data)
	}
	answers, ok := data["answers"].([]any)
	if !ok || len(answers) == 0 {
		t.Fatalf("expected localhost answers, got %#v", body.Data)
	}
}

func TestDNSJSONQueryUsesConfiguredUpstream(t *testing.T) {
	upstream := startTestDNSServer(t, "example.test.", "203.0.113.10")
	server := createHTTPServer()
	req := httptest.NewRequest(http.MethodPost, "/dns/query", bytes.NewReader([]byte(`{"name":"example.test","type":"A","upstreams":["udp://`+upstream+`"],"timeout":1000}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS JSON query 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body.Data.(map[string]any)
	if data["server"] != "udp://"+upstream {
		t.Fatalf("expected configured upstream server, got %#v", body.Data)
	}
	answers := data["answers"].([]any)
	first := answers[0].(map[string]any)
	if first["value"] != "203.0.113.10" {
		t.Fatalf("expected upstream answer, got %#v", body.Data)
	}
}

func TestDNSJSONQueryFallsBackWhenPrimaryFails(t *testing.T) {
	fallback := startTestDNSServer(t, "fallback.test.", "203.0.113.11")
	server := createHTTPServer()
	body := []byte(`{"name":"fallback.test","type":"A","upstreams":["udp://127.0.0.1:1"],"fallbacks":["udp://` + fallback + `"],"timeout":150}`)
	req := httptest.NewRequest(http.MethodPost, "/dns/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS fallback query 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var res response
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	data := res.Data.(map[string]any)
	if data["server"] != "udp://"+fallback {
		t.Fatalf("expected fallback server, got %#v", res.Data)
	}
}

func TestDNSWireQueryUsesUpstreamHeader(t *testing.T) {
	upstream := startTestDNSServer(t, "wire.test.", "203.0.113.12")
	query := new(dns.Msg)
	query.SetQuestion("wire.test.", dns.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	server := createHTTPServer()
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("X-Upstreams", "udp://"+upstream)
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS wire query 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var msg dns.Msg
	if err := msg.Unpack(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected one answer, got %#v", msg.Answer)
	}
	record, ok := msg.Answer[0].(*dns.A)
	if !ok || record.A.String() != "203.0.113.12" {
		t.Fatalf("unexpected DNS wire answer: %#v", msg.Answer)
	}
}

func TestDNSJSONQueryUsesTCPUpstream(t *testing.T) {
	upstream := startTestTCPDNSServer(t, "tcp.test.", "203.0.113.13")
	server := createHTTPServer()
	body := []byte(`{"name":"tcp.test","type":"A","upstreams":"tcp://` + upstream + `","timeout":1000}`)
	req := httptest.NewRequest(http.MethodPost, "/dns/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS TCP query 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var res response
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	data := res.Data.(map[string]any)
	if data["server"] != "tcp://"+upstream {
		t.Fatalf("expected TCP upstream server, got %#v", res.Data)
	}
}

func TestDNSJSONQueryUsesDoHUpstream(t *testing.T) {
	upstream := startTestDoHServer(t, "doh.test.", "203.0.113.14")
	server := createHTTPServer()
	body := []byte(`{"name":"doh.test","type":"A","upstreams":["` + upstream + `"],"timeout":1000}`)
	req := httptest.NewRequest(http.MethodPost, "/dns/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS DoH query 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var res response
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	data := res.Data.(map[string]any)
	if data["server"] != upstream {
		t.Fatalf("expected DoH upstream server, got %#v", res.Data)
	}
}

func TestDNSJSONQueryBootstrapResolvesUpstreamHost(t *testing.T) {
	bootstrap := startTestDNSServer(t, "dns.upstream.test.", "127.0.0.1")
	upstream := startTestDNSServer(t, "bootstrap.test.", "203.0.113.15")
	_, port, err := net.SplitHostPort(upstream)
	if err != nil {
		t.Fatal(err)
	}
	server := createHTTPServer()
	body := []byte(`{"name":"bootstrap.test","type":"A","upstreams":["udp://dns.upstream.test:` + port + `"],"bootstrap_addrs":"udp://` + bootstrap + `","timeout":1000}`)
	req := httptest.NewRequest(http.MethodPost, "/dns/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS bootstrap query 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var res response
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	data := res.Data.(map[string]any)
	answers := data["answers"].([]any)
	first := answers[0].(map[string]any)
	if first["value"] != "203.0.113.15" {
		t.Fatalf("expected bootstrap-resolved upstream answer, got %#v", res.Data)
	}
}

func TestDNSJSONQueryUsesSOCKS5Proxy(t *testing.T) {
	upstream := startTestTCPDNSServer(t, "proxy.test.", "203.0.113.16")
	proxyAddr := startTestSOCKS5Proxy(t)
	server := createHTTPServer()
	body := []byte(`{"name":"proxy.test","type":"A","upstreams":["tcp://` + upstream + `"],"proxy":"socks5","proxy_addr":"` + proxyAddr + `","timeout":1000}`)
	req := httptest.NewRequest(http.MethodPost, "/dns/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected DNS SOCKS5 query 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var res response
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	data := res.Data.(map[string]any)
	answers := data["answers"].([]any)
	first := answers[0].(map[string]any)
	if first["value"] != "203.0.113.16" {
		t.Fatalf("expected SOCKS5 proxied upstream answer, got %#v", res.Data)
	}
}

func TestDNSJSONQueryUsesDoTUpstreamWithTrustedCA(t *testing.T) {
	addr, roots := startTestDoTServer(t, "dot.test.", "203.0.113.17")
	result, err := resolveDNSJSONWithOptions(context.Background(), dnsQueryRequest{
		Name: "dot.test",
		Type: "A",
	}, dnsResolveOptions{
		Upstreams: []string{"tls://" + addr},
		Timeout:   time.Second,
		RootCAs:   roots,
	})
	if err != nil {
		t.Fatalf("expected trusted DoT query to succeed: %v", err)
	}
	if result.Server != "tls://"+addr {
		t.Fatalf("expected DoT server in result, got %#v", result)
	}
	if len(result.Answers) != 1 || result.Answers[0].Value != "203.0.113.17" {
		t.Fatalf("unexpected DoT answer: %#v", result)
	}
}

func startTestDNSServer(t *testing.T, fqdn, ip string) string {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		if len(r.Question) > 0 && strings.EqualFold(r.Question[0].Name, fqdn) && r.Question[0].Qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			})
		}
		_ = w.WriteMsg(msg)
	})
	server := &dns.Server{PacketConn: packetConn, Handler: handler}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
		_ = packetConn.Close()
	})
	return packetConn.LocalAddr().String()
}

func startTestTCPDNSServer(t *testing.T, fqdn, ip string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{Listener: listener, Handler: testDNSHandler(fqdn, ip)}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
		_ = listener.Close()
	})
	return listener.Addr().String()
}

func startTestDoTServer(t *testing.T, fqdn, ip string) (string, *x509.CertPool) {
	t.Helper()
	cert, roots := generateTestTLSCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}})
	server := &dns.Server{Listener: tlsListener, Net: "tcp-tls", Handler: testDNSHandler(fqdn, ip)}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
		_ = listener.Close()
	})
	return listener.Addr().String(), roots
}

func startTestDoHServer(t *testing.T, fqdn, ip string) string {
	t.Helper()
	handler := testDNSHandler(fqdn, ip)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-query" {
			http.NotFound(w, r)
			return
		}
		payload, err := dnsWirePayload(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		recorder := &testDNSResponseWriter{}
		handler.ServeDNS(recorder, msg)
		out, err := recorder.msg.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(server.Close)
	return server.URL + "/dns-query"
}

func testDNSHandler(fqdn, ip string) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		if len(r.Question) > 0 && strings.EqualFold(r.Question[0].Name, fqdn) && r.Question[0].Qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			})
		}
		_ = w.WriteMsg(msg)
	})
}

type testDNSResponseWriter struct {
	msg *dns.Msg
}

func (w *testDNSResponseWriter) LocalAddr() net.Addr         { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (w *testDNSResponseWriter) RemoteAddr() net.Addr        { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (w *testDNSResponseWriter) WriteMsg(msg *dns.Msg) error { w.msg = msg; return nil }
func (w *testDNSResponseWriter) Write([]byte) (int, error)   { return 0, nil }
func (w *testDNSResponseWriter) Close() error                { return nil }
func (w *testDNSResponseWriter) TsigStatus() error           { return nil }
func (w *testDNSResponseWriter) TsigTimersOnly(bool)         {}
func (w *testDNSResponseWriter) Hijack()                     {}

func startTestSOCKS5Proxy(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleTestSOCKS5Conn(conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return listener.Addr().String()
}

func handleTestSOCKS5Conn(conn net.Conn) {
	defer conn.Close()
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	host, port, err := readSOCKS5Address(conn, req[3])
	if err != nil {
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, target)
		errCh <- err
	}()
	<-errCh
}

func readSOCKS5Address(conn net.Conn, atyp byte) (string, string, error) {
	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", "", err
		}
		port, err := readSOCKS5Port(conn)
		return net.IP(ip).String(), port, err
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", "", err
		}
		host := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, host); err != nil {
			return "", "", err
		}
		port, err := readSOCKS5Port(conn)
		return string(host), port, err
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", "", err
		}
		port, err := readSOCKS5Port(conn)
		return net.IP(ip).String(), port, err
	default:
		return "", "", fmt.Errorf("unsupported SOCKS5 address type %d", atyp)
	}
}

func readSOCKS5Port(conn net.Conn) (string, error) {
	raw := make([]byte, 2)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return "", err
	}
	return fmt.Sprint(int(raw[0])<<8 | int(raw[1])), nil
}

func generateTestTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Sandfox Test DNS CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: "Sandfox Test DoT"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, roots
}
