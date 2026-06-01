package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	apiVersion      = "1.1.0"
	defaultTimeout  = 30 * time.Second
	serviceName     = "RoverService"
	targetPath      = "/Library/PrivilegedHelperTools/roverservice"
	plistPath       = "/Library/LaunchDaemons/RoverService.plist"
	linuxTargetPath = "/usr/local/bin/roverservice"
	linuxUnitPath   = "/etc/systemd/system/RoverService.service"
)

var (
	socketPath = defaultSocketPath()

	singboxMu         sync.Mutex
	singboxProcess    *exec.Cmd
	singboxPID        int
	singboxStartTime  int64
	singboxConfigPath string
	singboxBinaryPath string

	dnsMu       sync.Mutex
	dnsServer   *http.Server
	dnsAddress  string
	dnsCertPath string
)

type response struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

type singboxStatus struct {
	Running    bool   `json:"running"`
	PID        int    `json:"pid,omitempty"`
	StartTime  int64  `json:"startTime,omitempty"`
	ConfigPath string `json:"configPath,omitempty"`
	BinaryPath string `json:"binaryPath,omitempty"`
}

type startRequest struct {
	ConfigPath string `json:"configPath"`
	BinaryPath string `json:"binaryPath"`
}

type processInfo struct {
	PID   int    `json:"pid"`
	PPID  int    `json:"ppid"`
	Name  string `json:"name"`
	User  string `json:"user"`
	State string `json:"state"`
}

type dnsStartRequest struct {
	Address    string `json:"address"`
	CertDir    string `json:"certDir"`
	LogEnabled bool   `json:"logEnabled"`
}

type dnsQueryRequest struct {
	Name           string        `json:"name"`
	Type           string        `json:"type"`
	Upstreams      dnsStringList `json:"upstreams"`
	Fallbacks      dnsStringList `json:"fallbacks"`
	FallbackAddrs  dnsStringList `json:"fallback_addrs"`
	Bootstrap      dnsStringList `json:"bootstrap"`
	BootstrapAddrs dnsStringList `json:"bootstrap_addrs"`
	Proxy          string        `json:"proxy"`
	ProxyAddr      string        `json:"proxy_addr"`
	ProxyUser      string        `json:"proxy_user"`
	ProxyPass      string        `json:"proxy_pass"`
	Timeout        int           `json:"timeout"`
}

type dnsQueryAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   int    `json:"ttl"`
	Value string `json:"value"`
}

type dnsQueryResponse struct {
	Answers []dnsQueryAnswer `json:"answers"`
	RCode   string           `json:"rcode"`
	Server  string           `json:"server,omitempty"`
}

func defaultSocketPath() string {
	if value := strings.TrimSpace(os.Getenv("SANDFOX_ROVERSERVICE_SOCKET")); value != "" {
		return value
	}
	if runtime.GOOS == "windows" {
		return `\\.\pipe\roverservice`
	}
	return "/var/run/roverservice.sock"
}

func main() {
	command := "run"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "run":
		if err := runPlatformServer(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "status":
		if err := printServiceStatus(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "install":
		mustRunServiceCommand(installService())
	case "uninstall":
		mustRunServiceCommand(uninstallService())
	case "start":
		mustRunServiceCommand(startService())
	case "stop":
		mustRunServiceCommand(stopService())
	case "restart":
		if err := stopService(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		mustRunServiceCommand(startService())
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		os.Exit(2)
	}
}

func printHelp() {
	fmt.Println("Sandfox RoverService-compatible helper")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  roverservice run       Run daemon and listen on the RoverService socket")
	fmt.Println("  roverservice install   Install and start the platform service")
	fmt.Println("  roverservice uninstall Stop and remove the platform service")
	fmt.Println("  roverservice start     Start the installed platform service")
	fmt.Println("  roverservice stop      Stop the installed platform service")
	fmt.Println("  roverservice restart   Restart the installed platform service")
	fmt.Println("  roverservice status    Check whether the daemon socket is reachable")
	fmt.Println("  roverservice help      Show this help")
}

func mustRunServiceCommand(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func printServiceStatus() error {
	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat(plistPath); err == nil {
			fmt.Println("Service is installed")
		} else {
			fmt.Println("Service is not installed")
		}
	case "windows":
		if windowsServiceInstalled() {
			fmt.Println("Service is installed")
		} else {
			fmt.Println("Service is not installed")
		}
	case "linux":
		if linuxServiceInstalled() {
			fmt.Println("Service is installed")
		} else {
			fmt.Println("Service is not installed")
		}
	default:
		fmt.Printf("Service installation is not implemented for %s\n", runtime.GOOS)
	}
	if socketAvailable() {
		fmt.Println("Service is running")
	} else {
		fmt.Println("Service is not running")
	}
	return nil
}

func installService() error {
	if runtime.GOOS == "windows" {
		return installWindowsService()
	}
	if runtime.GOOS == "linux" {
		return installLinuxService()
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("service install is not implemented for %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("install must be run as root")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return err
	}
	if filepath.Clean(exe) != targetPath {
		if err := copyFile(exe, targetPath, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(plistPath, []byte(launchDaemonPlist(targetPath)), 0o644); err != nil {
		return err
	}
	_ = runCommand("/bin/launchctl", "bootout", "system/"+serviceName)
	if err := runCommand("/bin/launchctl", "bootstrap", "system", plistPath); err != nil {
		return err
	}
	fmt.Println("Service installed successfully")
	return nil
}

func uninstallService() error {
	if runtime.GOOS == "windows" {
		return uninstallWindowsService()
	}
	if runtime.GOOS == "linux" {
		return uninstallLinuxService()
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("service uninstall is not implemented for %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("uninstall must be run as root")
	}
	_ = runCommand("/bin/launchctl", "bootout", "system/"+serviceName)
	_ = os.Remove(plistPath)
	_ = os.Remove(targetPath)
	cleanupSocket(socketPath)
	fmt.Println("Service uninstalled successfully")
	return nil
}

func startService() error {
	if runtime.GOOS == "windows" {
		if err := runCommand("sc.exe", "start", serviceName); err != nil {
			return err
		}
		fmt.Println("Service started successfully")
		return nil
	}
	if runtime.GOOS == "linux" {
		if err := runCommand("systemctl", "start", serviceName+".service"); err != nil {
			return err
		}
		fmt.Println("Service started successfully")
		return nil
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("service start is not implemented for %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("start must be run as root")
	}
	if _, err := os.Stat(plistPath); err != nil {
		return err
	}
	if err := runCommand("/bin/launchctl", "bootstrap", "system", plistPath); err != nil {
		return err
	}
	fmt.Println("Service started successfully")
	return nil
}

func stopService() error {
	if runtime.GOOS == "windows" {
		_ = runCommand("sc.exe", "stop", serviceName)
		fmt.Println("Service stopped successfully")
		return nil
	}
	if runtime.GOOS == "linux" {
		_ = runCommand("systemctl", "stop", serviceName+".service")
		cleanupSocket(socketPath)
		fmt.Println("Service stopped successfully")
		return nil
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("service stop is not implemented for %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("stop must be run as root")
	}
	_ = runCommand("/bin/launchctl", "bootout", "system/"+serviceName)
	cleanupSocket(socketPath)
	fmt.Println("Service stopped successfully")
	return nil
}

func installWindowsService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	target := windowsHelperTargetPath()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if !samePath(exe, target) {
		if err := copyFile(exe, target, 0o755); err != nil {
			return err
		}
	}
	_ = runCommand("sc.exe", "stop", serviceName)
	_ = runCommand("sc.exe", "delete", serviceName)
	binPath := fmt.Sprintf("%q run", target)
	if err := runCommand("sc.exe", "create", serviceName, "binPath=", binPath, "start=", "demand", "DisplayName=", "RoverService"); err != nil {
		return err
	}
	if err := runCommand("sc.exe", "start", serviceName); err != nil {
		return err
	}
	fmt.Println("Service installed successfully")
	return nil
}

func uninstallWindowsService() error {
	_ = runCommand("sc.exe", "stop", serviceName)
	if err := runCommand("sc.exe", "delete", serviceName); err != nil && windowsServiceInstalled() {
		return err
	}
	_ = os.Remove(windowsHelperTargetPath())
	fmt.Println("Service uninstalled successfully")
	return nil
}

func windowsServiceInstalled() bool {
	out, err := exec.Command("sc.exe", "query", serviceName).CombinedOutput()
	if err != nil {
		return false
	}
	text := strings.ToLower(string(out))
	return !strings.Contains(text, "does not exist") && !strings.Contains(string(out), "指定的服务不存在")
}

func installLinuxService() error {
	if os.Geteuid() != 0 {
		return errors.New("install must be run as root")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl is required to install Linux service")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(linuxTargetPath), 0o755); err != nil {
		return err
	}
	if filepath.Clean(exe) != linuxTargetPath {
		if err := copyFile(exe, linuxTargetPath, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(linuxUnitPath, []byte(linuxSystemdUnit(linuxTargetPath)), 0o644); err != nil {
		return err
	}
	_ = runCommand("systemctl", "stop", serviceName+".service")
	if err := runCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := runCommand("systemctl", "enable", "--now", serviceName+".service"); err != nil {
		return err
	}
	fmt.Println("Service installed successfully")
	return nil
}

func uninstallLinuxService() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must be run as root")
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = runCommand("systemctl", "disable", "--now", serviceName+".service")
		_ = runCommand("systemctl", "daemon-reload")
	}
	_ = os.Remove(linuxUnitPath)
	_ = os.Remove(linuxTargetPath)
	cleanupSocket(socketPath)
	fmt.Println("Service uninstalled successfully")
	return nil
}

func linuxServiceInstalled() bool {
	if info, err := os.Stat(linuxUnitPath); err == nil && !info.IsDir() {
		return true
	}
	if info, err := os.Stat(linuxTargetPath); err == nil && !info.IsDir() {
		return true
	}
	return false
}

func linuxSystemdUnit(binaryPath string) string {
	return fmt.Sprintf(`[Unit]
Description=RoverService privileged helper for Sandfox
After=network-online.target

[Service]
Type=simple
ExecStart=%s run
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`, systemdQuote(binaryPath))
}

func systemdQuote(value string) string {
	return strconv.Quote(value)
}

func windowsHelperTargetPath() string {
	base := strings.TrimSpace(os.Getenv("ProgramFiles"))
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "Rover", "Helper", "roverservice.exe")
}

func samePath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func launchDaemonPlist(binaryPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/roverservice.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/roverservice.err.log</string>
</dict>
</plist>
`, serviceName, xmlEscape(binaryPath))
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func runCommand(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func xmlEscape(value string) string {
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	value = strings.ReplaceAll(value, `"`, "&quot;")
	value = strings.ReplaceAll(value, `'`, "&apos;")
	return value
}

func runServer() error {
	listener, err := createListener(socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer cleanupSocket(socketPath)

	server := createHTTPServer()
	return server.Serve(listener)
}

func createHTTPServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", handleStatus)
	mux.HandleFunc("/version", handleStatus)
	mux.HandleFunc("/singbox/status", handleSingboxStatus)
	mux.HandleFunc("/singbox/start", handleSingboxStart)
	mux.HandleFunc("/singbox/stop", handleSingboxStop)
	mux.HandleFunc("/singbox/restart", handleSingboxRestart)
	mux.HandleFunc("/processes", handleListProcesses)
	mux.HandleFunc("/processes/kill", handleKillProcess)
	mux.HandleFunc("/dns/query", handleDNSQuery)
	mux.HandleFunc("/dns-query", handleDNSQuery)
	mux.HandleFunc("/dns/start", handleDNSStart)
	mux.HandleFunc("/dns/stop", handleDNSStop)
	mux.HandleFunc("/dns/status", handleDNSStatus)
	mux.HandleFunc("/check-path", handleCheckPath)
	mux.HandleFunc("/read-file", handleReadFile)
	return &http.Server{Handler: mux, ReadTimeout: defaultTimeout, WriteTimeout: defaultTimeout}
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	sendSuccess(w, map[string]any{
		"version":    apiVersion,
		"pid":        os.Getpid(),
		"uptime":     time.Now().Unix(),
		"socketPath": socketPath,
		"platform":   runtime.GOOS,
	}, "RoverService is running")
}

func handleSingboxStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	sendSuccess(w, currentSingboxStatus(), "")
}

func handleSingboxStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}
	if strings.TrimSpace(req.ConfigPath) == "" || strings.TrimSpace(req.BinaryPath) == "" {
		sendError(w, http.StatusBadRequest, "configPath and binaryPath are required", nil)
		return
	}
	if _, err := os.Stat(req.ConfigPath); err != nil {
		sendError(w, http.StatusBadRequest, "config file not found", err)
		return
	}
	if _, err := os.Stat(req.BinaryPath); err != nil {
		sendError(w, http.StatusBadRequest, "binary file not found", err)
		return
	}
	if status := currentSingboxStatus(); status.Running {
		sendError(w, http.StatusConflict, "sing-box is already running", nil)
		return
	}
	cmd := exec.CommandContext(context.Background(), req.BinaryPath, "run", "-c", req.ConfigPath)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true")
	cmd.Dir = filepath.Dir(req.ConfigPath)
	logFile, err := os.OpenFile(filepath.Join(cmd.Dir, "sing-box.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		sendError(w, http.StatusInternalServerError, "failed to start sing-box", err)
		return
	}
	singboxMu.Lock()
	singboxProcess = cmd
	singboxPID = cmd.Process.Pid
	singboxStartTime = time.Now().Unix()
	singboxConfigPath = req.ConfigPath
	singboxBinaryPath = req.BinaryPath
	status := currentSingboxStatusLocked()
	singboxMu.Unlock()
	go waitSingbox(cmd, logFile)
	sendSuccess(w, status, "sing-box started successfully")
}

func handleSingboxStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	if err := stopSingbox(); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to stop sing-box", err)
		return
	}
	sendSuccess(w, nil, "sing-box stopped successfully")
}

func handleSingboxRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	singboxMu.Lock()
	req := startRequest{ConfigPath: singboxConfigPath, BinaryPath: singboxBinaryPath}
	singboxMu.Unlock()
	if req.ConfigPath == "" || req.BinaryPath == "" {
		sendError(w, http.StatusBadRequest, "no previous sing-box configuration found", nil)
		return
	}
	_ = stopSingbox()
	r.Body = io.NopCloser(strings.NewReader(mustJSON(req)))
	handleSingboxStart(w, r)
}

func handleListProcesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	processes := make([]processInfo, 0)
	for _, pid := range findSingboxPIDs() {
		processes = append(processes, processInfo{PID: pid, Name: "sing-box", User: "unknown", State: "running"})
	}
	sendSuccess(w, processes, "")
}

func handleKillProcess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	var req struct {
		PID   int  `json:"pid"`
		Force bool `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}
	if req.PID <= 0 {
		sendError(w, http.StatusBadRequest, "invalid PID", nil)
		return
	}
	if err := killPID(req.PID, req.Force); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to kill process", err)
		return
	}
	sendSuccess(w, nil, fmt.Sprintf("process %d killed successfully", req.PID))
}

func handleCheckPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}
	if strings.TrimSpace(req.Path) == "" {
		sendError(w, http.StatusBadRequest, "path is required", nil)
		return
	}
	info, err := os.Stat(req.Path)
	if os.IsNotExist(err) {
		sendSuccess(w, map[string]any{"exists": false}, "Path does not exist")
		return
	}
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to check path", err)
		return
	}
	sendSuccess(w, map[string]any{
		"exists": true,
		"isDir":  info.IsDir(),
		"size":   info.Size(),
		"mode":   info.Mode().String(),
	}, "")
}

func handleReadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	var req struct {
		Path     string `json:"path"`
		MaxBytes int64  `json:"maxBytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}
	if strings.TrimSpace(req.Path) == "" {
		sendError(w, http.StatusBadRequest, "path is required", nil)
		return
	}
	if req.MaxBytes <= 0 {
		req.MaxBytes = 1024 * 1024
	}
	file, err := os.Open(req.Path)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to open file", err)
		return
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, req.MaxBytes))
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to read file", err)
		return
	}
	sendSuccess(w, map[string]any{"content": string(content), "size": len(content)}, "")
}

func handleDNSStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	var req dnsStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}
	if strings.TrimSpace(req.Address) == "" {
		req.Address = "127.0.0.1:5353"
	}
	if strings.TrimSpace(req.CertDir) == "" {
		req.CertDir = filepath.Join(os.TempDir(), "roverservice-dns")
	}
	address, certPath, err := startDNSServer(req.Address, req.CertDir)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to start DNS server", err)
		return
	}
	sendSuccess(w, map[string]string{"address": address, "status": "running", "cert_path": certPath}, "DNS server started")
}

func handleDNSStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	address := stopDNSServer()
	sendSuccess(w, map[string]string{"address": address, "status": "stopped"}, "DNS server stopped")
}

func handleDNSStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	dnsMu.Lock()
	running := dnsServer != nil
	address := dnsAddress
	certPath := dnsCertPath
	dnsMu.Unlock()
	message := "DNS server is not running"
	if running {
		message = "DNS server is running"
	}
	sendSuccess(w, map[string]any{"running": running, "address": address, "cert_path": certPath}, message)
}

func handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dns/query" && r.URL.Path != "/dns-query" {
		http.NotFound(w, r)
		return
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		handleDNSJSONQuery(w, r)
		return
	}
	payload, err := dnsWirePayload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if upstreams := headerList(r.Header.Get("X-Upstreams")); len(upstreams) > 0 {
		resp, err := resolveDNSWireQuery(r.Context(), payload, dnsResolveOptions{
			Upstreams: upstreams,
			Fallbacks: headerList(r.Header.Get("X-Fallback-Addrs")),
			Bootstrap: headerList(r.Header.Get("X-Bootstrap-Addrs")),
			Proxy:     r.Header.Get("X-Proxy"),
			ProxyAddr: r.Header.Get("X-Proxy-Addr"),
			ProxyUser: r.Header.Get("X-Proxy-User"),
			ProxyPass: r.Header.Get("X-Proxy-Pass"),
			Timeout:   8 * time.Second,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://1.1.1.1/dns-query", bytes.NewReader(payload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	res, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(res.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(res.Body, 64*1024))
}

func handleDNSJSONQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	var req dnsQueryRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}
	result, err := resolveDNSJSONQuery(r.Context(), req)
	if err != nil {
		sendError(w, http.StatusBadGateway, "DNS query failed", err)
		return
	}
	sendSuccess(w, result, "")
}

func resolveDNSJSONQuery(parent context.Context, req dnsQueryRequest) (dnsQueryResponse, error) {
	timeout := 10 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Millisecond
	}
	return resolveDNSJSONWithOptions(parent, req, dnsResolveOptions{
		Upstreams: mergeStringLists(req.Upstreams),
		Fallbacks: mergeStringLists(req.Fallbacks, req.FallbackAddrs),
		Bootstrap: mergeStringLists(req.Bootstrap, req.BootstrapAddrs),
		Proxy:     req.Proxy,
		ProxyAddr: req.ProxyAddr,
		ProxyUser: req.ProxyUser,
		ProxyPass: req.ProxyPass,
		Timeout:   timeout,
	})
}

func startDNSServer(address, certDir string) (string, string, error) {
	dnsMu.Lock()
	if dnsServer != nil {
		_ = dnsServer.Close()
		dnsServer = nil
	}
	dnsMu.Unlock()
	certPath, keyPath, err := ensureDNSCertificate(certDir)
	if err != nil {
		return "", "", err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return "", "", err
	}
	actualAddress := listener.Addr().String()
	server := &http.Server{Handler: http.HandlerFunc(handleDNSQuery)}
	dnsMu.Lock()
	dnsServer = server
	dnsAddress = actualAddress
	dnsCertPath = certPath
	dnsMu.Unlock()
	go func() {
		err := server.ServeTLS(listener, certPath, keyPath)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "DNS server error: %v\n", err)
		}
		dnsMu.Lock()
		if dnsServer == server {
			dnsServer = nil
			dnsAddress = ""
			dnsCertPath = ""
		}
		dnsMu.Unlock()
	}()
	return actualAddress, certPath, nil
}

func stopDNSServer() string {
	dnsMu.Lock()
	server := dnsServer
	address := dnsAddress
	dnsServer = nil
	dnsAddress = ""
	dnsCertPath = ""
	dnsMu.Unlock()
	if server != nil {
		_ = server.Close()
	}
	return address
}

func dnsWirePayload(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodPost:
		return io.ReadAll(io.LimitReader(r.Body, 64*1024))
	case http.MethodGet:
		value := strings.TrimSpace(r.URL.Query().Get("dns"))
		if value == "" {
			return nil, errors.New("missing dns query parameter")
		}
		if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
			return decoded, nil
		}
		return base64.URLEncoding.DecodeString(value)
	default:
		return nil, errors.New("method not allowed")
	}
}

func ensureDNSCertificate(dir string) (string, string, error) {
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
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Sandfox Rover DNS"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		return "", "", err
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func currentSingboxStatus() singboxStatus {
	singboxMu.Lock()
	defer singboxMu.Unlock()
	return currentSingboxStatusLocked()
}

func currentSingboxStatusLocked() singboxStatus {
	status := singboxStatus{ConfigPath: singboxConfigPath, BinaryPath: singboxBinaryPath}
	if singboxPID > 0 && processAlive(singboxPID) {
		status.Running = true
		status.PID = singboxPID
		status.StartTime = singboxStartTime
		return status
	}
	singboxPID = 0
	singboxStartTime = 0
	return status
}

func waitSingbox(cmd *exec.Cmd, logFile *os.File) {
	_ = cmd.Wait()
	if logFile != nil {
		_ = logFile.Close()
	}
	singboxMu.Lock()
	if singboxProcess == cmd {
		singboxProcess = nil
		singboxPID = 0
		singboxStartTime = 0
	}
	singboxMu.Unlock()
}

func stopSingbox() error {
	singboxMu.Lock()
	pid := singboxPID
	cmd := singboxProcess
	singboxProcess = nil
	singboxPID = 0
	singboxStartTime = 0
	singboxMu.Unlock()
	if cmd != nil && cmd.Process != nil {
		return killPID(cmd.Process.Pid, false)
	}
	if pid > 0 {
		return killPID(pid, false)
	}
	return nil
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist", "/fi", fmt.Sprintf("PID eq %d", pid), "/nh").Output()
		return err == nil && strings.Contains(string(out), strconv.Itoa(pid))
	}
	process, err := os.FindProcess(pid)
	return err == nil && process.Signal(syscall.Signal(0)) == nil
}

func killPID(pid int, force bool) error {
	if runtime.GOOS == "windows" {
		args := []string{"/PID", strconv.Itoa(pid), "/T"}
		if force {
			args = append(args, "/F")
		}
		return exec.Command("taskkill", args...).Run()
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if force {
		return process.Kill()
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	for i := 0; i < 20; i++ {
		if !processAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return process.Kill()
}

func findSingboxPIDs() []int {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist", "/fo", "csv", "/nh", "/fi", "IMAGENAME eq sing-box.exe").Output()
		if err != nil {
			return nil
		}
		return parseTasklistPIDs(string(out))
	}
	out, err := exec.Command("pgrep", "-x", "sing-box").Output()
	if err != nil {
		return nil
	}
	return parseLinePIDs(string(out))
}

func parseLinePIDs(text string) []int {
	var out []int
	for _, line := range strings.Split(text, "\n") {
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && pid > 0 {
			out = append(out, pid)
		}
	}
	return out
}

func parseTasklistPIDs(text string) []int {
	var out []int
	for _, line := range strings.Split(text, "\n") {
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		pidText := strings.Trim(parts[1], "\" \t\r\n")
		if pid, err := strconv.Atoi(pidText); err == nil && pid > 0 {
			out = append(out, pid)
		}
	}
	return out
}

func sendSuccess(w http.ResponseWriter, data any, message string) {
	sendJSON(w, http.StatusOK, response{Success: true, Message: message, Data: data})
}

func sendError(w http.ResponseWriter, statusCode int, message string, err error) {
	out := response{Success: false, Message: message}
	if err != nil {
		out.Error = err.Error()
	}
	sendJSON(w, statusCode, out)
}

func sendJSON(w http.ResponseWriter, statusCode int, body response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(body)
}

func mustJSON(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
