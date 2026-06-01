package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const launchAgentID = "app.sandfox.desktop"
const coreServiceID = "RoverService"
const roverServiceHelperTargetPath = "/Library/PrivilegedHelperTools/roverservice"
const linuxRoverServicePackagedPath = "/usr/local/lib/sandfox/roverservice"
const linuxRoverServiceHelperTargetPath = "/usr/local/bin/roverservice"
const linuxRoverServiceUnitPath = "/etc/systemd/system/RoverService.service"

func detectSingBox(configuredPath string) (string, string) {
	path := strings.TrimSpace(configuredPath)
	if path == "" {
		path, _ = findExecutable("sing-box", standardExecutablePaths("sing-box")...)
	}
	if path == "" {
		return "", ""
	}
	out, err := exec.Command(path, "version").CombinedOutput()
	if err != nil {
		return path, "version unavailable"
	}
	first := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	if first == "" {
		first = "version unavailable"
	}
	return path, first
}

func standardExecutablePaths(name string) []string {
	if filepath.IsAbs(name) {
		return []string{name}
	}
	candidates := []string{
		filepath.Join("/opt/homebrew/bin", name),
		filepath.Join("/usr/local/bin", name),
		filepath.Join("/usr/bin", name),
		filepath.Join("/bin", name),
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, "go", "bin", name))
	}
	if runtime.GOOS == "darwin" {
		if exe, err := os.Executable(); err == nil {
			resources := filepath.Join(filepath.Dir(exe), "..", "Resources")
			candidates = append(candidates, filepath.Clean(filepath.Join(resources, name)))
		}
	}
	return candidates
}

func findExecutable(name string, candidates ...string) (string, error) {
	path := strings.TrimSpace(name)
	if path != "" {
		if filepath.IsAbs(path) || strings.Contains(path, string(os.PathSeparator)) {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path, nil
			}
			return "", fmt.Errorf("%s does not exist or is not a file", path)
		}
		if resolved, err := exec.LookPath(path); err == nil {
			return resolved, nil
		}
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	if path == "" {
		path = "executable"
	}
	return "", fmt.Errorf("%s was not found in PATH or standard install locations", path)
}

func singBoxCommandEnv() []string {
	env := os.Environ()
	env = append(env, "ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true")
	return env
}

func platformMessage() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS system proxy, LaunchAgent auto-start, and privileged LaunchDaemon core service are supported."
	case "windows":
		return "Windows user system proxy, auto-start, and sc.exe core service management are supported; service actions may require administrator rights."
	case "linux":
		return "Linux GNOME system proxy, XDG auto-start, and systemd RoverService helper are supported when available."
	default:
		return "This platform can generate sing-box config but has no system integration implementation yet."
	}
}

func installCoreService(singBoxPath, configPath string) error {
	if runtime.GOOS == "windows" {
		if strings.TrimSpace(singBoxPath) == "" || strings.TrimSpace(configPath) == "" {
			return errors.New("sing-box path and config path are required")
		}
		return installWindowsCoreService(singBoxPath, configPath)
	}
	if runtime.GOOS == "linux" {
		if strings.TrimSpace(singBoxPath) == "" || strings.TrimSpace(configPath) == "" {
			return errors.New("sing-box path and config path are required")
		}
		return installLinuxCoreService()
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("privileged core service is not implemented for %s", runtime.GOOS)
	}
	helper, err := roverServiceHelperSourcePath()
	if err != nil {
		return err
	}
	tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("sandfox-roverservice-%d", time.Now().UnixNano()))
	if err := copyFileMode(helper, tempPath, 0o755); err != nil {
		return err
	}
	script := fmt.Sprintf(`set -e
src=%s
target=%s
mkdir -p "$(dirname "$target")"
cp "$src" "$target"
chmod 755 "$target"
chown root:wheel "$target"
codesign --sign - "$target" >/dev/null 2>&1 || true
"$target" install
rm -f "$src"
`, shellQuote(tempPath), shellQuote(roverServiceHelperTargetPath))
	return runAdminShell(script)
}

func uninstallCoreService() error {
	if runtime.GOOS == "windows" {
		return uninstallWindowsCoreService()
	}
	if runtime.GOOS == "linux" {
		return uninstallLinuxCoreService()
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("privileged core service is not implemented for %s", runtime.GOOS)
	}
	script := fmt.Sprintf(`set -e
target=%s
if [ -x "$target" ]; then
  "$target" uninstall
else
  /bin/launchctl bootout system/%s >/dev/null 2>&1 || true
  /bin/rm -f %s
  /bin/rm -f "$target"
fi
`, shellQuote(roverServiceHelperTargetPath), coreServiceID, shellQuote(coreServicePlistPath()))
	return runAdminShell(script)
}

func controlCoreService(action string) error {
	if runtime.GOOS == "windows" {
		return controlWindowsCoreService(action)
	}
	if runtime.GOOS == "linux" {
		return controlLinuxCoreService(action)
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("privileged core service is not implemented for %s", runtime.GOOS)
	}
	plist := coreServicePlistPath()
	switch action {
	case "bootstrap":
		if !isCoreServiceInstalled() {
			return errors.New("privileged core service is not installed")
		}
		return runAdminShell(fmt.Sprintf(`if [ -x %s ]; then %s start; else /bin/launchctl bootstrap system %s; fi`, shellQuote(roverServiceHelperTargetPath), shellQuote(roverServiceHelperTargetPath), shellQuote(plist)))
	case "bootout":
		return runAdminShell(fmt.Sprintf(`if [ -x %s ]; then %s stop; else /bin/launchctl bootout system/%s >/dev/null 2>&1 || true; fi`, shellQuote(roverServiceHelperTargetPath), shellQuote(roverServiceHelperTargetPath), coreServiceID))
	default:
		return errors.New("unknown service action")
	}
}

func isCoreServiceInstalled() bool {
	if runtime.GOOS == "windows" {
		return exec.Command("sc.exe", "query", coreServiceID).Run() == nil
	}
	if runtime.GOOS == "linux" {
		if info, err := os.Stat(linuxRoverServiceUnitPath); err == nil && !info.IsDir() {
			return true
		}
		info, err := os.Stat(linuxRoverServiceHelperTargetPath)
		return err == nil && !info.IsDir()
	}
	if runtime.GOOS != "darwin" {
		return false
	}
	if info, err := os.Stat(roverServiceHelperTargetPath); err == nil && !info.IsDir() {
		return true
	}
	if info, err := os.Stat(coreServicePlistPath()); err == nil && !info.IsDir() {
		return true
	}
	return false
}

func getCoreServiceStatus() CoreServiceStatus {
	status := CoreServiceStatus{
		Platform:        runtime.GOOS,
		Supported:       runtime.GOOS == "darwin" || runtime.GOOS == "windows" || runtime.GOOS == "linux",
		BinaryInstalled: isCoreServiceInstalled(),
	}
	if !status.Supported {
		status.Message = "privileged core service is not implemented for this platform"
		return status
	}
	switch runtime.GOOS {
	case "darwin":
		return getDarwinCoreServiceStatus(status)
	case "windows":
		return getWindowsCoreServiceStatus(status)
	case "linux":
		return getLinuxCoreServiceStatus(status)
	default:
		return status
	}
}

func getDarwinCoreServiceStatus(status CoreServiceStatus) CoreServiceStatus {
	status.ServicePath = coreServicePlistPath()
	out, err := exec.Command("launchctl", "print", "system/"+coreServiceID).CombinedOutput()
	text := string(out)
	if err != nil {
		status.Message = strings.TrimSpace(text)
		return status
	}
	status.ServiceLoaded = true
	status.Running = strings.Contains(text, "state = running") || strings.Contains(text, "state = active")
	if pid := firstIntAfter(text, "pid ="); pid > 0 {
		status.PID = pid
		status.Running = true
	}
	return status
}

func getWindowsCoreServiceStatus(status CoreServiceStatus) CoreServiceStatus {
	out, err := exec.Command("sc.exe", "query", coreServiceID).CombinedOutput()
	text := string(out)
	if err != nil {
		status.Message = strings.TrimSpace(text)
		return status
	}
	status.ServiceLoaded = true
	status.Running = strings.Contains(text, "RUNNING")
	return status
}

func getLinuxCoreServiceStatus(status CoreServiceStatus) CoreServiceStatus {
	status.ServicePath = linuxRoverServiceUnitPath
	if _, err := exec.LookPath("systemctl"); err != nil {
		status.Message = "systemctl is not available"
		return status
	}
	out, err := exec.Command("systemctl", "show", coreServiceID+".service", "--property=LoadState,ActiveState,MainPID", "--no-page").CombinedOutput()
	text := string(out)
	if err != nil {
		status.Message = strings.TrimSpace(text)
		return status
	}
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "LoadState":
			status.ServiceLoaded = value == "loaded"
		case "ActiveState":
			status.Running = value == "active"
		case "MainPID":
			status.PID, _ = strconv.Atoi(value)
		}
	}
	return status
}

func firstIntAfter(text, marker string) int {
	index := strings.Index(text, marker)
	if index < 0 {
		return 0
	}
	rest := strings.TrimSpace(text[index+len(marker):])
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.Atoi(strings.Trim(fields[0], ";,"))
	return value
}

func installWindowsCoreService(singBoxPath, configPath string) error {
	helper, err := roverServiceHelperSourcePath()
	if err != nil {
		return err
	}
	return runWindowsElevatedHelper(helper, "install")
}

func uninstallWindowsCoreService() error {
	return runWindowsElevatedHelper(windowsRoverServiceTargetPath(), "uninstall")
}

func controlWindowsCoreService(action string) error {
	if !isCoreServiceInstalled() {
		return errors.New("Windows core service is not installed")
	}
	switch action {
	case "bootstrap":
		return runWindowsElevatedHelper(windowsRoverServiceTargetPath(), "start")
	case "bootout":
		return runWindowsElevatedHelper(windowsRoverServiceTargetPath(), "stop")
	default:
		return errors.New("unknown service action")
	}
}

func installLinuxCoreService() error {
	helper, err := roverServiceHelperSourcePath()
	if err != nil {
		return err
	}
	return runLinuxElevatedHelper(helper, "install")
}

func uninstallLinuxCoreService() error {
	return runLinuxElevatedHelper(linuxRoverServiceHelperTargetPath, "uninstall")
}

func controlLinuxCoreService(action string) error {
	if !isCoreServiceInstalled() {
		return errors.New("Linux RoverService helper is not installed")
	}
	switch action {
	case "bootstrap":
		return runLinuxElevatedHelper(linuxRoverServiceHelperTargetPath, "start")
	case "bootout":
		return runLinuxElevatedHelper(linuxRoverServiceHelperTargetPath, "stop")
	default:
		return errors.New("unknown service action")
	}
}

func coreServicePlistPath() string {
	return filepath.Join("/Library", "LaunchDaemons", coreServiceID+".plist")
}

func roverServiceHelperSourcePath() (string, error) {
	if value := strings.TrimSpace(os.Getenv("SANDFOX_ROVERSERVICE_BINARY")); value != "" {
		if info, err := os.Stat(value); err == nil && !info.IsDir() {
			return value, nil
		}
		return "", fmt.Errorf("RoverService helper binary not found at %s", value)
	}
	exe, err := os.Executable()
	if err == nil {
		macosDir := filepath.Dir(exe)
		resourcesPath := filepath.Clean(filepath.Join(macosDir, "..", "Resources", roverServiceHelperBinaryName()))
		if info, statErr := os.Stat(resourcesPath); statErr == nil && !info.IsDir() {
			return resourcesPath, nil
		}
		adjacentPath := filepath.Join(macosDir, roverServiceHelperBinaryName())
		if info, statErr := os.Stat(adjacentPath); statErr == nil && !info.IsDir() {
			return adjacentPath, nil
		}
	}
	candidates := []string{
		filepath.Join("bin", roverServiceHelperBinaryName()),
		"./" + roverServiceHelperBinaryName(),
		roverServiceHelperTargetPath,
	}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, windowsRoverServiceTargetPath())
	}
	if runtime.GOOS == "linux" {
		candidates = append(candidates, linuxRoverServicePackagedPath, linuxRoverServiceHelperTargetPath)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", errors.New("RoverService helper binary not found; build or package the app first")
}

func roverServiceHelperBinaryName() string {
	if runtime.GOOS == "windows" {
		return "roverservice.exe"
	}
	return "roverservice"
}

func windowsRoverServiceTargetPath() string {
	base := strings.TrimSpace(os.Getenv("ProgramFiles"))
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "Rover", "Helper", "roverservice.exe")
}

func runWindowsElevatedHelper(helperPath, command string) error {
	if runtime.GOOS != "windows" {
		return runCommand(helperPath, command)
	}
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
Start-Process -FilePath %s -ArgumentList %s -Verb RunAs -Wait
`, powershellQuote(helperPath), powershellQuote(command))
	path := filepath.Join(os.TempDir(), fmt.Sprintf("sandfox-roverservice-%d.ps1", time.Now().UnixNano()))
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		return err
	}
	defer os.Remove(path)
	return runCommand("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path)
}

func runLinuxElevatedHelper(helperPath, command string) error {
	if runtime.GOOS != "linux" {
		return runCommand(helperPath, command)
	}
	if _, err := exec.LookPath("pkexec"); err == nil {
		return runCommand("pkexec", helperPath, command)
	}
	if _, err := exec.LookPath("sudo"); err == nil {
		return runCommand("sudo", helperPath, command)
	}
	return errors.New("pkexec or sudo is required to manage Linux RoverService")
}

func powershellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func copyFileMode(src, dst string, mode os.FileMode) error {
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

func coreServicePlist(singBoxPath, configPath string) string {
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
    <string>-c</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key>
  <false/>
  <key>KeepAlive</key>
  <false/>
  <key>StandardOutPath</key>
  <string>/tmp/sandfox-core.out.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/sandfox-core.err.log</string>
</dict>
</plist>
`, coreServiceID, xmlEscape(singBoxPath), xmlEscape(configPath))
}

func setSystemProxy(enabled bool, mixedPort int) error {
	switch runtime.GOOS {
	case "darwin":
		return setDarwinSystemProxy(enabled, mixedPort)
	case "windows":
		return setWindowsSystemProxy(enabled, mixedPort)
	case "linux":
		return setLinuxSystemProxy(enabled, mixedPort)
	default:
		if enabled {
			return fmt.Errorf("system proxy is not implemented for %s", runtime.GOOS)
		}
		return nil
	}
}

func setDarwinSystemProxy(enabled bool, mixedPort int) error {
	services, err := networkServices()
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return errors.New("no macOS network services found")
	}
	for _, service := range services {
		if enabled {
			if err := runNetworkSetup("-setwebproxy", service, "127.0.0.1", fmt.Sprint(mixedPort)); err != nil {
				return err
			}
			if err := runNetworkSetup("-setsecurewebproxy", service, "127.0.0.1", fmt.Sprint(mixedPort)); err != nil {
				return err
			}
			if err := runNetworkSetup("-setsocksfirewallproxy", service, "127.0.0.1", fmt.Sprint(mixedPort)); err != nil {
				return err
			}
		}
		state := "off"
		if enabled {
			state = "on"
		}
		for _, flag := range []string{"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"} {
			if err := runNetworkSetup(flag, service, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func setWindowsSystemProxy(enabled bool, mixedPort int) error {
	if enabled {
		if err := runCommand("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyServer", "/t", "REG_SZ", "/d", fmt.Sprintf("http=127.0.0.1:%d;https=127.0.0.1:%d;socks=127.0.0.1:%d", mixedPort, mixedPort, mixedPort), "/f"); err != nil {
			return err
		}
		return runCommand("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f")
	}
	if err := runCommand("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"); err != nil {
		return err
	}
	_ = runCommand("reg", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyServer", "/f")
	return nil
}

func setLinuxSystemProxy(enabled bool, mixedPort int) error {
	if _, err := exec.LookPath("gsettings"); err != nil {
		if enabled {
			return errors.New("gsettings is required to change Linux desktop proxy")
		}
		return nil
	}
	if enabled {
		if err := runCommand("gsettings", "set", "org.gnome.system.proxy", "mode", "manual"); err != nil {
			return err
		}
		for _, schema := range []string{"org.gnome.system.proxy.http", "org.gnome.system.proxy.https", "org.gnome.system.proxy.socks"} {
			if err := runCommand("gsettings", "set", schema, "host", "127.0.0.1"); err != nil {
				return err
			}
			if err := runCommand("gsettings", "set", schema, "port", fmt.Sprint(mixedPort)); err != nil {
				return err
			}
		}
		return nil
	}
	return runCommand("gsettings", "set", "org.gnome.system.proxy", "mode", "none")
}

func networkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("networksetup failed: %s", strings.TrimSpace(string(out)))
	}
	lines := strings.Split(string(out), "\n")
	services := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

func runNetworkSetup(args ...string) error {
	out, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup %s failed: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func runCommand(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %s", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func setAutoStart(enabled bool) error {
	switch runtime.GOOS {
	case "darwin":
		return setDarwinAutoStart(enabled)
	case "windows":
		return setWindowsAutoStart(enabled)
	case "linux":
		return setLinuxAutoStart(enabled)
	default:
		if enabled {
			return fmt.Errorf("auto-start is not implemented for %s", runtime.GOOS)
		}
		return nil
	}
}

func setDarwinAutoStart(enabled bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	launchDir := filepath.Join(home, "Library", "LaunchAgents")
	plistPath := filepath.Join(launchDir, launchAgentID+".plist")
	if !enabled {
		_ = exec.Command("launchctl", "bootout", "gui/"+fmt.Sprint(os.Getuid()), plistPath).Run()
		if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(launchDir, 0o755); err != nil {
		return err
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
`, launchAgentID, exe)
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "bootout", "gui/"+fmt.Sprint(os.Getuid()), plistPath).Run()
	out, err := exec.Command("launchctl", "bootstrap", "gui/"+fmt.Sprint(os.Getuid()), plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl bootstrap failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func setWindowsAutoStart(enabled bool) error {
	key := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	if !enabled {
		_ = runCommand("reg", "delete", key, "/v", "Sandfox", "/f")
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return runCommand("reg", "add", key, "/v", "Sandfox", "/t", "REG_SZ", "/d", exe, "/f")
}

func setLinuxAutoStart(enabled bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	autostartDir := filepath.Join(home, ".config", "autostart")
	desktopPath := filepath.Join(autostartDir, launchAgentID+".desktop")
	if !enabled {
		if err := os.Remove(desktopPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(autostartDir, 0o755); err != nil {
		return err
	}
	desktop := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=Sandfox
Exec="%s"
Terminal=false
X-GNOME-Autostart-enabled=true
`, desktopEscape(exe))
	return os.WriteFile(desktopPath, []byte(desktop), 0o644)
}

func isAutoStartInstalled() bool {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		info, err := os.Stat(filepath.Join(home, "Library", "LaunchAgents", launchAgentID+".plist"))
		return err == nil && !info.IsDir()
	case "windows":
		return exec.Command("reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "Sandfox").Run() == nil
	case "linux":
		home, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		info, err := os.Stat(filepath.Join(home, ".config", "autostart", launchAgentID+".desktop"))
		return err == nil && !info.IsDir()
	default:
		return false
	}
}

func isLauncherAvailable() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "windows" || runtime.GOOS == "linux"
}

func runLauncherTaskNow() error {
	if !isLauncherAvailable() {
		return fmt.Errorf("launcher task is not implemented for %s", runtime.GOOS)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "darwin":
		if isAutoStartInstalled() {
			_ = exec.Command("launchctl", "kickstart", "-k", "gui/"+fmt.Sprint(os.Getuid())+"/"+launchAgentID).Run()
		}
		return exec.Command("open", exe).Start()
	case "windows":
		return exec.Command("cmd", "/C", "start", "", exe).Start()
	default:
		return exec.Command(exe).Start()
	}
}

func runAdminShell(script string) error {
	path := filepath.Join(os.TempDir(), fmt.Sprintf("sandfox-admin-%d.sh", time.Now().UnixNano()))
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		return err
	}
	defer os.Remove(path)
	command := "/bin/sh " + shellQuote(path)
	out, err := exec.Command("osascript", "-e", `do shell script "`+appleScriptStringEscape(command)+`" with administrator privileges`).CombinedOutput()
	if err != nil {
		return fmt.Errorf("administrator command failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func appleScriptStringEscape(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	return strings.ReplaceAll(value, `"`, `\"`)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func xmlEscape(value string) string {
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	value = strings.ReplaceAll(value, `"`, "&quot;")
	value = strings.ReplaceAll(value, "'", "&apos;")
	return value
}

func desktopEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return strings.ReplaceAll(value, "%", "%%")
}

func systemdQuote(value string) string {
	return strconv.Quote(value)
}

func openPath(path string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", path).Start()
	case "windows":
		return exec.Command("explorer", path).Start()
	default:
		return exec.Command("xdg-open", path).Start()
	}
}
