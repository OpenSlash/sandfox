//go:build !windows

package main

import (
	"net"
	"os"
	"path/filepath"
	"time"
)

func createListener(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o666)
	return listener, nil
}

func cleanupSocket(path string) {
	_ = os.Remove(path)
}

func socketAvailable() bool {
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
