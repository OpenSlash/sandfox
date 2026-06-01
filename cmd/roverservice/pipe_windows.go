//go:build windows

package main

import (
	"context"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

func createListener(path string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGW;;;AU)",
	})
}

func cleanupSocket(_ string) {
}

func socketAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, socketPath)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
