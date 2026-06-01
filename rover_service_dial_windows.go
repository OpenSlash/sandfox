//go:build windows

package main

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

func dialRoverService(ctx context.Context, _ net.Dialer, socket string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, socket)
}
