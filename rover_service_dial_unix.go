//go:build !windows

package main

import (
	"context"
	"net"
)

func dialRoverService(ctx context.Context, dialer net.Dialer, socket string) (net.Conn, error) {
	return dialer.DialContext(ctx, "unix", socket)
}
