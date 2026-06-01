//go:build !windows

package main

func runPlatformServer() error {
	return runServer()
}
