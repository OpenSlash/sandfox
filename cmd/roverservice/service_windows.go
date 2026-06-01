//go:build windows

package main

import (
	"golang.org/x/sys/windows/svc"
)

type windowsService struct{}

func runPlatformServer() error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return runServer()
	}
	return svc.Run(serviceName, windowsService{})
}

func (windowsService) Execute(_ []string, changes <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	errc := make(chan error, 1)
	go func() {
		errc <- runServer()
	}()

	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case change := <-changes:
			switch change.Cmd {
			case svc.Interrogate:
				status <- change.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cleanupSocket(socketPath)
				return false, 0
			default:
				status <- svc.Status{State: svc.Running, Accepts: accepted}
			}
		case err := <-errc:
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}
