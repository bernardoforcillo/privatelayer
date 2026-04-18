//go:build windows

package main

import (
	"os/exec"
)

func runAsService(configDir string, exePath string) error {
	serviceName := "PrivateLayer"

	cmd := exec.Command("sc", "create", serviceName, "binPath=", exePath, "start=", "auto")
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("sc", "config", serviceName, "depend=", "TDI")
	return cmd.Run()
}

func stopService() error {
	cmd := exec.Command("sc", "stop", "PrivateLayer")
	return cmd.Run()
}

func removeService() error {
	cmd := exec.Command("sc", "delete", "PrivateLayer")
	return cmd.Run()
}
