//go:build darwin

package wireguard

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

type Tunnel struct {
	Name   string
	device tun.Device
}

func CreateTunnel(name string) (*Tunnel, error) {
	tunDev, err := tun.CreateTUN(name, 1420)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}
	return &Tunnel{Name: name, device: tunDev}, nil
}

func (t *Tunnel) Close() error {
	if t.device != nil {
		return t.device.Close()
	}
	return nil
}
