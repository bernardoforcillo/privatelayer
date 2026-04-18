//go:build !windows && !linux && !darwin

package wireguard

import (
	"fmt"
	"runtime"
)

type Tunnel struct {
	Name string
}

func CreateTunnel(name string) (*Tunnel, error) {
	return nil, fmt.Errorf("userspace TUN not supported on %s", runtime.GOOS)
}

func (t *Tunnel) Close() error {
	return nil
}
