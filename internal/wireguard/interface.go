package wireguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type InterfaceConfig struct {
	Name       string
	PrivateKey string
	Address    string
	ListenPort int
	Peers      []PeerConfig
}

type PeerConfig struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
}

func GenerateConfig(cfg *InterfaceConfig) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", cfg.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", cfg.Address))
	if cfg.ListenPort > 0 {
		sb.WriteString(fmt.Sprintf("ListenPort = %d\n", cfg.ListenPort))
	}

	sb.WriteString("\n")
	for _, peer := range cfg.Peers {
		sb.WriteString("[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
		if peer.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}
		sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", ")))
		sb.WriteString("\n")
	}

	return sb.String()
}

func SaveConfig(cfg *InterfaceConfig, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	config := GenerateConfig(cfg)
	filename := filepath.Join(dir, cfg.Name+".conf")

	if err := os.WriteFile(filename, []byte(config), 0600); err != nil {
		return "", err
	}

	return filename, nil
}

func GetFreePort() (int, error) {
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port, nil
}

func DecodeBase64Key(key string) ([32]byte, error) {
	var result [32]byte
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return result, err
	}
	copy(result[:], decoded)
	return result, nil
}

func ParseAllowedIP(cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	return []netip.Addr{prefix.Addr()}, nil
}

func ParseEndpoint(endpoint string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", endpoint)
}

func GetConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "WireGuard", "Configurations")
	default:
		return "/etc/wireguard"
	}
}

func SetupInstructions(name string) string {
	filename := filepath.Join(GetConfigDir(), name+".conf")
	switch runtime.GOOS {
	case "windows":
		return fmt.Sprintf(`
WireGuard config saved. To bring up the interface:

1. Open WireGuard application
2. Import tunnel from: %s
3. Or run: wireguard /installtunnelservice %s

`, filename, filename)
	case "linux", "darwin":
		return fmt.Sprintf(`
WireGuard config saved. To bring up the interface:

  sudo wg-quick up %s

`, name)
	default:
		return fmt.Sprintf("WireGuard config saved to %s\n", filename)
	}
}
