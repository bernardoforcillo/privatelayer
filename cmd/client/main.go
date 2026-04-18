package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	meshv1 "github.com/bernardoforcillo/privatelayer/internal/gen/mesh/v1"
	meshv1connect "github.com/bernardoforcillo/privatelayer/internal/gen/mesh/v1/meshv1connect"
	"github.com/bernardoforcillo/privatelayer/internal/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	controlAddr   string
	interfaceName string
	userspace     bool
	authKey       string
	daemonMode    bool
	configDir     string
)

type MeshClient struct {
	nodeID     string
	localIP    string
	privateKey string
	publicKey  string
	listenPort int
	ifaceName  string
	httpClient *http.Client
	client     meshv1connect.MeshServiceClient
	controlURL string
	ctx        context.Context
	tunnel     *wireguard.Tunnel
	wgConfig   *wireguard.InterfaceConfig
	running    bool
	stopChan   chan struct{}
}

func main() {
	cobra.OnInitialize(initConfig)

	rootCmd := &cobra.Command{
		Use:   "client",
		Short: "PrivateLayer Mesh Client",
		Long:  `Mesh VPN client that connects to control plane`,
	}

	connectCmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect to mesh network (interactive)",
		RunE:  runClient,
	}

	daemonCmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run as background daemon",
		RunE:  runDaemon,
	}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Run as daemon (alias for daemon)",
		RunE:  runDaemon,
	}

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install as Windows service",
		RunE:  runInstall,
	}

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall Windows service",
		RunE:  runUninstall,
	}

	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)

	rootCmd.PersistentFlags().StringVar(&controlAddr, "control", "localhost:8080", "control plane address")
	rootCmd.PersistentFlags().StringVarP(&interfaceName, "interface", "i", "wg0", "wireguard interface name")
	rootCmd.PersistentFlags().BoolVar(&userspace, "userspace", true, "use userspace tunnel")
	rootCmd.PersistentFlags().StringVar(&authKey, "auth-key", "", "pre-authentication key")
	rootCmd.PersistentFlags().BoolVarP(&daemonMode, "daemon", "d", false, "run as daemon")
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "", "config directory")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initConfig() {
	// Note: flags are parsed after initConfig, so we rely on flag defaults, not viper defaults
	if configDir != "" {
		viper.AddConfigPath(configDir)
		viper.SetConfigName("client")
		viper.SetConfigType("yaml")
		if err := viper.ReadInConfig(); err == nil {
			slog.Info("loaded config", "file", viper.ConfigFileUsed())
			// Use config file values (higher precedence than defaults)
			if c := viper.GetString("control"); c != "" {
				controlAddr = c
			}
			if i := viper.GetString("interface"); i != "" {
				interfaceName = i
			}
			if u := viper.GetBool("userspace"); u != userspace {
				userspace = u
			}
		}
	}
}

func runDaemon(cmd *cobra.Command, args []string) error {
	daemonMode = true
	return runClient(cmd, args)
}

func runClient(cmd *cobra.Command, args []string) error {
	// Use values from flags (which are already set by cobra)
	// If config file was loaded in initConfig, values are already in the variables

	if configDir == "" {
		configDir = getDefaultConfigDir()
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	keyPair, err := loadOrGenerateKeyPair(configDir)
	if err != nil {
		return fmt.Errorf("failed to load keys: %w", err)
	}

	nodeID, err := loadOrGenerateNodeID(configDir)
	if err != nil {
		return fmt.Errorf("failed to load node ID: %w", err)
	}

	slog.Info("starting PrivateLayer client", "nodeID", nodeID)

	tlsSkipVerify := viper.GetBool("tls_insecure_skip_verify")
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: tlsSkipVerify},
			ForceAttemptHTTP2: true,
		},
	}

	controlURL := controlAddr
	if !strings.HasPrefix(controlURL, "http") {
		controlURL = "https://" + controlURL
	}

	client := meshv1connect.NewMeshServiceClient(httpClient, controlURL)
	ctx := context.Background()

	listenPort, err := wireguard.GetFreePort()
	if err != nil {
		listenPort = 51820
	}

	mc := &MeshClient{
		nodeID:     nodeID,
		privateKey: keyPair.PrivateKey,
		publicKey:  keyPair.PublicKey,
		listenPort: listenPort,
		ifaceName:  interfaceName,
		httpClient: httpClient,
		client:     client,
		controlURL: controlURL,
		ctx:        ctx,
		stopChan:   make(chan struct{}),
	}

	resp, err := client.Register(ctx, connect.NewRequest(&meshv1.RegisterRequest{
		Id:        nodeID,
		PublicKey: keyPair.PublicKey,
		Endpoint:  fmt.Sprintf("0.0.0.0:%d", listenPort),
		AuthKey:   authKey,
	}))
	if err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	slog.Info("authenticated", "nodeID", nodeID)

	peers := resp.Msg.Peers
	if len(peers) > 0 {
		mc.localIP = peers[0].AllowedIps[0]
	}

	slog.Info("assigned IP", "ip", mc.localIP)

	mc.updatePeerConfig(peers)
	if err := mc.provisionWireGuard(userspace); err != nil {
		return err
	}

	mc.saveState(configDir)

	mc.running = true
	go mc.startPeerStream()
	go mc.startStatusUpdates()
	go mc.startNetworkMapStream()
	go mc.startReconnectLoop()

	slog.Info("client running", "daemon", daemonMode, "nodeID", nodeID)
	slog.Info("node info", "nodeID", nodeID, "ip", mc.localIP, "interface", interfaceName)
	slog.Info("public key", "key", keyPair.PublicKey)

	if daemonMode {
		writePidFile(configDir)
		slog.Info("daemon started successfully")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	if daemonMode {
		signal.Notify(sigChan, syscall.SIGHUP)
	}

	<-sigChan

	slog.Info("shutting down...")
	mc.running = false
	close(mc.stopChan)

	mc.client.Disconnect(ctx, connect.NewRequest(&meshv1.DisconnectRequest{Id: nodeID}))
	mc.cleanup()

	removePidFile(configDir)
	fmt.Println("Shutdown complete")
	return nil
}

func (mc *MeshClient) updatePeerConfig(peers []*meshv1.Peer) {
	peerConfigs := make([]wireguard.PeerConfig, 0)
	for _, p := range peers {
		if p.Id == mc.nodeID {
			continue
		}
		peerConfigs = append(peerConfigs, wireguard.PeerConfig{
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIPs: p.AllowedIps,
		})
	}

	mc.wgConfig = &wireguard.InterfaceConfig{
		Name:       mc.ifaceName,
		PrivateKey: mc.privateKey,
		Address:    mc.localIP,
		ListenPort: mc.listenPort,
		Peers:      peerConfigs,
	}
}

func (mc *MeshClient) provisionWireGuard(userspace bool) error {
	var err error

	if userspace {
		mc.tunnel, err = wireguard.CreateTunnel(mc.ifaceName)
		if err != nil {
			slog.Warn("userspace tunnel failed, falling back to config file", "err", err)
		} else {
			slog.Info("userspace tunnel created", "interface", mc.ifaceName)
			return nil
		}
	}

	configFile, err := wireguard.SaveConfig(mc.wgConfig, configDir)
	if err != nil {
		return fmt.Errorf("failed to save WireGuard config: %w", err)
	}
	slog.Info("WireGuard config saved", "path", configFile)
	return nil
}

func (mc *MeshClient) startPeerStream() {
	for mc.running {
		stream, err := mc.client.StreamPeers(mc.ctx, connect.NewRequest(&meshv1.StreamPeersRequest{Id: mc.nodeID}))
		if err != nil {
			slog.Warn("peer stream error", "err", err)
			select {
			case <-mc.stopChan:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		for stream.Receive() {
			select {
			case <-mc.stopChan:
				return
			default:
				mc.updatePeerConfig(stream.Msg().Peers)
			}
		}
		if err := stream.Err(); err != nil {
			slog.Warn("peer stream disconnected", "err", err)
		}

		select {
		case <-mc.stopChan:
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (mc *MeshClient) startStatusUpdates() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !mc.running {
				return
			}
			if _, err := mc.client.Heartbeat(mc.ctx, connect.NewRequest(&meshv1.HeartbeatRequest{Id: mc.nodeID})); err != nil {
				slog.Warn("heartbeat failed", "err", err)
			}

			mc.client.UpdateStatus(mc.ctx, connect.NewRequest(&meshv1.UpdateStatusRequest{
				NodeId:  mc.nodeID,
				Online:  true,
				Version: "1.0.0",
				State:   collectState(),
			}))
		case <-mc.stopChan:
			return
		}
	}
}

func (mc *MeshClient) startNetworkMapStream() {
	for mc.running {
		stream, err := mc.client.StreamMap(mc.ctx, connect.NewRequest(&meshv1.StreamMapRequest{NodeId: mc.nodeID}))
		if err != nil {
			slog.Warn("network map stream error", "err", err)
			select {
			case <-mc.stopChan:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		for stream.Receive() {
			select {
			case <-mc.stopChan:
				return
			default:
				msg := stream.Msg()
				slog.Info("network map update", "version", msg.Version, "peers", len(msg.Peers))
				mc.updatePeerConfig(msg.Peers)
			}
		}
		if err := stream.Err(); err != nil {
			slog.Warn("network map stream disconnected", "err", err)
		}

		select {
		case <-mc.stopChan:
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (mc *MeshClient) startReconnectLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !mc.running {
				return
			}
			mc.reconnect()
		case <-mc.stopChan:
			return
		}
	}
}

func (mc *MeshClient) reconnect() {
	mc.client = meshv1connect.NewMeshServiceClient(mc.httpClient, mc.controlURL)
	slog.Info("reconnected to control plane")
}

func (mc *MeshClient) cleanup() {
	if mc.tunnel != nil {
		mc.tunnel.Close()
	}
}

func getDefaultConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "privatelayer")
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "privatelayer")
	default:
		return filepath.Join(os.Getenv("HOME"), ".config", "privatelayer")
	}
}

func loadOrGenerateKeyPair(configDir string) (*wireguard.KeyPair, error) {
	keyFile := filepath.Join(configDir, "keypair.json")

	data, err := os.ReadFile(keyFile)
	if err == nil {
		var kp wireguard.KeyPair
		if err := json.Unmarshal(data, &kp); err == nil {
			return &kp, nil
		}
	}

	kp, err := wireguard.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	data, _ = json.Marshal(kp)
	os.WriteFile(keyFile, data, 0600)
	slog.Info("generated new key pair")

	return kp, nil
}

func loadOrGenerateNodeID(configDir string) (string, error) {
	idFile := filepath.Join(configDir, "nodeid.txt")

	data, err := os.ReadFile(idFile)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id, nil
		}
	}

	id := fmt.Sprintf("node-%d", time.Now().UnixNano())
	os.WriteFile(idFile, []byte(id), 0600)
	slog.Info("generated new node ID", "nodeID", id)

	return id, nil
}

func (mc *MeshClient) saveState(configDir string) {
	state := map[string]interface{}{
		"node_id":    mc.nodeID,
		"local_ip":   mc.localIP,
		"public_key": mc.publicKey,
		"interface":  mc.ifaceName,
	}

	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile(filepath.Join(configDir, "state.json"), data, 0600)
}

func writePidFile(configDir string) {
	pid := os.Getpid()
	os.WriteFile(filepath.Join(configDir, "daemon.pid"), []byte(fmt.Sprintf("%d", pid)), 0644)
}

func removePidFile(configDir string) {
	os.Remove(filepath.Join(configDir, "daemon.pid"))
}

func collectState() *meshv1.State {
	hostname, _ := os.Hostname()

	return &meshv1.State{
		Timestamp: time.Now().UnixMilli(),
		System: &meshv1.SystemInfo{
			Hostname: hostname,
			Os:       runtime.GOOS,
			Arch:     runtime.GOARCH,
		},
		Network: &meshv1.NetworkInfo{
			NatType: "unknown",
		},
		Wireguard: &meshv1.WireGuardInfo{
			InterfaceName: "wg0",
		},
	}
}

func runInstall(cmd *cobra.Command, args []string) error {
	if configDir == "" {
		configDir = getDefaultConfigDir()
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	slog.Info("installing PrivateLayer service", "executable", exePath, "configDir", configDir)

	if runtime.GOOS == "windows" {
		return runAsService(configDir, exePath)
	}

	slog.Warn("service installation not supported on this platform")
	return nil
}

func runUninstall(cmd *cobra.Command, args []string) error {
	slog.Info("uninstalling PrivateLayer service")

	if runtime.GOOS == "windows" {
		if err := stopService(); err != nil {
			slog.Warn("could not stop service", "err", err)
		}
		return removeService()
	}

	slog.Warn("service uninstallation not supported on this platform")
	return nil
}
