package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	meshv1 "github.com/bernardoforcillo/privatelayer/internal/gen/mesh/v1"
	"github.com/bernardoforcillo/privatelayer/internal/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	conn       *grpc.ClientConn
	client     meshv1.MeshServiceClient
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
			log.Printf("Loaded config from: %s\n", viper.ConfigFileUsed())
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

	log.Printf("Starting PrivateLayer client: %s\n", nodeID)

	conn, err := grpc.Dial(controlAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to control plane: %w", err)
	}
	defer conn.Close()

	client := meshv1.NewMeshServiceClient(conn)
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
		conn:       conn,
		client:     client,
		ctx:        ctx,
		stopChan:   make(chan struct{}),
	}

	resp, err := client.Register(ctx, &meshv1.RegisterRequest{
		Id:         nodeID,
		PublicKey:  keyPair.PublicKey,
		Endpoint:   fmt.Sprintf("0.0.0.0:%d", listenPort),
		AllowedIps: nil,
	})
	if err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	log.Printf("Authenticated: %s\n", nodeID)

	if len(resp.Peers) > 0 {
		mc.localIP = resp.Peers[0].AllowedIps[0]
	}

	log.Printf("Assigned IP: %s\n", mc.localIP)

	mc.updatePeerConfig(resp.Peers)
	if err := mc.provisionWireGuard(userspace); err != nil {
		return err
	}

	mc.saveState(configDir)

	mc.running = true
	go mc.startPeerStream()
	go mc.startStatusUpdates()
	go mc.startNetworkMapStream()
	go mc.startReconnectLoop()

	log.Printf("Client running (daemon=%v): %s\n", daemonMode, nodeID)
	log.Printf("Node: %s, IP: %s, Interface: %s\n", nodeID, mc.localIP, interfaceName)
	log.Printf("Public key: %s\n", keyPair.PublicKey)

	if daemonMode {
		writePidFile(configDir)
		log.Println("Daemon started successfully")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	if daemonMode {
		signal.Notify(sigChan, syscall.SIGHUP)
	}

	<-sigChan

	log.Println("Shutting down...")
	mc.running = false
	close(mc.stopChan)

	client.Disconnect(ctx, &meshv1.DisconnectRequest{Id: nodeID})
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
			log.Printf("Userspace tunnel failed: %v, falling back to config file\n", err)
		} else {
			log.Printf("Userspace tunnel %s created\n", mc.ifaceName)
			return nil
		}
	}

	configFile, err := wireguard.SaveConfig(mc.wgConfig, configDir)
	if err != nil {
		return fmt.Errorf("failed to save WireGuard config: %w", err)
	}
	log.Printf("WireGuard config saved to: %s\n", configFile)
	return nil
}

func (mc *MeshClient) startPeerStream() {
	for mc.running {
		stream, err := mc.client.StreamPeers(mc.ctx, &meshv1.StreamPeersRequest{Id: mc.nodeID})
		if err != nil {
			log.Printf("Peer stream error: %v\n", err)
			select {
			case <-mc.stopChan:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		for {
			select {
			case <-mc.stopChan:
				return
			default:
				update, err := stream.Recv()
				if err != nil {
					log.Printf("Peer stream disconnected: %v\n", err)
					goto reconnect
				}
				log.Printf("Peer update: %d peers\n", len(update.Peers))
				mc.updatePeerConfig(update.Peers)
			}
		}
	reconnect:
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
			if _, err := mc.client.Heartbeat(mc.ctx, &meshv1.HeartbeatRequest{Id: mc.nodeID}); err != nil {
				log.Printf("Heartbeat failed: %v\n", err)
			}

			mc.client.UpdateStatus(mc.ctx, &meshv1.UpdateStatusRequest{
				NodeId:  mc.nodeID,
				Online:  true,
				Version: "1.0.0",
				State:   collectState(),
			})
		case <-mc.stopChan:
			return
		}
	}
}

func (mc *MeshClient) startNetworkMapStream() {
	for mc.running {
		stream, err := mc.client.StreamMap(mc.ctx, &meshv1.StreamMapRequest{NodeId: mc.nodeID})
		if err != nil {
			log.Printf("Network map stream error: %v\n", err)
			select {
			case <-mc.stopChan:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		for {
			select {
			case <-mc.stopChan:
				return
			default:
				update, err := stream.Recv()
				if err != nil {
					log.Printf("Network map stream disconnected: %v\n", err)
					goto reconnectNM
				}
				log.Printf("Network map: version=%d, peers=%d\n", update.Version, len(update.Peers))
				mc.updatePeerConfig(update.Peers)
			}
		}
	reconnectNM:
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
			if mc.conn == nil {
				log.Println("Connection lost, reconnecting...")
				mc.reconnect()
			}
		case <-mc.stopChan:
			return
		}
	}
}

func (mc *MeshClient) reconnect() {
	for i := 0; i < 5; i++ {
		conn, err := grpc.Dial(controlAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Printf("Reconnect attempt %d failed: %v\n", i+1, err)
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}

		mc.conn = conn
		mc.client = meshv1.NewMeshServiceClient(conn)
		log.Println("Reconnected to control plane")
		return
	}
	log.Println("Failed to reconnect after 5 attempts")
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
	log.Printf("Generated new key pair\n")

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
	log.Printf("Generated new node ID: %s\n", id)

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

	log.Printf("Installing PrivateLayer service...\n")
	log.Printf("Executable: %s\n", exePath)
	log.Printf("Config dir: %s\n", configDir)

	if runtime.GOOS == "windows" {
		return runAsService(configDir, exePath)
	}

	log.Println("Service installation not supported on this platform")
	return nil
}

func runUninstall(cmd *cobra.Command, args []string) error {
	log.Printf("Uninstalling PrivateLayer service...\n")

	if runtime.GOOS == "windows" {
		if err := stopService(); err != nil {
			log.Printf("Warning: Could not stop service: %v\n", err)
		}
		return removeService()
	}

	log.Println("Service uninstallation not supported on this platform")
	return nil
}
