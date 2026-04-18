package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bernardoforcillo/privatelayer/internal/mesh"
	meshv1 "github.com/bernardoforcillo/privatelayer/internal/gen/mesh/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

var (
	cfgFile     string
	port        int
	cidr        string
	stateFile   string
	peerTimeout int
)

func main() {
	cobra.OnInitialize(initConfig)

	rootCmd := &cobra.Command{
		Use:   "controlplane",
		Short: "PrivateLayer Control Plane",
		Long:  `Mesh VPN control plane for peer coordination via gRPC`,
	}

	serverCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the control plane server",
		RunE:  runServer,
	}

	rootCmd.AddCommand(serverCmd)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")
	rootCmd.PersistentFlags().IntVarP(&port, "port", "p", 8080, "gRPC listen port")
	rootCmd.PersistentFlags().StringVar(&cidr, "cidr", "10.0.0.0/8", "mesh network CIDR")
	rootCmd.PersistentFlags().StringVar(&stateFile, "state", "", "state file for persistence")
	rootCmd.PersistentFlags().IntVar(&peerTimeout, "peer-timeout", 60, "peer timeout in seconds")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	viper.SetDefault("port", 8080)
	viper.SetDefault("cidr", "10.0.0.0/8")
	viper.SetDefault("peer-timeout", 60)

	if err := viper.ReadInConfig(); err == nil {
		log.Printf("Using config file: %s\n", viper.ConfigFileUsed())
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	port = viper.GetInt("port")
	cidr = viper.GetString("cidr")
	stateFile = viper.GetString("state")
	peerTimeout = viper.GetInt("peer-timeout")

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	config := &mesh.ServerConfig{
		Port:             port,
		CIDR:             cidr,
		Network:          ipnet,
		HeartbeatTimeout: time.Duration(peerTimeout) * time.Second,
	}

	server := mesh.NewServer(config)

	grpcServer := grpc.NewServer()
	meshv1.RegisterMeshServiceServer(grpcServer, server)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}

	go server.CleanupStalePeers()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nShutting down control plane...")
		grpcServer.GracefulStop()
	}()

	log.Printf("Control plane listening on :%d\n", port)
	log.Printf("Network CIDR: %s\n", cidr)
	log.Printf("gRPC/HTTP2 transport")

	return grpcServer.Serve(listener)
}
