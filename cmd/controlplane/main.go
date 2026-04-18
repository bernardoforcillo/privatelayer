package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/bernardoforcillo/privatelayer/internal/api"
	"github.com/bernardoforcillo/privatelayer/internal/db"
	managementv1connect "github.com/bernardoforcillo/privatelayer/internal/gen/management/v1/managementv1connect"
	meshv1connect "github.com/bernardoforcillo/privatelayer/internal/gen/mesh/v1/meshv1connect"
	"github.com/bernardoforcillo/privatelayer/internal/mesh"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var cfgFile string

func main() {
	rootCmd := &cobra.Command{Use: "controlplane", Short: "PrivateLayer Control Plane"}
	serveCmd := &cobra.Command{Use: "serve", Short: "Start the control plane", RunE: runServer}

	rootCmd.AddCommand(serveCmd)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func setupLogger() {
	format := viper.GetString("log_format")
	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stdout, nil)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, nil)
	}
	slog.SetDefault(slog.New(handler))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}
	viper.SetEnvPrefix("PL")
	viper.AutomaticEnv()
	viper.SetDefault("port", 8080)
	viper.SetDefault("metrics_port", 9090)
	viper.SetDefault("cidr", "10.0.0.0/8")
	viper.SetDefault("peer_timeout", 60)
	viper.SetDefault("dev_mode", false)
	viper.SetDefault("log_format", "json")
	if err := viper.ReadInConfig(); err == nil {
		slog.Info("loaded config", "file", viper.ConfigFileUsed())
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	initConfig()
	setupLogger()

	database, err := db.NewDatabase(&db.Config{
		Type:            viper.GetString("database.type"),
		DSN:             viper.GetString("database.dsn"),
		MaxOpenConns:    viper.GetInt("database.max_open_conns"),
		MaxIdleConns:    viper.GetInt("database.max_idle_conns"),
		ConnMaxLifetime: viper.GetDuration("database.conn_max_lifetime"),
	})
	if err != nil {
		return fmt.Errorf("database init failed: %w", err)
	}
	defer database.Close()

	serverConfig := &mesh.ServerConfig{
		Port:             viper.GetInt("port"),
		CIDR:             viper.GetString("cidr"),
		HeartbeatTimeout: time.Duration(viper.GetInt("peer_timeout")) * time.Second,
	}
	_, ipnet, err := net.ParseCIDR(serverConfig.CIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}
	serverConfig.Network = ipnet

	meshServer := mesh.NewServer(serverConfig, database)
	managementSvc := api.NewManagementService(database)

	bootstrapKey := viper.GetString("bootstrap_key")
	interceptor := api.NewAPIKeyInterceptor(database, bootstrapKey)

	mux := http.NewServeMux()
	meshPath, meshHandler := meshv1connect.NewMeshServiceHandler(
		meshServer,
		connect.WithInterceptors(mesh.NewMeshNodeInterceptor(meshServer)),
	)
	mux.Handle(meshPath, meshHandler)
	mux.Handle(managementv1connect.NewManagementServiceHandler(
		managementSvc,
		connect.WithInterceptors(interceptor),
	))

	go meshServer.CleanupStalePeers()

	metricsPort := viper.GetInt("metrics_port")
	go func() {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		addr := fmt.Sprintf(":%d", metricsPort)
		slog.Info("metrics server listening", "addr", addr)
		if err := http.ListenAndServe(addr, metricsMux); err != nil {
			slog.Error("metrics server error", "err", err)
		}
	}()

	port := viper.GetInt("port")
	addr := fmt.Sprintf(":%d", port)

	tlsCert, tlsKey := viper.GetString("tls_cert_file"), viper.GetString("tls_key_file")
	devMode := viper.GetBool("dev_mode")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if tlsCert != "" && tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			return fmt.Errorf("failed to load TLS cert: %w", err)
		}
		srv := &http.Server{
			Addr:      addr,
			Handler:   mux,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		}
		slog.Info("control plane listening (TLS)", "addr", addr)
		go func() {
			<-sigChan
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				slog.Error("shutdown error", "err", err)
			}
		}()
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}

	if devMode {
		slog.Warn("dev mode: using self-signed certificate")
		cert, err := generateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("self-signed cert failed: %w", err)
		}
		srv := &http.Server{
			Addr:      addr,
			Handler:   mux,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		}
		slog.Info("control plane listening (dev TLS)", "addr", addr)
		go func() {
			<-sigChan
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				slog.Error("shutdown error", "err", err)
			}
		}()
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}

	// H2C (plain HTTP/2) for deployments that terminate TLS upstream
	srv := &http.Server{
		Addr:    addr,
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}
	slog.Info("control plane listening (h2c)", "addr", addr)
	go func() {
		<-sigChan
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("shutdown error", "err", err)
		}
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"PrivateLayer Dev"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}
