package client

import (
	"context"
	"fmt"
	"time"

	meshv1 "github.com/bernardoforcillo/privatelayer/internal/gen/mesh/v1"
	"github.com/bernardoforcillo/privatelayer/internal/wireguard"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	ID         string
	PublicKey  string
	PrivateKey string
	Endpoint   string
	LocalIP    string

	controlPlaneAddr string
	client           meshv1.MeshServiceClient
	conn             *grpc.ClientConn
	stream           meshv1.MeshService_StreamPeersClient
}

type ClientConfig struct {
	ControlPlaneAddr string
	PrivateKey       string
	PublicKey        string
	Endpoint         string
	InterfaceName    string
}

func NewClient(cfg *ClientConfig) (*Client, error) {
	var publicKey, privateKey string

	if cfg.PrivateKey == "" || cfg.PublicKey == "" {
		keyPair, err := wireguard.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate keys: %w", err)
		}
		publicKey = keyPair.PublicKey
		privateKey = keyPair.PrivateKey
	} else {
		publicKey = cfg.PublicKey
		privateKey = cfg.PrivateKey
	}

	return &Client{
		ID:               generateNodeID(),
		PublicKey:        publicKey,
		PrivateKey:       privateKey,
		Endpoint:         cfg.Endpoint,
		controlPlaneAddr: cfg.ControlPlaneAddr,
	}, nil
}

func (c *Client) Connect() error {
	conn, err := grpc.Dial(c.controlPlaneAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to control plane: %w", err)
	}

	c.conn = conn
	c.client = meshv1.NewMeshServiceClient(conn)
	return nil
}

func (c *Client) Disconnect() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) Register() error {
	ctx := context.Background()

	resp, err := c.client.Register(ctx, &meshv1.RegisterRequest{
		Id:         c.ID,
		PublicKey:  c.PublicKey,
		Endpoint:   c.Endpoint,
		AllowedIps: []string{c.LocalIP},
	})
	if err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	c.LocalIP = resp.Peers[0].AllowedIps[0]
	return nil
}

func (c *Client) StreamPeers() error {
	ctx := context.Background()
	stream, err := c.client.StreamPeers(ctx, &meshv1.StreamPeersRequest{Id: c.ID})
	if err != nil {
		return err
	}
	c.stream = stream
	return nil
}

func (c *Client) Heartbeat() error {
	ctx := context.Background()
	_, err := c.client.Heartbeat(ctx, &meshv1.HeartbeatRequest{Id: c.ID})
	return err
}

func generateNodeID() string {
	return fmt.Sprintf("node-%d", time.Now().UnixNano())
}
