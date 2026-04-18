package mesh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	meshv1 "github.com/bernardoforcillo/privatelayer/internal/gen/mesh/v1"
)

type PeerInfo struct {
	ID            string
	PublicKey     string
	Endpoint      string
	AllowedIPs    []string
	LastSeen      time.Time
	Online        bool
	Authenticated bool
	AuthMethod    string
}

type ServerConfig struct {
	Port             int
	CIDR             string
	Network          *net.IPNet
	HeartbeatTimeout time.Duration
	RequireAuth      bool
}

type Server struct {
	meshv1.UnimplementedMeshServiceServer
	config           *ServerConfig
	db               interface{}
	peers            map[string]*PeerInfo
	mu               sync.RWMutex
	heartbeatTimeout time.Duration
	peerStreams      map[string]meshv1.MeshService_StreamPeersServer
	streamMu         sync.RWMutex
	mapStreams       map[string]meshv1.MeshService_StreamMapServer
	mapStreamMu      sync.RWMutex
	peerIndex        int
	peerIndexMu      sync.Mutex
	authKeys         map[string]*PreAuthKey
	authMu           sync.RWMutex
}

type PreAuthKey struct {
	ID        string
	Key       string
	Reusable  bool
	Ephemeral bool
	Used      bool
	UsedBy    string
	ExpiresAt *time.Time
	CreatedAt time.Time
}

func NewServer(config *ServerConfig) *Server {
	if config.HeartbeatTimeout == 0 {
		config.HeartbeatTimeout = 60 * time.Second
	}
	return &Server{
		config:           config,
		peers:            make(map[string]*PeerInfo),
		heartbeatTimeout: config.HeartbeatTimeout,
		peerStreams:      make(map[string]meshv1.MeshService_StreamPeersServer),
		mapStreams:       make(map[string]meshv1.MeshService_StreamMapServer),
		authKeys:         make(map[string]*PreAuthKey),
	}
}

func (s *Server) AddPreAuthKey(key *PreAuthKey) {
	s.authMu.Lock()
	s.authKeys[key.Key] = key
	s.authMu.Unlock()
	log.Printf("Created pre-auth key: %s (reusable=%v, ephemeral=%v)\n", key.Key[:16], key.Reusable, key.Ephemeral)
}

func (s *Server) CreatePreAuthKey(reusable, ephemeral bool, expiresIn time.Duration) *PreAuthKey {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	keyStr := base64.URLEncoding.EncodeToString(bytes)

	key := &PreAuthKey{
		ID:        fmt.Sprintf("pak_%d", time.Now().UnixNano()),
		Key:       keyStr,
		Reusable:  reusable,
		Ephemeral: ephemeral,
		Used:      false,
		CreatedAt: time.Now(),
	}

	if expiresIn > 0 {
		t := time.Now().Add(expiresIn)
		key.ExpiresAt = &t
	}

	s.AddPreAuthKey(key)
	return key
}

func (s *Server) ValidatePreAuthKey(keyStr string) error {
	s.authMu.RLock()
	key, exists := s.authKeys[keyStr]
	s.authMu.RUnlock()

	if !exists {
		return fmt.Errorf("invalid pre-auth key")
	}

	if key.Used && !key.Reusable {
		return fmt.Errorf("pre-auth key already used")
	}

	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return fmt.Errorf("pre-auth key expired")
	}

	if !key.Reusable {
		s.authMu.Lock()
		key.Used = true
		s.authMu.Unlock()
	}

	return nil
}

func (s *Server) ListPreAuthKeys() []*PreAuthKey {
	s.authMu.RLock()
	defer s.authMu.RUnlock()

	keys := make([]*PreAuthKey, 0, len(s.authKeys))
	for _, k := range s.authKeys {
		keys = append(keys, k)
	}
	return keys
}

func (s *Server) DeletePreAuthKey(keyStr string) error {
	s.authMu.Lock()
	defer s.authMu.Unlock()

	if _, exists := s.authKeys[keyStr]; !exists {
		return fmt.Errorf("pre-auth key not found")
	}

	delete(s.authKeys, keyStr)
	log.Printf("Deleted pre-auth key")
	return nil
}

func (s *Server) Register(ctx context.Context, req *meshv1.RegisterRequest) (*meshv1.RegisterResponse, error) {
	// Validate pre-auth key if required
	authMethod := "none"
	if s.config.RequireAuth || req.GetAuthKey() != "" {
		if err := s.ValidatePreAuthKey(req.GetAuthKey()); err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
		authMethod = "preauthkey"
	}

	s.peerIndexMu.Lock()
	peerIP := s.nextIP()
	s.peerIndexMu.Unlock()

	peerInfo := &PeerInfo{
		ID:            req.Id,
		PublicKey:     req.PublicKey,
		Endpoint:      req.Endpoint,
		AllowedIPs:    []string{peerIP + "/32"},
		LastSeen:      time.Now(),
		Online:        true,
		Authenticated: authMethod != "none",
		AuthMethod:    authMethod,
	}

	s.mu.Lock()
	s.peers[req.Id] = peerInfo
	s.mu.Unlock()

	log.Printf("Peer registered: %s -> %s (%s) [auth=%s]\n", req.Id, peerIP, req.Endpoint, authMethod)

	s.broadcastPeerUpdate(req.Id)
	s.broadcastMapUpdate(req.Id)

	return &meshv1.RegisterResponse{
		Peers: s.getPeersList(),
	}, nil
}

func (s *Server) nextIP() string {
	if s.config.Network == nil {
		return fmt.Sprintf("10.0.%d.1", s.peerIndex%256)
	}

	ip := s.config.Network.IP.To4()
	ip[2] = byte(s.peerIndex >> 8)
	ip[3] = byte(s.peerIndex & 0xFF)
	s.peerIndex++

	return ip.String()
}

func (s *Server) Heartbeat(ctx context.Context, req *meshv1.HeartbeatRequest) (*meshv1.HeartbeatResponse, error) {
	s.mu.Lock()
	if peer, ok := s.peers[req.Id]; ok {
		peer.LastSeen = time.Now()
		peer.Online = true
	}
	s.mu.Unlock()

	return &meshv1.HeartbeatResponse{Success: true}, nil
}

func (s *Server) StreamPeers(req *meshv1.StreamPeersRequest, stream meshv1.MeshService_StreamPeersServer) error {
	s.streamMu.Lock()
	s.peerStreams[req.Id] = stream
	s.streamMu.Unlock()

	defer func() {
		s.streamMu.Lock()
		delete(s.peerStreams, req.Id)
		s.streamMu.Unlock()
	}()

	peers := s.getPeersList()
	if err := stream.Send(&meshv1.PeerList{Peers: peers}); err != nil {
		return err
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			if err := stream.Send(&meshv1.PeerList{Peers: s.getPeersList()}); err != nil {
				return err
			}
		}
	}
}

func (s *Server) Disconnect(ctx context.Context, req *meshv1.DisconnectRequest) (*meshv1.DisconnectResponse, error) {
	s.mu.Lock()
	if peer, ok := s.peers[req.Id]; ok {
		peer.Online = false
	}
	s.mu.Unlock()

	log.Printf("Peer disconnected: %s\n", req.Id)

	s.broadcastPeerUpdate(req.Id)
	s.broadcastMapUpdate(req.Id)

	return &meshv1.DisconnectResponse{Success: true}, nil
}

func (s *Server) UpdateStatus(ctx context.Context, req *meshv1.UpdateStatusRequest) (*meshv1.UpdateStatusResponse, error) {
	s.mu.Lock()
	if peer, ok := s.peers[req.NodeId]; ok {
		peer.Online = req.Online
		peer.LastSeen = time.Now()
	}
	s.mu.Unlock()

	return &meshv1.UpdateStatusResponse{
		Success:   true,
		Timestamp: time.Now().UnixMilli(),
	}, nil
}

func (s *Server) StreamMap(req *meshv1.StreamMapRequest, stream meshv1.MeshService_StreamMapServer) error {
	s.mapStreamMu.Lock()
	s.mapStreams[req.NodeId] = stream
	s.mapStreamMu.Unlock()

	defer func() {
		s.mapStreamMu.Lock()
		delete(s.mapStreams, req.NodeId)
		s.mapStreamMu.Unlock()
	}()

	if err := stream.Send(s.buildNetworkMap()); err != nil {
		return err
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			if err := stream.Send(s.buildNetworkMap()); err != nil {
				return err
			}
		}
	}
}

func (s *Server) GetNodes(ctx context.Context, req *meshv1.GetNodesRequest) (*meshv1.GetNodesResponse, error) {
	return &meshv1.GetNodesResponse{
		Nodes: s.getNodesList(req.OnlineOnly),
	}, nil
}

func (s *Server) getPeersList() []*meshv1.Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peers := make([]*meshv1.Peer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, &meshv1.Peer{
			Id:         p.ID,
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIps: p.AllowedIPs,
			Online:     p.Online,
			LastSeen:   p.LastSeen.UnixMilli(),
		})
	}
	return peers
}

func (s *Server) getNodesList(onlineOnly bool) []*meshv1.NodeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nodes := make([]*meshv1.NodeInfo, 0, len(s.peers))
	for _, p := range s.peers {
		if onlineOnly && !p.Online {
			continue
		}
		nodes = append(nodes, &meshv1.NodeInfo{
			Id:          p.ID,
			Hostname:    p.ID,
			PublicKey:   p.PublicKey,
			IpAddresses: p.AllowedIPs,
			Online:      p.Online,
			LastSeen:    p.LastSeen.UnixMilli(),
		})
	}
	return nodes
}

func (s *Server) buildNetworkMap() *meshv1.NetworkMap {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peers := make([]*meshv1.Peer, 0, len(s.peers))
	for _, p := range s.peers {
		if !p.Online {
			continue
		}
		peers = append(peers, &meshv1.Peer{
			Id:         p.ID,
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIps: p.AllowedIPs,
			Online:     p.Online,
			LastSeen:   p.LastSeen.UnixMilli(),
		})
	}

	return &meshv1.NetworkMap{
		NodeId:    "controlplane",
		Peers:     peers,
		Version:   time.Now().UnixMilli(),
		Timestamp: time.Now().UnixMilli(),
	}
}

func (s *Server) broadcastPeerUpdate(excludeID string) {
	peerList := &meshv1.PeerList{Peers: s.getPeersList()}

	s.streamMu.RLock()
	defer s.streamMu.RUnlock()

	for id, stream := range s.peerStreams {
		if id == excludeID {
			continue
		}
		if err := stream.Send(peerList); err != nil {
			log.Printf("Failed to send peer update to %s: %v\n", id, err)
		}
	}
}

func (s *Server) broadcastMapUpdate(excludeID string) {
	networkMap := s.buildNetworkMap()

	s.mapStreamMu.RLock()
	defer s.mapStreamMu.RUnlock()

	for id, stream := range s.mapStreams {
		if id == excludeID {
			continue
		}
		if err := stream.Send(networkMap); err != nil {
			log.Printf("Failed to send map update to %s: %v\n", id, err)
		}
	}
}

func (s *Server) CleanupStalePeers() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		for id, peer := range s.peers {
			if time.Since(peer.LastSeen) > s.heartbeatTimeout {
				peer.Online = false
				log.Printf("Peer expired: %s\n", id)
				s.broadcastPeerUpdate(id)
				s.broadcastMapUpdate(id)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Server) GetPeers() []*meshv1.Peer {
	return s.getPeersList()
}

func (s *Server) SetDatabase(db interface{}) {
	s.db = db
}
