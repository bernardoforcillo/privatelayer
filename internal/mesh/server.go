package mesh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/bernardoforcillo/privatelayer/internal/db"
	meshv1 "github.com/bernardoforcillo/privatelayer/internal/gen/mesh/v1"
	"github.com/bernardoforcillo/privatelayer/internal/gen/mesh/v1/meshv1connect"
)

var (
	nodesActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "privatelayer_nodes_active",
		Help: "Online nodes per org",
	}, []string{"org_id"})

	registrationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "privatelayer_registrations_total",
		Help: "Total node registrations",
	}, []string{"org_id"})

	heartbeatsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "privatelayer_heartbeats_total",
		Help: "Total heartbeats",
	}, []string{"org_id"})

	peerStreamsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "privatelayer_peer_streams_active",
		Help: "Active peer streams",
	})
)

type PeerInfo struct {
	ID         string
	OrgID      uuid.UUID
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
	LastSeen   time.Time
	Online     bool
}

type ServerConfig struct {
	Port             int
	CIDR             string
	Network          *net.IPNet
	HeartbeatTimeout time.Duration
}

type Server struct {
	meshv1connect.UnimplementedMeshServiceHandler
	config           *ServerConfig
	database         *db.Database
	peers            map[string]*PeerInfo
	mu               sync.RWMutex
	heartbeatTimeout time.Duration
	peerStreams       map[string]*connect.ServerStream[meshv1.PeerList]
	streamMu         sync.RWMutex
	mapStreams        map[string]*connect.ServerStream[meshv1.NetworkMap]
	mapStreamMu      sync.RWMutex
}

func NewServer(config *ServerConfig, database *db.Database) *Server {
	if config.HeartbeatTimeout == 0 {
		config.HeartbeatTimeout = 60 * time.Second
	}
	s := &Server{
		config:           config,
		database:         database,
		peers:            make(map[string]*PeerInfo),
		heartbeatTimeout: config.HeartbeatTimeout,
		peerStreams:       make(map[string]*connect.ServerStream[meshv1.PeerList]),
		mapStreams:        make(map[string]*connect.ServerStream[meshv1.NetworkMap]),
	}
	s.loadStateFromDB()
	return s
}

func (s *Server) loadStateFromDB() {
	nodes, err := s.database.GetAllNodes()
	if err != nil {
		slog.Error("failed to load nodes from DB", "err", err)
		return
	}
	for _, n := range nodes {
		s.peers[n.MachineKey] = &PeerInfo{
			ID:         n.MachineKey,
			OrgID:      n.OrgID,
			PublicKey:  n.PublicKey,
			AllowedIPs: []string(n.IPAddresses),
			LastSeen:   n.LastSeen,
			Online:     n.Online,
		}
	}
	slog.Info("loaded nodes from DB", "count", len(nodes))
}

func (s *Server) Register(ctx context.Context, req *connect.Request[meshv1.RegisterRequest]) (*connect.Response[meshv1.RegisterResponse], error) {
	authKey := req.Msg.GetAuthKey()
	if authKey == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("auth_key required"))
	}

	pak, err := s.database.GetPreAuthKey(authKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid auth key"))
	}
	if pak.Used && !pak.Reusable {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("auth key already used"))
	}
	if pak.ExpiresAt != nil && time.Now().After(*pak.ExpiresAt) {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("auth key expired"))
	}

	org, err := s.database.GetOrgByID(pak.OrgID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("org not found"))
	}

	peerIP, err := s.database.AllocateIP(org.ID, org.CIDR)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("IP allocation failed: %w", err))
	}

	nodeID := req.Msg.Id
	if nodeID == "" {
		nodeID = uuid.New().String()
	}

	dbNode := &db.Node{
		MachineKey:  nodeID,
		OrgID:       org.ID,
		PublicKey:   req.Msg.PublicKey,
		IPAddresses: db.StringJSON{peerIP + "/32"},
		Hostname:    nodeID,
		Online:      true,
		LastSeen:    time.Now(),
	}
	if err := s.database.CreateNode(dbNode); err != nil {
		dbNode2, _ := s.database.GetNodeByMachineKey(nodeID)
		if dbNode2 != nil {
			dbNode2.Online = true
			dbNode2.LastSeen = time.Now()
			_ = s.database.UpdateNode(dbNode2)
		}
	}

	if !pak.Reusable {
		_ = s.database.UsePreAuthKey(authKey, nodeID)
	}

	peerInfo := &PeerInfo{
		ID:         nodeID,
		OrgID:      org.ID,
		PublicKey:  req.Msg.PublicKey,
		Endpoint:   req.Msg.Endpoint,
		AllowedIPs: []string{peerIP + "/32"},
		LastSeen:   time.Now(),
		Online:     true,
	}

	s.mu.Lock()
	s.peers[nodeID] = peerInfo
	s.mu.Unlock()

	registrationsTotal.WithLabelValues(org.ID.String()).Inc()
	nodesActive.WithLabelValues(org.ID.String()).Inc()

	slog.Info("peer registered", "node_id", nodeID, "ip", peerIP, "org", org.Slug)

	s.broadcastPeerUpdate(nodeID, org.ID)
	s.broadcastMapUpdate(nodeID, org.ID)

	return connect.NewResponse(&meshv1.RegisterResponse{
		Peers: s.getPeersList(org.ID),
	}), nil
}

func (s *Server) Heartbeat(ctx context.Context, req *connect.Request[meshv1.HeartbeatRequest]) (*connect.Response[meshv1.HeartbeatResponse], error) {
	s.mu.Lock()
	if peer, ok := s.peers[req.Msg.Id]; ok {
		peer.LastSeen = time.Now()
		peer.Online = true
		heartbeatsTotal.WithLabelValues(peer.OrgID.String()).Inc()
	}
	s.mu.Unlock()
	return connect.NewResponse(&meshv1.HeartbeatResponse{Success: true}), nil
}

func (s *Server) StreamPeers(ctx context.Context, req *connect.Request[meshv1.StreamPeersRequest], stream *connect.ServerStream[meshv1.PeerList]) error {
	id := req.Msg.Id

	s.mu.RLock()
	peer, exists := s.peers[id]
	s.mu.RUnlock()
	if !exists {
		return connect.NewError(connect.CodeNotFound, fmt.Errorf("node not registered"))
	}
	orgID := peer.OrgID

	s.streamMu.Lock()
	s.peerStreams[id] = stream
	s.streamMu.Unlock()
	peerStreamsActive.Inc()

	defer func() {
		s.streamMu.Lock()
		delete(s.peerStreams, id)
		s.streamMu.Unlock()
		peerStreamsActive.Dec()
	}()

	if err := stream.Send(&meshv1.PeerList{Peers: s.getPeersList(orgID)}); err != nil {
		return err
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := stream.Send(&meshv1.PeerList{Peers: s.getPeersList(orgID)}); err != nil {
				return err
			}
		}
	}
}

func (s *Server) Disconnect(ctx context.Context, req *connect.Request[meshv1.DisconnectRequest]) (*connect.Response[meshv1.DisconnectResponse], error) {
	s.mu.Lock()
	if peer, ok := s.peers[req.Msg.Id]; ok {
		peer.Online = false
		nodesActive.WithLabelValues(peer.OrgID.String()).Dec()
		orgID := peer.OrgID
		s.mu.Unlock()
		s.broadcastPeerUpdate(req.Msg.Id, orgID)
		s.broadcastMapUpdate(req.Msg.Id, orgID)
	} else {
		s.mu.Unlock()
	}
	slog.Info("peer disconnected", "node_id", req.Msg.Id)
	return connect.NewResponse(&meshv1.DisconnectResponse{Success: true}), nil
}

func (s *Server) UpdateStatus(ctx context.Context, req *connect.Request[meshv1.UpdateStatusRequest]) (*connect.Response[meshv1.UpdateStatusResponse], error) {
	s.mu.Lock()
	if peer, ok := s.peers[req.Msg.NodeId]; ok {
		peer.Online = req.Msg.Online
		peer.LastSeen = time.Now()
	}
	s.mu.Unlock()
	return connect.NewResponse(&meshv1.UpdateStatusResponse{
		Success:   true,
		Timestamp: time.Now().UnixMilli(),
	}), nil
}

func (s *Server) StreamMap(ctx context.Context, req *connect.Request[meshv1.StreamMapRequest], stream *connect.ServerStream[meshv1.NetworkMap]) error {
	id := req.Msg.NodeId

	s.mu.RLock()
	peer, exists := s.peers[id]
	s.mu.RUnlock()
	if !exists {
		return connect.NewError(connect.CodeNotFound, fmt.Errorf("node not registered"))
	}
	orgID := peer.OrgID

	s.mapStreamMu.Lock()
	s.mapStreams[id] = stream
	s.mapStreamMu.Unlock()

	defer func() {
		s.mapStreamMu.Lock()
		delete(s.mapStreams, id)
		s.mapStreamMu.Unlock()
	}()

	if err := stream.Send(s.buildNetworkMap(orgID)); err != nil {
		return err
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := stream.Send(s.buildNetworkMap(orgID)); err != nil {
				return err
			}
		}
	}
}

func (s *Server) GetNodes(ctx context.Context, req *connect.Request[meshv1.GetNodesRequest]) (*connect.Response[meshv1.GetNodesResponse], error) {
	orgID, ok := db.OrgIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing org context"))
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	nodes := make([]*meshv1.NodeInfo, 0)
	for _, p := range s.peers {
		if p.OrgID != orgID {
			continue
		}
		if req.Msg.OnlineOnly && !p.Online {
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
	return connect.NewResponse(&meshv1.GetNodesResponse{Nodes: nodes}), nil
}

func (s *Server) getPeersList(orgID uuid.UUID) []*meshv1.Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peers := make([]*meshv1.Peer, 0)
	for _, p := range s.peers {
		if p.OrgID != orgID {
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
	return peers
}

func (s *Server) buildNetworkMap(orgID uuid.UUID) *meshv1.NetworkMap {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peers := make([]*meshv1.Peer, 0)
	for _, p := range s.peers {
		if p.OrgID != orgID || !p.Online {
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

func (s *Server) broadcastPeerUpdate(excludeID string, orgID uuid.UUID) {
	peerList := &meshv1.PeerList{Peers: s.getPeersList(orgID)}
	s.streamMu.RLock()
	defer s.streamMu.RUnlock()
	for id, stream := range s.peerStreams {
		if id == excludeID {
			continue
		}
		s.mu.RLock()
		peer, ok := s.peers[id]
		s.mu.RUnlock()
		if !ok || peer.OrgID != orgID {
			continue
		}
		if err := stream.Send(peerList); err != nil {
			slog.Warn("failed to send peer update", "node_id", id, "err", err)
		}
	}
}

func (s *Server) broadcastMapUpdate(excludeID string, orgID uuid.UUID) {
	networkMap := s.buildNetworkMap(orgID)
	s.mapStreamMu.RLock()
	defer s.mapStreamMu.RUnlock()
	for id, stream := range s.mapStreams {
		if id == excludeID {
			continue
		}
		s.mu.RLock()
		peer, ok := s.peers[id]
		s.mu.RUnlock()
		if !ok || peer.OrgID != orgID {
			continue
		}
		if err := stream.Send(networkMap); err != nil {
			slog.Warn("failed to send map update", "node_id", id, "err", err)
		}
	}
}

func (s *Server) CleanupStalePeers() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		for id, peer := range s.peers {
			if time.Since(peer.LastSeen) > s.heartbeatTimeout && peer.Online {
				peer.Online = false
				nodesActive.WithLabelValues(peer.OrgID.String()).Dec()
				slog.Info("peer expired", "node_id", id)
				orgID := peer.OrgID
				s.mu.Unlock()
				s.broadcastPeerUpdate(id, orgID)
				s.broadcastMapUpdate(id, orgID)
				s.mu.Lock()
			}
		}
		s.mu.Unlock()
	}
}

// generatePreAuthKey creates a random pre-auth key string (used internally).
func generatePreAuthKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
