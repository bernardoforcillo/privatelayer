package derp

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/bernardoforcillo/privatelayer/internal/db"
)

const (
	ServerVersion    = 2
	DefaultStunPort  = 3478
	DefaultDerpPort  = 443
	MaxPacketSize    = 65536
	HandshakeTimeout = 10 * time.Second
)

type Server struct {
	_addr     *net.UDPAddr
	_stunAddr *net.UDPAddr
	_udpConn  *net.UDPConn
	_tcpLn    net.Listener
	_streams  map[string]*Stream
	_mu       sync.RWMutex
	_database *db.Database
	_orgID    db.StringJSON
}

type Stream struct {
	nodeID string
	peerID string
	queue  chan []byte
	closed bool
}

type Message struct {
	Opcode     uint8
	SourceNode string
	TargetNode string
	Payload    []byte
}

const (
	OpForward   = 0x01
	OpHandshake = 0x02
	OpPing      = 0x03
	OpPong      = 0x04
	OpClose     = 0x05
)

func (s *Server) ListenAndServe(dDerpPort, dStunPort int) error {
	var err error

	udpAddr := &net.UDPAddr{IP: net.IPv4zero, Port: dDerpPort}
	s._udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on DERP UDP: %w", err)
	}

	s._stunAddr = &net.UDPAddr{IP: net.IPv4zero, Port: dStunPort}
	stunConn, err := net.ListenUDP("udp", s._stunAddr)
	if err != nil {
		s._udpConn.Close()
		return fmt.Errorf("failed to listen on STUN UDP: %w", err)
	}
	_ = stunConn

	s._streams = make(map[string]*Stream)

	go s.serveUDP()
	go s.serveSTUN()

	slog.Info("DERP server started", "derp_port", dDerpPort, "stun_port", dStunPort)

	return nil
}

func (s *Server) serveUDP() {
	buf := make([]byte, MaxPacketSize)
	for {
		n, addr, err := s._udpConn.ReadFromUDP(buf)
		if err != nil {
			if s._udpConn == nil {
				return
			}
			slog.Error("DERP UDP read error", "err", err)
			continue
		}

		go s.handlePacket(buf[:n], addr)
	}
}

func (s *Server) handlePacket(data []byte, src *net.UDPAddr) {
	if len(data) < 2 {
		return
	}

	opcode := data[0]

	switch opcode {
	case OpForward:
		s.handleForward(data[1:])
	case OpPing:
		s.handlePing(src)
	}
}

func (s *Server) handleForward(data []byte) {
	if len(data) < 64 {
		return
	}

	_ = string(data[:32]) // srcNode (reserved for future use)
	tgtNode := string(data[32:64])
	payload := data[64:]

	s._mu.RLock()
	stream, ok := s._streams[tgtNode]
	s._mu.RUnlock()

	if !ok {
		return
	}

	select {
	case stream.queue <- payload:
	default:
		slog.Warn("stream queue full", "node", tgtNode)
	}
}

func (s *Server) handlePing(src *net.UDPAddr) {
	resp := make([]byte, 5)
	resp[0] = OpPong
	binary.BigEndian.PutUint32(resp[1:5], uint32(time.Now().Unix()))
	_, _ = s._udpConn.WriteToUDP(resp, src)
}

func (s *Server) serveSTUN() {
	buf := make([]byte, MaxPacketSize)
	ln, err := net.ListenUDP("udp", s._stunAddr)
	if err != nil {
		slog.Error("STUN server failed", "err", err)
		return
	}

	for {
		n, addr, err := ln.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		go s.handleSTUNRequest(buf[:n], addr, ln)
	}
}

func (s *Server) handleSTUNRequest(data []byte, addr *net.UDPAddr, ln *net.UDPConn) {
	if len(data) < 20 {
		return
	}

	transactionID := data[4:20]

	resp := make([]byte, 20+len(addr.IP))
	resp[0], resp[1] = 0x01, 0x01
	binary.BigEndian.PutUint16(resp[2:4], 20+uint16(len(addr.IP)))
	copy(resp[4:20], transactionID)

	// IPv4
	if ip := addr.IP.To4(); ip != nil {
		resp[1] = 0x01
		resp[20] = 0x01
		resp[21] = 0x04
		binary.BigEndian.PutUint16(resp[22:24], 3478)
		copy(resp[24:28], ip)
	}

	_, _ = ln.WriteToUDP(resp, addr)
}

func BuildDERPMap(orgID string) *DERPMap {
	return &DERPMap{
		Regions: []DERPRegion{
			{
				RegionID:   1,
				RegionCode: "us-east",
				RegionName: "US East",
				Nodes: []DERPNode{
					{
						Name: "derp-us-east-1.privatelayer.local",
						URL:  "https://derp-us-east-1.privatelayer.local",
						STUN: true,
					},
				},
			},
			{
				RegionID:   2,
				RegionCode: "eu-west",
				RegionName: "EU West",
				Nodes: []DERPNode{
					{
						Name: "derp-eu-west-1.privatelayer.local",
						URL:  "https://derp-eu-west-1.privatelayer.local",
						STUN: true,
					},
				},
			},
		},
	}
}

type DERPMap struct {
	Regions []DERPRegion
}

type DERPRegion struct {
	RegionID   int32
	RegionCode string
	RegionName string
	Nodes      []DERPNode
}

type DERPNode struct {
	Name string
	URL  string
	STUN bool
}

func (d *DERPMap) WriteTo(w io.Writer) error {
	for _, r := range d.Regions {
		if _, err := fmt.Fprintf(w, "%s: %s\n", r.RegionCode, r.RegionName); err != nil {
			return err
		}
		for _, n := range r.Nodes {
			if _, err := fmt.Fprintf(w, "  - %s (%s stun=%v)\n", n.Name, n.URL, n.STUN); err != nil {
				return err
			}
		}
	}
	return nil
}
