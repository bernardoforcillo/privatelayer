package dns

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultDNSPort = 53
	DomainSuffix   = "privatelayer.local"
)

type Server struct {
	_addr    *net.UDPAddr
	_udpConn *net.UDPConn
	_tcpLn   *net.TCPListener
	_zones   map[string]*Zone
	_mu      sync.RWMutex
}

type Zone struct {
	Name      string
	Origin    string
	Records   map[string][]ResourceRecord
	TTL       uint32
	CreatedAt time.Time
}

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

const (
	TypeA     = 1
	TypeAAAA  = 28
	TypeCNAME = 5
	TypeTXT   = 16
	TypeSOA   = 6
	TypeNS    = 2
	TypePTR   = 12
	TypeMX    = 15
)

const (
	ClassIN = 1
)

func NewServer() *Server {
	return &Server{
		_zones: make(map[string]*Zone),
	}
}

func (s *Server) ListenAndServe(ip string, port int) error {
	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on DNS: %w", err)
	}
	s._udpConn = conn

	// Create default zone
	s._zones[DomainSuffix] = &Zone{
		Name:    DomainSuffix,
		Origin:  DomainSuffix + ".",
		Records: make(map[string][]ResourceRecord),
		TTL:     300,
	}

	go s.serveUDP()
	go s.serveTCP()

	slog.Info("DNS server started", "ip", ip, "port", port)
	return nil
}

func (s *Server) serveUDP() {
	buf := make([]byte, 512)
	for {
		n, addr, err := s._udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		go s.handleQuery(buf[:n], addr)
	}
}

func (s *Server) serveTCP() {
	// TCP handling would go here
}

func (s *Server) handleQuery(data []byte, addr *net.UDPAddr) {
	if len(data) < 12 {
		return
	}

	id := binary.BigEndian.Uint16(data[:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	questions := binary.BigEndian.Uint16(data[4:6])
	_ = questions

	// Only handle standard queries
	if (flags & 0x8000) != 0 {
		return
	}

	// Parse question name
	offset := 12
	name, newOffset := parseName(data, offset)
	if name == "" {
		return
	}

	qtype := uint16(TypeA)
	if offset+4 <= len(data) {
		qtype = binary.BigEndian.Uint16(data[newOffset : newOffset+2])
	}

	// Build response
	resp := s.buildResponse(id, name, qtype)
	if len(resp) > 0 {
		_, _ = s._udpConn.WriteToUDP(resp, addr)
	}
}

func (s *Server) buildResponse(id uint16, qname string, qtype uint16) []byte {
	// Extract hostname and org from tailnet format: hostname.orgname.privatelayer.local
	parts := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(parts) < 2 || parts[len(parts)-1] != DomainSuffix {
		return nil
	}

	hostname := parts[0]
	_ = strings.Join(parts[1:len(parts)-1], ".")

	// Find IP for this node
	s._mu.RLock()
	zone, ok := s._zones[DomainSuffix]
	records := zone.Records[hostname]
	s._mu.RUnlock()

	if !ok || records == nil {
		return nil
	}

	// Build response header
	resp := make([]byte, 12+len(qname)+12)
	binary.BigEndian.PutUint16(resp[:2], id)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)               // Response flags
	binary.BigEndian.PutUint16(resp[4:6], 1)                    // 1 question
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(records))) // Answer count

	// Copy question
	offset := 12
	copy(resp[offset:offset+len(qname)], []byte(qname))
	offset += len(qname)
	binary.BigEndian.PutUint16(resp[offset:offset+2], qtype)
	offset += 2
	binary.BigEndian.PutUint16(resp[offset:offset+2], ClassIN)

	// Add answer records
	for _, r := range records {
		if r.Type == qtype {
			ansOffset := offset
			copy(resp[ansOffset:ansOffset+len(qname)], []byte(qname))
			ansOffset += len(qname)
			binary.BigEndian.PutUint16(resp[ansOffset:ansOffset+2], r.Type)
			ansOffset += 2
			binary.BigEndian.PutUint16(resp[ansOffset:ansOffset+2], ClassIN)
			ansOffset += 2
			binary.BigEndian.PutUint32(resp[ansOffset:ansOffset+4], r.TTL)
			ansOffset += 4
			// RDLength and RDATA would follow
		}
	}

	return resp
}

func parseName(data []byte, offset int) (string, int) {
	if offset >= len(data) {
		return "", 0
	}

	var labels []string
	for {
		if offset >= len(data) {
			return "", 0
		}
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		// Check for compression pointer
		if length >= 0xC0 {
			if offset+1 >= len(data) {
				return "", 0
			}
			pointer := int(uint16(length&0x3F)<<8) | int(data[offset+1])
			_, newOffset := parseName(data, pointer)
			return strings.Join(labels, "."), newOffset
		}
		offset++
		if offset+length > len(data) {
			return "", 0
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	if len(labels) == 0 {
		return "", offset
	}
	return strings.Join(labels, "."), offset
}

// AddNode registers a node in DNS
func (s *Server) AddNode(orgSlug, hostname string, ip net.IP) error {
	zoneName := orgSlug + "." + DomainSuffix

	s._mu.Lock()
	defer s._mu.Unlock()

	zone, ok := s._zones[zoneName]
	if !ok {
		zone = &Zone{
			Name:    zoneName,
			Origin:  zoneName + ".",
			Records: make(map[string][]ResourceRecord),
			TTL:     300,
		}
		s._zones[zoneName] = zone
	}

	// Add A record
	if ip4 := ip.To4(); ip4 != nil {
		zone.Records[hostname] = append(zone.Records[hostname], ResourceRecord{
			Name:  hostname,
			Type:  TypeA,
			Class: ClassIN,
			TTL:   zone.TTL,
			RData: ip4,
		})
	}

	slog.Info("DNS node added", "hostname", hostname, "ip", ip.String(), "zone", zoneName)
	return nil
}

// RemoveNode removes a node from DNS
func (s *Server) RemoveNode(orgSlug, hostname string) error {
	zoneName := orgSlug + "." + DomainSuffix

	s._mu.Lock()
	defer s._mu.Unlock()

	if zone, ok := s._zones[zoneName]; ok {
		delete(zone.Records, hostname)
	}

	return nil
}

// BuildMagicDNSZone generates a zone file for the org
func (s *Server) BuildMagicDNSZone(orgID uuid.UUID, orgSlug string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("$ORIGIN %s.%s\n", orgSlug, DomainSuffix))
	sb.WriteString(fmt.Sprintf("$TTL 300\n\n"))

	s._mu.RLock()
	zone, ok := s._zones[orgSlug+"."+DomainSuffix]
	s._mu.RUnlock()

	if !ok {
		return sb.String()
	}

	for name, records := range zone.Records {
		for _, r := range records {
			if r.Type == TypeA {
				sb.WriteString(fmt.Sprintf("%s IN A %s\n", name, net.IP(r.RData).String()))
			} else if r.Type == TypeCNAME {
				sb.WriteString(fmt.Sprintf("%s IN CNAME %s\n", name, string(r.RData)))
			}
		}
	}

	return sb.String()
}
