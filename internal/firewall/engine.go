package firewall

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	policies map[uuid.UUID][]ACLPolicy
	mu       sync.RWMutex
	groups   map[string][]string
	groupMu  sync.RWMutex
}

type ACLPolicy struct {
	Comment   string   `json:"comment,omitempty"`
	Action    string   `json:"action"`
	Protocol  string   `json:"proto,omitempty"`
	SrcIP     string   `json:"srcIp,omitempty"`
	SrcPort   string   `json:"srcPort,omitempty"`
	DstIP     string   `json:"dstIp,omitempty"`
	DstPort   string   `json:"dstPort,omitempty"`
	Src       string   `json:"src,omitempty"`
	Dst       string   `json:"dst,omitempty"`
	SrcGroups []string `json:"srcGroups,omitempty"`
	DstGroups []string `json:"dstGroups,omitempty"`
	Users     []string `json:"users,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	Tag       string   `json:"tag,omitempty"`
	IcmpType  string   `json:"icmpType,omitempty"`
}

type Groups []string

type PolicyAction string

const (
	ActionAccept PolicyAction = "accept"
	ActionDrop   PolicyAction = "drop"
)

const (
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoICMP = "icmp"
)

func NewEngine() *Engine {
	return &Engine{
		policies: make(map[uuid.UUID][]ACLPolicy),
		groups:   make(map[string][]string),
	}
}

func (e *Engine) SetPolicies(orgID uuid.UUID, policies []ACLPolicy) error {
	for _, p := range policies {
		if err := p.validate(); err != nil {
			return fmt.Errorf("invalid policy: %w", err)
		}
	}

	e.mu.Lock()
	e.policies[orgID] = policies
	e.mu.Unlock()

	slog.Info("ACL policies updated", "org", orgID, "count", len(policies))
	return nil
}

func (e *Engine) GetPolicies(orgID uuid.UUID) []ACLPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policies[orgID]
}

func (p *ACLPolicy) validate() error {
	if p.Action != string(ActionAccept) && p.Action != string(ActionDrop) {
		return fmt.Errorf("invalid action: %s", p.Action)
	}
	if p.Protocol != "" && p.Protocol != ProtoTCP && p.Protocol != ProtoUDP && p.Protocol != ProtoICMP {
		return fmt.Errorf("invalid protocol: %s", p.Protocol)
	}
	return nil
}

// Allow checks if traffic should be allowed for a specific org
func (e *Engine) Allow(orgID uuid.UUID, srcNode, dstNode string, srcIP, dstIP string, srcPort, dstPort int, proto string) bool {
	e.mu.RLock()
	policies := e.policies[orgID]
	e.mu.RUnlock()

	for _, policy := range policies {
		if e.matchPolicy(policy, srcNode, dstNode, srcIP, dstIP, srcPort, dstPort, proto) {
			return policy.Action == string(ActionAccept)
		}
	}

	// Default deny
	return false
}

func (e *Engine) matchPolicy(policy ACLPolicy, srcNode, dstNode string, srcIP, dstIP string, srcPort, dstPort int, proto string) bool {
	// Check src
	if policy.Src != "" && policy.Src != srcNode {
		return false
	}
	if policy.Dst != "" && policy.Dst != dstNode {
		return false
	}

	// Check srcGroups
	e.groupMu.RLock()
	for _, g := range policy.SrcGroups {
		if nodes, ok := e.groups[g]; ok {
			found := false
			for _, n := range nodes {
				if n == srcNode {
					found = true
					break
				}
			}
			if !found {
				e.groupMu.RUnlock()
				return false
			}
		}
	}
	e.groupMu.RUnlock()

	e.groupMu.RLock()
	for _, g := range policy.DstGroups {
		if nodes, ok := e.groups[g]; ok {
			found := false
			for _, n := range nodes {
				if n == dstNode {
					found = true
					break
				}
			}
			if !found {
				e.groupMu.RUnlock()
				return false
			}
		}
	}
	e.groupMu.RUnlock()

	// Check IP filters
	if policy.SrcIP != "" && !matchIP(policy.SrcIP, srcIP) {
		return false
	}
	if policy.DstIP != "" && !matchIP(policy.DstIP, dstIP) {
		return false
	}

	// Check ports
	if policy.SrcPort != "" && !matchPort(policy.SrcPort, srcPort) {
		return false
	}
	if policy.DstPort != "" && !matchPort(policy.DstPort, dstPort) {
		return false
	}

	// Check protocol
	if policy.Protocol != "" && !strings.EqualFold(policy.Protocol, proto) {
		return false
	}

	return true
}

func matchIP(pattern string, ip string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	// Simple prefix match
	return strings.HasPrefix(ip, strings.TrimSuffix(pattern, "/*"))
}

func matchPort(pattern string, port int) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "*" || pattern == "" {
		return true
	}
	// Port range
	if strings.Contains(pattern, "-") {
		var start, end int
		_, _ = fmt.Sscanf(pattern, "%d-%d", &start, &end)
		return port >= start && port <= end
	}
	// Exact match
	var p int
	_, _ = fmt.Sscanf(pattern, "%d", &p)
	return port == p
}

func (e *Engine) AddNodeToGroup(nodeID, group string) {
	e.groupMu.Lock()
	defer e.groupMu.Unlock()

	e.groups[group] = append(e.groups[group], nodeID)
}

func (e *Engine) RemoveNodeFromGroup(nodeID, group string) {
	e.groupMu.Lock()
	defer e.groupMu.Unlock()

	nodes := e.groups[group]
	for i, n := range nodes {
		if n == nodeID {
			e.groups[group] = append(nodes[:i], nodes[i+1:]...)
			break
		}
	}
}

func (e *Engine) Groups() map[string][]string {
	e.groupMu.RLock()
	defer e.groupMu.RUnlock()

	result := make(map[string][]string)
	for k, v := range e.groups {
		result[k] = v
	}
	return result
}

func (e *Engine) ExportACLs(orgID uuid.UUID) (json.RawMessage, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policies := e.policies[orgID]
	if len(policies) == 0 {
		// Default allow all within org
		policies = []ACLPolicy{
			{
				Action: string(ActionAccept),
				Src:    "*",
				Dst:    "*",
			},
		}
	}

	return json.MarshalIndent(policies, "", "  ")
}

func ParseACLPolicy(data json.RawMessage) ([]ACLPolicy, error) {
	var policies []ACLPolicy
	err := json.Unmarshal(data, &policies)
	return policies, err
}

func DefaultACLPolicy() []ACLPolicy {
	return []ACLPolicy{
		{
			Comment: "Allow all traffic within the org",
			Action:  string(ActionAccept),
			Src:     "*",
			Dst:     "*",
		},
	}
}

func (e *Engine) StartRetentionCleanup(deleteBefore time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for orgID, policies := range e.policies {
		var kept []ACLPolicy
		for _, p := range policies {
			if p.Tag != "" {
				kept = append(kept, p)
			}
		}
		e.policies[orgID] = kept
	}
}
