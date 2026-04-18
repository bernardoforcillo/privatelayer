package db

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type Node struct {
	ID            uint       `gorm:"primarykey" json:"id"`
	MachineKey    string     `gorm:"uniqueIndex;size:64" json:"machine_key"`
	NodeKey       string     `gorm:"size:64" json:"node_key"`
	PublicKey     string     `gorm:"size:44" json:"public_key"`
	IPAddresses   StringJSON `gorm:"type:jsonb" json:"ip_addresses"`
	Hostname      string     `gorm:"size:255" json:"hostname"`
	Online        bool       `gorm:"default:false" json:"online"`
	LastSeen      time.Time  `gorm:"index" json:"last_seen"`
	LastHandshake time.Time  `json:"last_handshake"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`

	Status *NodeStatus `gorm:"foreignKey:NodeID" json:"status,omitempty"`
}

func (Node) TableName() string {
	return "nodes"
}

type NodeStatus struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	NodeID        uint      `gorm:"uniqueIndex" json:"node_id"`
	Online        bool      `json:"online"`
	Version       string    `gorm:"size:32" json:"version"`
	State         StateJSON `gorm:"type:jsonb" json:"state"`
	LastHandshake time.Time `json:"last_handshake"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`

	Node *Node `gorm:"foreignKey:NodeID" json:"-"`
}

func (NodeStatus) TableName() string {
	return "node_status"
}

type NodeRoute struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	NodeID    uint      `gorm:"index" json:"node_id"`
	Prefix    string    `gorm:"size:64" json:"prefix"`
	Enabled   bool      `gorm:"default:true" json:"enabled"`
	CreatedAt time.Time `json:"created_at"`

	Node *Node `gorm:"foreignKey:NodeID" json:"-"`
}

func (NodeRoute) TableName() string {
	return "node_routes"
}

type PreAuthKey struct {
	ID        uint       `gorm:"primarykey" json:"id"`
	Key       string     `gorm:"uniqueIndex;size:64" json:"key"`
	Reusable  bool       `gorm:"default:false" json:"reusable"`
	Ephemeral bool       `gorm:"default:false" json:"ephemeral"`
	Used      bool       `gorm:"default:false" json:"used"`
	UsedBy    string     `gorm:"size:64" json:"used_by"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedBy string     `gorm:"size:64" json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

func (PreAuthKey) TableName() string {
	return "preauth_keys"
}

type APIKey struct {
	ID          uint       `gorm:"primarykey" json:"id"`
	Key         string     `gorm:"uniqueIndex;size:128" json:"key"`
	Prefix      string     `gorm:"size:16" json:"prefix"`
	Description string     `gorm:"size:255" json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

func (APIKey) TableName() string {
	return "api_keys"
}

// Custom JSON types
type StringJSON []string

func (s *StringJSON) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan StringJSON: %v", value)
	}
	return json.Unmarshal(bytes, s)
}

func (s StringJSON) Value() (interface{}, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

type StateJSON struct {
	Timestamp int64         `json:"timestamp"`
	System    SystemInfo    `json:"system"`
	Network   NetworkInfo   `json:"network"`
	WireGuard WireGuardInfo `json:"wireguard"`
}

func (s *StateJSON) Scan(value interface{}) error {
	if value == nil {
		*s = StateJSON{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan StateJSON: %v", value)
	}
	return json.Unmarshal(bytes, s)
}

func (s StateJSON) Value() (interface{}, error) {
	if s.Timestamp == 0 {
		return nil, nil
	}
	return json.Marshal(s)
}

type SystemInfo struct {
	Hostname      string  `json:"hostname"`
	OS            string  `json:"os"`
	Arch          string  `json:"arch"`
	Uptime        int64   `json:"uptime"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
}

type NetworkInfo struct {
	PublicIP       string `json:"public_ip"`
	NATType        string `json:"nat_type"`
	PeersConnected int32  `json:"peers_connected"`
}

type WireGuardInfo struct {
	InterfaceName string `json:"interface_name"`
	RXBytes       int64  `json:"rx_bytes"`
	TXBytes       int64  `json:"tx_bytes"`
	HandshakeLast int32  `json:"handshake_last"`
}

// GORM hooks
func (n *Node) BeforeCreate(tx *gorm.DB) error {
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now()
	}
	if n.UpdatedAt.IsZero() {
		n.UpdatedAt = time.Now()
	}
	return nil
}

func (n *Node) BeforeUpdate(tx *gorm.DB) error {
	n.UpdatedAt = time.Now()
	return nil
}
