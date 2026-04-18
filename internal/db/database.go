package db

import (
	"fmt"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database struct {
	db     *gorm.DB
	dbType string
	dsn    string
}

type Config struct {
	Type            string // "sqlite" or "postgres"
	DSN             string // connection string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

func NewDatabase(config *Config) (*Database, error) {
	var dialector gorm.Dialector

	switch config.Type {
	case "postgres":
		dialector = postgres.Open(config.DSN)
	case "sqlite", "sqlite3":
		// Ensure parent directory exists
		if config.DSN != ":memory:" {
			dir := config.DSN[:len(config.DSN)-len("/"+config.Type)]
			if dir != "" && dir != config.Type {
				os.MkdirAll(dir, 0755)
			}
		}
		dialector = sqlite.Open(config.DSN)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// Connection pool settings
	if config.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(config.MaxOpenConns)
	} else {
		sqlDB.SetMaxOpenConns(25)
	}

	if config.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	} else {
		sqlDB.SetMaxIdleConns(10)
	}

	if config.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(config.ConnMaxLifetime)
	} else {
		sqlDB.SetConnMaxLifetime(time.Hour)
	}

	database := &Database{
		db:     db,
		dbType: config.Type,
		dsn:    config.DSN,
	}

	// Auto migrate
	if err := database.migrate(); err != nil {
		return nil, fmt.Errorf("failed to migrate: %w", err)
	}

	return database, nil
}

func (d *Database) migrate() error {
	return d.db.AutoMigrate(
		&Org{},
		&IPAllocation{},
		&Node{},
		&NodeStatus{},
		&NodeRoute{},
		&PreAuthKey{},
		&APIKey{},
	)
}

func (d *Database) DB() *gorm.DB {
	return d.db
}

// Node operations
func (d *Database) CreateNode(node *Node) error {
	return d.db.Create(node).Error
}

func (d *Database) GetNodeByMachineKey(machineKey string) (*Node, error) {
	var node Node
	err := d.db.Preload("Status").Where("machine_key = ?", machineKey).First(&node).Error
	return &node, err
}

func (d *Database) GetNodeByID(id uint) (*Node, error) {
	var node Node
	err := d.db.Preload("Status").Where("id = ?", id).First(&node).Error
	return &node, err
}

func (d *Database) GetAllNodes() ([]Node, error) {
	var nodes []Node
	err := d.db.Preload("Status").Order("created_at DESC").Find(&nodes).Error
	return nodes, err
}

func (d *Database) GetOnlineNodes(within time.Duration) ([]Node, error) {
	var nodes []Node
	since := time.Now().Add(-within)
	err := d.db.Preload("Status").Where("last_seen > ?", since).Find(&nodes).Error
	return nodes, err
}

func (d *Database) UpdateNode(node *Node) error {
	return d.db.Save(node).Error
}

func (d *Database) DeleteNode(id uint) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("node_id = ?", id).Delete(&NodeStatus{}).Error; err != nil {
			return err
		}
		if err := tx.Where("node_id = ?", id).Delete(&NodeRoute{}).Error; err != nil {
			return err
		}
		return tx.Delete(&Node{}, id).Error
	})
}

func (d *Database) UpdateNodeStatus(nodeID uint, online bool, state *StateJSON) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		// Update node
		if err := tx.Model(&Node{}).Where("id = ?", nodeID).Updates(map[string]interface{}{
			"online":    online,
			"last_seen": time.Now(),
		}).Error; err != nil {
			return err
		}

		// Update or create status
		status := NodeStatus{
			NodeID:    nodeID,
			Online:    online,
			State:     StateJSON{},
			UpdatedAt: time.Now(),
		}
		if state != nil {
			status.State = *state
		}

		return tx.Where("node_id = ?", nodeID).Assign(status).FirstOrCreate(&status).Error
	})
}

// PreAuthKey operations
func (d *Database) CreatePreAuthKey(key *PreAuthKey) error {
	return d.db.Create(key).Error
}

func (d *Database) GetPreAuthKey(key string) (*PreAuthKey, error) {
	var preauth PreAuthKey
	err := d.db.Where("key = ? AND (expires_at IS NULL OR expires_at > ?)", key, time.Now()).First(&preauth).Error
	return &preauth, err
}

func (d *Database) UsePreAuthKey(key string, usedBy string) error {
	return d.db.Model(&PreAuthKey{}).Where("key = ?", key).Updates(map[string]interface{}{
		"used":    true,
		"used_by": usedBy,
	}).Error
}

func (d *Database) GetAllPreAuthKeys() ([]PreAuthKey, error) {
	var keys []PreAuthKey
	err := d.db.Order("created_at DESC").Find(&keys).Error
	return keys, err
}

// APIKey operations
func (d *Database) CreateAPIKey(key *APIKey) error {
	return d.db.Create(key).Error
}

func (d *Database) GetAPIKey(key string) (*APIKey, error) {
	var apiKey APIKey
	err := d.db.Where("key = ? AND (expires_at IS NULL OR expires_at > ?)", key, time.Now()).First(&apiKey).Error
	return &apiKey, err
}

func (d *Database) GetAllAPIKeys() ([]APIKey, error) {
	var keys []APIKey
	err := d.db.Order("created_at DESC").Find(&keys).Error
	return keys, err
}

func (d *Database) DeleteAPIKey(id uint) error {
	return d.db.Delete(&APIKey{}, id).Error
}

// Network Map operations
func (d *Database) GetNetworkMap() ([]Node, error) {
	var nodes []Node
	err := d.db.Preload("Status").Where("online = ?", true).Find(&nodes).Error
	return nodes, err
}

// Route operations
func (d *Database) UpsertRoute(nodeID uint, prefix string) error {
	route := NodeRoute{
		NodeID:  nodeID,
		Prefix:  prefix,
		Enabled: true,
	}
	return d.db.Where("node_id = ? AND prefix = ?", nodeID, prefix).Assign(route).FirstOrCreate(&route).Error
}

func (d *Database) GetNodeRoutes(nodeID uint) ([]NodeRoute, error) {
	var routes []NodeRoute
	err := d.db.Where("node_id = ? AND enabled = ?", nodeID, true).Find(&routes).Error
	return routes, err
}

func (d *Database) GetAllEnabledRoutes() ([]NodeRoute, error) {
	var routes []NodeRoute
	err := d.db.Where("enabled = ?", true).Find(&routes).Error
	return routes, err
}

func (d *Database) Close() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
