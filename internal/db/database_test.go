package db

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) *Database {
	t.Helper()
	db, err := NewDatabase(&Config{Type: "sqlite", DSN: ":memory:"})
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCreateAndGetOrg(t *testing.T) {
	db := setupTestDB(t)

	org := &Org{Name: "Acme Corp", Slug: "acme-corp", CIDR: "10.0.0.0/8"}
	err := db.CreateOrg(org)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, org.ID)

	got, err := db.GetOrgBySlug("acme-corp")
	require.NoError(t, err)
	require.Equal(t, "Acme Corp", got.Name)
}

func TestGetNextIP(t *testing.T) {
	db := setupTestDB(t)

	org := &Org{Name: "Test", Slug: "test", CIDR: "10.0.0.0/8"}
	require.NoError(t, db.CreateOrg(org))

	ip1, err := db.AllocateIP(org.ID, "10.0.0.0/8")
	require.NoError(t, err)
	require.Equal(t, "10.0.0.1", ip1)

	ip2, err := db.AllocateIP(org.ID, "10.0.0.0/8")
	require.NoError(t, err)
	require.Equal(t, "10.0.0.2", ip2)
}

func TestOrgAPIKey(t *testing.T) {
	db := setupTestDB(t)

	org := &Org{Name: "Test", Slug: "test", CIDR: "10.0.0.0/8"}
	require.NoError(t, db.CreateOrg(org))

	key := &APIKey{
		OrgID:       org.ID,
		Key:         "hashvalue",
		Prefix:      "pl_abc",
		Description: "CI",
	}
	require.NoError(t, db.CreateAPIKey(key))

	got, err := db.GetAPIKey("hashvalue")
	require.NoError(t, err)
	require.Equal(t, org.ID, got.OrgID)
}
