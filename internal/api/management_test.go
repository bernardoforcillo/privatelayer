package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	"github.com/bernardoforcillo/privatelayer/internal/db"
	managementv1 "github.com/bernardoforcillo/privatelayer/internal/gen/management/v1"
	"github.com/bernardoforcillo/privatelayer/internal/gen/management/v1/managementv1connect"
)

func newTestManagementServer(t *testing.T) (managementv1connect.ManagementServiceClient, *db.Database) {
	t.Helper()
	database := setupTestDB(t)
	svc := NewManagementService(database)
	mux := http.NewServeMux()
	mux.Handle(managementv1connect.NewManagementServiceHandler(svc))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := managementv1connect.NewManagementServiceClient(http.DefaultClient, srv.URL)
	return client, database
}

func TestCreateOrg(t *testing.T) {
	client, _ := newTestManagementServer(t)

	resp, err := client.CreateOrg(context.Background(), connect.NewRequest(&managementv1.CreateOrgRequest{
		Name: "Acme Corp",
		Cidr: "10.0.0.0/8",
	}))
	require.NoError(t, err)
	require.Equal(t, "acme-corp", resp.Msg.Org.Slug)
	require.NotEmpty(t, resp.Msg.ApiKey)
}

func TestListNodes_Empty(t *testing.T) {
	database := setupTestDB(t)
	svc := NewManagementService(database)

	org := &db.Org{Name: "Test", Slug: "test", CIDR: "10.0.0.0/8"}
	require.NoError(t, database.CreateOrg(org))

	ctx := db.WithOrgIDCtx(context.Background(), org.ID)
	resp, err := svc.ListNodes(ctx, connect.NewRequest(&managementv1.ListNodesRequest{}))
	require.NoError(t, err)
	require.Empty(t, resp.Msg.Nodes)
}

func TestListNodes_MissingOrgID(t *testing.T) {
	database := setupTestDB(t)
	svc := NewManagementService(database)

	_, err := svc.ListNodes(context.Background(), connect.NewRequest(&managementv1.ListNodesRequest{}))
	require.Error(t, err)
	var connectErr *connect.Error
	require.ErrorAs(t, err, &connectErr)
	require.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
}

func TestCreatePreAuthKey(t *testing.T) {
	database := setupTestDB(t)
	svc := NewManagementService(database)

	org := &db.Org{Name: "Test", Slug: "test", CIDR: "10.0.0.0/8"}
	require.NoError(t, database.CreateOrg(org))

	ctx := db.WithOrgIDCtx(context.Background(), org.ID)
	resp, err := svc.CreatePreAuthKey(ctx, connect.NewRequest(&managementv1.CreatePreAuthKeyRequest{
		Reusable:  false,
		ExpiresIn: "24h",
	}))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Msg.Key.Key)
}
