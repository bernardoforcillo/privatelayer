package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/bernardoforcillo/privatelayer/internal/db"
	managementv1 "github.com/bernardoforcillo/privatelayer/internal/gen/management/v1"
	"github.com/bernardoforcillo/privatelayer/internal/gen/management/v1/managementv1connect"
)

func setupTestDB(t *testing.T) *db.Database {
	t.Helper()
	database, err := db.NewDatabase(&db.Config{Type: "sqlite", DSN: ":memory:"})
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	return database
}

// stubManagement is a minimal ManagementService that returns empty responses
type stubManagement struct {
	managementv1connect.UnimplementedManagementServiceHandler
}

func (s *stubManagement) CreateOrg(_ context.Context, _ *connect.Request[managementv1.CreateOrgRequest]) (*connect.Response[managementv1.CreateOrgResponse], error) {
	return connect.NewResponse(&managementv1.CreateOrgResponse{}), nil
}

func newTestServerWithInterceptor(t *testing.T, bootstrapKey string) (managementv1connect.ManagementServiceClient, *db.Database) {
	t.Helper()
	database := setupTestDB(t)
	interceptor := NewAPIKeyInterceptor(database, bootstrapKey)
	mux := http.NewServeMux()
	mux.Handle(managementv1connect.NewManagementServiceHandler(
		&stubManagement{},
		connect.WithInterceptors(interceptor),
	))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := managementv1connect.NewManagementServiceClient(http.DefaultClient, srv.URL)
	return client, database
}

func TestAPIKeyInterceptor_MissingKey(t *testing.T) {
	database := setupTestDB(t)
	interceptor := NewAPIKeyInterceptor(database, "bootstrap-secret")

	called := false
	handler := interceptor.WrapUnary(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		called = true
		return nil, nil
	})

	req := connect.NewRequest(&struct{}{})
	_, err := handler(context.Background(), req)
	require.Error(t, err)
	require.False(t, called)
}

func TestAPIKeyInterceptor_BootstrapKey_Accepted(t *testing.T) {
	client, _ := newTestServerWithInterceptor(t, "my-bootstrap-secret")

	req := connect.NewRequest(&managementv1.CreateOrgRequest{Name: "Test", Cidr: "10.0.0.0/8"})
	req.Header().Set("X-API-Key", "my-bootstrap-secret")
	_, err := client.CreateOrg(context.Background(), req)
	require.NoError(t, err)
}

func TestAPIKeyInterceptor_BootstrapKey_Rejected(t *testing.T) {
	client, _ := newTestServerWithInterceptor(t, "my-bootstrap-secret")

	req := connect.NewRequest(&managementv1.CreateOrgRequest{Name: "Test", Cidr: "10.0.0.0/8"})
	req.Header().Set("X-API-Key", "wrong-key")
	_, err := client.CreateOrg(context.Background(), req)
	require.Error(t, err)
	var connectErr *connect.Error
	require.ErrorAs(t, err, &connectErr)
	require.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
}

func TestAPIKeyInterceptor_ValidOrgKey(t *testing.T) {
	database := setupTestDB(t)

	org := &db.Org{Name: "Test", Slug: "test", CIDR: "10.0.0.0/8"}
	require.NoError(t, database.CreateOrg(org))

	rawKey := "pl_testkey123"
	hash := hashAPIKey(rawKey)
	apiKey := &db.APIKey{OrgID: org.ID, Key: hash, Prefix: "pl_te", Description: "test"}
	require.NoError(t, database.CreateAPIKey(apiKey))

	interceptor := NewAPIKeyInterceptor(database, "bootstrap-secret")
	var capturedOrgID uuid.UUID
	handler := interceptor.WrapUnary(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		capturedOrgID, _ = db.OrgIDFromContext(ctx)
		return nil, nil
	})

	req := connect.NewRequest(&struct{}{})
	req.Header().Set("X-API-Key", rawKey)
	_, err := handler(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, org.ID, capturedOrgID)
}

func TestAPIKeyInterceptor_InvalidOrgKey(t *testing.T) {
	database := setupTestDB(t)
	interceptor := NewAPIKeyInterceptor(database, "bootstrap-secret")

	called := false
	handler := interceptor.WrapUnary(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		called = true
		return nil, nil
	})

	req := connect.NewRequest(&struct{}{})
	req.Header().Set("X-API-Key", "invalid-key-that-does-not-exist")
	_, err := handler(context.Background(), req)
	require.Error(t, err)
	require.False(t, called)
}
