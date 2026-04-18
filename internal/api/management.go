package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/bernardoforcillo/privatelayer/internal/db"
	managementv1 "github.com/bernardoforcillo/privatelayer/internal/gen/management/v1"
	"github.com/bernardoforcillo/privatelayer/internal/gen/management/v1/managementv1connect"
)

type ManagementService struct {
	managementv1connect.UnimplementedManagementServiceHandler
	db *db.Database
}

func NewManagementService(database *db.Database) *ManagementService {
	return &ManagementService{db: database}
}

func slugify(name string) string {
	lower := strings.ToLower(name)
	re := regexp.MustCompile(`[^a-z0-9]+`)
	slug := re.ReplaceAllString(lower, "-")
	return strings.Trim(slug, "-")
}

func generateRawAPIKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "pl_" + base64.URLEncoding.EncodeToString(b), nil
}

func (s *ManagementService) CreateOrg(ctx context.Context, req *connect.Request[managementv1.CreateOrgRequest]) (*connect.Response[managementv1.CreateOrgResponse], error) {
	cidr := req.Msg.Cidr
	if cidr == "" {
		cidr = "10.0.0.0/8"
	}
	org := &db.Org{
		Name: req.Msg.Name,
		Slug: slugify(req.Msg.Name),
		CIDR: cidr,
	}
	if err := s.db.CreateOrg(org); err != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("org slug already taken"))
	}

	rawKey, err := generateRawAPIKey()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	hash := hashAPIKey(rawKey)
	apiKey := &db.APIKey{
		OrgID:       org.ID,
		Key:         hash,
		Prefix:      rawKey[:6],
		Description: "initial key",
	}
	if err := s.db.CreateAPIKey(apiKey); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&managementv1.CreateOrgResponse{
		Org: &managementv1.Org{
			Id:        org.ID.String(),
			Name:      org.Name,
			Slug:      org.Slug,
			Cidr:      org.CIDR,
			CreatedAt: org.CreatedAt.UnixMilli(),
		},
		ApiKey: rawKey,
	}), nil
}

func (s *ManagementService) GetOrg(ctx context.Context, req *connect.Request[managementv1.GetOrgRequest]) (*connect.Response[managementv1.GetOrgResponse], error) {
	org, err := s.db.GetOrgBySlug(req.Msg.Slug)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("org not found"))
	}
	return connect.NewResponse(&managementv1.GetOrgResponse{
		Org: &managementv1.Org{
			Id:        org.ID.String(),
			Name:      org.Name,
			Slug:      org.Slug,
			Cidr:      org.CIDR,
			CreatedAt: org.CreatedAt.UnixMilli(),
		},
	}), nil
}

func (s *ManagementService) ListNodes(ctx context.Context, req *connect.Request[managementv1.ListNodesRequest]) (*connect.Response[managementv1.ListNodesResponse], error) {
	orgID, ok := db.OrgIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing org context"))
	}
	nodes, err := s.db.GetAllNodes()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	result := make([]*managementv1.MgmtNode, 0)
	for _, n := range nodes {
		if n.OrgID != orgID {
			continue
		}
		result = append(result, &managementv1.MgmtNode{
			Id:          n.MachineKey,
			Hostname:    n.Hostname,
			PublicKey:   n.PublicKey,
			IpAddresses: []string(n.IPAddresses),
			Online:      n.Online,
			LastSeen:    n.LastSeen.UnixMilli(),
		})
	}
	return connect.NewResponse(&managementv1.ListNodesResponse{Nodes: result}), nil
}

func (s *ManagementService) DeleteNode(ctx context.Context, req *connect.Request[managementv1.DeleteNodeRequest]) (*connect.Response[managementv1.DeleteNodeResponse], error) {
	orgID, ok := db.OrgIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing org context"))
	}
	node, err := s.db.GetNodeByMachineKey(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("node not found"))
	}
	if node.OrgID != orgID {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("node belongs to different org"))
	}
	if err := s.db.DeleteNode(node.ID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&managementv1.DeleteNodeResponse{}), nil
}

func (s *ManagementService) CreatePreAuthKey(ctx context.Context, req *connect.Request[managementv1.CreatePreAuthKeyRequest]) (*connect.Response[managementv1.CreatePreAuthKeyResponse], error) {
	orgID, ok := db.OrgIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing org context"))
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate key: %w", err))
	}
	keyStr := base64.URLEncoding.EncodeToString(b)

	var expiresAt *time.Time
	if req.Msg.ExpiresIn != "" {
		d, err := time.ParseDuration(req.Msg.ExpiresIn)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid expires_in: %w", err))
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}

	pak := &db.PreAuthKey{
		OrgID:     orgID,
		Key:       keyStr,
		Reusable:  req.Msg.Reusable,
		Ephemeral: req.Msg.Ephemeral,
		ExpiresAt: expiresAt,
		CreatedBy: orgID.String(),
	}
	if err := s.db.CreatePreAuthKey(pak); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	var expiresAtMs int64
	if pak.ExpiresAt != nil {
		expiresAtMs = pak.ExpiresAt.UnixMilli()
	}
	return connect.NewResponse(&managementv1.CreatePreAuthKeyResponse{
		Key: &managementv1.PreAuthKey{
			Id:        fmt.Sprintf("%d", pak.ID),
			Key:       keyStr,
			Reusable:  pak.Reusable,
			Ephemeral: pak.Ephemeral,
			Used:      pak.Used,
			ExpiresAt: expiresAtMs,
			CreatedAt: pak.CreatedAt.UnixMilli(),
		},
	}), nil
}

func (s *ManagementService) ListPreAuthKeys(ctx context.Context, req *connect.Request[managementv1.ListPreAuthKeysRequest]) (*connect.Response[managementv1.ListPreAuthKeysResponse], error) {
	orgID, ok := db.OrgIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing org context"))
	}
	keys, err := s.db.GetAllPreAuthKeys()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	result := make([]*managementv1.PreAuthKey, 0)
	for _, k := range keys {
		if k.OrgID != orgID {
			continue
		}
		var expiresAtMs int64
		if k.ExpiresAt != nil {
			expiresAtMs = k.ExpiresAt.UnixMilli()
		}
		result = append(result, &managementv1.PreAuthKey{
			Id:        fmt.Sprintf("%d", k.ID),
			Key:       k.Key,
			Reusable:  k.Reusable,
			Ephemeral: k.Ephemeral,
			Used:      k.Used,
			ExpiresAt: expiresAtMs,
			CreatedAt: k.CreatedAt.UnixMilli(),
		})
	}
	return connect.NewResponse(&managementv1.ListPreAuthKeysResponse{Keys: result}), nil
}

func (s *ManagementService) RevokePreAuthKey(ctx context.Context, req *connect.Request[managementv1.RevokePreAuthKeyRequest]) (*connect.Response[managementv1.RevokePreAuthKeyResponse], error) {
	orgID, ok := db.OrgIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing org context"))
	}
	pak, err := s.db.GetPreAuthKey(req.Msg.Key)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("key not found"))
	}
	if pak.OrgID != orgID {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("key belongs to different org"))
	}
	if err := s.db.UsePreAuthKey(req.Msg.Key, "revoked"); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&managementv1.RevokePreAuthKeyResponse{}), nil
}

func (s *ManagementService) CreateAPIKey(ctx context.Context, req *connect.Request[managementv1.CreateAPIKeyRequest]) (*connect.Response[managementv1.CreateAPIKeyResponse], error) {
	orgID, ok := db.OrgIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing org context"))
	}

	rawKey, err := generateRawAPIKey()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	hash := hashAPIKey(rawKey)

	var expiresAt *time.Time
	if req.Msg.ExpiresIn != "" {
		d, err := time.ParseDuration(req.Msg.ExpiresIn)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid expires_in"))
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}

	key := &db.APIKey{
		OrgID:       orgID,
		Key:         hash,
		Prefix:      rawKey[:6],
		Description: req.Msg.Description,
		ExpiresAt:   expiresAt,
	}
	if err := s.db.CreateAPIKey(key); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	var expiresAtMs int64
	if key.ExpiresAt != nil {
		expiresAtMs = key.ExpiresAt.UnixMilli()
	}
	return connect.NewResponse(&managementv1.CreateAPIKeyResponse{
		Key: &managementv1.APIKey{
			Id:          fmt.Sprintf("%d", key.ID),
			Prefix:      key.Prefix,
			Description: key.Description,
			CreatedAt:   key.CreatedAt.UnixMilli(),
			ExpiresAt:   expiresAtMs,
		},
		RawKey: rawKey,
	}), nil
}

func (s *ManagementService) ListAPIKeys(ctx context.Context, req *connect.Request[managementv1.ListAPIKeysRequest]) (*connect.Response[managementv1.ListAPIKeysResponse], error) {
	orgID, ok := db.OrgIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing org context"))
	}
	keys, err := s.db.GetAllAPIKeys()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	result := make([]*managementv1.APIKey, 0)
	for _, k := range keys {
		if k.OrgID != orgID {
			continue
		}
		var expiresAtMs int64
		if k.ExpiresAt != nil {
			expiresAtMs = k.ExpiresAt.UnixMilli()
		}
		result = append(result, &managementv1.APIKey{
			Id:          fmt.Sprintf("%d", k.ID),
			Prefix:      k.Prefix,
			Description: k.Description,
			CreatedAt:   k.CreatedAt.UnixMilli(),
			ExpiresAt:   expiresAtMs,
		})
	}
	return connect.NewResponse(&managementv1.ListAPIKeysResponse{Keys: result}), nil
}

func (s *ManagementService) RevokeAPIKey(ctx context.Context, req *connect.Request[managementv1.RevokeAPIKeyRequest]) (*connect.Response[managementv1.RevokeAPIKeyResponse], error) {
	orgID, ok := db.OrgIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing org context"))
	}
	var id uint
	fmt.Sscanf(req.Msg.Id, "%d", &id)
	keys, err := s.db.GetAllAPIKeys()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	for _, k := range keys {
		if k.ID == id && k.OrgID == orgID {
			if err := s.db.DeleteAPIKey(id); err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			return connect.NewResponse(&managementv1.RevokeAPIKeyResponse{}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("API key not found"))
}
