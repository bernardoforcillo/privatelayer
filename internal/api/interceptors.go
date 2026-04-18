package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/bernardoforcillo/privatelayer/internal/db"
	"gorm.io/gorm"
)

func hashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

// NewAPIKeyInterceptor returns a ConnectRPC interceptor that:
// - For CreateOrg: validates against bootstrapKey
// - For all other management calls: looks up org API key in DB and injects org_id into context
func NewAPIKeyInterceptor(database *db.Database, bootstrapKey string) connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure
			apiKey := req.Header().Get("X-API-Key")

			if apiKey == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("X-API-Key header required"))
			}

			// CreateOrg uses the bootstrap key
			if strings.HasSuffix(procedure, "/CreateOrg") {
				if subtle.ConstantTimeCompare([]byte(apiKey), []byte(bootstrapKey)) == 0 {
					return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid bootstrap key"))
				}
				return next(ctx, req)
			}

			// All other calls: resolve org from API key
			// Use constant-time comparison to prevent timing attacks
			hash := hashAPIKey(apiKey)
			key, err := database.GetAPIKey(hash)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					// Perform constant-time dummy hash to maintain timing consistency
					_ = hashAPIKey("dummy")
					return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid API key"))
				}
				return nil, connect.NewError(connect.CodeInternal, errors.New("failed to validate API key"))
			}
			// Verify key hash with constant-time comparison
			if subtle.ConstantTimeCompare([]byte(key.Key), []byte(hash)) == 0 {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid API key"))
			}

			ctx = db.WithOrgIDCtx(ctx, key.OrgID)
			return next(ctx, req)
		}
	})
}
