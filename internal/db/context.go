package db

import (
	"context"

	"github.com/google/uuid"
)

type ctxKey string

const orgCtxKey ctxKey = "org_id"

// WithOrgIDCtx returns a new context with the org ID stored.
func WithOrgIDCtx(ctx context.Context, orgID uuid.UUID) context.Context {
	return context.WithValue(ctx, orgCtxKey, orgID)
}

// OrgIDFromContext retrieves the org ID from context.
func OrgIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(orgCtxKey).(uuid.UUID)
	return id, ok
}
