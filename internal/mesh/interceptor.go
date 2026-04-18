package mesh

import (
	"context"
	"errors"

	"connectrpc.com/connect"
)

type nodeIDCtxKey struct{}

// NodeIDFromContext returns the authenticated node ID from context.
func NodeIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(nodeIDCtxKey{}).(string)
	return id, ok
}

func withNodeID(ctx context.Context, nodeID string) context.Context {
	return context.WithValue(ctx, nodeIDCtxKey{}, nodeID)
}

// NewMeshNodeInterceptor returns a ConnectRPC interceptor that validates
// the X-Node-Token header for all mesh RPCs except Register.
func NewMeshNodeInterceptor(srv *Server) connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Register uses a pre-auth key, not a session token
			if req.Spec().Procedure == "/mesh.v1.MeshService/Register" {
				return next(ctx, req)
			}

			token := req.Header().Get("X-Node-Token")
			if token == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("X-Node-Token header required"))
			}

			nodeID, ok := srv.ValidateNodeToken(token)
			if !ok {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired node token"))
			}

			return next(withNodeID(ctx, nodeID), req)
		}
	})
}
