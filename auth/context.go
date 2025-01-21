package auth

import "context"

type userIDContextKey struct{}

func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDContextKey{}, userID)
}

func UserID(ctx context.Context) string {
	userID, _ := ctx.Value(userIDContextKey{}).(string)
	return userID
}
