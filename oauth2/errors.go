package oauth2

import "errors"

var (
	ErrTokenExpired        = errors.New("token has expired")
	ErrTokenInvalid        = errors.New("token is invalid")
	ErrTokenStorageMissing = errors.New("token storage is not configured")
	ErrRefreshTokenMissing = errors.New("refresh token is missing")
)

