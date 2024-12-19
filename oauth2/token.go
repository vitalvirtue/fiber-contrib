package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Token represents an OAuth2 access token with its metadata.
type Token struct {
	AccessToken  string    `json:"access_token"`  // OAuth2 access token
	RefreshToken string    `json:"refresh_token"` // OAuth2 refresh token
	Expiry       time.Time `json:"expiry"`        // Token expiration time
	TokenType    string    `json:"token_type"`    // Token type (e.g., "Bearer")
	Scope        string    `json:"scope"`         // Scopes granted for the token
}

// IsExpired checks if the token has expired.
func (t *Token) IsExpired() bool {
	return time.Now().After(t.Expiry)
}

func RefreshToken(provider ProviderConfig, currentToken Token, storage TokenStorage) (*Token, error) {
	if currentToken.RefreshToken == "" {
		return nil, ErrRefreshTokenMissing
	}

	// Prepare the POST request payload
	data := url.Values{}
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)
	data.Set("refresh_token", currentToken.RefreshToken)
	data.Set("grant_type", "refresh_token")

	// Send the token refresh request
	resp, err := http.PostForm(provider.TokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to request token refresh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status: %s", resp.Status)
	}

	// Decode the new token response
	var newToken Token
	err = json.NewDecoder(resp.Body).Decode(&newToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Set expiration time if not provided
	if newToken.Expiry.IsZero() {
		newToken.Expiry = time.Now().Add(1 * time.Hour) // Default: 1 hour
	}

	// Remove the old Refresh Token from storage
	if storage != nil {
		if err := storage.Delete(currentToken.RefreshToken); err != nil {
			return nil, fmt.Errorf("failed to delete old refresh token: %w", err)
		}
	}

	// Save the new Refresh Token
	if storage != nil {
		err = storage.Save(newToken.RefreshToken, map[string]interface{}{
			"scope":  newToken.Scope,
			"expiry": newToken.Expiry,
		}, time.Until(newToken.Expiry))
		if err != nil {
			return nil, fmt.Errorf("failed to save new refresh token: %w", err)
		}
	}

	return &newToken, nil
}

func RevokeToken(provider ProviderConfig, token string, storage TokenStorage) error {
	if token == "" {
		return ErrTokenInvalid
	}

	// Remove the token from storage
	if storage != nil {
		if err := storage.Delete(token); err != nil {
			return fmt.Errorf("failed to delete token from storage: %w", err)
		}
	}

	// Revoke token with provider
	req, err := http.NewRequest("POST", provider.RevokeURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}

	q := req.URL.Query()
	q.Set("token", token)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke token with provider: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("provider revoke request failed with status: %s", resp.Status)
	}

	return nil
}

func createJWT(config Config, subject string, expiry time.Duration) (string, error) {
	if len(config.JWTSecretKey) == 0 {
		return "", fmt.Errorf("JWT secret key is not configured")
	}

	claims := jwt.MapClaims{
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(expiry).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(config.JWTSecretKey)
}

func validateJWT(config Config, tokenString string) (jwt.MapClaims, error) {
	if len(config.JWTSecretKey) == 0 {
		return nil, fmt.Errorf("JWT secret key is not configured")
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return config.JWTSecretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims or token")
	}

	return claims, nil
}
