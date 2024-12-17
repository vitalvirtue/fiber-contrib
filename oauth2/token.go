package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
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

// SaveToken stores a token in the provided storage backend.
func SaveToken(storage TokenStorage, token Token, claims map[string]interface{}) error {
	if storage == nil {
		return ErrTokenStorageMissing
	}

	// Add expiration info to claims
	claims["expiry"] = token.Expiry
	claims["scope"] = token.Scope

	// Calculate token expiration duration
	expiryDuration := time.Until(token.Expiry)
	if expiryDuration <= 0 {
		return ErrTokenExpired
	}

	// Save the token to storage
	err := storage.Save(token.AccessToken, claims, expiryDuration)
	if err != nil {
		return err
	}

	return nil
}

// RefreshToken renews an access token using the refresh token.
func RefreshToken(provider ProviderConfig, currentToken Token) (*Token, error) {
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

	return &newToken, nil
}

// RevokeToken invalidates a token using the provider's revoke endpoint.
func RevokeToken(provider ProviderConfig, token string, storage TokenStorage) error {
	if token == "" {
		return ErrTokenInvalid
	}

	// Remove the token from storage
	err := storage.Delete(token)
	if err != nil {
		return fmt.Errorf("failed to delete token from storage: %w", err)
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

	client := &http.Client{}
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
