package oauth2

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

// Config defines the global OAuth2 configuration
type Config struct {
	Providers       []ProviderConfig // List of Oauth2 providers
	RedirectURL     string           // Global callback URL
	Scopes          []string         // Default scopes for OAuth2 flows
	TokenStorage    TokenStorage     // Token storage interface
	Timeout         time.Duration    // Timeout for requests to OAuth2 providers
	EnableDebugLogs bool             // Enable debug logs for troubleshooting
	JWTSecretKey    []byte           // Secret key for signing JWT tokens
	UseJWTForRefresh bool            // Use JWT for refresh tokens (if false, use UUID)
}

// ProviderConfig defines the configuration for an individual OAuth2 provider
type ProviderConfig struct {
	Name					string          // Unique provider name (e.g., "google", "github")
	ClientID			string          // Client ID from OAuth2 provider
	ClientSecret	string          // Client secret from OAuth2 provider
	AuthURL				string          // Authorization URL
	TokenURL			string          // Token URL
	UserInfoURL		string          // URL to fetch user info
	RevokeURL			string          // URL to revoke tokens
	Scopes				[]string        // Provider-specific scopes
	ValidateSSL		bool            // Whether to validate SSL certificates
}

// DefaultConfig returns a Config struct with default values
func DefaultConfig() Config {
	return Config{
		Providers:       []ProviderConfig{},
		Scopes:          []string{"openid", "email", "profile"},
		Timeout:         5 * time.Second,
		EnableDebugLogs: false,
		JWTSecretKey:    nil, // User defined secret key for JWT
		TokenStorage:    nil,
		UseJWTForRefresh: true, // Default: use JWT for refresh tokens
	}
}


// Validate checks if the Config is correctly set up
func (c *Config) Validate() error {
	if len(c.Providers) == 0 {
		return errors.New("at least one OAuth2 provider must be configured")
	}

	if c.RedirectURL == "" {
		return errors.New("redirect URL is required")
	}

	// Validate global redirect URL
	if _, err := url.ParseRequestURI(c.RedirectURL); err != nil {
		return fmt.Errorf("invalid redirect URL: %w", err)
	}

	// Validate each provider
	for _, provider := range c.Providers {
		if err := provider.Validate(); err != nil {
			return fmt.Errorf("provider '%s' validation failed: %w", provider.Name, err)
		}
	}

	return nil
}

// Validate checks if the ProviderConfig is correctly set up.
func (p *ProviderConfig) Validate() error {
	if p.Name == "" {
		return errors.New("provider name is required")
	}

	if p.ClientID == "" {
		return fmt.Errorf("client ID is required for provider '%s'", p.Name)
	}

	if p.ClientSecret == "" {
		return fmt.Errorf("client secret is required for provider '%s'", p.Name)
	}

	// Validate URLs
	if _, err := url.ParseRequestURI(p.AuthURL); err != nil {
		return fmt.Errorf("invalid Auth URL for provider '%s': %w", p.Name, err)
	}

	if _, err := url.ParseRequestURI(p.TokenURL); err != nil {
		return fmt.Errorf("invalid Token URL for provider '%s': %w", p.Name, err)
	}

	// Optional URLs validation
	if p.UserInfoURL != "" {
		if _, err := url.ParseRequestURI(p.UserInfoURL); err != nil {
			return fmt.Errorf("invalid UserInfo URL for provider '%s': %w", p.Name, err)
		}
	}

	if p.RevokeURL != "" {
		if _, err := url.ParseRequestURI(p.RevokeURL); err != nil {
			return fmt.Errorf("invalid Revoke URL for provider '%s': %w", p.Name, err)
		}
	}

	return nil
}

// GetProvider retrieves a provider configuration by name.
func (c *Config) GetProvider(name string) (*ProviderConfig, error) {
	for _, provider := range c.Providers {
		if provider.Name == name {
			return &provider, nil
		}
	}
	return nil, fmt.Errorf("provider '%s' not found", name)
}
