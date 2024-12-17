package oauth2_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/gofiber/contrib/oauth2"
)

func TestConfig_Validation(t *testing.T) {
	t.Run("Valid Configuration", func(t *testing.T) {
		config := oauth2.Config{
			RedirectURL: "https://example.com/callback",
			Providers: []oauth2.ProviderConfig{
				{
					Name:         "google",
					ClientID:     "valid-client-id",
					ClientSecret: "valid-client-secret",
					AuthURL:      "https://accounts.google.com/o/oauth2/auth",
					TokenURL:     "https://oauth2.googleapis.com/token",
				},
			},
			Timeout: 5 * time.Second,
		}

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("Missing Redirect URL", func(t *testing.T) {
		config := oauth2.Config{
			Providers: []oauth2.ProviderConfig{
				{
					Name:         "google",
					ClientID:     "valid-client-id",
					ClientSecret: "valid-client-secret",
					AuthURL:      "https://accounts.google.com/o/oauth2/auth",
					TokenURL:     "https://oauth2.googleapis.com/token",
				},
			},
		}

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redirect URL is required")
	})

	t.Run("Invalid Provider Configuration", func(t *testing.T) {
		config := oauth2.Config{
			RedirectURL: "https://example.com/callback",
			Providers: []oauth2.ProviderConfig{
				{
					Name: "google",
				},
			},
		}

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client ID is required")
	})
}
