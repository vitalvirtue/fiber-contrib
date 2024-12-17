package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/gofiber/contrib/oauth2"
)

func TestOAuth2Middleware(t *testing.T) {
	// Create Fiber app
	app := fiber.New()

	// Initialize In-Memory Token Storage
	storage := oauth2.NewInMemoryStorage()

	// Save a test token
	validToken := "valid-token"
	expiredToken := "expired-token"

	validClaims := map[string]interface{}{"user_id": 123, "expiry": time.Now().Add(1 * time.Hour)}
	expiredClaims := map[string]interface{}{"user_id": 123, "expiry": time.Now().Add(-1 * time.Hour)}

	_ = storage.Save(validToken, validClaims, 1*time.Hour)
	_ = storage.Save(expiredToken, expiredClaims, -1*time.Hour)

	// OAuth2 Config with a valid provider
	config := oauth2.Config{
		RedirectURL: "https://example.com/callback",
		Providers: []oauth2.ProviderConfig{
			{
				Name:         "google",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
				TokenURL:     "https://oauth2.googleapis.com/token",
			},
		},
		TokenStorage: storage,
	}

	// Apply middleware
	app.Use(oauth2.OAuth2(config))

	// Protected Route
	app.Get("/secure", func(c *fiber.Ctx) error {
		user := c.Locals("user")
		return c.JSON(user)
	})

	t.Run("Valid Token", func(t *testing.T) {
		// Simulate request with valid token
		req := httptest.NewRequest("GET", "/secure", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)

		// Perform test
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Expired Token", func(t *testing.T) {
		// Simulate request with expired token
		req := httptest.NewRequest("GET", "/secure", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)

		// Perform test
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Missing Authorization Header", func(t *testing.T) {
		// Simulate request without Authorization header
		req := httptest.NewRequest("GET", "/secure", nil)

		// Perform test
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Invalid Authorization Header", func(t *testing.T) {
		// Simulate request with invalid Authorization header
		req := httptest.NewRequest("GET", "/secure", nil)
		req.Header.Set("Authorization", "InvalidTokenFormat")

		// Perform test
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
