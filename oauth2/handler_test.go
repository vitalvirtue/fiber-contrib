package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/gofiber/contrib/oauth2"
)

func TestLoginHandler(t *testing.T) {
	t.Run("Redirect to Authorization URL", func(t *testing.T) {
		// Mock provider configuration
		config := oauth2.Config{
			RedirectURL: "https://example.com/callback",
			Providers: []oauth2.ProviderConfig{
				{
					Name:     "google",
					ClientID: "test-client-id",
					AuthURL:  "https://accounts.google.com/o/oauth2/auth",
					Scopes:   []string{"openid", "profile", "email"},
				},
			},
		}
	
		// Initialize Fiber app
		app := fiber.New()
		app.Get("/login", oauth2.LoginHandler("google", config))
	
		// Simulate HTTP request
		req := httptest.NewRequest("GET", "/login", nil)
		resp, err := app.Test(req)
	
		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, resp.StatusCode) // Expect redirect (302)
	
		// Verify the redirect location
		location := resp.Header.Get("Location")
	
		// Parse the redirect URL
		expectedBase := "https://accounts.google.com/o/oauth2/auth"
		expectedParams := []string{
			"client_id=test-client-id",
			"redirect_uri=https%3A%2F%2Fexample.com%2Fcallback", // URL-encoded redirect URI
			"response_type=code",
			"scope=openid+profile+email",
			"state=random_state_string",
		}
	
		assert.Contains(t, location, expectedBase)
		for _, param := range expectedParams {
			assert.Contains(t, location, param)
		}
	})
}

func TestCallbackHandler(t *testing.T) {
	// Mock OAuth2 provider
	mockToken := oauth2.Token{
		AccessToken:  "mock-access-token",
		RefreshToken: "mock-refresh-token",
		TokenType:    "Bearer",
	}
	mockUserInfo := map[string]interface{}{
		"id":    "12345",
		"email": "test@example.com",
		"name":  "Test User",
	}

	// Mock OAuth2 provider server
	mockProviderServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			// Mock access token response
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mockToken)
		} else if r.URL.Path == "/userinfo" {
			// Mock user info response
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mockUserInfo)
		}
	}))
	defer mockProviderServer.Close()

	t.Run("Successful Token Exchange and User Info Fetch", func(t *testing.T) {
		// Mock provider configuration
		config := oauth2.Config{
			RedirectURL: "https://example.com/callback",
			TokenStorage: oauth2.NewInMemoryStorage(),
			Providers: []oauth2.ProviderConfig{
				{
					Name:         "google",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
					AuthURL:      mockProviderServer.URL + "/auth",
					TokenURL:     mockProviderServer.URL + "/token",
					UserInfoURL:  mockProviderServer.URL + "/userinfo",
				},
			},
		}

		// Initialize Fiber app
		app := fiber.New()
		app.Get("/callback", oauth2.CallbackHandler("google", config))

		// Simulate HTTP request with authorization code
		req := httptest.NewRequest("GET", "/callback?code=test-auth-code", nil)
		resp, err := app.Test(req)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)

		// Verify access token and user info
		assert.Equal(t, "mock-access-token", result["access_token"])
		assert.Equal(t, mockUserInfo, result["user_info"])
	})

	t.Run("Missing Authorization Code", func(t *testing.T) {
		// Initialize Fiber app
		app := fiber.New()
		app.Get("/callback", oauth2.CallbackHandler("google", oauth2.Config{}))

		// Simulate HTTP request without authorization code
		req := httptest.NewRequest("GET", "/callback", nil)
		resp, err := app.Test(req)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// Parse response
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		assert.Equal(t, "Authorization code is missing", result["error"])
	})

	t.Run("Token Exchange Failure", func(t *testing.T) {
		// Mock server returning error for token exchange
		errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "invalid grant", http.StatusBadRequest)
		}))
		defer errorServer.Close()

		// Mock provider configuration
		config := oauth2.Config{
			RedirectURL: "https://example.com/callback",
			Providers: []oauth2.ProviderConfig{
				{
					Name:         "google",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
					TokenURL:     errorServer.URL + "/token",
				},
			},
		}

		// Initialize Fiber app
		app := fiber.New()
		app.Get("/callback", oauth2.CallbackHandler("google", config))

		// Simulate HTTP request with authorization code
		req := httptest.NewRequest("GET", "/callback?code=test-auth-code", nil)
		resp, err := app.Test(req)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}
