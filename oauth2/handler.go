package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func generateState() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func LoginHandler(providerName string, config Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Generate a secure state parameter
		state, err := generateState()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate state"})
		}

		// Store the state in a cookie
		c.Cookie(&fiber.Cookie{
			Name:     "oauth_state",
			Value:    state,
			HTTPOnly: true,
			Secure:   true, // Ensure secure in production
			Path:     "/",
		})

		// Find the provider configuration
		provider, err := config.GetProvider(providerName)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		// Construct the authorization URL
		authURL, err := constructAuthURL(*provider, config.RedirectURL, provider.Scopes, state)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		// Redirect the user to the provider's authorization page
		return c.Redirect(authURL)
	}
}

// constructAuthURL updated to include state
func constructAuthURL(provider ProviderConfig, redirectURL string, scopes []string, state string) (string, error) {
	u, err := url.Parse(provider.AuthURL)
	if err != nil {
		return "", fmt.Errorf("invalid auth URL: %w", err)
	}

	// Query parameters for the OAuth2 authorization URL
	q := u.Query()
	q.Set("client_id", provider.ClientID)
	q.Set("redirect_uri", redirectURL)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func CallbackHandler(providerName string, config Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Extract the state from the query and the cookie
		queryState := c.Query("state")
		cookieState := c.Cookies("oauth_state")

		if queryState == "" || cookieState == "" || queryState != cookieState {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid or missing state parameter"})
		}

		// Extract the authorization code from the query
		code := c.Query("code")
		if code == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Authorization code is missing"})
		}

		// Find the provider configuration
		provider, err := config.GetProvider(providerName)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		// Exchange the authorization code for an access token
		token, err := exchangeCodeForToken(*provider, code, config.RedirectURL)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to exchange token"})
		}

		// Fetch user information (if available)
		userInfo, err := fetchUserInfo(*provider, token.AccessToken)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch user info"})
		}

		// Save the token and user info in storage
		if config.TokenStorage != nil {
			expiryDuration := time.Until(token.Expiry)
			err = config.TokenStorage.Save(token.AccessToken, userInfo, expiryDuration)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save token"})
			}
		}

		// Return user info to the client
		return c.JSON(fiber.Map{
			"access_token": token.AccessToken,
			"user_info":    userInfo,
		})
	}
}

func RefreshTokenHandler(config Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the refresh token from the request body
		refreshToken := c.FormValue("refresh_token")
		if refreshToken == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing refresh token"})
		}

		// Validate the refresh token
		var userID string
		if config.UseJWTForRefresh {
			// Validate JWT refresh token
			claims, err := validateJWT(config, refreshToken)
			if err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid refresh token"})
			}
			userID, _ = claims["sub"].(string)
		} else {
			// Validate UUID refresh token
			claims, err := config.TokenStorage.Get(refreshToken)
			if err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired refresh token"})
			}
			userID, _ = claims["user_id"].(string)
		}

		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
		}

		// Remove the old refresh token from storage
		if !config.UseJWTForRefresh && config.TokenStorage != nil {
			if err := config.TokenStorage.Delete(refreshToken); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete old refresh token"})
			}
		}

		// Generate a new access token
		newAccessToken, err := createJWT(config, userID, 15*time.Minute) // 15-minute validity
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create access token"})
		}

		var newRefreshToken string
		if config.UseJWTForRefresh {
			// Generate a new JWT refresh token
			newRefreshToken, err = createJWT(config, userID, 24*time.Hour) // 24-hour validity
		} else {
			// Generate a new UUID refresh token
			newRefreshToken = generateToken()
		}
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create refresh token"})
		}

		// Save the new refresh token to storage (if UUID)
		if !config.UseJWTForRefresh && config.TokenStorage != nil {
			err = config.TokenStorage.Save(newRefreshToken, map[string]interface{}{
				"user_id": userID,
			}, 24*time.Hour)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save new refresh token"})
			}
		}

		// Return the new tokens to the client
		return c.JSON(fiber.Map{
			"access_token":  newAccessToken,
			"refresh_token": newRefreshToken,
			"expires_in":    15 * 60, // 15 minutes in seconds
		})
	}
}

// exchangeCodeForToken exchanges the authorization code for an access token.
func exchangeCodeForToken(provider ProviderConfig, code, redirectURL string) (*Token, error) {
	data := url.Values{}
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)
	data.Set("grant_type", "authorization_code")

	resp, err := http.PostForm(provider.TokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	var token Token
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Set expiration if not provided
	if token.Expiry.IsZero() {
		token.Expiry = time.Now().Add(1 * time.Hour)
	}

	return &token, nil
}

// fetchUserInfo fetches user information using the access token.
func fetchUserInfo(provider ProviderConfig, accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", provider.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return userInfo, nil
}

func ClientCredentialsHandler(config Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		clientID := c.FormValue("client_id")
		clientSecret := c.FormValue("client_secret")

		// Validate client credentials
		_, err := validateClientCredentials(config.Providers, clientID, clientSecret)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid client credentials"})
		}

		// Create token
		newAccessToken, err := createJWT(config, clientID, 1*time.Hour)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create access token"})
		}

		return c.JSON(fiber.Map{
			"access_token": newAccessToken,
			"expires_in":   3600, // 1 hour in seconds
			"token_type":   "Bearer",
		})
	}
}

func validateClientCredentials(providers []ProviderConfig, clientID, clientSecret string) (*ProviderConfig, error) {
	for _, provider := range providers {
		if provider.ClientID == clientID && provider.ClientSecret == clientSecret {
			return &provider, nil
		}
	}
	return nil, errors.New("invalid client credentials")
}

func generateToken() string {
	return uuid.New().String()
}
