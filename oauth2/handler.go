package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// LoginHandler redirects users to the OAuth2 provider's authorization page.
func LoginHandler(providerName string, config Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Find the provider configuration
		provider, err := config.GetProvider(providerName)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		// Construct the authorization URL
		authURL, err := constructAuthURL(*provider, config.RedirectURL, provider.Scopes)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		// Redirect the user to the provider's authorization page
		return c.Redirect(authURL)
	}
}

// constructAuthURL builds the authorization URL with required query parameters.
func constructAuthURL(provider ProviderConfig, redirectURL string, scopes []string) (string, error) {
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
	q.Set("state", "random_state_string") // TODO: Replace with secure state generation

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// CallbackHandler processes the OAuth2 callback, exchanges the code for an access token.
func CallbackHandler(providerName string, config Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
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
