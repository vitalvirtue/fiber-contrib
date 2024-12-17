package oauth2

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// OAuth2 creates a Fiber middleware handler for OAuth2 authentication.
func OAuth2(config Config) fiber.Handler {
	// Validate the middleware configuration
	if err := config.Validate(); err != nil {
		log.Fatalf("OAuth2 middleware configuration error: %v", err)
	}

	return func(c *fiber.Ctx) error {
		// Retrieve the Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			logUnauthorizedAccess(c, "Missing Authorization header")
			return unauthorizedResponse(c, "missing_authorization_header")
		}

		// Extract the Bearer token
		token, err := extractBearerToken(authHeader)
		if err != nil {
			logUnauthorizedAccess(c, err.Error())
			return unauthorizedResponse(c, "invalid_authorization_header")
		}

		// Validate the token using TokenStorage
		claims, err := ValidateToken(token, config.TokenStorage)
		if err != nil {
			logUnauthorizedAccess(c, fmt.Sprintf("Invalid token: %v", err))
			return unauthorizedResponse(c, "invalid_token")
		}

		// Store user claims in the context for downstream handlers
		c.Locals("user", claims)

		// Proceed to the next handler
		return c.Next()
	}
}

// extractBearerToken parses the Authorization header and extracts the Bearer token.
func extractBearerToken(authHeader string) (string, error) {
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", errors.New("authorization header must start with 'Bearer'")
	}

	token := strings.TrimSpace(strings.TrimPrefix(authHeader, bearerPrefix))
	if token == "" {
		return "", errors.New("bearer token is empty")
	}
	return token, nil
}

// unauthorizedResponse sends a standardized unauthorized JSON response.
func unauthorizedResponse(c *fiber.Ctx, errorCode string) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": errorCode,
		"message": "Unauthorized access",
	})
}

// logUnauthorizedAccess logs unauthorized access attempts for debugging purposes.
func logUnauthorizedAccess(c *fiber.Ctx, reason string) {
	log.Printf("[OAuth2 Middleware] Unauthorized access from IP %s: %s", c.IP(), reason)
}

// ValidateToken validates the given token using the provided TokenStorage.
func ValidateToken(token string, storage TokenStorage) (map[string]interface{}, error) {
	// Retrieve claims from TokenStorage
	claims, err := storage.Get(token)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve token: %w", err)
	}

	// Check for expiration
	expiry, ok := claims["expiry"].(time.Time)
	if !ok || time.Now().After(expiry) {
		return nil, ErrTokenExpired
	}

	return claims, nil
}
