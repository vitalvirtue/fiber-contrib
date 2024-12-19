package oauth2

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

// New initializes and returns the OAuth2 middleware.
func New(config Config) fiber.Handler {
	// Validate configuration
	if err := config.Validate(); err != nil {
		log.Fatalf("OAuth2 middleware configuration error: %v", err)
	}

	// Initialize rate limiting and CORS middleware
	rateLimiter := limiter.New(limiter.Config{
		Max:        10,             // Maximum 10 requests
		Expiration: 1 * time.Minute, // Per minute
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP() // Rate limit based on IP address
		},
	})

	corsMiddleware := cors.New(cors.Config{
		AllowOrigins: "http://example.com, https://example.com",
		AllowMethods: "GET,POST,OPTIONS",
		AllowHeaders: "Authorization, Content-Type",
	})

	// Return a combined middleware handler
	return func(c *fiber.Ctx) error {
		// Apply CORS middleware
		if err := corsMiddleware(c); err != nil {
			return err
		}

		// Apply Rate Limiting middleware
		if err := rateLimiter(c); err != nil {
			return err
		}

		// OAuth2 handler logic
		return oauth2Handler(c, config)
	}
}

func oauth2Handler(c *fiber.Ctx, config Config) error {
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

// extractBearerToken extracts the token from the Authorization header.
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

// unauthorizedResponse sends an unauthorized JSON response.
func unauthorizedResponse(c *fiber.Ctx, errorCode string) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error":   errorCode,
		"message": "Unauthorized access",
	})
}

// logUnauthorizedAccess logs unauthorized access attempts.
func logUnauthorizedAccess(c *fiber.Ctx, reason string) {
	log.Printf("[OAuth2 Middleware] Unauthorized access from IP %s: %s", c.IP(), reason)
}
