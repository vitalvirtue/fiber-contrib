package oauth2_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/gofiber/contrib/oauth2"
)

func TestToken_IsExpired(t *testing.T) {
	t.Run("Expired Token", func(t *testing.T) {
		token := oauth2.Token{
			Expiry: time.Now().Add(-1 * time.Minute),
		}
		assert.True(t, token.IsExpired())
	})

	t.Run("Valid Token", func(t *testing.T) {
		token := oauth2.Token{
			Expiry: time.Now().Add(1 * time.Hour),
		}
		assert.False(t, token.IsExpired())
	})
}
