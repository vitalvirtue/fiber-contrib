package oauth2_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/gofiber/contrib/oauth2"
)

func TestInMemoryStorage(t *testing.T) {
	storage := oauth2.NewInMemoryStorage()

	t.Run("Save and Get Token", func(t *testing.T) {
		token := "test-token"
		claims := map[string]interface{}{"user_id": 123}
		expiration := 1 * time.Minute

		err := storage.Save(token, claims, expiration)
		assert.NoError(t, err)

		retrievedClaims, err := storage.Get(token)
		assert.NoError(t, err)
		assert.Equal(t, claims["user_id"], retrievedClaims["user_id"])
	})

	t.Run("Token Expiration", func(t *testing.T) {
    storage := oauth2.NewInMemoryStorage()
    token := "expired-token"
    claims := map[string]interface{}{"user_id": 123}

    // Token'ı hemen süresi dolacak şekilde kaydedelim
    err := storage.Save(token, claims, 1*time.Nanosecond)
    assert.NoError(t, err)

    // Token kaydettikten sonra bir süre bekle
    time.Sleep(2 * time.Nanosecond)

    // Token'ı almaya çalıştığımızda süresinin dolmuş olması lazım
    _, err = storage.Get(token)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "expired")
})

	t.Run("Delete Token", func(t *testing.T) {
		token := "delete-token"
		claims := map[string]interface{}{"user_id": 456}
		expiration := 1 * time.Minute

		err := storage.Save(token, claims, expiration)
		assert.NoError(t, err)

		err = storage.Delete(token)
		assert.NoError(t, err)

		_, err = storage.Get(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}
