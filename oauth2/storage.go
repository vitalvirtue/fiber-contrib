package oauth2

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenStorage defines the interface for managing OAuth2 tokens.
type TokenStorage interface {
	Save(token string, claims map[string]interface{}, expiration time.Duration) error
	Get(token string) (map[string]interface{}, error)
	Delete(token string) error
	Cleanup() error
}

// InMemoryStorage implements TokenStorage with an in-memory backend.
type InMemoryStorage struct {
	data  map[string]storageEntry
	mutex sync.RWMutex
}

// storageEntry represents a token with claims and expiration time.
type storageEntry struct {
	claims     map[string]interface{}
	expiration time.Time
}

// NewInMemoryStorage creates a new instance of InMemoryStorage.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		data: make(map[string]storageEntry),
	}
}

// Save stores a token and its claims with an expiration duration.
func (s *InMemoryStorage) Save(token string, claims map[string]interface{}, expiration time.Duration) error {
	if token == "" {
		return errors.New("token cannot be empty")
	}

	if expiration <= 0 {
		return errors.New("expiration must be greater than zero")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.data[token] = storageEntry{
		claims:     claims,
		expiration: time.Now().Add(expiration),
	}

	return nil
}

// Get retrieves the claims for a given token.
func (s *InMemoryStorage) Get(token string) (map[string]interface{}, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}

	s.mutex.RLock()
	entry, exists := s.data[token]
	s.mutex.RUnlock()

	if !exists {
		return nil, errors.New("token not found")
	}

	if time.Now().After(entry.expiration) {
		// Token expired, delete it
		s.Delete(token)
		return nil, errors.New("token expired")
	}

	return entry.claims, nil
}

// Delete removes a token from the storage.
func (s *InMemoryStorage) Delete(token string) error {
	if token == "" {
		return errors.New("token cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.data, token)
	return nil
}

// Cleanup removes expired tokens from the storage.
func (s *InMemoryStorage) Cleanup() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	for token, entry := range s.data {
		if now.After(entry.expiration) {
			delete(s.data, token)
		}
	}

	return nil
}

// RedisStorage implements TokenStorage using Redis.
type RedisStorage struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisStorage creates a new RedisStorage instance.
func NewRedisStorage(addr, password string, db int) *RedisStorage {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return &RedisStorage{
		client: client,
		ctx:    context.Background(),
	}
}

// Save stores a token and its claims in Redis with an expiration.
func (r *RedisStorage) Save(token string, claims map[string]interface{}, expiration time.Duration) error {
	if token == "" {
		return errors.New("token cannot be empty")
	}

	if expiration <= 0 {
		return errors.New("expiration must be greater than zero")
	}

	return r.client.HSet(r.ctx, token, claims).Err()
}

// Get retrieves the claims for a given token.
func (r *RedisStorage) Get(token string) (map[string]interface{}, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}

	result, err := r.client.HGetAll(r.ctx, token).Result()
	if err != nil || len(result) == 0 {
		return nil, errors.New("token not found")
	}

	// Convert map[string]string to map[string]interface{}
	claims := make(map[string]interface{})
	for k, v := range result {
		claims[k] = v
	}

	return claims, nil
}

// Delete removes a token from Redis.
func (r *RedisStorage) Delete(token string) error {
	return r.client.Del(r.ctx, token).Err()
}

// Cleanup does nothing in Redis since keys expire automatically.
func (r *RedisStorage) Cleanup() error {
	return nil
}
