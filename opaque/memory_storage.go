package opaque

import (
	"context"
	"sync"
	"time"
)

// MemoryStorage implements TokenStorage using in-memory map
type MemoryStorage struct {
	tokens map[string]*OpaqueTokenInfo
	mutex  sync.RWMutex
}

// NewMemoryStorage creates a new in-memory storage instance
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		tokens: make(map[string]*OpaqueTokenInfo),
	}
}

// Store stores a token with its information
func (ms *MemoryStorage) Store(ctx context.Context, token string, info *OpaqueTokenInfo) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	ms.tokens[token] = info
	return nil
}

// Get retrieves token information by token string
func (ms *MemoryStorage) Get(ctx context.Context, token string) (*OpaqueTokenInfo, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	info, exists := ms.tokens[token]
	if !exists {
		return nil, &StorageError{
			Type:    "TOKEN_NOT_FOUND",
			Message: "token not found",
		}
	}

	// Return a copy to prevent external modifications
	infoCopy := *info
	return &infoCopy, nil
}

// Update updates an existing token's information
func (ms *MemoryStorage) Update(ctx context.Context, token string, info *OpaqueTokenInfo) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	_, exists := ms.tokens[token]
	if !exists {
		return &StorageError{
			Type:    "TOKEN_NOT_FOUND",
			Message: "token not found",
		}
	}

	ms.tokens[token] = info
	return nil
}

// Delete removes a token from storage
func (ms *MemoryStorage) Delete(ctx context.Context, token string) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	_, exists := ms.tokens[token]
	if !exists {
		return &StorageError{
			Type:    "TOKEN_NOT_FOUND",
			Message: "token not found",
		}
	}

	delete(ms.tokens, token)
	return nil
}

// List retrieves tokens based on filters
func (ms *MemoryStorage) List(ctx context.Context, filters *ListFilters) ([]*OpaqueTokenInfo, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var results []*OpaqueTokenInfo
	count := 0

	for _, info := range ms.tokens {
		// Apply filters
		if filters.UserID != "" && info.UserID != filters.UserID {
			continue
		}

		if filters.ClientID != "" && info.ClientID != filters.ClientID {
			continue
		}

		if filters.Active != nil && info.IsActive != *filters.Active {
			continue
		}

		// Apply pagination
		if filters.Offset > 0 && count < filters.Offset {
			count++
			continue
		}

		if filters.Limit > 0 && len(results) >= filters.Limit {
			break
		}

		// Return a copy to prevent external modifications
		infoCopy := *info
		results = append(results, &infoCopy)
		count++
	}

	return results, nil
}

// CleanupExpired removes expired tokens from storage
func (ms *MemoryStorage) CleanupExpired(ctx context.Context) (int, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	now := time.Now()
	removedCount := 0

	for token, info := range ms.tokens {
		if now.After(info.ExpiresAt) {
			delete(ms.tokens, token)
			removedCount++
		}
	}

	return removedCount, nil
}

// Close closes the storage connection (no-op for memory storage)
func (ms *MemoryStorage) Close() error {
	// For memory storage, we don't clear tokens on close
	// This allows the manager to continue working after close
	return nil
}

// GetStats returns storage statistics
func (ms *MemoryStorage) GetStats() map[string]interface{} {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	activeCount := 0
	expiredCount := 0
	now := time.Now()

	for _, info := range ms.tokens {
		if now.After(info.ExpiresAt) {
			expiredCount++
		} else if info.IsActive {
			activeCount++
		}
	}

	return map[string]interface{}{
		"total_tokens":   len(ms.tokens),
		"active_tokens":  activeCount,
		"expired_tokens": expiredCount,
		"storage_type":   "memory",
	}
}
