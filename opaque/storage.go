package opaque

import (
	"context"
	"time"
)

// TokenStorage defines the interface for storing and retrieving opaque tokens
type TokenStorage interface {
	// Store stores a token with its information
	Store(ctx context.Context, token string, info *OpaqueTokenInfo) error

	// Get retrieves token information by token string
	Get(ctx context.Context, token string) (*OpaqueTokenInfo, error)

	// Update updates an existing token's information
	Update(ctx context.Context, token string, info *OpaqueTokenInfo) error

	// Delete removes a token from storage
	Delete(ctx context.Context, token string) error

	// List retrieves tokens based on filters
	List(ctx context.Context, filters *ListFilters) ([]*OpaqueTokenInfo, error)

	// CleanupExpired removes expired tokens from storage
	CleanupExpired(ctx context.Context) (int, error)

	// Close closes the storage connection
	Close() error
}

// ListFilters defines filters for listing tokens
type ListFilters struct {
	UserID   string
	ClientID string
	Active   *bool
	Limit    int
	Offset   int
}

// StorageConfig defines configuration for storage implementations
type StorageConfig struct {
	// Common fields
	Type string // "memory", "mysql", "postgres", etc.

	// Database connection fields
	Host     string
	Port     int
	Database string
	Username string
	Password string

	// Connection pool settings
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration

	// Table/collection name
	TableName string

	// Additional options
	Options map[string]interface{}
}

// StorageFactory creates storage instances based on configuration
type StorageFactory struct{}

// NewStorage creates a new storage instance based on the configuration
func (sf *StorageFactory) NewStorage(config *StorageConfig) (TokenStorage, error) {
	switch config.Type {
	case "memory":
		return NewMemoryStorage(), nil
	case "mysql":
		return NewMySQLStorage(config)
	case "postgres", "postgresql":
		return NewPostgreSQLStorage(config)
	// case "redis":
	//	return NewRedisStorage(config)
	default:
		return nil, &StorageError{
			Type:    "UNSUPPORTED_STORAGE_TYPE",
			Message: "unsupported storage type: " + config.Type,
		}
	}
}

// StorageError represents storage-related errors
type StorageError struct {
	Type    string
	Message string
	Err     error
}

func (e *StorageError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *StorageError) Unwrap() error {
	return e.Err
}
