package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/cjwt/opaque"
)

func main() {
	fmt.Println("=== OpaqueTokenManager Storage Examples ===")

	// Example 1: Memory Storage (Default)
	fmt.Println("\n--- Example 1: Memory Storage ---")
	memoryExample()

	// Example 2: MySQL Storage
	fmt.Println("\n--- Example 2: MySQL Storage ---")
	mysqlExample()

	// Example 3: PostgreSQL Storage
	fmt.Println("\n--- Example 3: PostgreSQL Storage ---")
	postgresqlExample()

	// Example 4: Storage Factory
	fmt.Println("\n--- Example 4: Storage Factory ---")
	storageFactoryExample()
}

func memoryExample() {
	// Create manager with default memory storage
	otm := opaque.NewOpaqueTokenManager()
	defer otm.Close()

	// Generate token
	req := opaque.OpaqueTokenRequest{
		UserID:    "user123",
		ClientID:  "client456",
		Scope:     []string{"read", "write"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CustomData: map[string]interface{}{
			"role": "admin",
		},
	}

	resp, err := otm.GenerateToken(req)
	if err != nil {
		log.Printf("Failed to generate token: %v", err)
		return
	}

	fmt.Printf("Generated token: %s\n", resp.Token)
	fmt.Printf("Token ID: %s\n", resp.TokenID)

	// Validate token
	validateReq := opaque.ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateToken(validateReq)
	if validateResp.Valid {
		fmt.Println("Token is valid!")
		fmt.Printf("User ID: %s\n", validateResp.TokenInfo.UserID)
	} else {
		fmt.Printf("Token validation failed: %s\n", validateResp.Error)
	}
}

func mysqlExample() {
	// MySQL storage configuration
	config := &opaque.StorageConfig{
		Type:            "mysql",
		Host:            "localhost",
		Port:            3306,
		Database:        "token_db",
		Username:        "root",
		Password:        "password",
		TableName:       "opaque_tokens",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 30 * time.Minute,
	}

	// Create storage
	storage, err := opaque.NewMySQLStorage(config)
	if err != nil {
		log.Printf("Failed to create MySQL storage: %v", err)
		return
	}
	defer storage.Close()

	// Create manager with MySQL storage
	otm := opaque.NewOpaqueTokenManagerWithStorage(storage, 32, "mysql_")

	// Generate token with context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := opaque.OpaqueTokenRequest{
		UserID:    "mysql_user",
		ClientID:  "mysql_client",
		Scope:     []string{"read"},
		ExpiresAt: time.Now().Add(12 * time.Hour),
		CustomData: map[string]interface{}{
			"database": "mysql",
			"version":  "8.0",
		},
	}

	resp, err := otm.GenerateTokenWithContext(ctx, req)
	if err != nil {
		log.Printf("Failed to generate token: %v", err)
		return
	}

	fmt.Printf("Generated MySQL token: %s\n", resp.Token)

	// Validate token
	validateReq := opaque.ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateTokenWithContext(ctx, validateReq)
	if validateResp.Valid {
		fmt.Println("MySQL token is valid!")
		fmt.Printf("Custom data: %+v\n", validateResp.TokenInfo.CustomData)
	}
}

func postgresqlExample() {
	// PostgreSQL storage configuration
	config := &opaque.StorageConfig{
		Type:            "postgresql",
		Host:            "localhost",
		Port:            5432,
		Database:        "token_db",
		Username:        "postgres",
		Password:        "password",
		TableName:       "opaque_tokens",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 30 * time.Minute,
	}

	// Create storage
	storage, err := opaque.NewPostgreSQLStorage(config)
	if err != nil {
		log.Printf("Failed to create PostgreSQL storage: %v", err)
		return
	}
	defer storage.Close()

	// Create manager with PostgreSQL storage
	otm := opaque.NewOpaqueTokenManagerWithStorage(storage, 48, "pg_")

	// Generate token
	req := opaque.OpaqueTokenRequest{
		UserID:    "postgres_user",
		ClientID:  "postgres_client",
		Scope:     []string{"read", "write", "admin"},
		ExpiresAt: time.Now().Add(6 * time.Hour),
		CustomData: map[string]interface{}{
			"database": "postgresql",
			"version":  "14.0",
			"features": []string{"jsonb", "indexes", "triggers"},
		},
	}

	resp, err := otm.GenerateToken(req)
	if err != nil {
		log.Printf("Failed to generate token: %v", err)
		return
	}

	fmt.Printf("Generated PostgreSQL token: %s\n", resp.Token)

	// List tokens
	listReq := opaque.ListTokensRequest{
		UserID: "postgres_user",
	}
	listResp := otm.ListTokens(listReq)
	fmt.Printf("Found %d tokens for user\n", listResp.Count)

	// Revoke token
	revokeReq := opaque.RevokeRequest{Token: resp.Token}
	revokeResp := otm.RevokeToken(revokeReq)
	if revokeResp.Success {
		fmt.Println("Token revoked successfully!")
	}
}

func storageFactoryExample() {
	// Create storage factory
	factory := &opaque.StorageFactory{}

	// Memory storage via factory
	memoryConfig := &opaque.StorageConfig{
		Type: "memory",
	}
	memoryStorage, err := factory.NewStorage(memoryConfig)
	if err != nil {
		log.Printf("Failed to create memory storage: %v", err)
		return
	}
	defer memoryStorage.Close()

	// Create manager with factory-created storage
	otm := opaque.NewOpaqueTokenManagerWithStorage(memoryStorage, 32, "factory_")

	// Generate multiple tokens
	for i := 0; i < 3; i++ {
		req := opaque.OpaqueTokenRequest{
			UserID:    fmt.Sprintf("factory_user_%d", i),
			ClientID:  "factory_client",
			Scope:     []string{"read"},
			ExpiresAt: time.Now().Add(1 * time.Hour),
			CustomData: map[string]interface{}{
				"batch": i,
				"type":  "factory_generated",
			},
		}

		resp, err := otm.GenerateToken(req)
		if err != nil {
			log.Printf("Failed to generate token %d: %v", i, err)
			continue
		}

		fmt.Printf("Generated factory token %d: %s\n", i, resp.Token[:20]+"...")
	}

	// List all tokens
	listReq := opaque.ListTokensRequest{
		ClientID: "factory_client",
	}
	listResp := otm.ListTokens(listReq)
	fmt.Printf("Total tokens in factory storage: %d\n", listResp.Count)

	// Cleanup expired tokens
	removedCount := otm.CleanupExpiredTokens()
	fmt.Printf("Cleaned up %d expired tokens\n", removedCount)
}

// Example of custom storage implementation
type CustomStorage struct {
	data map[string]*opaque.OpaqueTokenInfo
}

func NewCustomStorage() *CustomStorage {
	return &CustomStorage{
		data: make(map[string]*opaque.OpaqueTokenInfo),
	}
}

func (cs *CustomStorage) Store(ctx context.Context, token string, info *opaque.OpaqueTokenInfo) error {
	cs.data[token] = info
	return nil
}

func (cs *CustomStorage) Get(ctx context.Context, token string) (*opaque.OpaqueTokenInfo, error) {
	info, exists := cs.data[token]
	if !exists {
		return nil, &opaque.StorageError{
			Type:    "TOKEN_NOT_FOUND",
			Message: "token not found",
		}
	}
	return info, nil
}

func (cs *CustomStorage) Update(ctx context.Context, token string, info *opaque.OpaqueTokenInfo) error {
	cs.data[token] = info
	return nil
}

func (cs *CustomStorage) Delete(ctx context.Context, token string) error {
	delete(cs.data, token)
	return nil
}

func (cs *CustomStorage) List(ctx context.Context, filters *opaque.ListFilters) ([]*opaque.OpaqueTokenInfo, error) {
	var results []*opaque.OpaqueTokenInfo
	for _, info := range cs.data {
		// Apply filters here
		if filters.UserID != "" && info.UserID != filters.UserID {
			continue
		}
		results = append(results, info)
	}
	return results, nil
}

func (cs *CustomStorage) CleanupExpired(ctx context.Context) (int, error) {
	now := time.Now()
	count := 0
	for token, info := range cs.data {
		if now.After(info.ExpiresAt) {
			delete(cs.data, token)
			count++
		}
	}
	return count, nil
}

func (cs *CustomStorage) Close() error {
	cs.data = make(map[string]*opaque.OpaqueTokenInfo)
	return nil
}
