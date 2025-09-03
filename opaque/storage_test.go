package opaque

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStorage_StoreAndGet(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()
	token := "test_token_123"
	info := &OpaqueTokenInfo{
		TokenID:    "token_id_123",
		UserID:     "user_123",
		ClientID:   "client_456",
		Scope:      []string{"read", "write"},
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		IssuedAt:   time.Now(),
		CustomData: map[string]interface{}{"role": "admin"},
		IsActive:   true,
		CreatedAt:  time.Now(),
	}

	// Test store
	err := storage.Store(ctx, token, info)
	if err != nil {
		t.Fatalf("Failed to store token: %v", err)
	}

	// Test get
	retrievedInfo, err := storage.Get(ctx, token)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	if retrievedInfo.TokenID != info.TokenID {
		t.Errorf("Expected TokenID %s, got %s", info.TokenID, retrievedInfo.TokenID)
	}
	if retrievedInfo.UserID != info.UserID {
		t.Errorf("Expected UserID %s, got %s", info.UserID, retrievedInfo.UserID)
	}
	if retrievedInfo.ClientID != info.ClientID {
		t.Errorf("Expected ClientID %s, got %s", info.ClientID, retrievedInfo.ClientID)
	}
	if len(retrievedInfo.Scope) != len(info.Scope) {
		t.Errorf("Expected Scope length %d, got %d", len(info.Scope), len(retrievedInfo.Scope))
	}
	if retrievedInfo.IsActive != info.IsActive {
		t.Errorf("Expected IsActive %v, got %v", info.IsActive, retrievedInfo.IsActive)
	}
}

func TestMemoryStorage_GetNotFound(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()
	_, err := storage.Get(ctx, "nonexistent_token")
	if err == nil {
		t.Error("Expected error for nonexistent token")
	}

	storageErr, ok := err.(*StorageError)
	if !ok {
		t.Error("Expected StorageError type")
	}
	if storageErr.Type != "TOKEN_NOT_FOUND" {
		t.Errorf("Expected error type TOKEN_NOT_FOUND, got %s", storageErr.Type)
	}
}

func TestMemoryStorage_Update(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()
	token := "test_token_123"
	info := &OpaqueTokenInfo{
		TokenID:   "token_id_123",
		UserID:    "user_123",
		ClientID:  "client_456",
		Scope:     []string{"read"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
		IsActive:  true,
		CreatedAt: time.Now(),
	}

	// Store initial token
	err := storage.Store(ctx, token, info)
	if err != nil {
		t.Fatalf("Failed to store token: %v", err)
	}

	// Update token
	info.IsActive = false
	info.Scope = []string{"read", "write", "admin"}
	err = storage.Update(ctx, token, info)
	if err != nil {
		t.Fatalf("Failed to update token: %v", err)
	}

	// Verify update
	retrievedInfo, err := storage.Get(ctx, token)
	if err != nil {
		t.Fatalf("Failed to get updated token: %v", err)
	}

	if retrievedInfo.IsActive != false {
		t.Error("Expected IsActive to be false after update")
	}
	if len(retrievedInfo.Scope) != 3 {
		t.Errorf("Expected Scope length 3, got %d", len(retrievedInfo.Scope))
	}
}

func TestMemoryStorage_UpdateNotFound(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()
	info := &OpaqueTokenInfo{
		TokenID:   "token_id_123",
		UserID:    "user_123",
		IsActive:  false,
		CreatedAt: time.Now(),
	}

	err := storage.Update(ctx, "nonexistent_token", info)
	if err == nil {
		t.Error("Expected error for updating nonexistent token")
	}

	storageErr, ok := err.(*StorageError)
	if !ok {
		t.Error("Expected StorageError type")
	}
	if storageErr.Type != "TOKEN_NOT_FOUND" {
		t.Errorf("Expected error type TOKEN_NOT_FOUND, got %s", storageErr.Type)
	}
}

func TestMemoryStorage_Delete(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()
	token := "test_token_123"
	info := &OpaqueTokenInfo{
		TokenID:   "token_id_123",
		UserID:    "user_123",
		IsActive:  true,
		CreatedAt: time.Now(),
	}

	// Store token
	err := storage.Store(ctx, token, info)
	if err != nil {
		t.Fatalf("Failed to store token: %v", err)
	}

	// Delete token
	err = storage.Delete(ctx, token)
	if err != nil {
		t.Fatalf("Failed to delete token: %v", err)
	}

	// Verify deletion
	_, err = storage.Get(ctx, token)
	if err == nil {
		t.Error("Expected error for deleted token")
	}
}

func TestMemoryStorage_DeleteNotFound(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()
	err := storage.Delete(ctx, "nonexistent_token")
	if err == nil {
		t.Error("Expected error for deleting nonexistent token")
	}

	storageErr, ok := err.(*StorageError)
	if !ok {
		t.Error("Expected StorageError type")
	}
	if storageErr.Type != "TOKEN_NOT_FOUND" {
		t.Errorf("Expected error type TOKEN_NOT_FOUND, got %s", storageErr.Type)
	}
}

func TestMemoryStorage_List(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()

	// Store multiple tokens
	tokens := []struct {
		token string
		info  *OpaqueTokenInfo
	}{
		{
			token: "token1",
			info: &OpaqueTokenInfo{
				TokenID:   "id1",
				UserID:    "user1",
				ClientID:  "client1",
				IsActive:  true,
				ExpiresAt: time.Now().Add(1 * time.Hour),
				CreatedAt: time.Now(),
			},
		},
		{
			token: "token2",
			info: &OpaqueTokenInfo{
				TokenID:   "id2",
				UserID:    "user1",
				ClientID:  "client2",
				IsActive:  false,
				ExpiresAt: time.Now().Add(1 * time.Hour),
				CreatedAt: time.Now(),
			},
		},
		{
			token: "token3",
			info: &OpaqueTokenInfo{
				TokenID:   "id3",
				UserID:    "user2",
				ClientID:  "client1",
				IsActive:  true,
				ExpiresAt: time.Now().Add(1 * time.Hour),
				CreatedAt: time.Now(),
			},
		},
	}

	for _, tokenData := range tokens {
		err := storage.Store(ctx, tokenData.token, tokenData.info)
		if err != nil {
			t.Fatalf("Failed to store token %s: %v", tokenData.token, err)
		}
	}

	// Test list all tokens
	allTokens, err := storage.List(ctx, &ListFilters{})
	if err != nil {
		t.Fatalf("Failed to list all tokens: %v", err)
	}
	if len(allTokens) != 3 {
		t.Errorf("Expected 3 tokens, got %d", len(allTokens))
	}

	// Test filter by user ID
	user1Tokens, err := storage.List(ctx, &ListFilters{UserID: "user1"})
	if err != nil {
		t.Fatalf("Failed to list user1 tokens: %v", err)
	}
	if len(user1Tokens) != 2 {
		t.Errorf("Expected 2 tokens for user1, got %d", len(user1Tokens))
	}

	// Test filter by client ID
	client1Tokens, err := storage.List(ctx, &ListFilters{ClientID: "client1"})
	if err != nil {
		t.Fatalf("Failed to list client1 tokens: %v", err)
	}
	if len(client1Tokens) != 2 {
		t.Errorf("Expected 2 tokens for client1, got %d", len(client1Tokens))
	}

	// Test filter by active status
	activeTokens, err := storage.List(ctx, &ListFilters{Active: &[]bool{true}[0]})
	if err != nil {
		t.Fatalf("Failed to list active tokens: %v", err)
	}
	if len(activeTokens) != 2 {
		t.Errorf("Expected 2 active tokens, got %d", len(activeTokens))
	}

	// Test filter by inactive status
	inactiveTokens, err := storage.List(ctx, &ListFilters{Active: &[]bool{false}[0]})
	if err != nil {
		t.Fatalf("Failed to list inactive tokens: %v", err)
	}
	if len(inactiveTokens) != 1 {
		t.Errorf("Expected 1 inactive token, got %d", len(inactiveTokens))
	}

	// Test pagination
	limitedTokens, err := storage.List(ctx, &ListFilters{Limit: 2})
	if err != nil {
		t.Fatalf("Failed to list limited tokens: %v", err)
	}
	if len(limitedTokens) != 2 {
		t.Errorf("Expected 2 limited tokens, got %d", len(limitedTokens))
	}
}

func TestMemoryStorage_CleanupExpired(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()
	now := time.Now()

	// Store expired and non-expired tokens
	tokens := []struct {
		token string
		info  *OpaqueTokenInfo
	}{
		{
			token: "expired_token",
			info: &OpaqueTokenInfo{
				TokenID:   "id1",
				UserID:    "user1",
				ExpiresAt: now.Add(-1 * time.Hour), // Expired
				CreatedAt: now,
			},
		},
		{
			token: "valid_token",
			info: &OpaqueTokenInfo{
				TokenID:   "id2",
				UserID:    "user1",
				ExpiresAt: now.Add(1 * time.Hour), // Valid
				CreatedAt: now,
			},
		},
	}

	for _, tokenData := range tokens {
		err := storage.Store(ctx, tokenData.token, tokenData.info)
		if err != nil {
			t.Fatalf("Failed to store token %s: %v", tokenData.token, err)
		}
	}

	// Cleanup expired tokens
	removedCount, err := storage.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("Failed to cleanup expired tokens: %v", err)
	}
	if removedCount != 1 {
		t.Errorf("Expected 1 expired token removed, got %d", removedCount)
	}

	// Verify only valid token remains
	remainingTokens, err := storage.List(ctx, &ListFilters{})
	if err != nil {
		t.Fatalf("Failed to list remaining tokens: %v", err)
	}
	if len(remainingTokens) != 1 {
		t.Errorf("Expected 1 remaining token, got %d", len(remainingTokens))
	}
	if remainingTokens[0].TokenID != "id2" {
		t.Errorf("Expected remaining token ID to be id2, got %s", remainingTokens[0].TokenID)
	}
}

func TestMemoryStorage_ContextCancellation(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	token := "test_token"
	info := &OpaqueTokenInfo{
		TokenID:   "id1",
		UserID:    "user1",
		IsActive:  true,
		CreatedAt: time.Now(),
	}

	// Store should fail due to cancelled context
	err := storage.Store(ctx, token, info)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}

	// Get should fail due to cancelled context
	_, err = storage.Get(ctx, token)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

func TestMemoryStorage_GetStats(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()
	now := time.Now()

	// Store tokens with different states
	tokens := []struct {
		token string
		info  *OpaqueTokenInfo
	}{
		{
			token: "active_token",
			info: &OpaqueTokenInfo{
				TokenID:   "id1",
				UserID:    "user1",
				IsActive:  true,
				ExpiresAt: now.Add(1 * time.Hour),
				CreatedAt: now,
			},
		},
		{
			token: "expired_token",
			info: &OpaqueTokenInfo{
				TokenID:   "id2",
				UserID:    "user1",
				IsActive:  true,
				ExpiresAt: now.Add(-1 * time.Hour),
				CreatedAt: now,
			},
		},
		{
			token: "inactive_token",
			info: &OpaqueTokenInfo{
				TokenID:   "id3",
				UserID:    "user1",
				IsActive:  false,
				ExpiresAt: now.Add(1 * time.Hour),
				CreatedAt: now,
			},
		},
	}

	for _, tokenData := range tokens {
		err := storage.Store(ctx, tokenData.token, tokenData.info)
		if err != nil {
			t.Fatalf("Failed to store token %s: %v", tokenData.token, err)
		}
	}

	stats := storage.GetStats()
	if stats["total_tokens"] != 3 {
		t.Errorf("Expected total_tokens 3, got %v", stats["total_tokens"])
	}
	if stats["active_tokens"] != 1 {
		t.Errorf("Expected active_tokens 1, got %v", stats["active_tokens"])
	}
	if stats["expired_tokens"] != 1 {
		t.Errorf("Expected expired_tokens 1, got %v", stats["expired_tokens"])
	}
	if stats["storage_type"] != "memory" {
		t.Errorf("Expected storage_type 'memory', got %v", stats["storage_type"])
	}
}

func TestStorageFactory_NewStorage(t *testing.T) {
	factory := &StorageFactory{}

	// Test memory storage
	memoryConfig := &StorageConfig{
		Type: "memory",
	}
	memoryStorage, err := factory.NewStorage(memoryConfig)
	if err != nil {
		t.Fatalf("Failed to create memory storage: %v", err)
	}
	defer memoryStorage.Close()

	if memoryStorage == nil {
		t.Error("Expected memory storage to be created")
	}

	// Test unsupported storage type
	unsupportedConfig := &StorageConfig{
		Type: "unsupported",
	}
	_, err = factory.NewStorage(unsupportedConfig)
	if err == nil {
		t.Error("Expected error for unsupported storage type")
	}

	storageErr, ok := err.(*StorageError)
	if !ok {
		t.Error("Expected StorageError type")
	}
	if storageErr.Type != "UNSUPPORTED_STORAGE_TYPE" {
		t.Errorf("Expected error type UNSUPPORTED_STORAGE_TYPE, got %s", storageErr.Type)
	}
}

func TestStorageError_Error(t *testing.T) {
	// Test error without underlying error
	err := &StorageError{
		Type:    "TEST_ERROR",
		Message: "test message",
	}
	expected := "test message"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}

	// Test error with underlying error
	underlyingErr := &StorageError{
		Type:    "UNDERLYING_ERROR",
		Message: "underlying message",
	}
	err = &StorageError{
		Type:    "TEST_ERROR",
		Message: "test message",
		Err:     underlyingErr,
	}
	expected = "test message: underlying message"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestStorageError_Unwrap(t *testing.T) {
	underlyingErr := &StorageError{
		Type:    "UNDERLYING_ERROR",
		Message: "underlying message",
	}
	err := &StorageError{
		Type:    "TEST_ERROR",
		Message: "test message",
		Err:     underlyingErr,
	}

	unwrapped := err.Unwrap()
	if unwrapped != underlyingErr {
		t.Error("Expected unwrapped error to match underlying error")
	}
}

// Test custom storage implementation
type TestStorage struct {
	data map[string]*OpaqueTokenInfo
}

func NewTestStorage() *TestStorage {
	return &TestStorage{
		data: make(map[string]*OpaqueTokenInfo),
	}
}

func (ts *TestStorage) Store(ctx context.Context, token string, info *OpaqueTokenInfo) error {
	ts.data[token] = info
	return nil
}

func (ts *TestStorage) Get(ctx context.Context, token string) (*OpaqueTokenInfo, error) {
	info, exists := ts.data[token]
	if !exists {
		return nil, &StorageError{
			Type:    "TOKEN_NOT_FOUND",
			Message: "token not found",
		}
	}
	return info, nil
}

func (ts *TestStorage) Update(ctx context.Context, token string, info *OpaqueTokenInfo) error {
	ts.data[token] = info
	return nil
}

func (ts *TestStorage) Delete(ctx context.Context, token string) error {
	delete(ts.data, token)
	return nil
}

func (ts *TestStorage) List(ctx context.Context, filters *ListFilters) ([]*OpaqueTokenInfo, error) {
	var results []*OpaqueTokenInfo
	for _, info := range ts.data {
		if filters.UserID != "" && info.UserID != filters.UserID {
			continue
		}
		results = append(results, info)
	}
	return results, nil
}

func (ts *TestStorage) CleanupExpired(ctx context.Context) (int, error) {
	now := time.Now()
	count := 0
	for token, info := range ts.data {
		if now.After(info.ExpiresAt) {
			delete(ts.data, token)
			count++
		}
	}
	return count, nil
}

func (ts *TestStorage) Close() error {
	ts.data = make(map[string]*OpaqueTokenInfo)
	return nil
}

func TestCustomStorage(t *testing.T) {
	storage := NewTestStorage()
	defer storage.Close()

	ctx := context.Background()
	token := "test_token"
	info := &OpaqueTokenInfo{
		TokenID:   "id1",
		UserID:    "user1",
		IsActive:  true,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}

	// Test store
	err := storage.Store(ctx, token, info)
	if err != nil {
		t.Fatalf("Failed to store token: %v", err)
	}

	// Test get
	retrievedInfo, err := storage.Get(ctx, token)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if retrievedInfo.TokenID != info.TokenID {
		t.Errorf("Expected TokenID %s, got %s", info.TokenID, retrievedInfo.TokenID)
	}

	// Test list
	tokens, err := storage.List(ctx, &ListFilters{UserID: "user1"})
	if err != nil {
		t.Fatalf("Failed to list tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("Expected 1 token, got %d", len(tokens))
	}

	// Test delete
	err = storage.Delete(ctx, token)
	if err != nil {
		t.Fatalf("Failed to delete token: %v", err)
	}

	// Verify deletion
	_, err = storage.Get(ctx, token)
	if err == nil {
		t.Error("Expected error for deleted token")
	}
}
