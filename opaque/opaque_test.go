package opaque_test

import (
	"cjwt/opaque"
	"testing"
	"time"
)

func TestOpaqueTokenManager_GenerateToken(t *testing.T) {
	// Create opaque token manager
	otm := opaque.NewOpaqueTokenManager()

	// Test data
	req := opaque.OpaqueTokenRequest{
		UserID:    "test-user",
		ClientID:  "test-client",
		Scope:     []string{"read", "write"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomData: map[string]interface{}{
			"role": "admin",
		},
		TokenLength: 32,
		TokenPrefix: "op_",
	}

	// Generate token
	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate opaque token: %v", err)
	}

	if resp.Token == "" {
		t.Error("Generated token is empty")
	}

	if resp.TokenID == "" {
		t.Error("Token ID is empty")
	}

	if resp.UserID != "test-user" {
		t.Errorf("Expected user ID 'test-user', got '%s'", resp.UserID)
	}

	if resp.ClientID != "test-client" {
		t.Errorf("Expected client ID 'test-client', got '%s'", resp.ClientID)
	}

	if len(resp.Scope) != 2 {
		t.Errorf("Expected scope length 2, got %d", len(resp.Scope))
	}

	// Check token prefix
	if len(resp.Token) < 3 || resp.Token[:3] != "op_" {
		t.Errorf("Expected token to start with 'op_', got '%s'", resp.Token[:3])
	}
}

func TestOpaqueTokenManager_ValidateToken(t *testing.T) {
	// Create opaque token manager
	otm := opaque.NewOpaqueTokenManager()

	// Generate a token first
	req := opaque.OpaqueTokenRequest{
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Validate token
	validateReq := opaque.ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateToken(validateReq)

	if !validateResp.Valid {
		t.Errorf("Token validation failed: %s", validateResp.Error)
	}

	if validateResp.TokenInfo == nil {
		t.Error("Token info should not be nil")
	}

	if validateResp.TokenInfo.UserID != "test-user" {
		t.Errorf("Expected user ID 'test-user', got '%s'", validateResp.TokenInfo.UserID)
	}
}

func TestOpaqueTokenManager_InvalidToken(t *testing.T) {
	// Create opaque token manager
	otm := opaque.NewOpaqueTokenManager()

	// Test with invalid token
	validateReq := opaque.ValidateRequest{Token: "invalid-token"}
	validateResp := otm.ValidateToken(validateReq)

	if validateResp.Valid {
		t.Error("Expected invalid token to fail validation")
	}

	if validateResp.Error == "" {
		t.Error("Expected error message for invalid token")
	}
}

func TestOpaqueTokenManager_ExpiredToken(t *testing.T) {
	// Create opaque token manager
	otm := opaque.NewOpaqueTokenManager()

	// Generate expired token
	req := opaque.OpaqueTokenRequest{
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	// Validate expired token
	validateReq := opaque.ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateToken(validateReq)

	if validateResp.Valid {
		t.Error("Expired token should not be valid")
	}

	if validateResp.Error == "" {
		t.Error("Expected error message for expired token")
	}
}

func TestOpaqueTokenManager_RevokeToken(t *testing.T) {
	// Create opaque token manager
	otm := opaque.NewOpaqueTokenManager()

	// Generate a token
	req := opaque.OpaqueTokenRequest{
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Revoke token
	revokeReq := opaque.RevokeRequest{Token: resp.Token}
	revokeResp := otm.RevokeToken(revokeReq)

	if !revokeResp.Success {
		t.Errorf("Token revocation failed: %s", revokeResp.Error)
	}

	// Try to validate revoked token
	validateReq := opaque.ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateToken(validateReq)

	if validateResp.Valid {
		t.Error("Revoked token should not be valid")
	}

	if validateResp.Error == "" {
		t.Error("Expected error message for revoked token")
	}
}

func TestOpaqueTokenManager_RevokeInvalidToken(t *testing.T) {
	// Create opaque token manager
	otm := opaque.NewOpaqueTokenManager()

	// Try to revoke invalid token
	revokeReq := opaque.RevokeRequest{Token: "invalid-token"}
	revokeResp := otm.RevokeToken(revokeReq)

	if revokeResp.Success {
		t.Error("Expected revocation of invalid token to fail")
	}

	if revokeResp.Error == "" {
		t.Error("Expected error message for invalid token revocation")
	}
}

func TestOpaqueTokenManager_ListTokens(t *testing.T) {
	// Create opaque token manager
	otm := opaque.NewOpaqueTokenManager()

	// Generate multiple tokens for the same user
	userID := "test-user"
	for i := 0; i < 3; i++ {
		req := opaque.OpaqueTokenRequest{
			UserID:    userID,
			ClientID:  "client1",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		_, err := otm.GenerateToken(req)
		if err != nil {
			t.Fatalf("Failed to generate token %d: %v", i, err)
		}
	}

	// Generate token for different user
	req := opaque.OpaqueTokenRequest{
		UserID:    "other-user",
		ClientID:  "client1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	_, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token for other user: %v", err)
	}

	// List tokens for test-user
	listReq := opaque.ListTokensRequest{UserID: userID}
	listResp := otm.ListTokens(listReq)

	if listResp.Count != 3 {
		t.Errorf("Expected 3 tokens for user, got %d", listResp.Count)
	}

	if len(listResp.Tokens) != 3 {
		t.Errorf("Expected 3 tokens in response, got %d", len(listResp.Tokens))
	}

	// List tokens with client filter
	listReq.ClientID = "client1"
	listResp = otm.ListTokens(listReq)

	if listResp.Count != 3 {
		t.Errorf("Expected 3 tokens for user and client, got %d", listResp.Count)
	}

	// List tokens with non-existent client
	listReq.ClientID = "nonexistent"
	listResp = otm.ListTokens(listReq)

	if listResp.Count != 0 {
		t.Errorf("Expected 0 tokens for non-existent client, got %d", listResp.Count)
	}
}

func TestOpaqueTokenManager_ListTokensWithActiveFilter(t *testing.T) {
	// Create opaque token manager
	otm := opaque.NewOpaqueTokenManager()

	// Generate a token
	req := opaque.OpaqueTokenRequest{
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// List active tokens
	active := true
	listReq := opaque.ListTokensRequest{
		UserID: "test-user",
		Active: &active,
	}
	listResp := otm.ListTokens(listReq)

	if listResp.Count != 1 {
		t.Errorf("Expected 1 active token, got %d", listResp.Count)
	}

	// Revoke the token
	revokeReq := opaque.RevokeRequest{Token: resp.Token}
	otm.RevokeToken(revokeReq)

	// List active tokens again
	listResp = otm.ListTokens(listReq)

	if listResp.Count != 0 {
		t.Errorf("Expected 0 active tokens after revocation, got %d", listResp.Count)
	}

	// List inactive tokens
	inactive := false
	listReq.Active = &inactive
	listResp = otm.ListTokens(listReq)

	if listResp.Count != 1 {
		t.Errorf("Expected 1 inactive token, got %d", listResp.Count)
	}
}

func TestOpaqueTokenManager_CleanupExpiredTokens(t *testing.T) {
	// Create opaque token manager
	otm := opaque.NewOpaqueTokenManager()

	// Generate expired token
	req := opaque.OpaqueTokenRequest{
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	_, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	// Generate valid token
	req.ExpiresAt = time.Now().Add(1 * time.Hour)
	_, err = otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate valid token: %v", err)
	}

	// Check token count before cleanup
	countBefore := otm.GetTokenCount()
	if countBefore != 2 {
		t.Errorf("Expected 2 tokens before cleanup, got %d", countBefore)
	}

	// Cleanup expired tokens
	removedCount := otm.CleanupExpiredTokens()

	if removedCount != 1 {
		t.Errorf("Expected 1 token to be removed, got %d", removedCount)
	}

	// Check token count after cleanup
	countAfter := otm.GetTokenCount()
	if countAfter != 1 {
		t.Errorf("Expected 1 token after cleanup, got %d", countAfter)
	}
}

func TestOpaqueTokenManager_NotBeforeValidation(t *testing.T) {
	// Create opaque token manager
	otm := opaque.NewOpaqueTokenManager()

	// Generate token that's not yet valid
	notBefore := time.Now().Add(1 * time.Hour)
	req := opaque.OpaqueTokenRequest{
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(2 * time.Hour),
		NotBefore: &notBefore,
	}

	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Validate token (should fail because it's not yet valid)
	validateReq := opaque.ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateToken(validateReq)

	if validateResp.Valid {
		t.Error("Token should not be valid before NotBefore time")
	}

	if validateResp.Error == "" {
		t.Error("Expected error message for token not yet valid")
	}
}

func TestOpaqueTokenManager_DefaultConfiguration(t *testing.T) {
	// Create opaque token manager with default configuration
	otm := opaque.NewOpaqueTokenManager()

	// Generate token without specifying length or prefix
	req := opaque.OpaqueTokenRequest{
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Check that default prefix is applied
	if len(resp.Token) < 3 || resp.Token[:3] != "op_" {
		t.Errorf("Expected default prefix 'op_', got '%s'", resp.Token[:3])
	}

	// Check that default length is applied (32 bytes = 64 hex chars + 3 char prefix = 67 total)
	expectedLength := 3 + 64 // "op_" + 64 hex characters
	if len(resp.Token) != expectedLength {
		t.Errorf("Expected token length %d, got %d", expectedLength, len(resp.Token))
	}
}

func TestOpaqueTokenManager_CustomConfiguration(t *testing.T) {
	// Create opaque token manager with custom configuration
	otm := opaque.NewOpaqueTokenManagerWithConfig(16, "custom_")

	// Generate token
	req := opaque.OpaqueTokenRequest{
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Check that custom prefix is applied
	if len(resp.Token) < 7 || resp.Token[:7] != "custom_" {
		t.Errorf("Expected custom prefix 'custom_', got '%s'", resp.Token[:7])
	}

	// Check that custom length is applied (16 bytes = 32 hex chars + 7 char prefix = 39 total)
	expectedLength := 7 + 32 // "custom_" + 32 hex characters
	if len(resp.Token) != expectedLength {
		t.Errorf("Expected token length %d, got %d", expectedLength, len(resp.Token))
	}
}

func TestOpaqueTokenManager_WithCustomStorage(t *testing.T) {
	// Create custom storage
	storage := opaque.NewMemoryStorage()
	defer storage.Close()

	// Create manager with custom storage
	otm := opaque.NewOpaqueTokenManagerWithStorage(storage, 32, "storage_")

	req := opaque.OpaqueTokenRequest{
		UserID:    "storage_user",
		ClientID:  "storage_client",
		Scope:     []string{"read", "write"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomData: map[string]interface{}{
			"storage_type": "custom",
		},
	}

	// Generate token
	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Check token prefix
	if len(resp.Token) < 8 || resp.Token[:8] != "storage_" {
		t.Errorf("Expected token to have prefix 'storage_', got %s", resp.Token[:8])
	}

	// Validate token
	validateReq := opaque.ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateToken(validateReq)
	if !validateResp.Valid {
		t.Errorf("Token validation failed: %s", validateResp.Error)
	}

	// Check custom data
	if validateResp.TokenInfo.CustomData["storage_type"] != "custom" {
		t.Error("Expected storage_type to be 'custom'")
	}

	// Test storage access
	retrievedStorage := otm.GetStorage()
	if retrievedStorage == nil {
		t.Error("Expected storage to be accessible")
	}
}

func TestOpaqueTokenManager_Close(t *testing.T) {
	// Test close functionality
	otm := opaque.NewOpaqueTokenManager()

	// Generate a token first
	req := opaque.OpaqueTokenRequest{
		UserID:    "close_user",
		ClientID:  "close_client",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Close the manager
	err = otm.Close()
	if err != nil {
		t.Errorf("Failed to close manager: %v", err)
	}

	// Try to validate token after close (should still work for memory storage)
	validateReq := opaque.ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateToken(validateReq)
	if !validateResp.Valid {
		t.Errorf("Token validation failed after close: %s", validateResp.Error)
	}
}

func TestOpaqueTokenManager_GetTokenCount(t *testing.T) {
	otm := opaque.NewOpaqueTokenManager()

	// Initial count should be 0
	count := otm.GetTokenCount()
	if count != 0 {
		t.Errorf("Expected initial count 0, got %d", count)
	}

	// Generate tokens
	for i := 0; i < 3; i++ {
		req := opaque.OpaqueTokenRequest{
			UserID:    "count_user",
			ClientID:  "count_client",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		_, err := otm.GenerateToken(req)
		if err != nil {
			t.Fatalf("Failed to generate token %d: %v", i, err)
		}
	}

	// Count should be 3
	count = otm.GetTokenCount()
	if count != 3 {
		t.Errorf("Expected count 3, got %d", count)
	}

	// Revoke one token
	req := opaque.OpaqueTokenRequest{
		UserID:    "count_user",
		ClientID:  "count_client",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	resp, err := otm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token for revocation test: %v", err)
	}

	revokeReq := opaque.RevokeRequest{Token: resp.Token}
	revokeResp := otm.RevokeToken(revokeReq)
	if !revokeResp.Success {
		t.Errorf("Failed to revoke token: %s", revokeResp.Error)
	}

	// Count should still be 4 (revoked tokens are not deleted)
	count = otm.GetTokenCount()
	if count != 4 {
		t.Errorf("Expected count 4 after revocation, got %d", count)
	}
}
