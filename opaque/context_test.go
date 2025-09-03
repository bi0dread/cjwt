package opaque

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// isContextError checks if an error is a context error or wraps one
func isContextError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a direct context error
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Check if the error message contains context error information
	errMsg := err.Error()
	return strings.Contains(errMsg, "context canceled") || strings.Contains(errMsg, "context deadline exceeded")
}

func TestOpaqueTokenManager_ContextOperations(t *testing.T) {
	otm := NewOpaqueTokenManager()
	defer otm.Close()

	// Test context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Generate token with context
	req := OpaqueTokenRequest{
		UserID:    "context_user",
		ClientID:  "context_client",
		Scope:     []string{"read", "write"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomData: map[string]interface{}{
			"test": "context_operation",
		},
	}

	resp, err := otm.GenerateTokenWithContext(ctx, req)
	if err != nil {
		t.Fatalf("Failed to generate token with context: %v", err)
	}

	if resp.Token == "" {
		t.Error("Generated token is empty")
	}

	// Validate token with context
	validateReq := ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateTokenWithContext(ctx, validateReq)
	if !validateResp.Valid {
		t.Errorf("Token validation failed: %s", validateResp.Error)
	}

	// List tokens with context
	listReq := ListTokensRequest{
		UserID: "context_user",
	}
	listResp := otm.ListTokensWithContext(ctx, listReq)
	if listResp.Count != 1 {
		t.Errorf("Expected 1 token, got %d", listResp.Count)
	}

	// Revoke token with context
	revokeReq := RevokeRequest{Token: resp.Token}
	revokeResp := otm.RevokeTokenWithContext(ctx, revokeReq)
	if !revokeResp.Success {
		t.Errorf("Token revocation failed: %s", revokeResp.Error)
	}

	// Verify token is revoked
	validateResp = otm.ValidateTokenWithContext(ctx, validateReq)
	if validateResp.Valid {
		t.Error("Expected revoked token to be invalid")
	}
}

func TestOpaqueTokenManager_ContextCancellation(t *testing.T) {
	otm := NewOpaqueTokenManager()
	defer otm.Close()

	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := OpaqueTokenRequest{
		UserID:    "cancel_user",
		ClientID:  "cancel_client",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Generate token should fail due to cancelled context
	_, err := otm.GenerateTokenWithContext(ctx, req)
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
	// Check if the error is context.Canceled or wraps it
	if err != context.Canceled && !isContextError(err) {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}

	// Validate token should fail due to cancelled context
	validateReq := ValidateRequest{Token: "some_token"}
	validateResp := otm.ValidateTokenWithContext(ctx, validateReq)
	if validateResp.Valid {
		t.Error("Expected validation to fail due to cancelled context")
	}

	// List tokens should fail due to cancelled context
	listReq := ListTokensRequest{UserID: "cancel_user"}
	listResp := otm.ListTokensWithContext(ctx, listReq)
	if listResp.Count != 0 {
		t.Error("Expected no tokens due to cancelled context")
	}

	// Revoke token should fail due to cancelled context
	revokeReq := RevokeRequest{Token: "some_token"}
	revokeResp := otm.RevokeTokenWithContext(ctx, revokeReq)
	if revokeResp.Success {
		t.Error("Expected revocation to fail due to cancelled context")
	}
}

func TestOpaqueTokenManager_ContextTimeout(t *testing.T) {
	otm := NewOpaqueTokenManager()
	defer otm.Close()

	// Test context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout
	time.Sleep(1 * time.Millisecond)

	req := OpaqueTokenRequest{
		UserID:    "timeout_user",
		ClientID:  "timeout_client",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Generate token should fail due to timeout
	_, err := otm.GenerateTokenWithContext(ctx, req)
	if err == nil {
		t.Error("Expected error for timeout context")
	}
	// Check if the error is context.DeadlineExceeded or wraps it
	if err != context.DeadlineExceeded && !isContextError(err) {
		t.Errorf("Expected context.DeadlineExceeded error, got %v", err)
	}
}

func TestOpaqueTokenManager_ContextWithDifferentStorages(t *testing.T) {
	// Test with memory storage
	memoryStorage := NewMemoryStorage()
	defer memoryStorage.Close()

	otm := NewOpaqueTokenManagerWithStorage(memoryStorage, 32, "ctx_")
	defer otm.Close()

	ctx := context.Background()

	req := OpaqueTokenRequest{
		UserID:    "storage_user",
		ClientID:  "storage_client",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomData: map[string]interface{}{
			"storage_type": "memory",
		},
	}

	// Generate token
	resp, err := otm.GenerateTokenWithContext(ctx, req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Validate token
	validateReq := ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateTokenWithContext(ctx, validateReq)
	if !validateResp.Valid {
		t.Errorf("Token validation failed: %s", validateResp.Error)
	}

	// Check custom data
	if validateResp.TokenInfo.CustomData["storage_type"] != "memory" {
		t.Error("Expected storage_type to be 'memory'")
	}
}

func TestOpaqueTokenManager_ContextCleanup(t *testing.T) {
	otm := NewOpaqueTokenManager()
	defer otm.Close()

	ctx := context.Background()
	now := time.Now()

	// Generate expired token
	req := OpaqueTokenRequest{
		UserID:    "cleanup_user",
		ClientID:  "cleanup_client",
		ExpiresAt: now.Add(-1 * time.Hour), // Expired
	}

	resp, err := otm.GenerateTokenWithContext(ctx, req)
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	// Generate valid token
	req.ExpiresAt = now.Add(1 * time.Hour)
	req.UserID = "cleanup_user2"
	resp2, err := otm.GenerateTokenWithContext(ctx, req)
	if err != nil {
		t.Fatalf("Failed to generate valid token: %v", err)
	}

	// Cleanup expired tokens with context
	removedCount := otm.CleanupExpiredTokensWithContext(ctx)
	if removedCount != 1 {
		t.Errorf("Expected 1 expired token removed, got %d", removedCount)
	}

	// Verify expired token is gone
	validateReq := ValidateRequest{Token: resp.Token}
	validateResp := otm.ValidateTokenWithContext(ctx, validateReq)
	if validateResp.Valid {
		t.Error("Expected expired token to be invalid")
	}

	// Verify valid token still exists
	validateReq2 := ValidateRequest{Token: resp2.Token}
	validateResp2 := otm.ValidateTokenWithContext(ctx, validateReq2)
	if !validateResp2.Valid {
		t.Errorf("Expected valid token to remain valid: %s", validateResp2.Error)
	}
}

func TestOpaqueTokenManager_ContextTokenCount(t *testing.T) {
	otm := NewOpaqueTokenManager()
	defer otm.Close()

	ctx := context.Background()

	// Initial count should be 0
	count := otm.GetTokenCountWithContext(ctx)
	if count != 0 {
		t.Errorf("Expected initial count 0, got %d", count)
	}

	// Generate tokens
	for i := 0; i < 3; i++ {
		req := OpaqueTokenRequest{
			UserID:    "count_user",
			ClientID:  "count_client",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		_, err := otm.GenerateTokenWithContext(ctx, req)
		if err != nil {
			t.Fatalf("Failed to generate token %d: %v", i, err)
		}
	}

	// Count should be 3
	count = otm.GetTokenCountWithContext(ctx)
	if count != 3 {
		t.Errorf("Expected count 3, got %d", count)
	}

	// Test with cancelled context
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	count = otm.GetTokenCountWithContext(cancelledCtx)
	if count != 0 {
		t.Errorf("Expected count 0 with cancelled context, got %d", count)
	}
}

func TestOpaqueTokenManager_ContextConcurrentOperations(t *testing.T) {
	otm := NewOpaqueTokenManager()
	defer otm.Close()

	const numGoroutines = 10
	const tokensPerGoroutine = 5

	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			ctx := context.Background()

			for j := 0; j < tokensPerGoroutine; j++ {
				req := OpaqueTokenRequest{
					UserID:    "concurrent_user",
					ClientID:  "concurrent_client",
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CustomData: map[string]interface{}{
						"goroutine": goroutineID,
						"token":     j,
					},
				}

				resp, err := otm.GenerateTokenWithContext(ctx, req)
				if err != nil {
					errors <- err
					return
				}

				// Validate token
				validateReq := ValidateRequest{Token: resp.Token}
				validateResp := otm.ValidateTokenWithContext(ctx, validateReq)
				if !validateResp.Valid {
					errors <- err
					return
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Check for errors
	close(errors)
	for err := range errors {
		t.Error(err)
	}

	// Verify total count
	ctx := context.Background()
	count := otm.GetTokenCountWithContext(ctx)
	expectedCount := numGoroutines * tokensPerGoroutine
	if count != expectedCount {
		t.Errorf("Expected %d tokens, got %d", expectedCount, count)
	}
}
