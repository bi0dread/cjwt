package opaque

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OpaqueTokenManager manages opaque tokens
type OpaqueTokenManager struct {
	// Token storage interface
	storage TokenStorage

	// Configuration
	defaultTokenLength int
	defaultTokenPrefix string
}

// NewOpaqueTokenManager creates a new opaque token manager with memory storage
func NewOpaqueTokenManager() *OpaqueTokenManager {
	return &OpaqueTokenManager{
		storage:            NewMemoryStorage(),
		defaultTokenLength: 32,
		defaultTokenPrefix: "op_",
	}
}

// NewOpaqueTokenManagerWithConfig creates a new opaque token manager with custom configuration and memory storage
func NewOpaqueTokenManagerWithConfig(tokenLength int, tokenPrefix string) *OpaqueTokenManager {
	if tokenLength <= 0 {
		tokenLength = 32
	}
	return &OpaqueTokenManager{
		storage:            NewMemoryStorage(),
		defaultTokenLength: tokenLength,
		defaultTokenPrefix: tokenPrefix,
	}
}

// NewOpaqueTokenManagerWithStorage creates a new opaque token manager with custom storage
func NewOpaqueTokenManagerWithStorage(storage TokenStorage, tokenLength int, tokenPrefix string) *OpaqueTokenManager {
	if tokenLength <= 0 {
		tokenLength = 32
	}
	if tokenPrefix == "" {
		tokenPrefix = "op_"
	}
	return &OpaqueTokenManager{
		storage:            storage,
		defaultTokenLength: tokenLength,
		defaultTokenPrefix: tokenPrefix,
	}
}

// GenerateToken creates a new opaque token
func (otm *OpaqueTokenManager) GenerateToken(req OpaqueTokenRequest) (*OpaqueTokenResponse, error) {
	ctx := context.Background()
	return otm.GenerateTokenWithContext(ctx, req)
}

// GenerateTokenWithContext creates a new opaque token with context
func (otm *OpaqueTokenManager) GenerateTokenWithContext(ctx context.Context, req OpaqueTokenRequest) (*OpaqueTokenResponse, error) {
	// Set default values
	now := time.Now()
	if req.IssuedAt == nil {
		req.IssuedAt = &now
	}
	if req.TokenLength <= 0 {
		req.TokenLength = otm.defaultTokenLength
	}
	if req.TokenPrefix == "" {
		req.TokenPrefix = otm.defaultTokenPrefix
	}

	// Generate unique token ID
	tokenID := uuid.New().String()

	// Generate opaque token
	opaqueToken, err := otm.generateOpaqueToken(req.TokenLength, req.TokenPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to generate opaque token: %w", err)
	}

	// Ensure CustomData is never nil
	customData := req.CustomData
	if customData == nil {
		customData = make(map[string]interface{})
	}

	// Create token info
	tokenInfo := &OpaqueTokenInfo{
		TokenID:    tokenID,
		UserID:     req.UserID,
		ClientID:   req.ClientID,
		Scope:      req.Scope,
		ExpiresAt:  req.ExpiresAt,
		IssuedAt:   *req.IssuedAt,
		NotBefore:  req.NotBefore,
		CustomData: customData,
		IsActive:   true,
		CreatedAt:  now,
	}

	// Store token using storage interface
	err = otm.storage.Store(ctx, opaqueToken, tokenInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	// Prepare response
	response := &OpaqueTokenResponse{
		Token:      opaqueToken,
		TokenID:    tokenID,
		ExpiresAt:  req.ExpiresAt,
		IssuedAt:   *req.IssuedAt,
		UserID:     req.UserID,
		ClientID:   req.ClientID,
		Scope:      req.Scope,
		CustomData: customData,
	}

	return response, nil
}

// ValidateToken validates an opaque token
func (otm *OpaqueTokenManager) ValidateToken(req ValidateRequest) *ValidateResponse {
	ctx := context.Background()
	return otm.ValidateTokenWithContext(ctx, req)
}

// ValidateTokenWithContext validates an opaque token with context
func (otm *OpaqueTokenManager) ValidateTokenWithContext(ctx context.Context, req ValidateRequest) *ValidateResponse {
	// Get token info from storage
	tokenInfo, err := otm.storage.Get(ctx, req.Token)
	if err != nil {
		return &ValidateResponse{
			Valid: false,
			Error: "token not found",
		}
	}

	// Check if token is active
	if !tokenInfo.IsActive {
		return &ValidateResponse{
			Valid: false,
			Error: "token is revoked",
		}
	}

	// Check if token is expired
	now := time.Now()
	if now.After(tokenInfo.ExpiresAt) {
		return &ValidateResponse{
			Valid: false,
			Error: "token is expired",
		}
	}

	// Check if token is not yet valid
	if tokenInfo.NotBefore != nil && now.Before(*tokenInfo.NotBefore) {
		return &ValidateResponse{
			Valid: false,
			Error: "token is not yet valid",
		}
	}

	return &ValidateResponse{
		Valid:     true,
		TokenInfo: tokenInfo,
	}
}

// RevokeToken revokes an opaque token
func (otm *OpaqueTokenManager) RevokeToken(req RevokeRequest) *RevokeResponse {
	ctx := context.Background()
	return otm.RevokeTokenWithContext(ctx, req)
}

// RevokeTokenWithContext revokes an opaque token with context
func (otm *OpaqueTokenManager) RevokeTokenWithContext(ctx context.Context, req RevokeRequest) *RevokeResponse {
	// Get token info from storage
	tokenInfo, err := otm.storage.Get(ctx, req.Token)
	if err != nil {
		return &RevokeResponse{
			Success: false,
			Error:   "token not found",
		}
	}

	// Mark token as inactive
	tokenInfo.IsActive = false

	// Update token in storage
	err = otm.storage.Update(ctx, req.Token, tokenInfo)
	if err != nil {
		return &RevokeResponse{
			Success: false,
			Error:   "failed to revoke token",
		}
	}

	return &RevokeResponse{
		Success: true,
	}
}

// ListTokens lists tokens for a user
func (otm *OpaqueTokenManager) ListTokens(req ListTokensRequest) *ListTokensResponse {
	ctx := context.Background()
	return otm.ListTokensWithContext(ctx, req)
}

// ListTokensWithContext lists tokens for a user with context
func (otm *OpaqueTokenManager) ListTokensWithContext(ctx context.Context, req ListTokensRequest) *ListTokensResponse {
	// Create filters
	filters := &ListFilters{
		UserID:   req.UserID,
		ClientID: req.ClientID,
		Active:   req.Active,
	}

	// Get tokens from storage
	tokenInfos, err := otm.storage.List(ctx, filters)
	if err != nil {
		return &ListTokensResponse{
			Tokens: []OpaqueTokenInfo{},
			Count:  0,
		}
	}

	// Convert to response format
	tokens := make([]OpaqueTokenInfo, len(tokenInfos))
	for i, info := range tokenInfos {
		tokens[i] = *info
	}

	return &ListTokensResponse{
		Tokens: tokens,
		Count:  len(tokens),
	}
}

// CleanupExpiredTokens removes expired tokens from storage
func (otm *OpaqueTokenManager) CleanupExpiredTokens() int {
	ctx := context.Background()
	return otm.CleanupExpiredTokensWithContext(ctx)
}

// CleanupExpiredTokensWithContext removes expired tokens from storage with context
func (otm *OpaqueTokenManager) CleanupExpiredTokensWithContext(ctx context.Context) int {
	removedCount, err := otm.storage.CleanupExpired(ctx)
	if err != nil {
		return 0
	}
	return removedCount
}

// GetTokenCount returns the total number of stored tokens
func (otm *OpaqueTokenManager) GetTokenCount() int {
	ctx := context.Background()
	return otm.GetTokenCountWithContext(ctx)
}

// GetTokenCountWithContext returns the total number of stored tokens with context
func (otm *OpaqueTokenManager) GetTokenCountWithContext(ctx context.Context) int {
	// Use List with empty filters to get all tokens
	filters := &ListFilters{}
	tokens, err := otm.storage.List(ctx, filters)
	if err != nil {
		return 0
	}
	return len(tokens)
}

// Close closes the storage connection
func (otm *OpaqueTokenManager) Close() error {
	if otm.storage != nil {
		return otm.storage.Close()
	}
	return nil
}

// GetStorage returns the storage interface (for advanced usage)
func (otm *OpaqueTokenManager) GetStorage() TokenStorage {
	return otm.storage
}

// generateOpaqueToken generates a random opaque token
func (otm *OpaqueTokenManager) generateOpaqueToken(length int, prefix string) (string, error) {
	// Generate random bytes
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Convert to hex string
	token := hex.EncodeToString(bytes)

	// Add prefix if specified
	if prefix != "" {
		token = prefix + token
	}

	return token, nil
}
