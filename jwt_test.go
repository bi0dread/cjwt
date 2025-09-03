package cjwt_test

import (
	"cjwt"
	"fmt"
	"testing"
	"time"
)

func TestJWTManager_GenerateAndVerifyToken(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Test data
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomClaims: map[string]interface{}{
			"role":        "user",
			"permissions": []string{"read"},
		},
	}

	// Generate token
	resp, err := jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if resp.Token == "" {
		t.Error("Generated token is empty")
	}

	if resp.JWTID == "" {
		t.Error("JWT ID is empty")
	}

	// Verify token
	verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: resp.Token})
	if !verifyResp.Valid {
		t.Errorf("Token verification failed: %s", verifyResp.Error)
	}

	if verifyResp.Subject != "test-user" {
		t.Errorf("Expected subject 'test-user', got '%s'", verifyResp.Subject)
	}

	if verifyResp.Issuer != "test-app" {
		t.Errorf("Expected issuer 'test-app', got '%s'", verifyResp.Issuer)
	}

	if len(verifyResp.Audience) != 1 || verifyResp.Audience[0] != "test-api" {
		t.Errorf("Expected audience ['test-api'], got %v", verifyResp.Audience)
	}

	// Check custom claims
	if role, ok := verifyResp.CustomClaims["role"].(string); !ok || role != "user" {
		t.Errorf("Expected custom claim 'role' to be 'user', got %v", verifyResp.CustomClaims["role"])
	}
}

func TestJWTManager_InvalidToken(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Test with invalid token
	verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: "invalid.token.here"})
	if verifyResp.Valid {
		t.Error("Expected invalid token to fail verification")
	}

	if verifyResp.Error == "" {
		t.Error("Expected error message for invalid token")
	}
}

func TestJWTManager_ExpiredToken(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Create expired token
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	resp, err := jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Verify expired token
	verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: resp.Token})
	if verifyResp.Valid {
		t.Error("Expected expired token to fail verification")
	}
}

func TestParseToken(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Generate token
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomClaims: map[string]interface{}{
			"role": "admin",
		},
	}

	resp, err := jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Parse token without verification
	parseResp := jwtManager.ParseToken(cjwt.ParseRequest{Token: resp.Token})
	if !parseResp.Valid {
		t.Errorf("Token parsing failed: %s", parseResp.Error)
	}

	if parseResp.Subject != "test-user" {
		t.Errorf("Expected subject 'test-user', got '%s'", parseResp.Subject)
	}

	if role, ok := parseResp.CustomClaims["role"].(string); !ok || role != "admin" {
		t.Errorf("Expected custom claim 'role' to be 'admin', got %v", parseResp.CustomClaims["role"])
	}
}

func TestUtilityFunctions(t *testing.T) {
	// Test JWT format validation
	if !cjwt.IsValidJWTFormat("header.payload.signature") {
		t.Error("Expected valid JWT format to return true")
	}

	if cjwt.IsValidJWTFormat("invalid") {
		t.Error("Expected invalid JWT format to return false")
	}

	// Test random token generation
	token, err := cjwt.GenerateRandomToken(16)
	if err != nil {
		t.Errorf("Failed to generate random token: %v", err)
	}

	if len(token) != 32 { // 16 bytes = 32 hex characters
		t.Errorf("Expected token length 32, got %d", len(token))
	}

	// Test SHA256 hash
	hash := cjwt.HashSHA256("test")
	expectedHash := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if hash != expectedHash {
		t.Errorf("Expected hash %s, got %s", expectedHash, hash)
	}
}

func TestMultipleSigningMethods(t *testing.T) {
	// Test ECDSA
	ecdsaPrivateKey, ecdsaPublicKey, err := cjwt.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA keys: %v", err)
	}

	ecdsaManager := cjwt.NewJWTManagerWithECDSA(ecdsaPrivateKey, ecdsaPublicKey)

	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomClaims: map[string]interface{}{
			"role": "user",
		},
	}

	// Test ECDSA token generation
	resp, err := ecdsaManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA token: %v", err)
	}

	if resp.Token == "" {
		t.Error("Generated ECDSA token is empty")
	}

	// Test HMAC
	hmacKey, err := cjwt.DefaultHMACKey()
	if err != nil {
		t.Fatalf("Failed to generate HMAC key: %v", err)
	}

	hmacManager := cjwt.NewJWTManagerWithHMAC(hmacKey)

	// Test HMAC token generation
	hmacResp, err := hmacManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate HMAC token: %v", err)
	}

	if hmacResp.Token == "" {
		t.Error("Generated HMAC token is empty")
	}
}

func TestTokenMetrics(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Reset metrics to ensure clean state
	jwtManager.ResetMetrics()

	// Initial metrics should be zero
	initialMetrics := jwtManager.GetMetrics()
	if initialMetrics.GeneratedTokens != 0 {
		t.Errorf("Expected initial generated tokens to be 0, got %d", initialMetrics.GeneratedTokens)
	}

	// Generate a token
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	_, err = jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Check metrics after generation
	metrics := jwtManager.GetMetrics()
	if metrics.GeneratedTokens < 1 {
		t.Errorf("Expected generated tokens to be at least 1, got %d", metrics.GeneratedTokens)
	}

	// Test reset metrics
	jwtManager.ResetMetrics()
	resetMetrics := jwtManager.GetMetrics()
	if resetMetrics.GeneratedTokens != 0 {
		t.Errorf("Expected reset generated tokens to be 0, got %d", resetMetrics.GeneratedTokens)
	}
}

func TestAuditLogging(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Initial audit logs should be empty
	initialLogs := jwtManager.GetAuditLogs()
	if len(initialLogs) != 0 {
		t.Errorf("Expected initial audit logs to be empty, got %d logs", len(initialLogs))
	}

	// Generate a token to create audit log
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	_, err = jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Check audit logs after generation
	logs := jwtManager.GetAuditLogs()
	if len(logs) == 0 {
		t.Error("Expected audit logs to contain entries after token generation")
	}

	// Check the last log entry
	lastLog := logs[len(logs)-1]
	if lastLog.Action != "generate" {
		t.Errorf("Expected last log action to be 'generate', got '%s'", lastLog.Action)
	}
	if !lastLog.Success {
		t.Error("Expected last log to be successful")
	}
	if lastLog.UserID != "test-user" {
		t.Errorf("Expected last log user ID to be 'test-user', got '%s'", lastLog.UserID)
	}

	// Test clear audit logs
	jwtManager.ClearAuditLogs()
	clearedLogs := jwtManager.GetAuditLogs()
	if len(clearedLogs) != 0 {
		t.Errorf("Expected cleared audit logs to be empty, got %d logs", len(clearedLogs))
	}
}

func TestKeyRotation(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Get initial key info
	initialKeyInfo := jwtManager.GetKeyInfo()
	if initialKeyInfo.KeyID == "" {
		t.Error("Expected initial key ID to be set")
	}
	if initialKeyInfo.Algorithm != "RS256" {
		t.Errorf("Expected initial algorithm to be 'RS256', got '%s'", initialKeyInfo.Algorithm)
	}

	// Test key rotation
	rotationReq := cjwt.KeyRotationRequest{
		Algorithm:   cjwt.RS256,
		GracePeriod: 24 * time.Hour,
	}

	rotationResp := jwtManager.RotateKey(rotationReq)
	if !rotationResp.Success {
		t.Errorf("Key rotation failed: %s", rotationResp.Error)
	}

	if rotationResp.NewKeyID == "" {
		t.Error("Expected new key ID to be set")
	}
	if rotationResp.OldKeyID != initialKeyInfo.KeyID {
		t.Errorf("Expected old key ID to match initial key ID")
	}

	// Get updated key info
	updatedKeyInfo := jwtManager.GetKeyInfo()
	if updatedKeyInfo.KeyID != rotationResp.NewKeyID {
		t.Errorf("Expected updated key ID to match new key ID")
	}
}

func TestTokenChunking(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Generate a token
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomClaims: map[string]interface{}{
			"large_data": "This is a large piece of data that will make the token bigger for chunking testing purposes. " +
				"We need enough data to ensure the token gets split into multiple chunks when we test the chunking functionality.",
		},
	}

	resp, err := jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Test token chunking
	chunkReq := cjwt.TokenChunkRequest{
		Token:        resp.Token,
		MaxChunkSize: 100,
	}

	chunkResp := jwtManager.ChunkToken(chunkReq)
	if chunkResp.TotalChunks == 0 {
		t.Error("Expected token to be chunked into multiple pieces")
	}
	if chunkResp.OriginalSize == 0 {
		t.Error("Expected original size to be greater than 0")
	}
	if chunkResp.ChunkID == "" {
		t.Error("Expected chunk ID to be set")
	}

	// Test token reassembly
	reassembleReq := cjwt.TokenReassembleRequest{
		Chunks:  chunkResp.Chunks,
		ChunkID: chunkResp.ChunkID,
	}

	reassembleResp := jwtManager.ReassembleToken(reassembleReq)
	if !reassembleResp.Success {
		t.Errorf("Token reassembly failed: %s", reassembleResp.Error)
	}
	if reassembleResp.Token != resp.Token {
		t.Error("Reassembled token does not match original token")
	}
	if reassembleResp.ReassembledSize != chunkResp.OriginalSize {
		t.Errorf("Expected reassembled size to match original size")
	}
}

func TestTokenChunkingEmptyChunks(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Test reassembly with empty chunks
	reassembleReq := cjwt.TokenReassembleRequest{
		Chunks:  []string{},
		ChunkID: "test-id",
	}

	reassembleResp := jwtManager.ReassembleToken(reassembleReq)
	if reassembleResp.Success {
		t.Error("Expected reassembly with empty chunks to fail")
	}
	if reassembleResp.Error == "" {
		t.Error("Expected error message for empty chunks")
	}
}

func TestKeyGeneration(t *testing.T) {
	// Test RSA key generation
	rsaPrivateKey, rsaPublicKey, err := cjwt.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	if rsaPrivateKey == nil || rsaPublicKey == nil {
		t.Error("Generated RSA keys should not be nil")
	}

	// Test default RSA key generation
	defaultRsaPrivateKey, defaultRsaPublicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate default RSA key pair: %v", err)
	}
	if defaultRsaPrivateKey == nil || defaultRsaPublicKey == nil {
		t.Error("Generated default RSA keys should not be nil")
	}

	// Test ECDSA key generation
	ecdsaPrivateKey, ecdsaPublicKey, err := cjwt.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	if ecdsaPrivateKey == nil || ecdsaPublicKey == nil {
		t.Error("Generated ECDSA keys should not be nil")
	}

	// Test HMAC key generation
	hmacKey, err := cjwt.GenerateHMACKey(32)
	if err != nil {
		t.Fatalf("Failed to generate HMAC key: %v", err)
	}
	if len(hmacKey) != 32 {
		t.Errorf("Expected HMAC key length to be 32, got %d", len(hmacKey))
	}

	// Test default HMAC key generation
	defaultHmacKey, err := cjwt.DefaultHMACKey()
	if err != nil {
		t.Fatalf("Failed to generate default HMAC key: %v", err)
	}
	if len(defaultHmacKey) != 32 {
		t.Errorf("Expected default HMAC key length to be 32, got %d", len(defaultHmacKey))
	}
}

func TestJWTManager_GenerateTokenWithMethod(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Test data
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomClaims: map[string]interface{}{
			"role": "admin",
		},
	}

	// Test generating token with specific method
	resp, err := jwtManager.GenerateTokenWithMethod(req, cjwt.RS256)
	if err != nil {
		t.Fatalf("Failed to generate token with method: %v", err)
	}

	if resp.Token == "" {
		t.Error("Generated token is empty")
	}

	// Verify the token
	verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: resp.Token})
	if !verifyResp.Valid {
		t.Errorf("Token verification failed: %s", verifyResp.Error)
	}
}

func TestJWTManager_InvalidSigningMethod(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Test data
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Test generating token with invalid method
	_, err = jwtManager.GenerateTokenWithMethod(req, "INVALID")
	if err == nil {
		t.Error("Expected error for invalid signing method")
	}
}

func TestJWTManager_NotBeforeToken(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Create token that's not yet valid
	notBefore := time.Now().Add(1 * time.Hour)
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(2 * time.Hour),
		NotBefore: &notBefore,
	}

	resp, err := jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Verify token (should fail because it's not yet valid)
	verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: resp.Token})
	if verifyResp.Valid {
		t.Error("Token should not be valid before NotBefore time")
	}

	if verifyResp.Error == "" {
		t.Error("Expected error message for token not yet valid")
	}
}

func TestJWTManager_IssuedAtToken(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Create token with specific issued at time
	issuedAt := time.Now().Add(-1 * time.Hour) // Issued 1 hour ago
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  &issuedAt,
	}

	resp, err := jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Verify token
	verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: resp.Token})
	if !verifyResp.Valid {
		t.Errorf("Token verification failed: %s", verifyResp.Error)
	}

	// Check that issued at time is correct (allow for small time differences due to precision)
	if verifyResp.IssuedAt == nil {
		t.Error("IssuedAt should not be nil")
	} else if verifyResp.IssuedAt.Sub(issuedAt).Abs() > time.Second {
		t.Errorf("Expected issued at time %v, got %v", issuedAt, verifyResp.IssuedAt)
	}
}

func TestJWTManager_EmptyAudience(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Test data with empty audience
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{}, // Empty audience
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	resp, err := jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Verify token
	verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: resp.Token})
	if !verifyResp.Valid {
		t.Errorf("Token verification failed: %s", verifyResp.Error)
	}

	// Check that audience is empty
	if len(verifyResp.Audience) != 0 {
		t.Errorf("Expected empty audience, got %v", verifyResp.Audience)
	}
}

func TestJWTManager_NilAudience(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Test data with nil audience
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  nil, // Nil audience
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	resp, err := jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Verify token
	verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: resp.Token})
	if !verifyResp.Valid {
		t.Errorf("Token verification failed: %s", verifyResp.Error)
	}

	// Check that audience is nil or empty
	if verifyResp.Audience != nil && len(verifyResp.Audience) != 0 {
		t.Errorf("Expected nil or empty audience, got %v", verifyResp.Audience)
	}
}

func TestJWTManager_ComplexCustomClaims(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Test data with complex custom claims
	req := cjwt.JWTRequest{
		Issuer:    "test-app",
		Subject:   "test-user",
		Audience:  []string{"test-api"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomClaims: map[string]interface{}{
			"role":        "admin",
			"permissions": []string{"read", "write", "delete"},
			"metadata": map[string]interface{}{
				"department": "engineering",
				"level":      5,
				"active":     true,
			},
			"numbers": []int{1, 2, 3, 4, 5},
		},
	}

	resp, err := jwtManager.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Verify token
	verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: resp.Token})
	if !verifyResp.Valid {
		t.Errorf("Token verification failed: %s", verifyResp.Error)
	}

	// Check complex custom claims
	if role, ok := verifyResp.CustomClaims["role"].(string); !ok || role != "admin" {
		t.Errorf("Expected custom claim 'role' to be 'admin', got %v", verifyResp.CustomClaims["role"])
	}

	if permissions, ok := verifyResp.CustomClaims["permissions"].([]interface{}); !ok || len(permissions) != 3 {
		t.Errorf("Expected custom claim 'permissions' to have 3 items, got %v", verifyResp.CustomClaims["permissions"])
	}

	if metadata, ok := verifyResp.CustomClaims["metadata"].(map[string]interface{}); !ok {
		t.Errorf("Expected custom claim 'metadata' to be a map, got %v", verifyResp.CustomClaims["metadata"])
	} else {
		if dept, ok := metadata["department"].(string); !ok || dept != "engineering" {
			t.Errorf("Expected metadata department to be 'engineering', got %v", metadata["department"])
		}
	}
}

func TestUtilityFunctions_EdgeCases(t *testing.T) {
	// Test JWT format validation with edge cases
	if cjwt.IsValidJWTFormat("") {
		t.Error("Empty string should not be valid JWT format")
	}

	if cjwt.IsValidJWTFormat("single") {
		t.Error("Single part should not be valid JWT format")
	}

	if cjwt.IsValidJWTFormat("two.parts") {
		t.Error("Two parts should not be valid JWT format")
	}

	if cjwt.IsValidJWTFormat("too.many.parts.here") {
		t.Error("More than three parts should not be valid JWT format")
	}

	// Test random token generation with different lengths
	for _, length := range []int{1, 8, 16, 32, 64} {
		token, err := cjwt.GenerateRandomToken(length)
		if err != nil {
			t.Errorf("Failed to generate random token of length %d: %v", length, err)
		}
		expectedLength := length * 2 // hex encoding doubles the length
		if len(token) != expectedLength {
			t.Errorf("Expected token length %d for input length %d, got %d", expectedLength, length, len(token))
		}
	}

	// Test SHA256 hash with empty string
	hash := cjwt.HashSHA256("")
	expectedEmptyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != expectedEmptyHash {
		t.Errorf("Expected empty string hash %s, got %s", expectedEmptyHash, hash)
	}

	// Test SHA256 hash with unicode
	unicodeHash := cjwt.HashSHA256("Hello 世界")
	expectedUnicodeHash := "4487dd5e89032c1794903afe6f4b90aaab69972697ea5d3baa215df27c679803"
	if unicodeHash != expectedUnicodeHash {
		t.Errorf("Expected unicode hash %s, got %s", expectedUnicodeHash, unicodeHash)
	}
}

func TestJWTManager_ConcurrentAccess(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Reset metrics to ensure clean state
	jwtManager.ResetMetrics()

	// Test concurrent token generation
	const numGoroutines = 10
	const tokensPerGoroutine = 5

	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			for j := 0; j < tokensPerGoroutine; j++ {
				req := cjwt.JWTRequest{
					Issuer:    "test-app",
					Subject:   fmt.Sprintf("user-%d-%d", goroutineID, j),
					Audience:  []string{"test-api"},
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CustomClaims: map[string]interface{}{
						"goroutine": goroutineID,
						"token":     j,
					},
				}

				resp, err := jwtManager.GenerateToken(req)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d, token %d: %v", goroutineID, j, err)
					return
				}

				// Verify the token
				verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: resp.Token})
				if !verifyResp.Valid {
					errors <- fmt.Errorf("goroutine %d, token %d verification failed: %s", goroutineID, j, verifyResp.Error)
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

	// Check metrics
	metrics := jwtManager.GetMetrics()
	expectedGenerated := int64(numGoroutines * tokensPerGoroutine)
	if metrics.GeneratedTokens < expectedGenerated {
		t.Errorf("Expected at least %d generated tokens, got %d", expectedGenerated, metrics.GeneratedTokens)
	}

	if metrics.VerifiedTokens < expectedGenerated {
		t.Errorf("Expected at least %d verified tokens, got %d", expectedGenerated, metrics.VerifiedTokens)
	}
}
