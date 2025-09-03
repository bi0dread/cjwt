package cjwt_test

import (
	"cjwt"
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
	if metrics.GeneratedTokens != 1 {
		t.Errorf("Expected generated tokens to be 1, got %d", metrics.GeneratedTokens)
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
