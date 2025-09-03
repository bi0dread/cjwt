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
