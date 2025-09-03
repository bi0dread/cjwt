package tokenmaker_test

import (
	"cjwt"
	"cjwt/tokenmaker"
	"fmt"
	"testing"
	"time"
)

func TestTokenMaker_JWTToken(t *testing.T) {
	// Generate RSA keys
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create token maker
	config := &tokenmaker.TokenMakerConfig{
		JWTPrivateKey:           privateKey,
		JWTPublicKey:            publicKey,
		DefaultJWTSigningMethod: tokenmaker.RS256,
	}

	tm, err := tokenmaker.NewTokenMaker(config)
	if err != nil {
		t.Fatalf("Failed to create token maker: %v", err)
	}

	// Generate JWT token
	req := tokenmaker.TokenRequest{
		Type:      tokenmaker.JWT,
		UserID:    "test-user",
		ClientID:  "test-client",
		Scope:     []string{"read", "write"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomData: map[string]interface{}{
			"role": "admin",
		},
		JWTConfig: &tokenmaker.JWTConfig{
			Issuer:        "test-app",
			Subject:       "test-user",
			Audience:      []string{"test-api"},
			SigningMethod: tokenmaker.RS256,
		},
	}

	resp, err := tm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate JWT token: %v", err)
	}

	if resp.Type != tokenmaker.JWT {
		t.Errorf("Expected token type JWT, got %s", resp.Type)
	}

	if resp.Token == "" {
		t.Error("Generated JWT token is empty")
	}

	if resp.UserID != "test-user" {
		t.Errorf("Expected user ID 'test-user', got '%s'", resp.UserID)
	}

	// Validate JWT token
	validateReq := tokenmaker.ValidateRequest{
		Type:  tokenmaker.JWT,
		Token: resp.Token,
	}

	validateResp := tm.ValidateToken(validateReq)
	if !validateResp.Valid {
		t.Errorf("JWT token validation failed: %s", validateResp.Error)
	}

	if validateResp.UserID != "test-user" {
		t.Errorf("Expected validated user ID 'test-user', got '%s'", validateResp.UserID)
	}
}

func TestTokenMaker_OpaqueToken(t *testing.T) {
	// Create token maker with opaque support only
	tm := tokenmaker.NewTokenMakerWithOpaque()

	// Generate opaque token
	req := tokenmaker.TokenRequest{
		Type:      tokenmaker.Opaque,
		UserID:    "test-user",
		ClientID:  "test-client",
		Scope:     []string{"read"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomData: map[string]interface{}{
			"role": "user",
		},
		OpaqueConfig: &tokenmaker.OpaqueConfig{
			TokenLength: 32,
			TokenPrefix: "op_",
		},
	}

	resp, err := tm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate opaque token: %v", err)
	}

	if resp.Type != tokenmaker.Opaque {
		t.Errorf("Expected token type Opaque, got %s", resp.Type)
	}

	if resp.Token == "" {
		t.Error("Generated opaque token is empty")
	}

	if resp.UserID != "test-user" {
		t.Errorf("Expected user ID 'test-user', got '%s'", resp.UserID)
	}

	// Validate opaque token
	validateReq := tokenmaker.ValidateRequest{
		Type:  tokenmaker.Opaque,
		Token: resp.Token,
	}

	validateResp := tm.ValidateToken(validateReq)
	if !validateResp.Valid {
		t.Errorf("Opaque token validation failed: %s", validateResp.Error)
	}

	if validateResp.UserID != "test-user" {
		t.Errorf("Expected validated user ID 'test-user', got '%s'", validateResp.UserID)
	}

	// Revoke opaque token
	revokeReq := tokenmaker.RevokeRequest{
		Type:  tokenmaker.Opaque,
		Token: resp.Token,
	}

	revokeResp := tm.RevokeToken(revokeReq)
	if !revokeResp.Success {
		t.Errorf("Failed to revoke opaque token: %s", revokeResp.Error)
	}

	// Validate revoked token
	revokedValidateResp := tm.ValidateToken(validateReq)
	if revokedValidateResp.Valid {
		t.Error("Revoked token should not be valid")
	}
}

func TestTokenMaker_InvalidTokenType(t *testing.T) {
	// Create token maker
	tm := tokenmaker.NewTokenMakerWithOpaque()

	// Try to generate token with invalid type
	req := tokenmaker.TokenRequest{
		Type:      "invalid",
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	_, err := tm.GenerateToken(req)
	if err == nil {
		t.Error("Expected error for invalid token type")
	}
}

func TestTokenMaker_JWTWithoutConfig(t *testing.T) {
	// Create token maker without JWT support
	tm := tokenmaker.NewTokenMakerWithOpaque()

	// Try to generate JWT token
	req := tokenmaker.TokenRequest{
		Type:      tokenmaker.JWT,
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		JWTConfig: &tokenmaker.JWTConfig{
			Issuer:  "test-app",
			Subject: "test-user",
		},
	}

	_, err := tm.GenerateToken(req)
	if err == nil {
		t.Error("Expected error when JWT manager is not initialized")
	}
}

func TestTokenMaker_JWTWithoutJWTConfig(t *testing.T) {
	// Generate RSA keys
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create token maker
	config := &tokenmaker.TokenMakerConfig{
		JWTPrivateKey: privateKey,
		JWTPublicKey:  publicKey,
	}

	tm, err := tokenmaker.NewTokenMaker(config)
	if err != nil {
		t.Fatalf("Failed to create token maker: %v", err)
	}

	// Try to generate JWT token without JWT config
	req := tokenmaker.TokenRequest{
		Type:      tokenmaker.JWT,
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	_, err = tm.GenerateToken(req)
	if err == nil {
		t.Error("Expected error when JWT config is missing")
	}
}

func TestTokenMaker_ExpiredToken(t *testing.T) {
	// Create token maker
	tm := tokenmaker.NewTokenMakerWithOpaque()

	// Generate expired opaque token
	req := tokenmaker.TokenRequest{
		Type:      tokenmaker.Opaque,
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	resp, err := tm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	// Validate expired token
	validateReq := tokenmaker.ValidateRequest{
		Type:  tokenmaker.Opaque,
		Token: resp.Token,
	}

	validateResp := tm.ValidateToken(validateReq)
	if validateResp.Valid {
		t.Error("Expired token should not be valid")
	}

	if validateResp.Error == "" {
		t.Error("Expected error message for expired token")
	}
}

func TestTokenMaker_ECDSAJWT(t *testing.T) {
	// Generate ECDSA keys
	privateKey, publicKey, err := cjwt.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA keys: %v", err)
	}

	// Create token maker with ECDSA
	config := &tokenmaker.TokenMakerConfig{
		JWTPrivateKey:           privateKey,
		JWTPublicKey:            publicKey,
		DefaultJWTSigningMethod: tokenmaker.ES256,
	}

	tm, err := tokenmaker.NewTokenMaker(config)
	if err != nil {
		t.Fatalf("Failed to create ECDSA token maker: %v", err)
	}

	// Generate ECDSA JWT token
	req := tokenmaker.TokenRequest{
		Type:      tokenmaker.JWT,
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		JWTConfig: &tokenmaker.JWTConfig{
			Issuer:        "test-app",
			Subject:       "test-user",
			SigningMethod: tokenmaker.ES256,
		},
	}

	resp, err := tm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA JWT token: %v", err)
	}

	if resp.Type != tokenmaker.JWT {
		t.Errorf("Expected token type JWT, got %s", resp.Type)
	}

	// Validate ECDSA JWT token
	validateReq := tokenmaker.ValidateRequest{
		Type:  tokenmaker.JWT,
		Token: resp.Token,
	}

	validateResp := tm.ValidateToken(validateReq)
	if !validateResp.Valid {
		t.Errorf("ECDSA JWT token validation failed: %s", validateResp.Error)
	}
}

func TestTokenMaker_HMACJWT(t *testing.T) {
	// Generate HMAC key
	hmacKey, err := cjwt.DefaultHMACKey()
	if err != nil {
		t.Fatalf("Failed to generate HMAC key: %v", err)
	}

	// Create token maker with HMAC
	config := &tokenmaker.TokenMakerConfig{
		JWTPrivateKey:           hmacKey,
		DefaultJWTSigningMethod: tokenmaker.HS256,
	}

	tm, err := tokenmaker.NewTokenMaker(config)
	if err != nil {
		t.Fatalf("Failed to create HMAC token maker: %v", err)
	}

	// Generate HMAC JWT token
	req := tokenmaker.TokenRequest{
		Type:      tokenmaker.JWT,
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		JWTConfig: &tokenmaker.JWTConfig{
			Issuer:        "test-app",
			Subject:       "test-user",
			SigningMethod: tokenmaker.HS256,
		},
	}

	resp, err := tm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate HMAC JWT token: %v", err)
	}

	if resp.Type != tokenmaker.JWT {
		t.Errorf("Expected token type JWT, got %s", resp.Type)
	}

	// Validate HMAC JWT token
	validateReq := tokenmaker.ValidateRequest{
		Type:  tokenmaker.JWT,
		Token: resp.Token,
	}

	validateResp := tm.ValidateToken(validateReq)
	if !validateResp.Valid {
		t.Errorf("HMAC JWT token validation failed: %s", validateResp.Error)
	}
}

func TestTokenMaker_JWTRevoke(t *testing.T) {
	// Generate RSA keys
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create token maker
	config := &tokenmaker.TokenMakerConfig{
		JWTPrivateKey: privateKey,
		JWTPublicKey:  publicKey,
	}

	tm, err := tokenmaker.NewTokenMaker(config)
	if err != nil {
		t.Fatalf("Failed to create token maker: %v", err)
	}

	// Try to revoke JWT token
	revokeReq := tokenmaker.RevokeRequest{
		Type:  tokenmaker.JWT,
		Token: "some-jwt-token",
	}

	revokeResp := tm.RevokeToken(revokeReq)
	if revokeResp.Success {
		t.Error("JWT token revocation should not succeed (JWT is stateless)")
	}

	if revokeResp.Error == "" {
		t.Error("Expected error message for JWT token revocation")
	}
}

func TestTokenMaker_ConcurrentAccess(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create token maker
	config := &tokenmaker.TokenMakerConfig{
		JWTPrivateKey:           privateKey,
		JWTPublicKey:            publicKey,
		DefaultJWTSigningMethod: tokenmaker.RS256,
	}

	tm, err := tokenmaker.NewTokenMaker(config)
	if err != nil {
		t.Fatalf("Failed to create token maker: %v", err)
	}

	// Test concurrent token generation
	const numGoroutines = 5
	const tokensPerGoroutine = 3

	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			for j := 0; j < tokensPerGoroutine; j++ {
				// Generate JWT token
				jwtReq := tokenmaker.TokenRequest{
					Type:      tokenmaker.JWT,
					UserID:    fmt.Sprintf("user-%d-%d", goroutineID, j),
					ExpiresAt: time.Now().Add(1 * time.Hour),
					JWTConfig: &tokenmaker.JWTConfig{
						Issuer:  "test-app",
						Subject: fmt.Sprintf("user-%d-%d", goroutineID, j),
					},
				}

				resp, err := tm.GenerateToken(jwtReq)
				if err != nil {
					errors <- fmt.Errorf("JWT goroutine %d, token %d: %v", goroutineID, j, err)
					return
				}

				// Validate JWT token
				validateReq := tokenmaker.ValidateRequest{
					Type:  tokenmaker.JWT,
					Token: resp.Token,
				}

				validateResp := tm.ValidateToken(validateReq)
				if !validateResp.Valid {
					errors <- fmt.Errorf("JWT validation goroutine %d, token %d: %s", goroutineID, j, validateResp.Error)
					return
				}

				// Generate Opaque token
				opaqueReq := tokenmaker.TokenRequest{
					Type:      tokenmaker.Opaque,
					UserID:    fmt.Sprintf("opaque-user-%d-%d", goroutineID, j),
					ExpiresAt: time.Now().Add(1 * time.Hour),
				}

				opaqueResp, err := tm.GenerateToken(opaqueReq)
				if err != nil {
					errors <- fmt.Errorf("Opaque goroutine %d, token %d: %v", goroutineID, j, err)
					return
				}

				// Validate Opaque token
				opaqueValidateReq := tokenmaker.ValidateRequest{
					Type:  tokenmaker.Opaque,
					Token: opaqueResp.Token,
				}

				opaqueValidateResp := tm.ValidateToken(opaqueValidateReq)
				if !opaqueValidateResp.Valid {
					errors <- fmt.Errorf("Opaque validation goroutine %d, token %d: %s", goroutineID, j, opaqueValidateResp.Error)
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
}

func TestTokenMaker_EdgeCases(t *testing.T) {
	// Create token maker with opaque support only
	tm := tokenmaker.NewTokenMakerWithOpaque()

	// Test with empty user ID
	req := tokenmaker.TokenRequest{
		Type:      tokenmaker.Opaque,
		UserID:    "", // Empty user ID
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	resp, err := tm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token with empty user ID: %v", err)
	}

	if resp.UserID != "" {
		t.Errorf("Expected empty user ID, got '%s'", resp.UserID)
	}

	// Test with nil custom data
	req.CustomData = nil
	resp, err = tm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token with nil custom data: %v", err)
	}

	if resp.CustomData == nil {
		t.Error("Custom data should not be nil in response")
	}

	// Test with empty scope
	req.Scope = []string{}
	resp, err = tm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token with empty scope: %v", err)
	}

	if len(resp.Scope) != 0 {
		t.Errorf("Expected empty scope, got %v", resp.Scope)
	}
}

func TestTokenMaker_InvalidConfiguration(t *testing.T) {
	// Test with nil configuration
	_, err := tokenmaker.NewTokenMaker(nil)
	if err == nil {
		t.Error("Expected error for nil configuration")
	}

	// Test with unsupported key type
	config := &tokenmaker.TokenMakerConfig{
		JWTPrivateKey: "invalid-key-type",
	}

	_, err = tokenmaker.NewTokenMaker(config)
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

func TestTokenMaker_GetManagers(t *testing.T) {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create token maker
	config := &tokenmaker.TokenMakerConfig{
		JWTPrivateKey: privateKey,
		JWTPublicKey:  publicKey,
	}

	tm, err := tokenmaker.NewTokenMaker(config)
	if err != nil {
		t.Fatalf("Failed to create token maker: %v", err)
	}

	// Test getting JWT manager
	jwtManager := tm.GetJWTManager()
	if jwtManager == nil {
		t.Error("JWT manager should not be nil")
	}

	// Test getting opaque manager
	opaqueManager := tm.GetOpaqueManager()
	if opaqueManager == nil {
		t.Error("Opaque manager should not be nil")
	}

	// Test with opaque-only token maker
	opaqueOnlyTM := tokenmaker.NewTokenMakerWithOpaque()

	jwtManager = opaqueOnlyTM.GetJWTManager()
	if jwtManager != nil {
		t.Error("JWT manager should be nil for opaque-only token maker")
	}

	opaqueManager = opaqueOnlyTM.GetOpaqueManager()
	if opaqueManager == nil {
		t.Error("Opaque manager should not be nil")
	}
}

func TestTokenMaker_ComplexCustomData(t *testing.T) {
	// Create token maker with opaque support only
	tm := tokenmaker.NewTokenMakerWithOpaque()

	// Test with complex custom data
	req := tokenmaker.TokenRequest{
		Type:      tokenmaker.Opaque,
		UserID:    "test-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CustomData: map[string]interface{}{
			"string":  "test",
			"number":  42,
			"boolean": true,
			"array":   []string{"a", "b", "c"},
			"object": map[string]interface{}{
				"nested": "value",
				"count":  5,
			},
		},
	}

	resp, err := tm.GenerateToken(req)
	if err != nil {
		t.Fatalf("Failed to generate token with complex custom data: %v", err)
	}

	// Validate token
	validateReq := tokenmaker.ValidateRequest{
		Type:  tokenmaker.Opaque,
		Token: resp.Token,
	}

	validateResp := tm.ValidateToken(validateReq)
	if !validateResp.Valid {
		t.Errorf("Token validation failed: %s", validateResp.Error)
	}

	// Check complex custom data
	if len(validateResp.CustomData) != 5 {
		t.Errorf("Expected 5 custom data fields, got %d", len(validateResp.CustomData))
	}

	if str, ok := validateResp.CustomData["string"].(string); !ok || str != "test" {
		t.Errorf("Expected string 'test', got %v", validateResp.CustomData["string"])
	}

	// Check if the number is stored as int or float64
	numValue := validateResp.CustomData["number"]
	switch v := numValue.(type) {
	case int:
		if v != 42 {
			t.Errorf("Expected number 42, got %v", v)
		}
	case float64:
		if v != 42.0 {
			t.Errorf("Expected number 42.0, got %v", v)
		}
	default:
		t.Errorf("Expected number to be int or float64, got %T: %v", v, v)
	}

	if boolVal, ok := validateResp.CustomData["boolean"].(bool); !ok || boolVal != true {
		t.Errorf("Expected boolean true, got %v", validateResp.CustomData["boolean"])
	}
}
