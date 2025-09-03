package encryption

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSecureTokenManager_CreateAndVerify(t *testing.T) {
	// Create secure token manager
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
		DefaultSignatureAlgorithm:  RS256,
	}

	stm, err := NewSecureTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create secure token manager: %v", err)
	}
	defer stm.Close()

	// Test data
	tokenData := map[string]interface{}{
		"user_id":     "user123",
		"role":        "admin",
		"permissions": []string{"read", "write", "delete"},
		"expires_at":  time.Now().Add(24 * time.Hour).Unix(),
	}

	data, err := json.Marshal(tokenData)
	if err != nil {
		t.Fatalf("Failed to marshal token data: %v", err)
	}

	// Create secure token
	req := SecureTokenRequest{
		TokenData:           data,
		EncryptionAlgorithm: AES256GCM,
		ExpiresAt:           time.Now().Add(24 * time.Hour),
		Metadata: map[string]interface{}{
			"created_by": "system",
			"purpose":    "authentication",
		},
	}

	resp, err := stm.CreateSecureToken(req)
	if err != nil {
		t.Fatalf("Failed to create secure token: %v", err)
	}

	if !resp.Success {
		t.Errorf("Token creation failed: %s", resp.Error)
	}

	if resp.EncryptedToken == nil {
		t.Error("Encrypted token should not be nil")
	}

	if resp.EncryptedToken.TokenID == "" {
		t.Error("Token ID should not be empty")
	}

	if resp.EncryptedToken.Encryption.Algorithm != AES256GCM {
		t.Errorf("Expected encryption algorithm %s, got %s", AES256GCM, resp.EncryptedToken.Encryption.Algorithm)
	}

	// Verify secure token
	verifyReq := VerifySecureTokenRequest{
		EncryptedToken: resp.EncryptedToken,
	}

	verifyResp, err := stm.VerifySecureToken(verifyReq)
	if err != nil {
		t.Fatalf("Failed to verify secure token: %v", err)
	}

	if !verifyResp.Valid {
		t.Errorf("Token verification failed: %s", verifyResp.Error)
	}

	// Decode and verify decrypted data
	var decryptedData map[string]interface{}
	err = json.Unmarshal(verifyResp.TokenData, &decryptedData)
	if err != nil {
		t.Fatalf("Failed to unmarshal decrypted data: %v", err)
	}

	if decryptedData["user_id"] != "user123" {
		t.Errorf("Expected user_id 'user123', got %v", decryptedData["user_id"])
	}

	if decryptedData["role"] != "admin" {
		t.Errorf("Expected role 'admin', got %v", decryptedData["role"])
	}
}

func TestSecureTokenManager_WithMultiSignature(t *testing.T) {
	// Create secure token manager
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
		DefaultSignatureAlgorithm:  RS256,
	}

	stm, err := NewSecureTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create secure token manager: %v", err)
	}
	defer stm.Close()

	// Test data
	tokenData := map[string]interface{}{
		"transaction_id": "txn_456",
		"amount":         1000.50,
		"currency":       "USD",
		"recipient":      "user789",
		"timestamp":      time.Now().Unix(),
	}

	data, err := json.Marshal(tokenData)
	if err != nil {
		t.Fatalf("Failed to marshal token data: %v", err)
	}

	// Create signers
	signers := []Signer{
		{
			ID:        "signer1",
			Algorithm: RS256,
			Role:      "approver",
			Weight:    1,
		},
		{
			ID:        "signer2",
			Algorithm: ES256,
			Role:      "auditor",
			Weight:    1,
		},
	}

	// Create signature policy
	policy := SignaturePolicy{
		Type:               ThresholdPolicy,
		RequiredSignatures: 2,
		RequiredRoles:      []string{"approver", "auditor"},
	}

	// Create secure token with multi-signature
	req := SecureTokenRequest{
		TokenData:           data,
		EncryptionAlgorithm: ChaCha20Poly1305,
		Signers:             signers,
		SignaturePolicy:     policy,
		ExpiresAt:           time.Now().Add(1 * time.Hour),
		Metadata: map[string]interface{}{
			"transaction_type": "transfer",
			"security_level":   "high",
		},
	}

	resp, err := stm.CreateSecureToken(req)
	if err != nil {
		t.Fatalf("Failed to create secure token: %v", err)
	}

	if !resp.Success {
		t.Errorf("Token creation failed: %s", resp.Error)
	}

	if resp.EncryptedToken.MultiSignature == nil {
		t.Error("Multi-signature should not be nil")
	}

	if len(resp.EncryptedToken.MultiSignature.Signatures) != 2 {
		t.Errorf("Expected 2 signatures, got %d", len(resp.EncryptedToken.MultiSignature.Signatures))
	}

	// Verify secure token
	verifyReq := VerifySecureTokenRequest{
		EncryptedToken: resp.EncryptedToken,
	}

	verifyResp, err := stm.VerifySecureToken(verifyReq)
	if err != nil {
		t.Fatalf("Failed to verify secure token: %v", err)
	}

	if !verifyResp.Valid {
		t.Errorf("Token verification failed: %s", verifyResp.Error)
	}

	if verifyResp.SignatureResults == nil {
		t.Error("Signature results should not be nil")
	}

	if !verifyResp.SignatureResults.Valid {
		t.Errorf("Signature verification failed: %s", verifyResp.SignatureResults.Error)
	}

	if !verifyResp.SignatureResults.PolicyCompliant {
		t.Error("Expected policy to be compliant")
	}

	// Check individual signature results
	if len(verifyResp.SignatureResults.SignatureResults) != 2 {
		t.Errorf("Expected 2 signature results, got %d", len(verifyResp.SignatureResults.SignatureResults))
	}

	for _, result := range verifyResp.SignatureResults.SignatureResults {
		if !result.Valid {
			t.Errorf("Signature from %s should be valid", result.SignerID)
		}
	}
}

func TestSecureTokenManager_ExpiredToken(t *testing.T) {
	// Create secure token manager
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
		DefaultSignatureAlgorithm:  RS256,
	}

	stm, err := NewSecureTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create secure token manager: %v", err)
	}
	defer stm.Close()

	// Test data
	tokenData := []byte("Test data for expired token")

	// Create secure token with past expiration
	req := SecureTokenRequest{
		TokenData:           tokenData,
		EncryptionAlgorithm: AES256GCM,
		ExpiresAt:           time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	resp, err := stm.CreateSecureToken(req)
	if err != nil {
		t.Fatalf("Failed to create secure token: %v", err)
	}

	if !resp.Success {
		t.Errorf("Token creation failed: %s", resp.Error)
	}

	// Try to verify expired token
	verifyReq := VerifySecureTokenRequest{
		EncryptedToken: resp.EncryptedToken,
	}

	verifyResp, err := stm.VerifySecureToken(verifyReq)
	if err != nil {
		t.Fatalf("Failed to verify secure token: %v", err)
	}

	if verifyResp.Valid {
		t.Error("Expected expired token to fail verification")
	}

	if verifyResp.Error == "" {
		t.Error("Expected error message for expired token")
	}
}

func TestSecureTokenManager_InvalidData(t *testing.T) {
	// Create secure token manager
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
		DefaultSignatureAlgorithm:  RS256,
	}

	stm, err := NewSecureTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create secure token manager: %v", err)
	}
	defer stm.Close()

	// Test with empty token data
	req := SecureTokenRequest{
		TokenData:           []byte{},
		EncryptionAlgorithm: AES256GCM,
		ExpiresAt:           time.Now().Add(1 * time.Hour),
	}

	resp, err := stm.CreateSecureToken(req)
	if err != nil {
		t.Fatalf("Failed to create secure token: %v", err)
	}

	if resp.Success {
		t.Error("Expected token creation to fail with empty data")
	}

	if resp.Error == "" {
		t.Error("Expected error message for empty data")
	}

	// Test with nil encrypted token
	verifyReq := VerifySecureTokenRequest{
		EncryptedToken: nil,
	}

	verifyResp, err := stm.VerifySecureToken(verifyReq)
	if err != nil {
		t.Fatalf("Failed to verify secure token: %v", err)
	}

	if verifyResp.Valid {
		t.Error("Expected nil token to fail verification")
	}

	if verifyResp.Error == "" {
		t.Error("Expected error message for nil token")
	}
}

func TestSecureTokenManager_DifferentAlgorithms(t *testing.T) {
	// Create secure token manager
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
		DefaultSignatureAlgorithm:  RS256,
	}

	stm, err := NewSecureTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create secure token manager: %v", err)
	}
	defer stm.Close()

	algorithms := []EncryptionAlgorithm{AES256GCM, ChaCha20Poly1305, AES256CBC}
	testData := []byte("Test data for different encryption algorithms")

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			// Create secure token
			req := SecureTokenRequest{
				TokenData:           testData,
				EncryptionAlgorithm: algorithm,
				ExpiresAt:           time.Now().Add(1 * time.Hour),
			}

			resp, err := stm.CreateSecureToken(req)
			if err != nil {
				t.Fatalf("Failed to create secure token with %s: %v", algorithm, err)
			}

			if !resp.Success {
				t.Errorf("Token creation failed with %s: %s", algorithm, resp.Error)
			}

			// Verify secure token
			verifyReq := VerifySecureTokenRequest{
				EncryptedToken: resp.EncryptedToken,
			}

			verifyResp, err := stm.VerifySecureToken(verifyReq)
			if err != nil {
				t.Fatalf("Failed to verify secure token with %s: %v", algorithm, err)
			}

			if !verifyResp.Valid {
				t.Errorf("Token verification failed with %s: %s", algorithm, verifyResp.Error)
			}

			if string(verifyResp.TokenData) != string(testData) {
				t.Errorf("Data mismatch with %s: expected %s, got %s",
					algorithm, string(testData), string(verifyResp.TokenData))
			}
		})
	}
}

func TestSecureTokenManager_KeyManagement(t *testing.T) {
	// Create secure token manager
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
		DefaultSignatureAlgorithm:  RS256,
	}

	stm, err := NewSecureTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create secure token manager: %v", err)
	}
	defer stm.Close()

	// Get key information
	keyInfo := stm.GetKeyInfo()

	// Check encryption keys
	if encryptionKeys, ok := keyInfo["encryption_keys"].(map[string]interface{}); ok {
		if len(encryptionKeys) == 0 {
			t.Error("Expected at least one encryption key")
		}
	} else {
		t.Error("Expected encryption keys to be present")
	}

	// Check signature keys (should be empty initially)
	if signatureKeys, ok := keyInfo["signature_keys"].(map[string]interface{}); ok {
		if len(signatureKeys) != 0 {
			t.Errorf("Expected no signature keys initially, got %d", len(signatureKeys))
		}
	} else {
		t.Error("Expected signature keys to be present")
	}

	// Rotate keys
	err = stm.RotateKeys()
	if err != nil {
		t.Fatalf("Failed to rotate keys: %v", err)
	}

	// Get updated key information
	updatedKeyInfo := stm.GetKeyInfo()

	// Check that encryption keys were rotated
	if encryptionKeys, ok := updatedKeyInfo["encryption_keys"].(map[string]interface{}); ok {
		if len(encryptionKeys) == 0 {
			t.Error("Expected at least one encryption key after rotation")
		}
	} else {
		t.Error("Expected encryption keys to be present after rotation")
	}
}
