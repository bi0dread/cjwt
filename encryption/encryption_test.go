package encryption

import (
	"testing"
)

func TestEncryptionManager_EncryptDecrypt(t *testing.T) {
	// Create encryption manager
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
	}

	em, err := NewEncryptionManager(config)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}
	defer em.Close()

	// Test data
	testData := []byte("This is sensitive token data that needs encryption")

	// Encrypt data
	encryptReq := EncryptedTokenRequest{
		TokenData: testData,
		Algorithm: AES256GCM,
	}

	encryptResp, err := em.EncryptToken(encryptReq)
	if err != nil {
		t.Fatalf("Failed to encrypt token: %v", err)
	}

	if encryptResp.EncryptedData == nil {
		t.Error("Encrypted data should not be nil")
	}

	if len(encryptResp.Nonce) == 0 {
		t.Error("Nonce should not be empty")
	}

	if len(encryptResp.Tag) == 0 {
		t.Error("Tag should not be empty")
	}

	if encryptResp.Algorithm != AES256GCM {
		t.Errorf("Expected algorithm %s, got %s", AES256GCM, encryptResp.Algorithm)
	}

	// Decrypt data
	decryptReq := DecryptTokenRequest{
		EncryptedData: encryptResp.EncryptedData,
		Nonce:         encryptResp.Nonce,
		Tag:           encryptResp.Tag,
		Algorithm:     encryptResp.Algorithm,
		KeyID:         encryptResp.KeyID,
	}

	decryptResp, err := em.DecryptToken(decryptReq)
	if err != nil {
		t.Fatalf("Failed to decrypt token: %v", err)
	}

	if !decryptResp.Success {
		t.Errorf("Decryption failed: %s", decryptResp.Error)
	}

	if string(decryptResp.TokenData) != string(testData) {
		t.Errorf("Expected decrypted data %s, got %s", string(testData), string(decryptResp.TokenData))
	}
}

func TestEncryptionManager_DifferentAlgorithms(t *testing.T) {
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
	}

	em, err := NewEncryptionManager(config)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}
	defer em.Close()

	algorithms := []EncryptionAlgorithm{AES256GCM, ChaCha20Poly1305, AES256CBC}
	testData := []byte("Test data for encryption")

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			// Encrypt
			encryptReq := EncryptedTokenRequest{
				TokenData: testData,
				Algorithm: algorithm,
			}

			encryptResp, err := em.EncryptToken(encryptReq)
			if err != nil {
				t.Fatalf("Failed to encrypt with %s: %v", algorithm, err)
			}

			// Decrypt
			decryptReq := DecryptTokenRequest{
				EncryptedData: encryptResp.EncryptedData,
				Nonce:         encryptResp.Nonce,
				Tag:           encryptResp.Tag,
				Algorithm:     encryptResp.Algorithm,
				KeyID:         encryptResp.KeyID,
			}

			decryptResp, err := em.DecryptToken(decryptReq)
			if err != nil {
				t.Fatalf("Failed to decrypt with %s: %v", algorithm, err)
			}

			if !decryptResp.Success {
				t.Errorf("Decryption failed with %s: %s", algorithm, decryptResp.Error)
			}

			if string(decryptResp.TokenData) != string(testData) {
				t.Errorf("Data mismatch with %s: expected %s, got %s",
					algorithm, string(testData), string(decryptResp.TokenData))
			}
		})
	}
}

func TestEncryptionManager_InvalidKey(t *testing.T) {
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
	}

	em, err := NewEncryptionManager(config)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}
	defer em.Close()

	// Try to decrypt with invalid key ID
	decryptReq := DecryptTokenRequest{
		EncryptedData: []byte("encrypted data"),
		Nonce:         []byte("nonce"),
		Tag:           []byte("tag"),
		Algorithm:     AES256GCM,
		KeyID:         "invalid-key-id",
	}

	decryptResp, err := em.DecryptToken(decryptReq)
	if err != nil {
		t.Fatalf("Failed to decrypt token: %v", err)
	}

	if decryptResp.Success {
		t.Error("Expected decryption to fail with invalid key ID")
	}

	if decryptResp.Error == "" {
		t.Error("Expected error message for invalid key ID")
	}
}

func TestEncryptionManager_KeyManagement(t *testing.T) {
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
	}

	em, err := NewEncryptionManager(config)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}
	defer em.Close()

	// Get key info
	keyInfo := em.GetKeyInfo()
	if len(keyInfo) == 0 {
		t.Error("Expected at least one encryption key")
	}

	// Rotate keys
	err = em.RotateKeys()
	if err != nil {
		t.Fatalf("Failed to rotate keys: %v", err)
	}

	// Get updated key info
	updatedKeyInfo := em.GetKeyInfo()
	if len(updatedKeyInfo) <= len(keyInfo) {
		t.Error("Expected more keys after rotation")
	}
}

func TestEncryptionManager_WithAAD(t *testing.T) {
	config := &KeyManagerConfig{
		DefaultEncryptionAlgorithm: AES256GCM,
	}

	em, err := NewEncryptionManager(config)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}
	defer em.Close()

	testData := []byte("Test data with AAD")
	aad := []byte("additional authenticated data")

	// Encrypt with AAD
	encryptReq := EncryptedTokenRequest{
		TokenData: testData,
		Algorithm: AES256GCM,
		AAD:       aad,
	}

	encryptResp, err := em.EncryptToken(encryptReq)
	if err != nil {
		t.Fatalf("Failed to encrypt with AAD: %v", err)
	}

	// Decrypt with correct AAD
	decryptReq := DecryptTokenRequest{
		EncryptedData: encryptResp.EncryptedData,
		Nonce:         encryptResp.Nonce,
		Tag:           encryptResp.Tag,
		Algorithm:     encryptResp.Algorithm,
		KeyID:         encryptResp.KeyID,
		AAD:           aad,
	}

	decryptResp, err := em.DecryptToken(decryptReq)
	if err != nil {
		t.Fatalf("Failed to decrypt with AAD: %v", err)
	}

	if !decryptResp.Success {
		t.Errorf("Decryption with AAD failed: %s", decryptResp.Error)
	}

	// Try to decrypt with wrong AAD
	wrongAAD := []byte("wrong AAD")
	decryptReq.AAD = wrongAAD

	decryptResp, err = em.DecryptToken(decryptReq)
	if err != nil {
		t.Fatalf("Failed to decrypt with wrong AAD: %v", err)
	}

	if decryptResp.Success {
		t.Error("Expected decryption to fail with wrong AAD")
	}
}
