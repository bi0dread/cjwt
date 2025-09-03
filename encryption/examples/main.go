package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/cjwt/encryption"
)

func main() {
	fmt.Println("=== Secure Token Manager Example ===")

	// Create secure token manager
	config := &encryption.KeyManagerConfig{
		DefaultEncryptionAlgorithm: encryption.AES256GCM,
		DefaultSignatureAlgorithm:  encryption.RS256,
	}

	stm, err := encryption.NewSecureTokenManager(config)
	if err != nil {
		log.Fatal(err)
	}
	defer stm.Close()

	// Example 1: Encrypted token without multi-signature
	fmt.Println("\n--- Example 1: Encrypted Token ---")
	encryptedTokenExample(stm)

	// Example 2: Encrypted token with multi-signature
	fmt.Println("\n--- Example 2: Encrypted Token with Multi-Signature ---")
	multiSignatureTokenExample(stm)

	// Example 3: Different encryption algorithms
	fmt.Println("\n--- Example 3: Different Encryption Algorithms ---")
	differentAlgorithmsExample(stm)

	// Example 4: Key management
	fmt.Println("\n--- Example 4: Key Management ---")
	keyManagementExample(stm)
}

func encryptedTokenExample(stm *encryption.SecureTokenManager) {
	// Create token data
	tokenData := map[string]interface{}{
		"user_id":     "user123",
		"role":        "admin",
		"permissions": []string{"read", "write", "delete"},
		"expires_at":  time.Now().Add(24 * time.Hour).Unix(),
	}

	data, err := json.Marshal(tokenData)
	if err != nil {
		log.Printf("Failed to marshal token data: %v", err)
		return
	}

	// Create secure token
	req := encryption.SecureTokenRequest{
		TokenData:           data,
		EncryptionAlgorithm: encryption.AES256GCM,
		ExpiresAt:           time.Now().Add(24 * time.Hour),
		Metadata: map[string]interface{}{
			"created_by": "system",
			"purpose":    "authentication",
		},
	}

	resp, err := stm.CreateSecureToken(req)
	if err != nil {
		log.Printf("Failed to create secure token: %v", err)
		return
	}

	if !resp.Success {
		log.Printf("Token creation failed: %s", resp.Error)
		return
	}

	fmt.Printf("Created encrypted token: %s\n", resp.EncryptedToken.TokenID)
	fmt.Printf("Encryption algorithm: %s\n", resp.EncryptedToken.Encryption.Algorithm)
	fmt.Printf("Key ID: %s\n", resp.EncryptedToken.Encryption.KeyID)

	// Verify token
	verifyReq := encryption.VerifySecureTokenRequest{
		EncryptedToken: resp.EncryptedToken,
	}

	verifyResp, err := stm.VerifySecureToken(verifyReq)
	if err != nil {
		log.Printf("Failed to verify secure token: %v", err)
		return
	}

	if !verifyResp.Valid {
		log.Printf("Token verification failed: %s", verifyResp.Error)
		return
	}

	// Decode and display decrypted data
	var decryptedData map[string]interface{}
	err = json.Unmarshal(verifyResp.TokenData, &decryptedData)
	if err != nil {
		log.Printf("Failed to unmarshal decrypted data: %v", err)
		return
	}

	fmt.Printf("Decrypted token data: %+v\n", decryptedData)
}

func multiSignatureTokenExample(stm *encryption.SecureTokenManager) {
	// Create token data
	tokenData := map[string]interface{}{
		"transaction_id": "txn_456",
		"amount":         1000.50,
		"currency":       "USD",
		"recipient":      "user789",
		"timestamp":      time.Now().Unix(),
	}

	data, err := json.Marshal(tokenData)
	if err != nil {
		log.Printf("Failed to marshal token data: %v", err)
		return
	}

	// Create signers
	signers := []encryption.Signer{
		{
			ID:        "signer1",
			Algorithm: encryption.RS256,
			Role:      "approver",
			Weight:    1,
		},
		{
			ID:        "signer2",
			Algorithm: encryption.ES256,
			Role:      "auditor",
			Weight:    1,
		},
	}

	// Create signature policy
	policy := encryption.SignaturePolicy{
		Type:               encryption.ThresholdPolicy,
		RequiredSignatures: 2,
		RequiredRoles:      []string{"approver", "auditor"},
	}

	// Create secure token with multi-signature
	req := encryption.SecureTokenRequest{
		TokenData:           data,
		EncryptionAlgorithm: encryption.ChaCha20Poly1305,
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
		log.Printf("Failed to create secure token: %v", err)
		return
	}

	if !resp.Success {
		log.Printf("Token creation failed: %s", resp.Error)
		return
	}

	fmt.Printf("Created multi-signature token: %s\n", resp.EncryptedToken.TokenID)
	fmt.Printf("Number of signatures: %d\n", len(resp.EncryptedToken.MultiSignature.Signatures))
	fmt.Printf("Signature policy: %s\n", resp.EncryptedToken.MultiSignature.Policy.Type)

	// Verify token
	verifyReq := encryption.VerifySecureTokenRequest{
		EncryptedToken: resp.EncryptedToken,
	}

	verifyResp, err := stm.VerifySecureToken(verifyReq)
	if err != nil {
		log.Printf("Failed to verify secure token: %v", err)
		return
	}

	if !verifyResp.Valid {
		log.Printf("Token verification failed: %s", verifyResp.Error)
		return
	}

	// Display signature results
	if verifyResp.SignatureResults != nil {
		fmt.Printf("Signature verification results:\n")
		for _, result := range verifyResp.SignatureResults.SignatureResults {
			status := "❌ Invalid"
			if result.Valid {
				status = "✅ Valid"
			}
			fmt.Printf("  Signer %s (%s): %s\n", result.SignerID, result.Algorithm, status)
		}
		fmt.Printf("Policy compliant: %t\n", verifyResp.SignatureResults.PolicyCompliant)
	}

	// Decode and display decrypted data
	var decryptedData map[string]interface{}
	err = json.Unmarshal(verifyResp.TokenData, &decryptedData)
	if err != nil {
		log.Printf("Failed to unmarshal decrypted data: %v", err)
		return
	}

	fmt.Printf("Decrypted transaction data: %+v\n", decryptedData)
}

func differentAlgorithmsExample(stm *encryption.SecureTokenManager) {
	algorithms := []encryption.EncryptionAlgorithm{
		encryption.AES256GCM,
		encryption.ChaCha20Poly1305,
		encryption.AES256CBC,
	}

	tokenData := []byte("Sensitive data that needs encryption")

	for _, algorithm := range algorithms {
		fmt.Printf("\nTesting %s:\n", algorithm)

		// Create secure token
		req := encryption.SecureTokenRequest{
			TokenData:           tokenData,
			EncryptionAlgorithm: algorithm,
			ExpiresAt:           time.Now().Add(1 * time.Hour),
		}

		resp, err := stm.CreateSecureToken(req)
		if err != nil {
			log.Printf("Failed to create secure token with %s: %v", algorithm, err)
			continue
		}

		if !resp.Success {
			log.Printf("Token creation failed with %s: %s", algorithm, resp.Error)
			continue
		}

		// Verify token
		verifyReq := encryption.VerifySecureTokenRequest{
			EncryptedToken: resp.EncryptedToken,
		}

		verifyResp, err := stm.VerifySecureToken(verifyReq)
		if err != nil {
			log.Printf("Failed to verify secure token with %s: %v", algorithm, err)
			continue
		}

		if !verifyResp.Valid {
			log.Printf("Token verification failed with %s: %s", algorithm, verifyResp.Error)
			continue
		}

		fmt.Printf("  ✅ Successfully encrypted and decrypted with %s\n", algorithm)
		fmt.Printf("  Key ID: %s\n", resp.EncryptedToken.Encryption.KeyID)
	}
}

func keyManagementExample(stm *encryption.SecureTokenManager) {
	// Get key information
	keyInfo := stm.GetKeyInfo()

	fmt.Printf("Encryption keys:\n")
	if encryptionKeys, ok := keyInfo["encryption_keys"].(map[string]interface{}); ok {
		for keyID, info := range encryptionKeys {
			if keyData, ok := info.(map[string]interface{}); ok {
				fmt.Printf("  Key %s: %s (version %v)\n",
					keyID, keyData["algorithm"], keyData["version"])
			}
		}
	}

	fmt.Printf("\nSignature keys:\n")
	if signatureKeys, ok := keyInfo["signature_keys"].(map[string]interface{}); ok {
		for keyID, info := range signatureKeys {
			if keyData, ok := info.(map[string]interface{}); ok {
				fmt.Printf("  Key %s: %s (version %v)\n",
					keyID, keyData["algorithm"], keyData["version"])
			}
		}
	}

	// Rotate keys
	fmt.Printf("\nRotating encryption keys...\n")
	err := stm.RotateKeys()
	if err != nil {
		log.Printf("Failed to rotate keys: %v", err)
		return
	}

	fmt.Printf("✅ Keys rotated successfully\n")

	// Get updated key information
	updatedKeyInfo := stm.GetKeyInfo()
	fmt.Printf("\nUpdated encryption keys:\n")
	if encryptionKeys, ok := updatedKeyInfo["encryption_keys"].(map[string]interface{}); ok {
		for keyID, info := range encryptionKeys {
			if keyData, ok := info.(map[string]interface{}); ok {
				fmt.Printf("  Key %s: %s (version %v)\n",
					keyID, keyData["algorithm"], keyData["version"])
			}
		}
	}
}
