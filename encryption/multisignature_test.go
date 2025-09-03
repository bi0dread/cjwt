package encryption

import (
	"testing"
)

func TestMultiSignatureManager_CreateAndVerify(t *testing.T) {
	// Create multi-signature manager
	config := &KeyManagerConfig{
		DefaultSignatureAlgorithm: RS256,
	}

	msm, err := NewMultiSignatureManager(config)
	if err != nil {
		t.Fatalf("Failed to create multi-signature manager: %v", err)
	}
	defer msm.Close()

	// Test data
	testData := []byte("Data to be signed by multiple signers")

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

	// Create multi-signature
	req := MultiSignatureRequest{
		Data:    testData,
		Signers: signers,
		Policy:  policy,
		Metadata: map[string]interface{}{
			"transaction_id": "txn_123",
		},
	}

	resp, err := msm.CreateMultiSignature(req)
	if err != nil {
		t.Fatalf("Failed to create multi-signature: %v", err)
	}

	if len(resp.Signatures) != 2 {
		t.Errorf("Expected 2 signatures, got %d", len(resp.Signatures))
	}

	if resp.Policy.Type != ThresholdPolicy {
		t.Errorf("Expected policy type %s, got %s", ThresholdPolicy, resp.Policy.Type)
	}

	if resp.SignatureID == "" {
		t.Error("Signature ID should not be empty")
	}

	// Verify multi-signature
	verifyReq := VerifyMultiSignatureRequest{
		Data:        testData,
		Signatures:  resp.Signatures,
		Policy:      resp.Policy,
		SignatureID: resp.SignatureID,
	}

	verifyResp, err := msm.VerifyMultiSignature(verifyReq)
	if err != nil {
		t.Fatalf("Failed to verify multi-signature: %v", err)
	}

	if !verifyResp.Valid {
		t.Errorf("Multi-signature verification failed: %s", verifyResp.Error)
	}

	if !verifyResp.PolicyCompliant {
		t.Error("Expected policy to be compliant")
	}

	if len(verifyResp.SignatureResults) != 2 {
		t.Errorf("Expected 2 signature results, got %d", len(verifyResp.SignatureResults))
	}

	// Check individual signature results
	for _, result := range verifyResp.SignatureResults {
		if !result.Valid {
			t.Errorf("Signature from %s should be valid", result.SignerID)
		}
	}
}

func TestMultiSignatureManager_DifferentAlgorithms(t *testing.T) {
	config := &KeyManagerConfig{
		DefaultSignatureAlgorithm: RS256,
	}

	msm, err := NewMultiSignatureManager(config)
	if err != nil {
		t.Fatalf("Failed to create multi-signature manager: %v", err)
	}
	defer msm.Close()

	algorithms := []SignatureAlgorithm{RS256, ES256, HS256, Ed25519}
	testData := []byte("Test data for different signature algorithms")

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			// Create signer
			signer := Signer{
				ID:        "signer_" + string(algorithm),
				Algorithm: algorithm,
				Role:      "tester",
				Weight:    1,
			}

			// Create signature policy
			policy := SignaturePolicy{
				Type:               ThresholdPolicy,
				RequiredSignatures: 1,
			}

			// Create multi-signature
			req := MultiSignatureRequest{
				Data:    testData,
				Signers: []Signer{signer},
				Policy:  policy,
			}

			resp, err := msm.CreateMultiSignature(req)
			if err != nil {
				t.Fatalf("Failed to create multi-signature with %s: %v", algorithm, err)
			}

			if len(resp.Signatures) != 1 {
				t.Errorf("Expected 1 signature, got %d", len(resp.Signatures))
			}

			// Verify multi-signature
			verifyReq := VerifyMultiSignatureRequest{
				Data:        testData,
				Signatures:  resp.Signatures,
				Policy:      resp.Policy,
				SignatureID: resp.SignatureID,
			}

			verifyResp, err := msm.VerifyMultiSignature(verifyReq)
			if err != nil {
				t.Fatalf("Failed to verify multi-signature with %s: %v", algorithm, err)
			}

			if !verifyResp.Valid {
				t.Errorf("Multi-signature verification failed with %s: %s", algorithm, verifyResp.Error)
			}

			if !verifyResp.PolicyCompliant {
				t.Errorf("Expected policy to be compliant with %s", algorithm)
			}
		})
	}
}

func TestMultiSignatureManager_PolicyTypes(t *testing.T) {
	config := &KeyManagerConfig{
		DefaultSignatureAlgorithm: RS256,
	}

	msm, err := NewMultiSignatureManager(config)
	if err != nil {
		t.Fatalf("Failed to create multi-signature manager: %v", err)
	}
	defer msm.Close()

	testData := []byte("Test data for different policy types")

	// Test ThresholdPolicy
	t.Run("ThresholdPolicy", func(t *testing.T) {
		signers := []Signer{
			{ID: "signer1", Algorithm: RS256, Role: "approver", Weight: 1},
			{ID: "signer2", Algorithm: ES256, Role: "auditor", Weight: 1},
			{ID: "signer3", Algorithm: HS256, Role: "manager", Weight: 1},
		}

		policy := SignaturePolicy{
			Type:               ThresholdPolicy,
			RequiredSignatures: 2,
		}

		req := MultiSignatureRequest{
			Data:    testData,
			Signers: signers,
			Policy:  policy,
		}

		resp, err := msm.CreateMultiSignature(req)
		if err != nil {
			t.Fatalf("Failed to create multi-signature: %v", err)
		}

		// Verify with all signatures
		verifyReq := VerifyMultiSignatureRequest{
			Data:        testData,
			Signatures:  resp.Signatures,
			Policy:      resp.Policy,
			SignatureID: resp.SignatureID,
		}

		verifyResp, err := msm.VerifyMultiSignature(verifyReq)
		if err != nil {
			t.Fatalf("Failed to verify multi-signature: %v", err)
		}

		if !verifyResp.Valid {
			t.Errorf("Threshold policy verification failed: %s", verifyResp.Error)
		}
	})

	// Test RoleBasedPolicy
	t.Run("RoleBasedPolicy", func(t *testing.T) {
		signers := []Signer{
			{ID: "signer1", Algorithm: RS256, Role: "approver", Weight: 1},
			{ID: "signer2", Algorithm: ES256, Role: "auditor", Weight: 1},
		}

		policy := SignaturePolicy{
			Type:          RoleBasedPolicy,
			RequiredRoles: []string{"approver", "auditor"},
		}

		req := MultiSignatureRequest{
			Data:    testData,
			Signers: signers,
			Policy:  policy,
		}

		resp, err := msm.CreateMultiSignature(req)
		if err != nil {
			t.Fatalf("Failed to create multi-signature: %v", err)
		}

		// Verify
		verifyReq := VerifyMultiSignatureRequest{
			Data:        testData,
			Signatures:  resp.Signatures,
			Policy:      resp.Policy,
			SignatureID: resp.SignatureID,
		}

		verifyResp, err := msm.VerifyMultiSignature(verifyReq)
		if err != nil {
			t.Fatalf("Failed to verify multi-signature: %v", err)
		}

		if !verifyResp.Valid {
			t.Errorf("Role-based policy verification failed: %s", verifyResp.Error)
		}
	})

	// Test WeightedPolicy
	t.Run("WeightedPolicy", func(t *testing.T) {
		signers := []Signer{
			{ID: "signer1", Algorithm: RS256, Role: "approver", Weight: 3},
			{ID: "signer2", Algorithm: ES256, Role: "auditor", Weight: 2},
		}

		policy := SignaturePolicy{
			Type:          WeightedPolicy,
			MinimumWeight: 4,
		}

		req := MultiSignatureRequest{
			Data:    testData,
			Signers: signers,
			Policy:  policy,
		}

		resp, err := msm.CreateMultiSignature(req)
		if err != nil {
			t.Fatalf("Failed to create multi-signature: %v", err)
		}

		// Verify
		verifyReq := VerifyMultiSignatureRequest{
			Data:        testData,
			Signatures:  resp.Signatures,
			Policy:      resp.Policy,
			SignatureID: resp.SignatureID,
		}

		verifyResp, err := msm.VerifyMultiSignature(verifyReq)
		if err != nil {
			t.Fatalf("Failed to verify multi-signature: %v", err)
		}

		if !verifyResp.Valid {
			t.Errorf("Weighted policy verification failed: %s", verifyResp.Error)
		}
	})
}

func TestMultiSignatureManager_InvalidData(t *testing.T) {
	config := &KeyManagerConfig{
		DefaultSignatureAlgorithm: RS256,
	}

	msm, err := NewMultiSignatureManager(config)
	if err != nil {
		t.Fatalf("Failed to create multi-signature manager: %v", err)
	}
	defer msm.Close()

	// Test with no signers
	req := MultiSignatureRequest{
		Data:    []byte("test data"),
		Signers: []Signer{},
		Policy: SignaturePolicy{
			Type:               ThresholdPolicy,
			RequiredSignatures: 1,
		},
	}

	_, err = msm.CreateMultiSignature(req)
	if err == nil {
		t.Error("Expected error when no signers provided")
	}

	// Test with empty data
	req = MultiSignatureRequest{
		Data: []byte{},
		Signers: []Signer{
			{ID: "signer1", Algorithm: RS256, Role: "tester", Weight: 1},
		},
		Policy: SignaturePolicy{
			Type:               ThresholdPolicy,
			RequiredSignatures: 1,
		},
	}

	_, err = msm.CreateMultiSignature(req)
	if err != nil {
		t.Errorf("Unexpected error with empty data: %v", err)
	}
}

func TestMultiSignatureManager_KeyManagement(t *testing.T) {
	config := &KeyManagerConfig{
		DefaultSignatureAlgorithm: RS256,
	}

	msm, err := NewMultiSignatureManager(config)
	if err != nil {
		t.Fatalf("Failed to create multi-signature manager: %v", err)
	}
	defer msm.Close()

	// Get key info (should be empty initially)
	keyInfo := msm.GetKeyInfo()
	if len(keyInfo) != 0 {
		t.Errorf("Expected no keys initially, got %d", len(keyInfo))
	}

	// Create a signature to generate keys
	testData := []byte("Test data for key generation")
	signer := Signer{
		ID:        "test_signer",
		Algorithm: RS256,
		Role:      "tester",
		Weight:    1,
	}

	req := MultiSignatureRequest{
		Data:    testData,
		Signers: []Signer{signer},
		Policy: SignaturePolicy{
			Type:               ThresholdPolicy,
			RequiredSignatures: 1,
		},
	}

	_, err = msm.CreateMultiSignature(req)
	if err != nil {
		t.Fatalf("Failed to create multi-signature: %v", err)
	}

	// Check that key was created
	updatedKeyInfo := msm.GetKeyInfo()
	if len(updatedKeyInfo) == 0 {
		t.Error("Expected at least one key after signature creation")
	}

	// Verify key info structure
	for keyID, info := range updatedKeyInfo {
		if keyID == "" {
			t.Error("Key ID should not be empty")
		}

		if keyData, ok := info.(map[string]interface{}); ok {
			if algorithm, ok := keyData["algorithm"].(SignatureAlgorithm); !ok {
				t.Error("Key algorithm should be present")
			} else if algorithm != RS256 {
				t.Errorf("Expected algorithm %s, got %s", RS256, algorithm)
			}
		} else {
			t.Error("Key info should be a map")
		}
	}
}
