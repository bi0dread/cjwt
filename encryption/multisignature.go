package encryption

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
)

// MultiSignatureManager manages multi-signature operations
type MultiSignatureManager struct {
	// Signature keys
	keys map[string]*SignatureKey

	// Configuration
	config *KeyManagerConfig
}

// NewMultiSignatureManager creates a new multi-signature manager
func NewMultiSignatureManager(config *KeyManagerConfig) (*MultiSignatureManager, error) {
	if config == nil {
		config = &KeyManagerConfig{
			DefaultSignatureAlgorithm: RS256,
		}
	}

	msm := &MultiSignatureManager{
		keys:   make(map[string]*SignatureKey),
		config: config,
	}

	return msm, nil
}

// CreateMultiSignature creates a multi-signature for data
func (msm *MultiSignatureManager) CreateMultiSignature(req MultiSignatureRequest) (*MultiSignatureResponse, error) {
	// Validate request
	if len(req.Signers) == 0 {
		return nil, fmt.Errorf("no signers provided")
	}

	// Create signature ID
	signatureID := uuid.New().String()

	// Create signatures
	signatures := make([]Signature, 0, len(req.Signers))

	for _, signer := range req.Signers {
		signature, err := msm.createSignature(req.Data, signer)
		if err != nil {
			return nil, fmt.Errorf("failed to create signature for signer %s: %w", signer.ID, err)
		}

		signatures = append(signatures, *signature)
	}

	// Create combined signature if policy requires it
	var combinedSignature []byte
	if req.Policy.Type == AllSignersPolicy || req.Policy.Type == WeightedPolicy {
		combinedSignature, _ = msm.createCombinedSignature(signatures, req.Policy)
	}

	response := &MultiSignatureResponse{
		Signatures:        signatures,
		CombinedSignature: combinedSignature,
		Policy:            req.Policy,
		SignedAt:          time.Now(),
		SignatureID:       signatureID,
	}

	return response, nil
}

// VerifyMultiSignature verifies a multi-signature
func (msm *MultiSignatureManager) VerifyMultiSignature(req VerifyMultiSignatureRequest) (*VerifyMultiSignatureResponse, error) {
	// Validate request
	if len(req.Signatures) == 0 {
		return &VerifyMultiSignatureResponse{
			Valid: false,
			Error: "no signatures provided",
		}, nil
	}

	// Verify individual signatures
	signatureResults := make([]SignatureResult, 0, len(req.Signatures))
	validSignatures := 0
	totalWeight := 0

	for _, signature := range req.Signatures {
		result, err := msm.verifySignature(req.Data, signature)
		if err != nil {
			result = &SignatureResult{
				SignerID:  signature.SignerID,
				Valid:     false,
				Error:     err.Error(),
				Algorithm: signature.Algorithm,
			}
		}

		signatureResults = append(signatureResults, *result)

		if result.Valid {
			validSignatures++
			// Add weight if available
			if signer, exists := msm.keys[signature.SignerID]; exists {
				if weight, ok := signer.Metadata["weight"].(int); ok {
					totalWeight += weight
				} else {
					totalWeight += 1 // Default weight
				}
			} else {
				totalWeight += 1 // Default weight if signer not found
			}
		}
	}

	// Check policy compliance
	policyCompliant := msm.checkPolicyCompliance(validSignatures, totalWeight, req.Policy, signatureResults)

	response := &VerifyMultiSignatureResponse{
		Valid:            policyCompliant,
		SignatureResults: signatureResults,
		PolicyCompliant:  policyCompliant,
		VerifiedAt:       time.Now(),
	}

	if !policyCompliant {
		response.Error = "signature policy not satisfied"
	}

	return response, nil
}

// createSignature creates a signature for a signer
func (msm *MultiSignatureManager) createSignature(data []byte, signer Signer) (*Signature, error) {
	// Get or create signature key
	key, err := msm.getOrCreateSignatureKey(signer)
	if err != nil {
		return nil, err
	}

	// Create signature based on algorithm
	var signatureData []byte

	switch signer.Algorithm {
	case RS256:
		signatureData, err = msm.signRS256(data, key.PrivateKey.(*rsa.PrivateKey))
	case ES256:
		signatureData, err = msm.signES256(data, key.PrivateKey.(*ecdsa.PrivateKey))
	case HS256:
		signatureData, err = msm.signHS256(data, key.PrivateKey.([]byte))
	case Ed25519:
		signatureData, err = msm.signEd25519(data, key.PrivateKey.(ed25519.PrivateKey))
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", signer.Algorithm)
	}

	if err != nil {
		return nil, err
	}

	signature := &Signature{
		SignerID:      signer.ID,
		SignatureData: signatureData,
		Algorithm:     signer.Algorithm,
		SignedAt:      time.Now(),
	}

	return signature, nil
}

// verifySignature verifies a single signature
func (msm *MultiSignatureManager) verifySignature(data []byte, signature Signature) (*SignatureResult, error) {
	// Get signature key
	key, exists := msm.keys[signature.SignerID]
	if !exists {
		return nil, fmt.Errorf("signature key not found for signer %s", signature.SignerID)
	}

	// Verify signature based on algorithm
	var valid bool
	var err error

	switch signature.Algorithm {
	case RS256:
		valid, err = msm.verifyRS256(data, signature.SignatureData, key.PublicKey.(*rsa.PublicKey))
	case ES256:
		valid, err = msm.verifyES256(data, signature.SignatureData, key.PublicKey.(*ecdsa.PublicKey))
	case HS256:
		valid, err = msm.verifyHS256(data, signature.SignatureData, key.PublicKey.([]byte))
	case Ed25519:
		valid, err = msm.verifyEd25519(data, signature.SignatureData, key.PublicKey.(ed25519.PublicKey))
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", signature.Algorithm)
	}

	if err != nil {
		return nil, err
	}

	result := &SignatureResult{
		SignerID:  signature.SignerID,
		Valid:     valid,
		Algorithm: signature.Algorithm,
	}

	if !valid {
		result.Error = "signature verification failed"
	}

	return result, nil
}

// signRS256 signs data using RS256
func (msm *MultiSignatureManager) signRS256(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// verifyRS256 verifies data using RS256
func (msm *MultiSignatureManager) verifyRS256(data []byte, signature []byte, publicKey *rsa.PublicKey) (bool, error) {
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash, signature)
	return err == nil, err
}

// signES256 signs data using ES256
func (msm *MultiSignatureManager) signES256(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, err
	}

	// Encode signature as ASN.1 DER
	signature, err := msm.encodeECDSASignature(r, s)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// verifyES256 verifies data using ES256
func (msm *MultiSignatureManager) verifyES256(data []byte, signature []byte, publicKey *ecdsa.PublicKey) (bool, error) {
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	// Decode signature from ASN.1 DER
	r, s, err := msm.decodeECDSASignature(signature)
	if err != nil {
		return false, err
	}

	valid := ecdsa.Verify(publicKey, hash, r, s)
	return valid, nil
}

// signHS256 signs data using HS256
func (msm *MultiSignatureManager) signHS256(data []byte, key []byte) ([]byte, error) {
	// Use direct HMAC-SHA256
	h := hmac.New(sha256.New, key)
	h.Write(data)
	signature := h.Sum(nil)
	return signature, nil
}

// verifyHS256 verifies data using HS256
func (msm *MultiSignatureManager) verifyHS256(data []byte, signature []byte, key []byte) (bool, error) {
	// Use direct HMAC-SHA256 verification
	h := hmac.New(sha256.New, key)
	h.Write(data)
	expectedSignature := h.Sum(nil)

	// Use constant time comparison
	return hmac.Equal(signature, expectedSignature), nil
}

// signEd25519 signs data using Ed25519
func (msm *MultiSignatureManager) signEd25519(data []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	signature := ed25519.Sign(privateKey, data)
	return signature, nil
}

// verifyEd25519 verifies data using Ed25519
func (msm *MultiSignatureManager) verifyEd25519(data []byte, signature []byte, publicKey ed25519.PublicKey) (bool, error) {
	valid := ed25519.Verify(publicKey, data, signature)
	return valid, nil
}

// encodeECDSASignature encodes ECDSA signature as ASN.1 DER
func (msm *MultiSignatureManager) encodeECDSASignature(r, s *big.Int) ([]byte, error) {
	// This is a simplified implementation
	// In production, use proper ASN.1 encoding
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	return signature, nil
}

// decodeECDSASignature decodes ECDSA signature from ASN.1 DER
func (msm *MultiSignatureManager) decodeECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	// This is a simplified implementation
	// In production, use proper ASN.1 decoding
	if len(signature) != 64 {
		return nil, nil, fmt.Errorf("invalid signature length")
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return r, s, nil
}

// createCombinedSignature creates a combined signature
func (msm *MultiSignatureManager) createCombinedSignature(signatures []Signature, policy SignaturePolicy) ([]byte, error) {
	// Serialize signatures
	signatureData, err := json.Marshal(signatures)
	if err != nil {
		return nil, err
	}

	// Create hash of all signatures
	hasher := sha256.New()
	hasher.Write(signatureData)
	hash := hasher.Sum(nil)

	return hash, nil
}

// checkPolicyCompliance checks if signatures comply with policy
func (msm *MultiSignatureManager) checkPolicyCompliance(validSignatures int, totalWeight int, policy SignaturePolicy, results []SignatureResult) bool {
	switch policy.Type {
	case ThresholdPolicy:
		return validSignatures >= policy.RequiredSignatures
	case RoleBasedPolicy:
		// Check if all required roles have valid signatures
		validRoles := make(map[string]bool)
		for _, result := range results {
			if result.Valid {
				if key, exists := msm.keys[result.SignerID]; exists {
					if role, ok := key.Metadata["role"].(string); ok {
						validRoles[role] = true
					}
				}
			}
		}

		for _, requiredRole := range policy.RequiredRoles {
			if !validRoles[requiredRole] {
				return false
			}
		}
		return true
	case WeightedPolicy:
		return totalWeight >= policy.MinimumWeight
	case AllSignersPolicy:
		return validSignatures == len(results)
	default:
		return false
	}
}

// getOrCreateSignatureKey gets or creates a signature key
func (msm *MultiSignatureManager) getOrCreateSignatureKey(signer Signer) (*SignatureKey, error) {
	// Check if key already exists
	if key, exists := msm.keys[signer.ID]; exists {
		return key, nil
	}

	// Create new signature key
	keyID := signer.ID
	var privateKey, publicKey interface{}
	var err error

	switch signer.Algorithm {
	case RS256:
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		publicKey = &privateKey.(*rsa.PrivateKey).PublicKey
	case ES256:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		publicKey = &privateKey.(*ecdsa.PrivateKey).PublicKey
	case HS256:
		key := make([]byte, 32)
		_, err = rand.Read(key)
		if err != nil {
			return nil, err
		}
		privateKey = key
		publicKey = key
	case Ed25519:
		publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", signer.Algorithm)
	}

	// Create signature key
	signatureKey := &SignatureKey{
		ID:         keyID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Algorithm:  signer.Algorithm,
		Version:    1,
		CreatedAt:  time.Now(),
		Metadata: map[string]interface{}{
			"role":   signer.Role,
			"weight": signer.Weight,
		},
	}

	// Store key
	msm.keys[keyID] = signatureKey

	return signatureKey, nil
}

// GetKeyInfo returns information about all signature keys
func (msm *MultiSignatureManager) GetKeyInfo() map[string]interface{} {
	keyInfo := make(map[string]interface{})

	for id, key := range msm.keys {
		keyInfo[id] = map[string]interface{}{
			"algorithm":  key.Algorithm,
			"version":    key.Version,
			"created_at": key.CreatedAt,
			"expires_at": key.ExpiresAt,
			"metadata":   key.Metadata,
		}
	}

	return keyInfo
}

// Close cleans up resources
func (msm *MultiSignatureManager) Close() error {
	// Clear all keys from memory
	for id := range msm.keys {
		delete(msm.keys, id)
	}

	return nil
}
