package encryption

import (
	"encoding/json"
	"fmt"
	"time"
)

// SecureTokenManager combines encryption and multi-signature functionality
type SecureTokenManager struct {
	// Encryption manager
	encryptionManager *EncryptionManager

	// Multi-signature manager
	multiSignatureManager *MultiSignatureManager

	// Configuration
	config *KeyManagerConfig
}

// NewSecureTokenManager creates a new secure token manager
func NewSecureTokenManager(config *KeyManagerConfig) (*SecureTokenManager, error) {
	// Create encryption manager
	encryptionManager, err := NewEncryptionManager(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %w", err)
	}

	// Create multi-signature manager
	multiSignatureManager, err := NewMultiSignatureManager(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create multi-signature manager: %w", err)
	}

	stm := &SecureTokenManager{
		encryptionManager:     encryptionManager,
		multiSignatureManager: multiSignatureManager,
		config:                config,
	}

	return stm, nil
}

// SecureTokenRequest represents a request to create a secure token
type SecureTokenRequest struct {
	// Token data to encrypt
	TokenData []byte `json:"token_data"`

	// Encryption algorithm
	EncryptionAlgorithm EncryptionAlgorithm `json:"encryption_algorithm,omitempty"`

	// Additional authenticated data for encryption
	AAD []byte `json:"aad,omitempty"`

	// Signers for multi-signature
	Signers []Signer `json:"signers,omitempty"`

	// Signature policy
	SignaturePolicy SignaturePolicy `json:"signature_policy,omitempty"`

	// Token metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Token expiration
	ExpiresAt time.Time `json:"expires_at"`
}

// SecureTokenResponse represents the response after creating a secure token
type SecureTokenResponse struct {
	// Encrypted token information
	EncryptedToken *EncryptedTokenInfo `json:"encrypted_token"`

	// Success flag
	Success bool `json:"success"`

	// Error message if creation failed
	Error string `json:"error,omitempty"`

	// Created timestamp
	CreatedAt time.Time `json:"created_at"`
}

// VerifySecureTokenRequest represents a request to verify a secure token
type VerifySecureTokenRequest struct {
	// Encrypted token information
	EncryptedToken *EncryptedTokenInfo `json:"encrypted_token"`

	// Additional authenticated data for decryption
	AAD []byte `json:"aad,omitempty"`
}

// VerifySecureTokenResponse represents the response after verifying a secure token
type VerifySecureTokenResponse struct {
	// Decrypted token data
	TokenData []byte `json:"token_data"`

	// Verification result
	Valid bool `json:"valid"`

	// Error message if verification failed
	Error string `json:"error,omitempty"`

	// Signature verification results
	SignatureResults *VerifyMultiSignatureResponse `json:"signature_results,omitempty"`

	// Verified timestamp
	VerifiedAt time.Time `json:"verified_at"`
}

// CreateSecureToken creates a secure token with encryption and multi-signature
func (stm *SecureTokenManager) CreateSecureToken(req SecureTokenRequest) (*SecureTokenResponse, error) {
	// Validate request
	if len(req.TokenData) == 0 {
		return &SecureTokenResponse{
			Success: false,
			Error:   "token data is required",
		}, nil
	}

	// Encrypt token data
	encryptReq := EncryptedTokenRequest{
		TokenData: req.TokenData,
		Algorithm: req.EncryptionAlgorithm,
		AAD:       req.AAD,
	}

	encryptedResp, err := stm.encryptionManager.EncryptToken(encryptReq)
	if err != nil {
		return &SecureTokenResponse{
			Success: false,
			Error:   fmt.Sprintf("encryption failed: %v", err),
		}, nil
	}

	// Create multi-signature if signers are provided
	var multiSignatureResp *MultiSignatureResponse
	if len(req.Signers) > 0 {
		// Create signature data (encrypted data + metadata)
		signatureData, err := json.Marshal(map[string]interface{}{
			"encrypted_data": encryptedResp.EncryptedData,
			"nonce":          encryptedResp.Nonce,
			"algorithm":      encryptedResp.Algorithm,
			"key_id":         encryptedResp.KeyID,
			"encrypted_at":   encryptedResp.EncryptedAt,
		})
		if err != nil {
			return &SecureTokenResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to create signature data: %v", err),
			}, nil
		}

		multiSigReq := MultiSignatureRequest{
			Data:     signatureData,
			Signers:  req.Signers,
			Policy:   req.SignaturePolicy,
			Metadata: req.Metadata,
		}

		multiSignatureResp, err = stm.multiSignatureManager.CreateMultiSignature(multiSigReq)
		if err != nil {
			return &SecureTokenResponse{
				Success: false,
				Error:   fmt.Sprintf("multi-signature creation failed: %v", err),
			}, nil
		}
	}

	// Create encrypted token info
	encryptedToken := &EncryptedTokenInfo{
		TokenID:        fmt.Sprintf("secure_%d", time.Now().UnixNano()),
		Encryption:     *encryptedResp,
		MultiSignature: multiSignatureResp,
		Metadata:       req.Metadata,
		CreatedAt:      time.Now(),
		ExpiresAt:      req.ExpiresAt,
	}

	response := &SecureTokenResponse{
		EncryptedToken: encryptedToken,
		Success:        true,
		CreatedAt:      time.Now(),
	}

	return response, nil
}

// VerifySecureToken verifies a secure token
func (stm *SecureTokenManager) VerifySecureToken(req VerifySecureTokenRequest) (*VerifySecureTokenResponse, error) {
	// Validate request
	if req.EncryptedToken == nil {
		return &VerifySecureTokenResponse{
			Valid: false,
			Error: "encrypted token is required",
		}, nil
	}

	// Check token expiration
	if time.Now().After(req.EncryptedToken.ExpiresAt) {
		return &VerifySecureTokenResponse{
			Valid: false,
			Error: "token has expired",
		}, nil
	}

	// Verify multi-signature if present
	var signatureResults *VerifyMultiSignatureResponse
	if req.EncryptedToken.MultiSignature != nil {
		// Create signature data for verification
		signatureData, err := json.Marshal(map[string]interface{}{
			"encrypted_data": req.EncryptedToken.Encryption.EncryptedData,
			"nonce":          req.EncryptedToken.Encryption.Nonce,
			"algorithm":      req.EncryptedToken.Encryption.Algorithm,
			"key_id":         req.EncryptedToken.Encryption.KeyID,
			"encrypted_at":   req.EncryptedToken.Encryption.EncryptedAt,
		})
		if err != nil {
			return &VerifySecureTokenResponse{
				Valid: false,
				Error: fmt.Sprintf("failed to create signature data: %v", err),
			}, nil
		}

		verifySigReq := VerifyMultiSignatureRequest{
			Data:        signatureData,
			Signatures:  req.EncryptedToken.MultiSignature.Signatures,
			Policy:      req.EncryptedToken.MultiSignature.Policy,
			SignatureID: req.EncryptedToken.MultiSignature.SignatureID,
		}

		signatureResults, err = stm.multiSignatureManager.VerifyMultiSignature(verifySigReq)
		if err != nil {
			return &VerifySecureTokenResponse{
				Valid: false,
				Error: fmt.Sprintf("signature verification failed: %v", err),
			}, nil
		}

		if !signatureResults.Valid {
			return &VerifySecureTokenResponse{
				Valid:            false,
				Error:            "signature verification failed",
				SignatureResults: signatureResults,
			}, nil
		}
	}

	// Decrypt token data
	decryptReq := DecryptTokenRequest{
		EncryptedData: req.EncryptedToken.Encryption.EncryptedData,
		Nonce:         req.EncryptedToken.Encryption.Nonce,
		Tag:           req.EncryptedToken.Encryption.Tag,
		Algorithm:     req.EncryptedToken.Encryption.Algorithm,
		KeyID:         req.EncryptedToken.Encryption.KeyID,
		AAD:           req.AAD,
	}

	decryptedResp, err := stm.encryptionManager.DecryptToken(decryptReq)
	if err != nil {
		return &VerifySecureTokenResponse{
			Valid: false,
			Error: fmt.Sprintf("decryption failed: %v", err),
		}, nil
	}

	if !decryptedResp.Success {
		return &VerifySecureTokenResponse{
			Valid: false,
			Error: decryptedResp.Error,
		}, nil
	}

	response := &VerifySecureTokenResponse{
		TokenData:        decryptedResp.TokenData,
		Valid:            true,
		SignatureResults: signatureResults,
		VerifiedAt:       time.Now(),
	}

	return response, nil
}

// GetKeyInfo returns information about all keys
func (stm *SecureTokenManager) GetKeyInfo() map[string]interface{} {
	encryptionKeys := stm.encryptionManager.GetKeyInfo()
	signatureKeys := stm.multiSignatureManager.GetKeyInfo()

	return map[string]interface{}{
		"encryption_keys": encryptionKeys,
		"signature_keys":  signatureKeys,
	}
}

// RotateKeys rotates all keys
func (stm *SecureTokenManager) RotateKeys() error {
	// Rotate encryption keys
	err := stm.encryptionManager.RotateKeys()
	if err != nil {
		return fmt.Errorf("failed to rotate encryption keys: %w", err)
	}

	// Note: Signature keys are typically not rotated automatically
	// as they are tied to specific signers/identities

	return nil
}

// Close cleans up resources
func (stm *SecureTokenManager) Close() error {
	// Close encryption manager
	err := stm.encryptionManager.Close()
	if err != nil {
		return fmt.Errorf("failed to close encryption manager: %w", err)
	}

	// Close multi-signature manager
	err = stm.multiSignatureManager.Close()
	if err != nil {
		return fmt.Errorf("failed to close multi-signature manager: %w", err)
	}

	return nil
}
