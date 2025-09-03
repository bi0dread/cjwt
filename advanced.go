package cjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// GetMetrics returns the current token metrics
func (jm *JWTManager) GetMetrics() TokenMetrics {
	jm.metricsMux.RLock()
	defer jm.metricsMux.RUnlock()
	return *jm.metrics
}

// ResetMetrics resets all metrics to zero
func (jm *JWTManager) ResetMetrics() {
	jm.metricsMux.Lock()
	defer jm.metricsMux.Unlock()
	jm.metrics = &TokenMetrics{LastReset: time.Now()}
}

// GetAuditLogs returns the audit logs
func (jm *JWTManager) GetAuditLogs() []TokenAuditLog {
	jm.logsMux.RLock()
	defer jm.logsMux.RUnlock()

	// Return a copy to prevent external modification
	logs := make([]TokenAuditLog, len(jm.auditLogs))
	copy(logs, jm.auditLogs)
	return logs
}

// ClearAuditLogs clears all audit logs
func (jm *JWTManager) ClearAuditLogs() {
	jm.logsMux.Lock()
	defer jm.logsMux.Unlock()
	jm.auditLogs = make([]TokenAuditLog, 0)
}

// RotateKey rotates the current signing key
func (jm *JWTManager) RotateKey(req KeyRotationRequest) *KeyRotationResponse {
	jm.keyManager.mutex.Lock()
	defer jm.keyManager.mutex.Unlock()

	oldKeyID := jm.keyManager.currentKeyID
	newKeyID := req.NewKeyID
	if newKeyID == "" {
		newKeyID = uuid.New().String()
	}

	// Generate new key based on algorithm
	var newKey interface{}
	var err error

	switch req.Algorithm {
	case RS256:
		newKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return &KeyRotationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to generate RSA key: %v", err),
			}
		}
	case ES256:
		newKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return &KeyRotationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to generate ECDSA key: %v", err),
			}
		}
	case HS256:
		newKey = make([]byte, 32)
		_, err = rand.Read(newKey.([]byte))
		if err != nil {
			return &KeyRotationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to generate HMAC key: %v", err),
			}
		}
	default:
		return &KeyRotationResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported algorithm: %s", req.Algorithm),
		}
	}

	// Store new key
	jm.keyManager.keys[newKeyID] = newKey
	jm.keyManager.currentKeyID = newKeyID

	// Update key history
	jm.keyManager.keyHistory[newKeyID] = KeyInfo{
		KeyID:     newKeyID,
		Algorithm: string(req.Algorithm),
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	// Mark old key as inactive
	if oldKeyInfo, exists := jm.keyManager.keyHistory[oldKeyID]; exists {
		oldKeyInfo.IsActive = false
		jm.keyManager.keyHistory[oldKeyID] = oldKeyInfo
	}

	// Set grace period
	jm.keyManager.gracePeriod = req.GracePeriod

	return &KeyRotationResponse{
		Success:     true,
		NewKeyID:    newKeyID,
		OldKeyID:    oldKeyID,
		RotatedAt:   time.Now(),
		GracePeriod: req.GracePeriod,
	}
}

// GetKeyInfo returns information about the current key
func (jm *JWTManager) GetKeyInfo() KeyInfo {
	jm.keyManager.mutex.RLock()
	defer jm.keyManager.mutex.RUnlock()

	keyID := jm.keyManager.currentKeyID
	if info, exists := jm.keyManager.keyHistory[keyID]; exists {
		return info
	}

	return KeyInfo{}
}

// ChunkToken splits a large token into smaller chunks
func (jm *JWTManager) ChunkToken(req TokenChunkRequest) *TokenChunkResponse {
	if req.MaxChunkSize <= 0 {
		req.MaxChunkSize = 1000 // Default chunk size
	}

	if req.ChunkID == "" {
		req.ChunkID = uuid.New().String()
	}

	tokenBytes := []byte(req.Token)
	originalSize := len(tokenBytes)

	var chunks []string
	for i := 0; i < len(tokenBytes); i += req.MaxChunkSize {
		end := i + req.MaxChunkSize
		if end > len(tokenBytes) {
			end = len(tokenBytes)
		}
		chunk := string(tokenBytes[i:end])
		chunks = append(chunks, chunk)
	}

	return &TokenChunkResponse{
		Chunks:       chunks,
		ChunkID:      req.ChunkID,
		TotalChunks:  len(chunks),
		OriginalSize: originalSize,
	}
}

// ReassembleToken reassembles token chunks back into the original token
func (jm *JWTManager) ReassembleToken(req TokenReassembleRequest) *TokenReassembleResponse {
	if len(req.Chunks) == 0 {
		return &TokenReassembleResponse{
			Success: false,
			Error:   "no chunks provided",
		}
	}

	var tokenBytes []byte
	for _, chunk := range req.Chunks {
		tokenBytes = append(tokenBytes, []byte(chunk)...)
	}

	token := string(tokenBytes)

	return &TokenReassembleResponse{
		Token:           token,
		Success:         true,
		ReassembledSize: len(tokenBytes),
	}
}
