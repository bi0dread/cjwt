package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// EncryptionManager manages token encryption and decryption
type EncryptionManager struct {
	// Key management
	keys map[string]*EncryptionKey

	// Configuration
	config *KeyManagerConfig

	// Default algorithm
	defaultAlgorithm EncryptionAlgorithm
}

// NewEncryptionManager creates a new encryption manager
func NewEncryptionManager(config *KeyManagerConfig) (*EncryptionManager, error) {
	if config == nil {
		config = &KeyManagerConfig{
			DefaultEncryptionAlgorithm: AES256GCM,
			DefaultSignatureAlgorithm:  RS256,
			KeyRotationInterval:        24 * time.Hour,
			MaxKeyAge:                  7 * 24 * time.Hour,
		}
	}

	em := &EncryptionManager{
		keys:             make(map[string]*EncryptionKey),
		config:           config,
		defaultAlgorithm: config.DefaultEncryptionAlgorithm,
	}

	// Generate initial key
	err := em.generateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate initial key: %w", err)
	}

	return em, nil
}

// EncryptToken encrypts token data
func (em *EncryptionManager) EncryptToken(req EncryptedTokenRequest) (*EncryptedTokenResponse, error) {
	// Use default algorithm if not specified
	if req.Algorithm == "" {
		req.Algorithm = em.defaultAlgorithm
	}

	// Get or create encryption key
	key, err := em.getOrCreateKey(req.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Encrypt the data
	encryptedData, nonce, tag, err := em.encryptData(req.TokenData, key.Key, req.Algorithm, req.AAD)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	response := &EncryptedTokenResponse{
		EncryptedData: encryptedData,
		Nonce:         nonce,
		Tag:           tag,
		Algorithm:     req.Algorithm,
		KeyID:         key.ID,
		EncryptedAt:   time.Now(),
	}

	return response, nil
}

// DecryptToken decrypts token data
func (em *EncryptionManager) DecryptToken(req DecryptTokenRequest) (*DecryptTokenResponse, error) {
	// Get encryption key
	key, exists := em.keys[req.KeyID]
	if !exists {
		return &DecryptTokenResponse{
			Success: false,
			Error:   "encryption key not found",
		}, nil
	}

	// Decrypt the data
	tokenData, err := em.decryptData(req.EncryptedData, key.Key, req.Algorithm, req.Nonce, req.Tag, req.AAD)
	if err != nil {
		return &DecryptTokenResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to decrypt data: %v", err),
		}, nil
	}

	response := &DecryptTokenResponse{
		TokenData:   tokenData,
		Success:     true,
		DecryptedAt: time.Now(),
	}

	return response, nil
}

// encryptData performs the actual encryption
func (em *EncryptionManager) encryptData(data []byte, key []byte, algorithm EncryptionAlgorithm, aad []byte) ([]byte, []byte, []byte, error) {
	switch algorithm {
	case AES256GCM:
		return em.encryptAES256GCM(data, key, aad)
	case ChaCha20Poly1305:
		return em.encryptChaCha20Poly1305(data, key, aad)
	case AES256CBC:
		return em.encryptAES256CBC(data, key)
	default:
		return nil, nil, nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}
}

// decryptData performs the actual decryption
func (em *EncryptionManager) decryptData(encryptedData []byte, key []byte, algorithm EncryptionAlgorithm, nonce []byte, tag []byte, aad []byte) ([]byte, error) {
	switch algorithm {
	case AES256GCM:
		return em.decryptAES256GCM(encryptedData, key, nonce, tag, aad)
	case ChaCha20Poly1305:
		return em.decryptChaCha20Poly1305(encryptedData, key, nonce, tag, aad)
	case AES256CBC:
		return em.decryptAES256CBC(encryptedData, key, nonce)
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}
}

// encryptAES256GCM encrypts data using AES-256-GCM
func (em *EncryptionManager) encryptAES256GCM(data []byte, key []byte, aad []byte) ([]byte, []byte, []byte, error) {
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, data, aad)

	// Split ciphertext and tag
	tag := ciphertext[len(ciphertext)-gcm.Overhead():]
	encryptedData := ciphertext[:len(ciphertext)-gcm.Overhead()]

	return encryptedData, nonce, tag, nil
}

// decryptAES256GCM decrypts data using AES-256-GCM
func (em *EncryptionManager) decryptAES256GCM(encryptedData []byte, key []byte, nonce []byte, tag []byte, aad []byte) ([]byte, error) {
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Combine encrypted data and tag
	ciphertext := append(encryptedData, tag...)

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// encryptChaCha20Poly1305 encrypts data using ChaCha20-Poly1305
func (em *EncryptionManager) encryptChaCha20Poly1305(data []byte, key []byte, aad []byte) ([]byte, []byte, []byte, error) {
	// Create cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, data, aad)

	// Split ciphertext and tag
	tag := ciphertext[len(ciphertext)-aead.Overhead():]
	encryptedData := ciphertext[:len(ciphertext)-aead.Overhead()]

	return encryptedData, nonce, tag, nil
}

// decryptChaCha20Poly1305 decrypts data using ChaCha20-Poly1305
func (em *EncryptionManager) decryptChaCha20Poly1305(encryptedData []byte, key []byte, nonce []byte, tag []byte, aad []byte) ([]byte, error) {
	// Create cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Combine encrypted data and tag
	ciphertext := append(encryptedData, tag...)

	// Decrypt
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// encryptAES256CBC encrypts data using AES-256-CBC
func (em *EncryptionManager) encryptAES256CBC(data []byte, key []byte) ([]byte, []byte, []byte, error) {
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, err
	}

	// Pad data
	paddedData := em.pkcs7Pad(data, aes.BlockSize)

	// Encrypt
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext, iv, nil, nil
}

// decryptAES256CBC decrypts data using AES-256-CBC
func (em *EncryptionManager) decryptAES256CBC(encryptedData []byte, key []byte, iv []byte) ([]byte, error) {
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext := make([]byte, len(encryptedData))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, encryptedData)

	// Remove padding
	unpaddedData, err := em.pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return unpaddedData, nil
}

// pkcs7Pad adds PKCS7 padding
func (em *EncryptionManager) pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// pkcs7Unpad removes PKCS7 padding
func (em *EncryptionManager) pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	padding := int(data[len(data)-1])
	if padding > blockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	// Check padding
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}

// generateKey generates a new encryption key
func (em *EncryptionManager) generateKey() error {
	keyID := uuid.New().String()

	// Generate key based on algorithm
	var key []byte
	var err error

	switch em.defaultAlgorithm {
	case AES256GCM, AES256CBC:
		key = make([]byte, 32) // 256 bits
		_, err = rand.Read(key)
	case ChaCha20Poly1305:
		key = make([]byte, 32) // 256 bits
		_, err = rand.Read(key)
	default:
		return fmt.Errorf("unsupported algorithm for key generation: %s", em.defaultAlgorithm)
	}

	if err != nil {
		return err
	}

	// Store key
	encryptionKey := &EncryptionKey{
		ID:        keyID,
		Key:       key,
		Algorithm: em.defaultAlgorithm,
		Version:   1,
		CreatedAt: time.Now(),
	}

	em.keys[keyID] = encryptionKey

	return nil
}

// getOrCreateKey gets an existing key or creates a new one
func (em *EncryptionManager) getOrCreateKey(algorithm EncryptionAlgorithm) (*EncryptionKey, error) {
	// Find existing key for algorithm
	for _, key := range em.keys {
		if key.Algorithm == algorithm && !em.isKeyExpired(key) {
			return key, nil
		}
	}

	// Create new key
	keyID := uuid.New().String()

	// Generate key based on algorithm
	var key []byte
	var err error

	switch algorithm {
	case AES256GCM, AES256CBC:
		key = make([]byte, 32) // 256 bits
		_, err = rand.Read(key)
	case ChaCha20Poly1305:
		key = make([]byte, 32) // 256 bits
		_, err = rand.Read(key)
	default:
		return nil, fmt.Errorf("unsupported algorithm for key generation: %s", algorithm)
	}

	if err != nil {
		return nil, err
	}

	// Store key
	encryptionKey := &EncryptionKey{
		ID:        keyID,
		Key:       key,
		Algorithm: algorithm,
		Version:   1,
		CreatedAt: time.Now(),
	}

	em.keys[keyID] = encryptionKey

	return encryptionKey, nil
}

// isKeyExpired checks if a key is expired
func (em *EncryptionManager) isKeyExpired(key *EncryptionKey) bool {
	if key.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*key.ExpiresAt)
}

// deriveKey derives a key from a password using PBKDF2
func (em *EncryptionManager) deriveKey(password []byte, salt []byte, iterations int) []byte {
	return pbkdf2.Key(password, salt, iterations, 32, sha256.New)
}

// GetKeyInfo returns information about all keys
func (em *EncryptionManager) GetKeyInfo() map[string]interface{} {
	keyInfo := make(map[string]interface{})

	for id, key := range em.keys {
		keyInfo[id] = map[string]interface{}{
			"algorithm":  key.Algorithm,
			"version":    key.Version,
			"created_at": key.CreatedAt,
			"expires_at": key.ExpiresAt,
			"is_expired": em.isKeyExpired(key),
		}
	}

	return keyInfo
}

// RotateKeys rotates all encryption keys
func (em *EncryptionManager) RotateKeys() error {
	// Generate new keys for all algorithms
	algorithms := []EncryptionAlgorithm{AES256GCM, ChaCha20Poly1305, AES256CBC}

	for _, algorithm := range algorithms {
		_, err := em.getOrCreateKey(algorithm)
		if err != nil {
			return fmt.Errorf("failed to rotate key for algorithm %s: %w", algorithm, err)
		}
	}

	return nil
}

// Close cleans up resources
func (em *EncryptionManager) Close() error {
	// Clear all keys from memory
	for id := range em.keys {
		delete(em.keys, id)
	}

	return nil
}
