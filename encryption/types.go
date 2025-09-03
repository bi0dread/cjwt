package encryption

import (
	"time"
)

// EncryptionAlgorithm represents supported encryption algorithms
type EncryptionAlgorithm string

const (
	AES256GCM        EncryptionAlgorithm = "AES-256-GCM"
	ChaCha20Poly1305 EncryptionAlgorithm = "ChaCha20-Poly1305"
	AES256CBC        EncryptionAlgorithm = "AES-256-CBC"
)

// SignatureAlgorithm represents supported signature algorithms
type SignatureAlgorithm string

const (
	RS256   SignatureAlgorithm = "RS256"
	ES256   SignatureAlgorithm = "ES256"
	HS256   SignatureAlgorithm = "HS256"
	Ed25519 SignatureAlgorithm = "Ed25519"
)

// EncryptedTokenRequest represents a request to encrypt token data
type EncryptedTokenRequest struct {
	// Token data to encrypt
	TokenData []byte `json:"token_data"`

	// Encryption algorithm
	Algorithm EncryptionAlgorithm `json:"algorithm"`

	// Additional authenticated data (optional)
	AAD []byte `json:"aad,omitempty"`

	// Key derivation parameters
	KeyDerivation KeyDerivationParams `json:"key_derivation,omitempty"`
}

// EncryptedTokenResponse represents the response after encryption
type EncryptedTokenResponse struct {
	// Encrypted data
	EncryptedData []byte `json:"encrypted_data"`

	// Nonce/IV used for encryption
	Nonce []byte `json:"nonce"`

	// Authentication tag
	Tag []byte `json:"tag,omitempty"`

	// Algorithm used
	Algorithm EncryptionAlgorithm `json:"algorithm"`

	// Key ID for key management
	KeyID string `json:"key_id"`

	// Timestamp when encrypted
	EncryptedAt time.Time `json:"encrypted_at"`
}

// DecryptTokenRequest represents a request to decrypt token data
type DecryptTokenRequest struct {
	// Encrypted data
	EncryptedData []byte `json:"encrypted_data"`

	// Nonce/IV used for encryption
	Nonce []byte `json:"nonce"`

	// Authentication tag
	Tag []byte `json:"tag,omitempty"`

	// Algorithm used
	Algorithm EncryptionAlgorithm `json:"algorithm"`

	// Key ID for key management
	KeyID string `json:"key_id"`

	// Additional authenticated data (optional)
	AAD []byte `json:"aad,omitempty"`
}

// DecryptTokenResponse represents the response after decryption
type DecryptTokenResponse struct {
	// Decrypted token data
	TokenData []byte `json:"token_data"`

	// Success flag
	Success bool `json:"success"`

	// Error message if decryption failed
	Error string `json:"error,omitempty"`

	// Timestamp when decrypted
	DecryptedAt time.Time `json:"decrypted_at"`
}

// KeyDerivationParams represents parameters for key derivation
type KeyDerivationParams struct {
	// Salt for key derivation
	Salt []byte `json:"salt"`

	// Iterations for PBKDF2
	Iterations int `json:"iterations,omitempty"`

	// Memory for Argon2
	Memory uint32 `json:"memory,omitempty"`

	// Time for Argon2
	Time uint32 `json:"time,omitempty"`

	// Threads for Argon2
	Threads uint8 `json:"threads,omitempty"`
}

// MultiSignatureRequest represents a request to create multi-signature
type MultiSignatureRequest struct {
	// Data to sign
	Data []byte `json:"data"`

	// List of signers
	Signers []Signer `json:"signers"`

	// Signature policy
	Policy SignaturePolicy `json:"policy"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// MultiSignatureResponse represents the response after multi-signature creation
type MultiSignatureResponse struct {
	// Signatures from all signers
	Signatures []Signature `json:"signatures"`

	// Combined signature (if applicable)
	CombinedSignature []byte `json:"combined_signature,omitempty"`

	// Signature policy used
	Policy SignaturePolicy `json:"policy"`

	// Timestamp when signed
	SignedAt time.Time `json:"signed_at"`

	// Signature ID for reference
	SignatureID string `json:"signature_id"`
}

// VerifyMultiSignatureRequest represents a request to verify multi-signature
type VerifyMultiSignatureRequest struct {
	// Original data
	Data []byte `json:"data"`

	// Signatures to verify
	Signatures []Signature `json:"signatures"`

	// Signature policy
	Policy SignaturePolicy `json:"policy"`

	// Signature ID
	SignatureID string `json:"signature_id"`
}

// VerifyMultiSignatureResponse represents the response after verification
type VerifyMultiSignatureResponse struct {
	// Verification result
	Valid bool `json:"valid"`

	// Error message if verification failed
	Error string `json:"error,omitempty"`

	// Individual signature results
	SignatureResults []SignatureResult `json:"signature_results"`

	// Policy compliance
	PolicyCompliant bool `json:"policy_compliant"`

	// Timestamp when verified
	VerifiedAt time.Time `json:"verified_at"`
}

// Signer represents a signer in multi-signature
type Signer struct {
	// Signer ID
	ID string `json:"id"`

	// Public key for verification
	PublicKey interface{} `json:"public_key"`

	// Signature algorithm
	Algorithm SignatureAlgorithm `json:"algorithm"`

	// Signer role/type
	Role string `json:"role,omitempty"`

	// Priority/weight for weighted signatures
	Weight int `json:"weight,omitempty"`
}

// Signature represents a single signature
type Signature struct {
	// Signer ID
	SignerID string `json:"signer_id"`

	// Signature data
	SignatureData []byte `json:"signature_data"`

	// Signature algorithm
	Algorithm SignatureAlgorithm `json:"algorithm"`

	// Timestamp when signed
	SignedAt time.Time `json:"signed_at"`

	// Signature metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// SignatureResult represents the result of verifying a single signature
type SignatureResult struct {
	// Signer ID
	SignerID string `json:"signer_id"`

	// Verification result
	Valid bool `json:"valid"`

	// Error message if verification failed
	Error string `json:"error,omitempty"`

	// Signature algorithm
	Algorithm SignatureAlgorithm `json:"algorithm"`
}

// SignaturePolicy represents the policy for multi-signature
type SignaturePolicy struct {
	// Policy type
	Type SignaturePolicyType `json:"type"`

	// Required number of signatures
	RequiredSignatures int `json:"required_signatures"`

	// Required signer roles
	RequiredRoles []string `json:"required_roles,omitempty"`

	// Minimum weight for weighted signatures
	MinimumWeight int `json:"minimum_weight,omitempty"`

	// Time window for signature collection
	TimeWindow time.Duration `json:"time_window,omitempty"`

	// Allow duplicate signers
	AllowDuplicates bool `json:"allow_duplicates"`
}

// SignaturePolicyType represents the type of signature policy
type SignaturePolicyType string

const (
	// ThresholdPolicy requires a minimum number of signatures
	ThresholdPolicy SignaturePolicyType = "threshold"

	// RoleBasedPolicy requires specific roles to sign
	RoleBasedPolicy SignaturePolicyType = "role_based"

	// WeightedPolicy uses weighted signatures
	WeightedPolicy SignaturePolicyType = "weighted"

	// AllSignersPolicy requires all signers to sign
	AllSignersPolicy SignaturePolicyType = "all_signers"
)

// EncryptionKey represents an encryption key
type EncryptionKey struct {
	// Key ID
	ID string `json:"id"`

	// Key material
	Key []byte `json:"key"`

	// Algorithm
	Algorithm EncryptionAlgorithm `json:"algorithm"`

	// Key version
	Version int `json:"version"`

	// Created timestamp
	CreatedAt time.Time `json:"created_at"`

	// Expiration timestamp
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Key metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// SignatureKey represents a signature key
type SignatureKey struct {
	// Key ID
	ID string `json:"id"`

	// Private key (for signing)
	PrivateKey interface{} `json:"private_key"`

	// Public key (for verification)
	PublicKey interface{} `json:"public_key"`

	// Algorithm
	Algorithm SignatureAlgorithm `json:"algorithm"`

	// Key version
	Version int `json:"version"`

	// Created timestamp
	CreatedAt time.Time `json:"created_at"`

	// Expiration timestamp
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Key metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// KeyManagerConfig represents configuration for key management
type KeyManagerConfig struct {
	// Default encryption algorithm
	DefaultEncryptionAlgorithm EncryptionAlgorithm `json:"default_encryption_algorithm"`

	// Default signature algorithm
	DefaultSignatureAlgorithm SignatureAlgorithm `json:"default_signature_algorithm"`

	// Key rotation interval
	KeyRotationInterval time.Duration `json:"key_rotation_interval"`

	// Maximum key age
	MaxKeyAge time.Duration `json:"max_key_age"`

	// Key storage configuration
	KeyStorage KeyStorageConfig `json:"key_storage"`
}

// KeyStorageConfig represents configuration for key storage
type KeyStorageConfig struct {
	// Storage type
	Type string `json:"type"` // "memory", "file", "database", "hsm"

	// Storage path (for file storage)
	Path string `json:"path,omitempty"`

	// Database configuration (for database storage)
	Database DatabaseConfig `json:"database,omitempty"`

	// HSM configuration (for HSM storage)
	HSM HSMConfig `json:"hsm,omitempty"`
}

// DatabaseConfig represents database configuration for key storage
type DatabaseConfig struct {
	// Database type
	Type string `json:"type"` // "mysql", "postgresql"

	// Connection parameters
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`

	// Table name
	TableName string `json:"table_name"`
}

// HSMConfig represents HSM configuration
type HSMConfig struct {
	// HSM type
	Type string `json:"type"` // "pkcs11", "azure", "aws"

	// HSM-specific configuration
	Config map[string]interface{} `json:"config"`
}

// EncryptedTokenInfo represents information about an encrypted token
type EncryptedTokenInfo struct {
	// Token ID
	TokenID string `json:"token_id"`

	// Encryption details
	Encryption EncryptedTokenResponse `json:"encryption"`

	// Multi-signature details
	MultiSignature *MultiSignatureResponse `json:"multi_signature,omitempty"`

	// Token metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Created timestamp
	CreatedAt time.Time `json:"created_at"`

	// Expiration timestamp
	ExpiresAt time.Time `json:"expires_at"`
}
