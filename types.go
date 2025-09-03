package cjwt

import "time"

// JWTRequest represents the request to generate a JWT token
type JWTRequest struct {
	// Standard JWT Claims
	Issuer    string     `json:"iss"`           // Issuer - who issued the token
	Subject   string     `json:"sub"`           // Subject - who the token is about
	Audience  []string   `json:"aud"`           // Audience - who the token is intended for
	ExpiresAt time.Time  `json:"exp"`           // Expiration time
	NotBefore *time.Time `json:"nbf,omitempty"` // Not before time (optional)
	IssuedAt  *time.Time `json:"iat,omitempty"` // Issued at time (optional)
	JWTID     string     `json:"jti,omitempty"` // JWT ID (optional, auto-generated if empty)

	// Custom Claims - additional data you want to include
	CustomClaims map[string]interface{} `json:"custom_claims,omitempty"`
}

// JWTResponse represents the response after generating a JWT token
type JWTResponse struct {
	Token     string                 `json:"token"`      // The generated JWT token
	Claims    map[string]interface{} `json:"claims"`     // All claims in the token
	ExpiresAt time.Time              `json:"expires_at"` // When the token expires
	IssuedAt  time.Time              `json:"issued_at"`  // When the token was issued
	JWTID     string                 `json:"jwt_id"`     // Unique JWT ID
}

// VerifyRequest represents the request to verify a JWT token
type VerifyRequest struct {
	Token string `json:"token"` // The JWT token to verify
}

// VerifyResponse represents the response after verifying a JWT token
type VerifyResponse struct {
	Valid        bool                   `json:"valid"`           // Whether the token is valid
	Claims       map[string]interface{} `json:"claims"`          // Claims from the token
	ExpiresAt    *time.Time             `json:"expires_at"`      // When the token expires
	IssuedAt     *time.Time             `json:"issued_at"`       // When the token was issued
	Subject      string                 `json:"subject"`         // Subject claim
	Audience     []string               `json:"audience"`        // Audience claims
	Issuer       string                 `json:"issuer"`          // Issuer claim
	JWTID        string                 `json:"jwt_id"`          // JWT ID
	CustomClaims map[string]interface{} `json:"custom_claims"`   // Custom claims
	Error        string                 `json:"error,omitempty"` // Error message if invalid
}

// ParseRequest represents the request to parse a JWT token without verification
type ParseRequest struct {
	Token string `json:"token"` // The JWT token to parse
}

// ParseResponse represents the response after parsing a JWT token
type ParseResponse struct {
	Valid        bool                   `json:"valid"`           // Whether the token format is valid
	Claims       map[string]interface{} `json:"claims"`          // Claims from the token
	ExpiresAt    *time.Time             `json:"expires_at"`      // When the token expires
	IssuedAt     *time.Time             `json:"issued_at"`       // When the token was issued
	Subject      string                 `json:"subject"`         // Subject claim
	Audience     []string               `json:"audience"`        // Audience claims
	Issuer       string                 `json:"issuer"`          // Issuer claim
	JWTID        string                 `json:"jwt_id"`          // JWT ID
	CustomClaims map[string]interface{} `json:"custom_claims"`   // Custom claims
	Error        string                 `json:"error,omitempty"` // Error message if parsing failed
}

// SigningMethod represents the JWT signing algorithm
type SigningMethod string

const (
	RS256 SigningMethod = "RS256" // RSA with SHA-256
	ES256 SigningMethod = "ES256" // ECDSA with SHA-256
	HS256 SigningMethod = "HS256" // HMAC with SHA-256
)

// TokenMetrics tracks JWT operation statistics
type TokenMetrics struct {
	GeneratedTokens     int64     `json:"generated_tokens"`
	VerifiedTokens      int64     `json:"verified_tokens"`
	FailedVerifications int64     `json:"failed_verifications"`
	ExpiredTokens       int64     `json:"expired_tokens"`
	RevokedTokens       int64     `json:"revoked_tokens"`
	LastReset           time.Time `json:"last_reset"`
}

// TokenAuditLog represents an audit log entry for JWT operations
type TokenAuditLog struct {
	Timestamp time.Time              `json:"timestamp"`
	Action    string                 `json:"action"` // "generate", "verify", "revoke", "parse"
	UserID    string                 `json:"user_id"`
	TokenID   string                 `json:"token_id"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Success   bool                   `json:"success"`
	ErrorMsg  string                 `json:"error_msg,omitempty"`
	Claims    map[string]interface{} `json:"claims,omitempty"`
}

// KeyInfo represents information about a cryptographic key
type KeyInfo struct {
	KeyID     string     `json:"key_id"`
	Algorithm string     `json:"algorithm"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	IsActive  bool       `json:"is_active"`
}

// KeyRotationRequest represents a request to rotate keys
type KeyRotationRequest struct {
	NewKeyID    string        `json:"new_key_id"`
	Algorithm   SigningMethod `json:"algorithm"`
	GracePeriod time.Duration `json:"grace_period"` // How long old keys remain valid
}

// KeyRotationResponse represents the response after key rotation
type KeyRotationResponse struct {
	Success     bool          `json:"success"`
	NewKeyID    string        `json:"new_key_id"`
	OldKeyID    string        `json:"old_key_id"`
	RotatedAt   time.Time     `json:"rotated_at"`
	GracePeriod time.Duration `json:"grace_period"`
	Error       string        `json:"error,omitempty"`
}

// TokenChunkRequest represents a request to chunk a large token
type TokenChunkRequest struct {
	Token        string `json:"token"`
	MaxChunkSize int    `json:"max_chunk_size"` // Maximum size per chunk
	ChunkID      string `json:"chunk_id"`       // Unique identifier for this chunking operation
}

// TokenChunkResponse represents the response after chunking a token
type TokenChunkResponse struct {
	Chunks       []string `json:"chunks"`
	ChunkID      string   `json:"chunk_id"`
	TotalChunks  int      `json:"total_chunks"`
	OriginalSize int      `json:"original_size"`
}

// TokenReassembleRequest represents a request to reassemble token chunks
type TokenReassembleRequest struct {
	Chunks  []string `json:"chunks"`
	ChunkID string   `json:"chunk_id"`
}

// TokenReassembleResponse represents the response after reassembling token chunks
type TokenReassembleResponse struct {
	Token           string `json:"token"`
	Success         bool   `json:"success"`
	Error           string `json:"error,omitempty"`
	ReassembledSize int    `json:"reassembled_size"`
}
