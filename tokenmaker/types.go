package tokenmaker

import (
	"time"

	"github.com/bi0dread/cjwt/opaque"
)

// TokenType represents the type of token to generate
type TokenType string

const (
	JWT    TokenType = "jwt"    // JSON Web Token
	Opaque TokenType = "opaque" // Opaque token
)

// SigningMethod represents the signing method for JWT tokens
type SigningMethod string

const (
	RS256 SigningMethod = "RS256" // RSA with SHA-256
	ES256 SigningMethod = "ES256" // ECDSA with SHA-256
	HS256 SigningMethod = "HS256" // HMAC with SHA-256
)

// TokenRequest represents a unified request for token generation
type TokenRequest struct {
	// Token type
	Type TokenType `json:"type"`

	// Common fields for all token types
	UserID     string                 `json:"user_id"`
	ClientID   string                 `json:"client_id,omitempty"`
	Scope      []string               `json:"scope,omitempty"`
	ExpiresAt  time.Time              `json:"expires_at"`
	IssuedAt   *time.Time             `json:"issued_at,omitempty"`
	NotBefore  *time.Time             `json:"not_before,omitempty"`
	CustomData map[string]interface{} `json:"custom_data,omitempty"`

	// JWT-specific fields
	JWTConfig *JWTConfig `json:"jwt_config,omitempty"`

	// Opaque-specific fields
	OpaqueConfig *OpaqueConfig `json:"opaque_config,omitempty"`
}

// JWTConfig contains JWT-specific configuration
type JWTConfig struct {
	Issuer        string                 `json:"issuer"`
	Subject       string                 `json:"subject"`
	Audience      []string               `json:"audience,omitempty"`
	SigningMethod SigningMethod          `json:"signing_method,omitempty"`
	CustomClaims  map[string]interface{} `json:"custom_claims,omitempty"`
}

// OpaqueConfig contains opaque token-specific configuration
type OpaqueConfig struct {
	TokenLength int    `json:"token_length,omitempty"`
	TokenPrefix string `json:"token_prefix,omitempty"`
}

// TokenResponse represents a unified response for token generation
type TokenResponse struct {
	// Common fields
	Type       TokenType              `json:"type"`
	Token      string                 `json:"token"`
	TokenID    string                 `json:"token_id"`
	UserID     string                 `json:"user_id"`
	ClientID   string                 `json:"client_id"`
	Scope      []string               `json:"scope"`
	ExpiresAt  time.Time              `json:"expires_at"`
	IssuedAt   time.Time              `json:"issued_at"`
	CustomData map[string]interface{} `json:"custom_data"`

	// JWT-specific fields
	JWTClaims map[string]interface{} `json:"jwt_claims,omitempty"`

	// Opaque-specific fields
	OpaqueInfo *opaque.OpaqueTokenInfo `json:"opaque_info,omitempty"`
}

// ValidateRequest represents a unified request for token validation
type ValidateRequest struct {
	Type  TokenType `json:"type"`
	Token string    `json:"token"`
}

// ValidateResponse represents a unified response for token validation
type ValidateResponse struct {
	Type       TokenType              `json:"type"`
	Valid      bool                   `json:"valid"`
	UserID     string                 `json:"user_id,omitempty"`
	ClientID   string                 `json:"client_id,omitempty"`
	Scope      []string               `json:"scope,omitempty"`
	ExpiresAt  *time.Time             `json:"expires_at,omitempty"`
	IssuedAt   *time.Time             `json:"issued_at,omitempty"`
	CustomData map[string]interface{} `json:"custom_data,omitempty"`
	Error      string                 `json:"error,omitempty"`

	// JWT-specific fields
	JWTClaims map[string]interface{} `json:"jwt_claims,omitempty"`

	// Opaque-specific fields
	OpaqueInfo *opaque.OpaqueTokenInfo `json:"opaque_info,omitempty"`
}

// RevokeRequest represents a unified request for token revocation
type RevokeRequest struct {
	Type  TokenType `json:"type"`
	Token string    `json:"token"`
}

// RevokeResponse represents a unified response for token revocation
type RevokeResponse struct {
	Type    TokenType `json:"type"`
	Success bool      `json:"success"`
	Error   string    `json:"error,omitempty"`
}

// TokenMakerConfig represents configuration for the token maker
type TokenMakerConfig struct {
	// JWT configuration
	JWTPrivateKey           interface{}   `json:"-"` // *rsa.PrivateKey, *ecdsa.PrivateKey, or []byte for HMAC
	JWTPublicKey            interface{}   `json:"-"` // *rsa.PublicKey, *ecdsa.PublicKey, or nil for HMAC
	DefaultJWTSigningMethod SigningMethod `json:"default_jwt_signing_method,omitempty"`

	// Opaque token configuration
	DefaultOpaqueTokenLength int    `json:"default_opaque_token_length,omitempty"`
	DefaultOpaqueTokenPrefix string `json:"default_opaque_token_prefix,omitempty"`
}
