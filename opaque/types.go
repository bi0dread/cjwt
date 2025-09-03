package opaque

import "time"

// OpaqueTokenRequest represents the request to generate an opaque token
type OpaqueTokenRequest struct {
	// Token metadata
	UserID    string     `json:"user_id"`
	ClientID  string     `json:"client_id,omitempty"`
	Scope     []string   `json:"scope,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	IssuedAt  *time.Time `json:"issued_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`

	// Custom data to store with the token
	CustomData map[string]interface{} `json:"custom_data,omitempty"`

	// Token configuration
	TokenLength int    `json:"token_length,omitempty"` // Length of the opaque token (default: 32)
	TokenPrefix string `json:"token_prefix,omitempty"` // Prefix for the token (e.g., "op_")
}

// OpaqueTokenResponse represents the response after generating an opaque token
type OpaqueTokenResponse struct {
	Token      string                 `json:"token"`       // The generated opaque token
	TokenID    string                 `json:"token_id"`    // Unique token identifier
	ExpiresAt  time.Time              `json:"expires_at"`  // When the token expires
	IssuedAt   time.Time              `json:"issued_at"`   // When the token was issued
	UserID     string                 `json:"user_id"`     // User ID associated with the token
	ClientID   string                 `json:"client_id"`   // Client ID associated with the token
	Scope      []string               `json:"scope"`       // Token scope
	CustomData map[string]interface{} `json:"custom_data"` // Custom data stored with the token
}

// OpaqueTokenInfo represents information about an opaque token
type OpaqueTokenInfo struct {
	TokenID    string                 `json:"token_id"`
	UserID     string                 `json:"user_id"`
	ClientID   string                 `json:"client_id"`
	Scope      []string               `json:"scope"`
	ExpiresAt  time.Time              `json:"expires_at"`
	IssuedAt   time.Time              `json:"issued_at"`
	NotBefore  *time.Time             `json:"not_before,omitempty"`
	CustomData map[string]interface{} `json:"custom_data"`
	IsActive   bool                   `json:"is_active"`
	CreatedAt  time.Time              `json:"created_at"`
}

// ValidateRequest represents a request to validate an opaque token
type ValidateRequest struct {
	Token string `json:"token"` // The opaque token to validate
}

// ValidateResponse represents the response after validating an opaque token
type ValidateResponse struct {
	Valid     bool             `json:"valid"`           // Whether the token is valid
	TokenInfo *OpaqueTokenInfo `json:"token_info"`      // Token information if valid
	Error     string           `json:"error,omitempty"` // Error message if invalid
}

// RevokeRequest represents a request to revoke an opaque token
type RevokeRequest struct {
	Token string `json:"token"` // The opaque token to revoke
}

// RevokeResponse represents the response after revoking an opaque token
type RevokeResponse struct {
	Success bool   `json:"success"`         // Whether the revocation was successful
	Error   string `json:"error,omitempty"` // Error message if revocation failed
}

// ListTokensRequest represents a request to list tokens for a user
type ListTokensRequest struct {
	UserID   string `json:"user_id"`             // User ID to list tokens for
	ClientID string `json:"client_id,omitempty"` // Optional client ID filter
	Active   *bool  `json:"active,omitempty"`    // Optional active status filter
}

// ListTokensResponse represents the response after listing tokens
type ListTokensResponse struct {
	Tokens []OpaqueTokenInfo `json:"tokens"` // List of tokens
	Count  int               `json:"count"`  // Total number of tokens
}
