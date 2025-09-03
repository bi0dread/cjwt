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
