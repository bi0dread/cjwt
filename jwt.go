package cjwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTManager handles JWT operations
type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewJWTManager creates a new JWT manager with RSA keys
func NewJWTManager(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *JWTManager {
	return &JWTManager{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// GenerateToken creates a new JWT token with the provided claims
func (jm *JWTManager) GenerateToken(req JWTRequest) (*JWTResponse, error) {
	if jm.privateKey == nil {
		return nil, errors.New("private key is required for token generation")
	}

	// Set default values
	now := time.Now()
	if req.IssuedAt == nil {
		req.IssuedAt = &now
	}
	if req.JWTID == "" {
		req.JWTID = uuid.New().String()
	}

	// Create claims map
	claims := jwt.MapClaims{
		"iss": req.Issuer,
		"sub": req.Subject,
		"exp": req.ExpiresAt.Unix(),
		"iat": req.IssuedAt.Unix(),
		"jti": req.JWTID,
	}

	// Add audience if provided
	if len(req.Audience) > 0 {
		if len(req.Audience) == 1 {
			claims["aud"] = req.Audience[0]
		} else {
			claims["aud"] = req.Audience
		}
	}

	// Add not before if provided
	if req.NotBefore != nil {
		claims["nbf"] = req.NotBefore.Unix()
	}

	// Add custom claims
	for key, value := range req.CustomClaims {
		claims[key] = value
	}

	// Create and sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(jm.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Prepare response
	response := &JWTResponse{
		Token:     tokenString,
		Claims:    claims,
		ExpiresAt: req.ExpiresAt,
		IssuedAt:  *req.IssuedAt,
		JWTID:     req.JWTID,
	}

	return response, nil
}

// VerifyToken verifies a JWT token and returns its claims
func (jm *JWTManager) VerifyToken(req VerifyRequest) *VerifyResponse {
	if jm.publicKey == nil {
		return &VerifyResponse{
			Valid: false,
			Error: "public key is required for token verification",
		}
	}

	// Parse and verify the token
	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jm.publicKey, nil
	})

	response := &VerifyResponse{}

	if err != nil {
		response.Valid = false
		response.Error = err.Error()
		return response
	}

	if !token.Valid {
		response.Valid = false
		response.Error = "token is not valid"
		return response
	}

	// Extract claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		response.Valid = true
		response.Claims = claims
		response.CustomClaims = make(map[string]interface{})

		// Extract standard claims
		if iss, ok := claims["iss"].(string); ok {
			response.Issuer = iss
		}
		if sub, ok := claims["sub"].(string); ok {
			response.Subject = sub
		}
		if jti, ok := claims["jti"].(string); ok {
			response.JWTID = jti
		}

		// Handle audience (can be string or array)
		if aud, ok := claims["aud"]; ok {
			switch v := aud.(type) {
			case string:
				response.Audience = []string{v}
			case []interface{}:
				audience := make([]string, len(v))
				for i, a := range v {
					if s, ok := a.(string); ok {
						audience[i] = s
					}
				}
				response.Audience = audience
			}
		}

		// Extract timestamps
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			response.ExpiresAt = &expTime
		}
		if iat, ok := claims["iat"].(float64); ok {
			iatTime := time.Unix(int64(iat), 0)
			response.IssuedAt = &iatTime
		}

		// Extract custom claims (exclude standard claims)
		standardClaims := map[string]bool{
			"iss": true, "sub": true, "aud": true, "exp": true,
			"nbf": true, "iat": true, "jti": true,
		}
		for key, value := range claims {
			if !standardClaims[key] {
				response.CustomClaims[key] = value
			}
		}
	}

	return response
}

// ParseToken parses a JWT token without verification (useful for debugging)
func (jm *JWTManager) ParseToken(req ParseRequest) *ParseResponse {
	// Parse without verification
	token, _, err := jwt.NewParser().ParseUnverified(req.Token, jwt.MapClaims{})

	response := &ParseResponse{}

	if err != nil {
		response.Valid = false
		response.Error = err.Error()
		return response
	}

	// Extract claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		response.Valid = true
		response.Claims = claims
		response.CustomClaims = make(map[string]interface{})

		// Extract standard claims
		if iss, ok := claims["iss"].(string); ok {
			response.Issuer = iss
		}
		if sub, ok := claims["sub"].(string); ok {
			response.Subject = sub
		}
		if jti, ok := claims["jti"].(string); ok {
			response.JWTID = jti
		}

		// Handle audience (can be string or array)
		if aud, ok := claims["aud"]; ok {
			switch v := aud.(type) {
			case string:
				response.Audience = []string{v}
			case []interface{}:
				audience := make([]string, len(v))
				for i, a := range v {
					if s, ok := a.(string); ok {
						audience[i] = s
					}
				}
				response.Audience = audience
			}
		}

		// Extract timestamps
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			response.ExpiresAt = &expTime
		}
		if iat, ok := claims["iat"].(float64); ok {
			iatTime := time.Unix(int64(iat), 0)
			response.IssuedAt = &iatTime
		}

		// Extract custom claims (exclude standard claims)
		standardClaims := map[string]bool{
			"iss": true, "sub": true, "aud": true, "exp": true,
			"nbf": true, "iat": true, "jti": true,
		}
		for key, value := range claims {
			if !standardClaims[key] {
				response.CustomClaims[key] = value
			}
		}
	}

	return response
}
