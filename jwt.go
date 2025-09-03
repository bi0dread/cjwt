package cjwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTManager handles JWT operations with support for multiple signing methods
type JWTManager struct {
	// RSA keys
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey

	// ECDSA keys
	ecdsaPrivateKey *ecdsa.PrivateKey
	ecdsaPublicKey  *ecdsa.PublicKey

	// HMAC key
	hmacKey []byte

	// Key management
	keyManager *KeyManager

	// Metrics and logging
	metrics    *TokenMetrics
	auditLogs  []TokenAuditLog
	metricsMux sync.RWMutex
	logsMux    sync.RWMutex

	// Configuration
	defaultSigningMethod SigningMethod
}

// KeyManager handles key rotation and management
type KeyManager struct {
	currentKeyID string
	keys         map[string]interface{} // keyID -> key
	keyHistory   map[string]KeyInfo
	gracePeriod  time.Duration
	mutex        sync.RWMutex
}

// NewKeyManager creates a new key manager
func NewKeyManager() *KeyManager {
	return &KeyManager{
		keys:        make(map[string]interface{}),
		keyHistory:  make(map[string]KeyInfo),
		gracePeriod: 24 * time.Hour, // Default grace period
	}
}

// NewJWTManager creates a new JWT manager with RSA keys
func NewJWTManager(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *JWTManager {
	keyManager := NewKeyManager()
	keyID := uuid.New().String()

	// Store the initial key
	keyManager.mutex.Lock()
	keyManager.currentKeyID = keyID
	keyManager.keys[keyID] = privateKey
	keyManager.keyHistory[keyID] = KeyInfo{
		KeyID:     keyID,
		Algorithm: string(RS256),
		CreatedAt: time.Now(),
		IsActive:  true,
	}
	keyManager.mutex.Unlock()

	return &JWTManager{
		privateKey:           privateKey,
		publicKey:            publicKey,
		keyManager:           keyManager,
		metrics:              &TokenMetrics{LastReset: time.Now()},
		auditLogs:            make([]TokenAuditLog, 0),
		defaultSigningMethod: RS256,
	}
}

// NewJWTManagerWithECDSA creates a new JWT manager with ECDSA keys
func NewJWTManagerWithECDSA(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) *JWTManager {
	keyManager := NewKeyManager()
	keyID := uuid.New().String()

	keyManager.mutex.Lock()
	keyManager.currentKeyID = keyID
	keyManager.keys[keyID] = privateKey
	keyManager.keyHistory[keyID] = KeyInfo{
		KeyID:     keyID,
		Algorithm: string(ES256),
		CreatedAt: time.Now(),
		IsActive:  true,
	}
	keyManager.mutex.Unlock()

	return &JWTManager{
		ecdsaPrivateKey:      privateKey,
		ecdsaPublicKey:       publicKey,
		keyManager:           keyManager,
		metrics:              &TokenMetrics{LastReset: time.Now()},
		auditLogs:            make([]TokenAuditLog, 0),
		defaultSigningMethod: ES256,
	}
}

// NewJWTManagerWithHMAC creates a new JWT manager with HMAC key
func NewJWTManagerWithHMAC(key []byte) *JWTManager {
	keyManager := NewKeyManager()
	keyID := uuid.New().String()

	keyManager.mutex.Lock()
	keyManager.currentKeyID = keyID
	keyManager.keys[keyID] = key
	keyManager.keyHistory[keyID] = KeyInfo{
		KeyID:     keyID,
		Algorithm: string(HS256),
		CreatedAt: time.Now(),
		IsActive:  true,
	}
	keyManager.mutex.Unlock()

	return &JWTManager{
		hmacKey:              key,
		keyManager:           keyManager,
		metrics:              &TokenMetrics{LastReset: time.Now()},
		auditLogs:            make([]TokenAuditLog, 0),
		defaultSigningMethod: HS256,
	}
}

// GenerateToken creates a new JWT token with the provided claims
func (jm *JWTManager) GenerateToken(req JWTRequest) (*JWTResponse, error) {
	return jm.GenerateTokenWithMethod(req, jm.defaultSigningMethod)
}

// GenerateTokenWithMethod creates a new JWT token with the specified signing method
func (jm *JWTManager) GenerateTokenWithMethod(req JWTRequest, method SigningMethod) (*JWTResponse, error) {
	startTime := time.Now()
	tokenID := uuid.New().String()

	// Log the operation
	jm.logAuditEvent(TokenAuditLog{
		Timestamp: startTime,
		Action:    "generate",
		UserID:    req.Subject,
		TokenID:   tokenID,
		Success:   false, // Will be updated on success
	})

	// Update metrics
	jm.updateMetrics(func(m *TokenMetrics) {
		m.GeneratedTokens++
	})

	var signingMethod jwt.SigningMethod
	var signingKey interface{}

	switch method {
	case RS256:
		if jm.privateKey == nil {
			jm.logAuditEvent(TokenAuditLog{
				Timestamp: time.Now(),
				Action:    "generate",
				UserID:    req.Subject,
				TokenID:   tokenID,
				Success:   false,
				ErrorMsg:  "RSA private key not available",
			})
			return nil, errors.New("RSA private key is required for RS256")
		}
		signingMethod = jwt.SigningMethodRS256
		signingKey = jm.privateKey
	case ES256:
		if jm.ecdsaPrivateKey == nil {
			jm.logAuditEvent(TokenAuditLog{
				Timestamp: time.Now(),
				Action:    "generate",
				UserID:    req.Subject,
				TokenID:   tokenID,
				Success:   false,
				ErrorMsg:  "ECDSA private key not available",
			})
			return nil, errors.New("ECDSA private key is required for ES256")
		}
		signingMethod = jwt.SigningMethodES256
		signingKey = jm.ecdsaPrivateKey
	case HS256:
		if jm.hmacKey == nil {
			jm.logAuditEvent(TokenAuditLog{
				Timestamp: time.Now(),
				Action:    "generate",
				UserID:    req.Subject,
				TokenID:   tokenID,
				Success:   false,
				ErrorMsg:  "HMAC key not available",
			})
			return nil, errors.New("HMAC key is required for HS256")
		}
		signingMethod = jwt.SigningMethodHS256
		signingKey = jm.hmacKey
	default:
		jm.logAuditEvent(TokenAuditLog{
			Timestamp: time.Now(),
			Action:    "generate",
			UserID:    req.Subject,
			TokenID:   tokenID,
			Success:   false,
			ErrorMsg:  "unsupported signing method",
		})
		return nil, fmt.Errorf("unsupported signing method: %s", method)
	}

	// Set default values
	now := time.Now()
	if req.IssuedAt == nil {
		req.IssuedAt = &now
	}
	if req.JWTID == "" {
		req.JWTID = tokenID
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
	token := jwt.NewWithClaims(signingMethod, claims)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		jm.logAuditEvent(TokenAuditLog{
			Timestamp: time.Now(),
			Action:    "generate",
			UserID:    req.Subject,
			TokenID:   tokenID,
			Success:   false,
			ErrorMsg:  fmt.Sprintf("failed to sign token: %v", err),
		})
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

	// Log successful generation
	jm.logAuditEvent(TokenAuditLog{
		Timestamp: time.Now(),
		Action:    "generate",
		UserID:    req.Subject,
		TokenID:   tokenID,
		Success:   true,
		Claims:    claims,
	})

	// Update metrics
	jm.updateMetrics(func(m *TokenMetrics) {
		m.GeneratedTokens++
	})

	return response, nil
}

// Helper functions for metrics and audit logging
func (jm *JWTManager) updateMetrics(updateFunc func(*TokenMetrics)) {
	jm.metricsMux.Lock()
	defer jm.metricsMux.Unlock()
	updateFunc(jm.metrics)
}

func (jm *JWTManager) logAuditEvent(log TokenAuditLog) {
	jm.logsMux.Lock()
	defer jm.logsMux.Unlock()
	jm.auditLogs = append(jm.auditLogs, log)

	// Keep only last 1000 logs to prevent memory issues
	if len(jm.auditLogs) > 1000 {
		jm.auditLogs = jm.auditLogs[len(jm.auditLogs)-1000:]
	}
}

// VerifyToken verifies a JWT token and returns its claims
func (jm *JWTManager) VerifyToken(req VerifyRequest) *VerifyResponse {
	// Determine which key to use for verification
	var verificationKey interface{}
	var expectedMethod jwt.SigningMethod

	if jm.publicKey != nil {
		verificationKey = jm.publicKey
		expectedMethod = jwt.SigningMethodRS256
	} else if jm.ecdsaPublicKey != nil {
		verificationKey = jm.ecdsaPublicKey
		expectedMethod = jwt.SigningMethodES256
	} else if jm.hmacKey != nil {
		verificationKey = jm.hmacKey
		expectedMethod = jwt.SigningMethodHS256
	} else {
		return &VerifyResponse{
			Valid: false,
			Error: "no verification key available",
		}
	}

	// Parse and verify the token
	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method matches what we expect
		if token.Method != expectedMethod {
			return nil, fmt.Errorf("unexpected signing method: %v, expected: %v", token.Header["alg"], expectedMethod.Alg())
		}
		return verificationKey, nil
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

		// Update metrics for successful verification
		jm.updateMetrics(func(m *TokenMetrics) {
			m.VerifiedTokens++
		})

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
