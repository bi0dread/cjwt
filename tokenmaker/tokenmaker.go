package tokenmaker

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"cjwt"
	"cjwt/opaque"
)

// TokenMaker provides a unified interface for creating and managing different types of tokens
type TokenMaker struct {
	// JWT manager
	jwtManager *cjwt.JWTManager

	// Opaque token manager
	opaqueManager *opaque.OpaqueTokenManager

	// Configuration
	config *TokenMakerConfig
}

// NewTokenMaker creates a new token maker with the provided configuration
func NewTokenMaker(config *TokenMakerConfig) (*TokenMaker, error) {
	if config == nil {
		return nil, errors.New("configuration is required")
	}

	tm := &TokenMaker{
		config: config,
	}

	// Initialize JWT manager if JWT keys are provided
	if config.JWTPrivateKey != nil {
		jwtManager, err := tm.createJWTManager(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT manager: %w", err)
		}
		tm.jwtManager = jwtManager
	}

	// Initialize opaque token manager
	tm.opaqueManager = opaque.NewOpaqueTokenManagerWithConfig(
		config.DefaultOpaqueTokenLength,
		config.DefaultOpaqueTokenPrefix,
	)

	return tm, nil
}

// NewTokenMakerWithJWT creates a new token maker with JWT support only
func NewTokenMakerWithJWT(privateKey, publicKey interface{}) (*TokenMaker, error) {
	config := &TokenMakerConfig{
		JWTPrivateKey:           privateKey,
		JWTPublicKey:            publicKey,
		DefaultJWTSigningMethod: RS256,
	}
	return NewTokenMaker(config)
}

// NewTokenMakerWithOpaque creates a new token maker with opaque token support only
func NewTokenMakerWithOpaque() *TokenMaker {
	config := &TokenMakerConfig{
		DefaultOpaqueTokenLength: 32,
		DefaultOpaqueTokenPrefix: "op_",
	}

	tm, _ := NewTokenMaker(config)
	return tm
}

// GenerateToken creates a token based on the request type
func (tm *TokenMaker) GenerateToken(req TokenRequest) (*TokenResponse, error) {
	switch req.Type {
	case JWT:
		return tm.generateJWTToken(req)
	case Opaque:
		return tm.generateOpaqueToken(req)
	default:
		return nil, fmt.Errorf("unsupported token type: %s", req.Type)
	}
}

// ValidateToken validates a token based on its type
func (tm *TokenMaker) ValidateToken(req ValidateRequest) *ValidateResponse {
	switch req.Type {
	case JWT:
		return tm.validateJWTToken(req)
	case Opaque:
		return tm.validateOpaqueToken(req)
	default:
		return &ValidateResponse{
			Type:  req.Type,
			Valid: false,
			Error: fmt.Sprintf("unsupported token type: %s", req.Type),
		}
	}
}

// RevokeToken revokes a token based on its type
func (tm *TokenMaker) RevokeToken(req RevokeRequest) *RevokeResponse {
	switch req.Type {
	case JWT:
		return &RevokeResponse{
			Type:    req.Type,
			Success: false,
			Error:   "JWT tokens cannot be revoked (they are stateless)",
		}
	case Opaque:
		return tm.revokeOpaqueToken(req)
	default:
		return &RevokeResponse{
			Type:    req.Type,
			Success: false,
			Error:   fmt.Sprintf("unsupported token type: %s", req.Type),
		}
	}
}

// generateJWTToken generates a JWT token
func (tm *TokenMaker) generateJWTToken(req TokenRequest) (*TokenResponse, error) {
	if tm.jwtManager == nil {
		return nil, errors.New("JWT manager not initialized")
	}

	if req.JWTConfig == nil {
		return nil, errors.New("JWT configuration is required")
	}

	// Convert to JWT request
	jwtReq := cjwt.JWTRequest{
		Issuer:       req.JWTConfig.Issuer,
		Subject:      req.JWTConfig.Subject,
		Audience:     req.JWTConfig.Audience,
		ExpiresAt:    req.ExpiresAt,
		NotBefore:    req.NotBefore,
		IssuedAt:     req.IssuedAt,
		CustomClaims: req.JWTConfig.CustomClaims,
	}

	// Add common data to custom claims
	if jwtReq.CustomClaims == nil {
		jwtReq.CustomClaims = make(map[string]interface{})
	}
	jwtReq.CustomClaims["user_id"] = req.UserID
	jwtReq.CustomClaims["client_id"] = req.ClientID
	jwtReq.CustomClaims["scope"] = req.Scope
	for k, v := range req.CustomData {
		jwtReq.CustomClaims[k] = v
	}

	// Generate JWT token
	var jwtResp *cjwt.JWTResponse
	var err error

	if req.JWTConfig.SigningMethod != "" {
		jwtResp, err = tm.jwtManager.GenerateTokenWithMethod(jwtReq, cjwt.SigningMethod(req.JWTConfig.SigningMethod))
	} else {
		jwtResp, err = tm.jwtManager.GenerateToken(jwtReq)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT token: %w", err)
	}

	// Convert to unified response
	response := &TokenResponse{
		Type:       JWT,
		Token:      jwtResp.Token,
		TokenID:    jwtResp.JWTID,
		UserID:     req.UserID,
		ClientID:   req.ClientID,
		Scope:      req.Scope,
		ExpiresAt:  jwtResp.ExpiresAt,
		IssuedAt:   jwtResp.IssuedAt,
		CustomData: req.CustomData,
		JWTClaims:  jwtResp.Claims,
	}

	return response, nil
}

// generateOpaqueToken generates an opaque token
func (tm *TokenMaker) generateOpaqueToken(req TokenRequest) (*TokenResponse, error) {
	// Convert to opaque token request
	opaqueReq := opaque.OpaqueTokenRequest{
		UserID:     req.UserID,
		ClientID:   req.ClientID,
		Scope:      req.Scope,
		ExpiresAt:  req.ExpiresAt,
		IssuedAt:   req.IssuedAt,
		NotBefore:  req.NotBefore,
		CustomData: req.CustomData,
	}

	// Apply opaque-specific configuration
	if req.OpaqueConfig != nil {
		opaqueReq.TokenLength = req.OpaqueConfig.TokenLength
		opaqueReq.TokenPrefix = req.OpaqueConfig.TokenPrefix
	}

	// Generate opaque token
	opaqueResp, err := tm.opaqueManager.GenerateToken(opaqueReq)
	if err != nil {
		return nil, fmt.Errorf("failed to generate opaque token: %w", err)
	}

	// Convert to unified response
	response := &TokenResponse{
		Type:       Opaque,
		Token:      opaqueResp.Token,
		TokenID:    opaqueResp.TokenID,
		UserID:     req.UserID,
		ClientID:   req.ClientID,
		Scope:      req.Scope,
		ExpiresAt:  opaqueResp.ExpiresAt,
		IssuedAt:   opaqueResp.IssuedAt,
		CustomData: opaqueResp.CustomData,
		OpaqueInfo: &opaque.OpaqueTokenInfo{
			TokenID:    opaqueResp.TokenID,
			UserID:     opaqueResp.UserID,
			ClientID:   opaqueResp.ClientID,
			Scope:      opaqueResp.Scope,
			ExpiresAt:  opaqueResp.ExpiresAt,
			IssuedAt:   opaqueResp.IssuedAt,
			CustomData: opaqueResp.CustomData,
			IsActive:   true,
			CreatedAt:  time.Now(),
		},
	}

	return response, nil
}

// validateJWTToken validates a JWT token
func (tm *TokenMaker) validateJWTToken(req ValidateRequest) *ValidateResponse {
	if tm.jwtManager == nil {
		return &ValidateResponse{
			Type:  JWT,
			Valid: false,
			Error: "JWT manager not initialized",
		}
	}

	// Validate JWT token
	jwtVerifyReq := cjwt.VerifyRequest{Token: req.Token}
	jwtVerifyResp := tm.jwtManager.VerifyToken(jwtVerifyReq)

	if !jwtVerifyResp.Valid {
		return &ValidateResponse{
			Type:  JWT,
			Valid: false,
			Error: jwtVerifyResp.Error,
		}
	}

	// Extract common fields from JWT claims
	response := &ValidateResponse{
		Type:      JWT,
		Valid:     true,
		JWTClaims: jwtVerifyResp.Claims,
	}

	// Extract user_id, client_id, scope from claims
	if userID, ok := jwtVerifyResp.Claims["user_id"].(string); ok {
		response.UserID = userID
	}
	if clientID, ok := jwtVerifyResp.Claims["client_id"].(string); ok {
		response.ClientID = clientID
	}
	if scope, ok := jwtVerifyResp.Claims["scope"].([]interface{}); ok {
		response.Scope = make([]string, len(scope))
		for i, s := range scope {
			if str, ok := s.(string); ok {
				response.Scope[i] = str
			}
		}
	}

	// Extract timestamps
	if jwtVerifyResp.ExpiresAt != nil {
		response.ExpiresAt = jwtVerifyResp.ExpiresAt
	}
	if jwtVerifyResp.IssuedAt != nil {
		response.IssuedAt = jwtVerifyResp.IssuedAt
	}

	// Extract custom data (exclude standard JWT claims)
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true,
		"nbf": true, "iat": true, "jti": true, "user_id": true,
		"client_id": true, "scope": true,
	}
	response.CustomData = make(map[string]interface{})
	for key, value := range jwtVerifyResp.Claims {
		if !standardClaims[key] {
			response.CustomData[key] = value
		}
	}

	return response
}

// validateOpaqueToken validates an opaque token
func (tm *TokenMaker) validateOpaqueToken(req ValidateRequest) *ValidateResponse {
	// Validate opaque token
	opaqueValidateReq := opaque.ValidateRequest{Token: req.Token}
	opaqueValidateResp := tm.opaqueManager.ValidateToken(opaqueValidateReq)

	if !opaqueValidateResp.Valid {
		return &ValidateResponse{
			Type:  Opaque,
			Valid: false,
			Error: opaqueValidateResp.Error,
		}
	}

	// Convert to unified response
	response := &ValidateResponse{
		Type:       Opaque,
		Valid:      true,
		UserID:     opaqueValidateResp.TokenInfo.UserID,
		ClientID:   opaqueValidateResp.TokenInfo.ClientID,
		Scope:      opaqueValidateResp.TokenInfo.Scope,
		ExpiresAt:  &opaqueValidateResp.TokenInfo.ExpiresAt,
		IssuedAt:   &opaqueValidateResp.TokenInfo.IssuedAt,
		CustomData: opaqueValidateResp.TokenInfo.CustomData,
		OpaqueInfo: opaqueValidateResp.TokenInfo,
	}

	return response
}

// revokeOpaqueToken revokes an opaque token
func (tm *TokenMaker) revokeOpaqueToken(req RevokeRequest) *RevokeResponse {
	// Revoke opaque token
	opaqueRevokeReq := opaque.RevokeRequest{Token: req.Token}
	opaqueRevokeResp := tm.opaqueManager.RevokeToken(opaqueRevokeReq)

	return &RevokeResponse{
		Type:    Opaque,
		Success: opaqueRevokeResp.Success,
		Error:   opaqueRevokeResp.Error,
	}
}

// createJWTManager creates a JWT manager based on the key types
func (tm *TokenMaker) createJWTManager(config *TokenMakerConfig) (*cjwt.JWTManager, error) {
	switch privateKey := config.JWTPrivateKey.(type) {
	case *rsa.PrivateKey:
		if publicKey, ok := config.JWTPublicKey.(*rsa.PublicKey); ok {
			return cjwt.NewJWTManager(privateKey, publicKey), nil
		}
		// If no public key provided, use the public key from the private key
		return cjwt.NewJWTManager(privateKey, &privateKey.PublicKey), nil

	case *ecdsa.PrivateKey:
		if publicKey, ok := config.JWTPublicKey.(*ecdsa.PublicKey); ok {
			return cjwt.NewJWTManagerWithECDSA(privateKey, publicKey), nil
		}
		// If no public key provided, use the public key from the private key
		return cjwt.NewJWTManagerWithECDSA(privateKey, &privateKey.PublicKey), nil

	case []byte:
		return cjwt.NewJWTManagerWithHMAC(privateKey), nil

	default:
		return nil, errors.New("unsupported private key type")
	}
}

// GetJWTManager returns the JWT manager (for advanced operations)
func (tm *TokenMaker) GetJWTManager() *cjwt.JWTManager {
	return tm.jwtManager
}

// GetOpaqueManager returns the opaque token manager (for advanced operations)
func (tm *TokenMaker) GetOpaqueManager() *opaque.OpaqueTokenManager {
	return tm.opaqueManager
}
