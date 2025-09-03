package main

import (
	"fmt"
	"log"
	"time"

	"cjwt"
	"cjwt/tokenmaker"
)

func main() {
	// Example 1: Create Token Maker with JWT support
	fmt.Println("=== Example 1: Token Maker with JWT Support ===")

	// Generate RSA keys for JWT
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create token maker with JWT configuration
	config := &tokenmaker.TokenMakerConfig{
		JWTPrivateKey:            privateKey,
		JWTPublicKey:             publicKey,
		DefaultJWTSigningMethod:  tokenmaker.RS256,
		DefaultOpaqueTokenLength: 32,
		DefaultOpaqueTokenPrefix: "op_",
	}

	tokenMaker, err := tokenmaker.NewTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Generate JWT token
	fmt.Println("\n--- Generating JWT Token ---")
	jwtReq := tokenmaker.TokenRequest{
		Type:      tokenmaker.JWT,
		UserID:    "user123",
		ClientID:  "client456",
		Scope:     []string{"read", "write"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CustomData: map[string]interface{}{
			"role":       "admin",
			"department": "engineering",
		},
		JWTConfig: &tokenmaker.JWTConfig{
			Issuer:        "my-app",
			Subject:       "user123",
			Audience:      []string{"my-api"},
			SigningMethod: tokenmaker.RS256,
			CustomClaims: map[string]interface{}{
				"permissions": []string{"read", "write", "delete"},
			},
		},
	}

	jwtResp, err := tokenMaker.GenerateToken(jwtReq)
	if err != nil {
		log.Fatalf("Failed to generate JWT token: %v", err)
	}

	fmt.Printf("JWT Token: %s\n", jwtResp.Token[:50]+"...")
	fmt.Printf("Token ID: %s\n", jwtResp.TokenID)
	fmt.Printf("User ID: %s\n", jwtResp.UserID)
	fmt.Printf("Expires At: %s\n", jwtResp.ExpiresAt.Format(time.RFC3339))

	// Validate JWT token
	fmt.Println("\n--- Validating JWT Token ---")
	jwtValidateReq := tokenmaker.ValidateRequest{
		Type:  tokenmaker.JWT,
		Token: jwtResp.Token,
	}

	jwtValidateResp := tokenMaker.ValidateToken(jwtValidateReq)
	if jwtValidateResp.Valid {
		fmt.Println("JWT Token is valid!")
		fmt.Printf("User ID: %s\n", jwtValidateResp.UserID)
		fmt.Printf("Client ID: %s\n", jwtValidateResp.ClientID)
		fmt.Printf("Scope: %v\n", jwtValidateResp.Scope)
		fmt.Printf("Custom Data: %+v\n", jwtValidateResp.CustomData)
	} else {
		fmt.Printf("JWT Token validation failed: %s\n", jwtValidateResp.Error)
	}

	// Generate Opaque token
	fmt.Println("\n--- Generating Opaque Token ---")
	opaqueReq := tokenmaker.TokenRequest{
		Type:      tokenmaker.Opaque,
		UserID:    "user789",
		ClientID:  "client101",
		Scope:     []string{"read"},
		ExpiresAt: time.Now().Add(12 * time.Hour),
		CustomData: map[string]interface{}{
			"role":  "user",
			"level": 2,
		},
		OpaqueConfig: &tokenmaker.OpaqueConfig{
			TokenLength: 32,
			TokenPrefix: "op_",
		},
	}

	opaqueResp, err := tokenMaker.GenerateToken(opaqueReq)
	if err != nil {
		log.Fatalf("Failed to generate opaque token: %v", err)
	}

	fmt.Printf("Opaque Token: %s\n", opaqueResp.Token)
	fmt.Printf("Token ID: %s\n", opaqueResp.TokenID)
	fmt.Printf("User ID: %s\n", opaqueResp.UserID)
	fmt.Printf("Expires At: %s\n", opaqueResp.ExpiresAt.Format(time.RFC3339))

	// Validate Opaque token
	fmt.Println("\n--- Validating Opaque Token ---")
	opaqueValidateReq := tokenmaker.ValidateRequest{
		Type:  tokenmaker.Opaque,
		Token: opaqueResp.Token,
	}

	opaqueValidateResp := tokenMaker.ValidateToken(opaqueValidateReq)
	if opaqueValidateResp.Valid {
		fmt.Println("Opaque Token is valid!")
		fmt.Printf("User ID: %s\n", opaqueValidateResp.UserID)
		fmt.Printf("Client ID: %s\n", opaqueValidateResp.ClientID)
		fmt.Printf("Scope: %v\n", opaqueValidateResp.Scope)
		fmt.Printf("Custom Data: %+v\n", opaqueValidateResp.CustomData)
	} else {
		fmt.Printf("Opaque Token validation failed: %s\n", opaqueValidateResp.Error)
	}

	// Revoke Opaque token
	fmt.Println("\n--- Revoking Opaque Token ---")
	revokeReq := tokenmaker.RevokeRequest{
		Type:  tokenmaker.Opaque,
		Token: opaqueResp.Token,
	}

	revokeResp := tokenMaker.RevokeToken(revokeReq)
	if revokeResp.Success {
		fmt.Println("Opaque Token revoked successfully!")
	} else {
		fmt.Printf("Failed to revoke opaque token: %s\n", revokeResp.Error)
	}

	// Try to validate revoked token
	fmt.Println("\n--- Validating Revoked Token ---")
	revokedValidateResp := tokenMaker.ValidateToken(opaqueValidateReq)
	if !revokedValidateResp.Valid {
		fmt.Printf("Revoked token validation correctly failed: %s\n", revokedValidateResp.Error)
	} else {
		fmt.Println("ERROR: Revoked token should not be valid!")
	}

	// Example 2: Different JWT Signing Methods
	fmt.Println("\n=== Example 2: Different JWT Signing Methods ===")

	// ECDSA example
	ecdsaPrivateKey, ecdsaPublicKey, err := cjwt.GenerateECDSAKeyPair()
	if err != nil {
		fmt.Printf("Failed to generate ECDSA keys: %v\n", err)
	} else {
		ecdsaConfig := &tokenmaker.TokenMakerConfig{
			JWTPrivateKey:           ecdsaPrivateKey,
			JWTPublicKey:            ecdsaPublicKey,
			DefaultJWTSigningMethod: tokenmaker.ES256,
		}

		ecdsaTokenMaker, err := tokenmaker.NewTokenMaker(ecdsaConfig)
		if err != nil {
			fmt.Printf("Failed to create ECDSA token maker: %v\n", err)
		} else {
			ecdsaReq := tokenmaker.TokenRequest{
				Type:      tokenmaker.JWT,
				UserID:    "user_ecdsa",
				ExpiresAt: time.Now().Add(1 * time.Hour),
				JWTConfig: &tokenmaker.JWTConfig{
					Issuer:        "ecdsa-app",
					Subject:       "user_ecdsa",
					SigningMethod: tokenmaker.ES256,
				},
			}

			ecdsaResp, err := ecdsaTokenMaker.GenerateToken(ecdsaReq)
			if err != nil {
				fmt.Printf("Failed to generate ECDSA token: %v\n", err)
			} else {
				fmt.Printf("ECDSA Token: %s...\n", ecdsaResp.Token[:50])
			}
		}
	}

	// HMAC example
	hmacKey, err := cjwt.DefaultHMACKey()
	if err != nil {
		fmt.Printf("Failed to generate HMAC key: %v\n", err)
	} else {
		hmacConfig := &tokenmaker.TokenMakerConfig{
			JWTPrivateKey:           hmacKey,
			DefaultJWTSigningMethod: tokenmaker.HS256,
		}

		hmacTokenMaker, err := tokenmaker.NewTokenMaker(hmacConfig)
		if err != nil {
			fmt.Printf("Failed to create HMAC token maker: %v\n", err)
		} else {
			hmacReq := tokenmaker.TokenRequest{
				Type:      tokenmaker.JWT,
				UserID:    "user_hmac",
				ExpiresAt: time.Now().Add(1 * time.Hour),
				JWTConfig: &tokenmaker.JWTConfig{
					Issuer:        "hmac-app",
					Subject:       "user_hmac",
					SigningMethod: tokenmaker.HS256,
				},
			}

			hmacResp, err := hmacTokenMaker.GenerateToken(hmacReq)
			if err != nil {
				fmt.Printf("Failed to generate HMAC token: %v\n", err)
			} else {
				fmt.Printf("HMAC Token: %s...\n", hmacResp.Token[:50])
			}
		}
	}

	// Example 3: Opaque Token Only
	fmt.Println("\n=== Example 3: Opaque Token Only ===")

	opaqueOnlyMaker := tokenmaker.NewTokenMakerWithOpaque()

	opaqueOnlyReq := tokenmaker.TokenRequest{
		Type:      tokenmaker.Opaque,
		UserID:    "opaque_user",
		ClientID:  "opaque_client",
		Scope:     []string{"read", "write", "admin"},
		ExpiresAt: time.Now().Add(6 * time.Hour),
		CustomData: map[string]interface{}{
			"session_id": "sess_12345",
			"ip_address": "192.168.1.100",
		},
		OpaqueConfig: &tokenmaker.OpaqueConfig{
			TokenLength: 48,
			TokenPrefix: "sess_",
		},
	}

	opaqueOnlyResp, err := opaqueOnlyMaker.GenerateToken(opaqueOnlyReq)
	if err != nil {
		fmt.Printf("Failed to generate opaque-only token: %v\n", err)
	} else {
		fmt.Printf("Opaque-Only Token: %s\n", opaqueOnlyResp.Token)
		fmt.Printf("Token ID: %s\n", opaqueOnlyResp.TokenID)
		fmt.Printf("User ID: %s\n", opaqueOnlyResp.UserID)
		fmt.Printf("Scope: %v\n", opaqueOnlyResp.Scope)
	}

	fmt.Println("\n=== Token Maker Examples Complete ===")
}
