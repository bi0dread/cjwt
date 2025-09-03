package main

import (
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/cjwt"
)

func main() {
	// Generate RSA key pair
	privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create JWT manager
	jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

	// Example 1: Generate a simple JWT token
	fmt.Println("=== Example 1: Simple JWT Token ===")
	simpleReq := cjwt.JWTRequest{
		Issuer:    "my-app",
		Subject:   "user123",
		Audience:  []string{"my-api"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	simpleResp, err := jwtManager.GenerateToken(simpleReq)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	fmt.Printf("Generated Token: %s\n", simpleResp.Token)
	fmt.Printf("JWT ID: %s\n", simpleResp.JWTID)
	fmt.Printf("Expires At: %s\n", simpleResp.ExpiresAt.Format(time.RFC3339))

	// Example 2: Generate a JWT token with custom claims
	fmt.Println("\n=== Example 2: JWT Token with Custom Claims ===")
	customReq := cjwt.JWTRequest{
		Issuer:    "my-app",
		Subject:   "user456",
		Audience:  []string{"my-api", "admin-api"},
		ExpiresAt: time.Now().Add(12 * time.Hour),
		CustomClaims: map[string]interface{}{
			"role":        "admin",
			"permissions": []string{"read", "write", "delete"},
			"department":  "engineering",
			"user_level":  5,
		},
	}

	customResp, err := jwtManager.GenerateToken(customReq)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	fmt.Printf("Generated Token: %s\n", customResp.Token)
	fmt.Printf("Custom Claims: %+v\n", customResp.Claims)

	// Example 3: Verify a token
	fmt.Println("\n=== Example 3: Verify Token ===")
	verifyReq := cjwt.VerifyRequest{Token: customResp.Token}
	verifyResp := jwtManager.VerifyToken(verifyReq)

	if verifyResp.Valid {
		fmt.Println("Token is valid!")
		fmt.Printf("Subject: %s\n", verifyResp.Subject)
		fmt.Printf("Issuer: %s\n", verifyResp.Issuer)
		fmt.Printf("Audience: %v\n", verifyResp.Audience)
		fmt.Printf("Custom Claims: %+v\n", verifyResp.CustomClaims)
	} else {
		fmt.Printf("Token is invalid: %s\n", verifyResp.Error)
	}

	// Example 4: Parse token without verification
	fmt.Println("\n=== Example 4: Parse Token (No Verification) ===")
	parseReq := cjwt.ParseRequest{Token: customResp.Token}
	parseResp := jwtManager.ParseToken(parseReq)

	if parseResp.Valid {
		fmt.Println("Token format is valid!")
		fmt.Printf("Subject: %s\n", parseResp.Subject)
		fmt.Printf("Expires At: %s\n", parseResp.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("Custom Claims: %+v\n", parseResp.CustomClaims)
	} else {
		fmt.Printf("Token parsing failed: %s\n", parseResp.Error)
	}

	// Example 5: Utility functions
	fmt.Println("\n=== Example 5: Utility Functions ===")

	// Check if token format is valid
	fmt.Printf("Is valid JWT format: %t\n", cjwt.IsValidJWTFormat(customResp.Token))

	// Check if token is expired
	expired, err := cjwt.IsTokenExpired(customResp.Token)
	if err != nil {
		fmt.Printf("Error checking expiration: %v\n", err)
	} else {
		fmt.Printf("Is token expired: %t\n", expired)
	}

	// Get token expiration time
	expTime, err := cjwt.GetTokenExpirationTime(customResp.Token)
	if err != nil {
		fmt.Printf("Error getting expiration time: %v\n", err)
	} else {
		fmt.Printf("Token expires at: %s\n", expTime.Format(time.RFC3339))
	}

	// Get token subject
	subject, err := cjwt.GetTokenSubject(customResp.Token)
	if err != nil {
		fmt.Printf("Error getting subject: %v\n", err)
	} else {
		fmt.Printf("Token subject: %s\n", subject)
	}

	// Generate random token
	randomToken, err := cjwt.GenerateRandomToken(32)
	if err != nil {
		fmt.Printf("Error generating random token: %v\n", err)
	} else {
		fmt.Printf("Random token: %s\n", randomToken)
	}

	// Hash a string
	hash := cjwt.HashSHA256("hello world")
	fmt.Printf("SHA256 hash of 'hello world': %s\n", hash)

	// Example 6: Advanced Features
	fmt.Println("\n=== Example 6: Advanced Features ===")

	// Get metrics
	metrics := jwtManager.GetMetrics()
	fmt.Printf("Generated tokens: %d\n", metrics.GeneratedTokens)
	fmt.Printf("Verified tokens: %d\n", metrics.VerifiedTokens)

	// Get audit logs
	auditLogs := jwtManager.GetAuditLogs()
	fmt.Printf("Audit logs count: %d\n", len(auditLogs))
	if len(auditLogs) > 0 {
		lastLog := auditLogs[len(auditLogs)-1]
		fmt.Printf("Last action: %s, Success: %t\n", lastLog.Action, lastLog.Success)
	}

	// Key rotation
	fmt.Println("\n--- Key Rotation ---")
	keyInfo := jwtManager.GetKeyInfo()
	fmt.Printf("Current key ID: %s, Algorithm: %s\n", keyInfo.KeyID, keyInfo.Algorithm)

	rotationReq := cjwt.KeyRotationRequest{
		Algorithm:   cjwt.RS256,
		GracePeriod: 24 * time.Hour,
	}
	rotationResp := jwtManager.RotateKey(rotationReq)
	if rotationResp.Success {
		fmt.Printf("Key rotated successfully! New key ID: %s\n", rotationResp.NewKeyID)
	} else {
		fmt.Printf("Key rotation failed: %s\n", rotationResp.Error)
	}

	// Token chunking
	fmt.Println("\n--- Token Chunking ---")
	chunkReq := cjwt.TokenChunkRequest{
		Token:        customResp.Token,
		MaxChunkSize: 100,
	}
	chunkResp := jwtManager.ChunkToken(chunkReq)
	fmt.Printf("Token chunked into %d pieces (original size: %d bytes)\n",
		chunkResp.TotalChunks, chunkResp.OriginalSize)

	// Reassemble token
	reassembleReq := cjwt.TokenReassembleRequest{
		Chunks:  chunkResp.Chunks,
		ChunkID: chunkResp.ChunkID,
	}
	reassembleResp := jwtManager.ReassembleToken(reassembleReq)
	if reassembleResp.Success {
		fmt.Printf("Token reassembled successfully (size: %d bytes)\n", reassembleResp.ReassembledSize)
		fmt.Printf("Reassembled token matches original: %t\n", reassembleResp.Token == customResp.Token)
	} else {
		fmt.Printf("Token reassembly failed: %s\n", reassembleResp.Error)
	}

	// Example 7: Different Signing Methods
	fmt.Println("\n=== Example 7: Different Signing Methods ===")

	// ECDSA example
	ecdsaPrivateKey, ecdsaPublicKey, err := cjwt.GenerateECDSAKeyPair()
	if err != nil {
		fmt.Printf("Failed to generate ECDSA keys: %v\n", err)
	} else {
		ecdsaManager := cjwt.NewJWTManagerWithECDSA(ecdsaPrivateKey, ecdsaPublicKey)
		ecdsaResp, err := ecdsaManager.GenerateToken(simpleReq)
		if err != nil {
			fmt.Printf("Failed to generate ECDSA token: %v\n", err)
		} else {
			fmt.Printf("ECDSA token generated: %s...\n", ecdsaResp.Token[:50])
		}
	}

	// HMAC example
	hmacKey, err := cjwt.DefaultHMACKey()
	if err != nil {
		fmt.Printf("Failed to generate HMAC key: %v\n", err)
	} else {
		hmacManager := cjwt.NewJWTManagerWithHMAC(hmacKey)
		hmacResp, err := hmacManager.GenerateToken(simpleReq)
		if err != nil {
			fmt.Printf("Failed to generate HMAC token: %v\n", err)
		} else {
			fmt.Printf("HMAC token generated: %s...\n", hmacResp.Token[:50])
		}
	}
}
