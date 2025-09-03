# cjwt - Clean JWT Library for Go

A clean, well-structured JWT (JSON Web Token) library for Go that supports both standard JWT claims and custom claims with RSA256 signing.

## Features

- ✅ **Standard JWT Claims**: Support for all standard JWT claims (iss, sub, aud, exp, nbf, iat, jti)
- ✅ **Custom Claims**: Add any custom data to your JWT tokens
- ✅ **RSA256 Signing**: Secure token signing with RSA256 algorithm
- ✅ **Token Verification**: Full token verification with public key validation
- ✅ **Token Parsing**: Parse tokens without verification for debugging
- ✅ **Utility Functions**: Helper functions for common JWT operations
- ✅ **Clean API**: Simple, intuitive API design
- ✅ **Type Safety**: Strong typing with Go structs

## Installation

```bash
go get github.com/your-username/cjwt
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "time"
    "cjwt"
)

func main() {
    // Generate RSA key pair
    privateKey, publicKey, err := cjwt.DefaultRSAKeyPair()
    if err != nil {
        log.Fatal(err)
    }

    // Create JWT manager
    jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

    // Generate a token
    req := cjwt.JWTRequest{
        Issuer:    "my-app",
        Subject:   "user123",
        Audience:  []string{"my-api"},
        ExpiresAt: time.Now().Add(24 * time.Hour),
        CustomClaims: map[string]interface{}{
            "role": "admin",
            "permissions": []string{"read", "write"},
        },
    }

    resp, err := jwtManager.GenerateToken(req)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Generated token: %s\n", resp.Token)

    // Verify the token
    verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{Token: resp.Token})
    if verifyResp.Valid {
        fmt.Printf("Token is valid! Subject: %s\n", verifyResp.Subject)
        fmt.Printf("Custom claims: %+v\n", verifyResp.CustomClaims)
    }
}
```

## API Reference

### JWTRequest

```go
type JWTRequest struct {
    // Standard JWT Claims
    Issuer     string        `json:"iss"`           // Issuer
    Subject    string        `json:"sub"`           // Subject
    Audience   []string      `json:"aud"`           // Audience
    ExpiresAt  time.Time     `json:"exp"`           // Expiration time
    NotBefore  *time.Time    `json:"nbf,omitempty"` // Not before (optional)
    IssuedAt   *time.Time    `json:"iat,omitempty"` // Issued at (optional)
    JWTID      string        `json:"jti,omitempty"` // JWT ID (optional)
    
    // Custom Claims
    CustomClaims map[string]interface{} `json:"custom_claims,omitempty"`
}
```

### JWTResponse

```go
type JWTResponse struct {
    Token      string                 `json:"token"`       // The JWT token
    Claims     map[string]interface{} `json:"claims"`      // All claims
    ExpiresAt  time.Time              `json:"expires_at"`  // Expiration time
    IssuedAt   time.Time              `json:"issued_at"`   // Issued time
    JWTID      string                 `json:"jwt_id"`      // JWT ID
}
```

### Main Functions

#### GenerateToken
```go
func (jm *JWTManager) GenerateToken(req JWTRequest) (*JWTResponse, error)
```
Creates a new JWT token with the provided claims.

#### VerifyToken
```go
func (jm *JWTManager) VerifyToken(req VerifyRequest) *VerifyResponse
```
Verifies a JWT token and returns its claims.

#### ParseToken
```go
func (jm *JWTManager) ParseToken(req ParseRequest) *ParseResponse
```
Parses a JWT token without verification (useful for debugging).

### Utility Functions

- `IsValidJWTFormat(token string) bool` - Check if string has JWT format
- `IsTokenExpired(token string) (bool, error)` - Check if token is expired
- `GetTokenExpirationTime(token string) (*time.Time, error)` - Get expiration time
- `GetTokenSubject(token string) (string, error)` - Get subject claim
- `GenerateRandomToken(length int) (string, error)` - Generate random token
- `HashSHA256(input string) string` - Create SHA256 hash
- `GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error)` - Generate RSA keys
- `DefaultRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error)` - Generate 2048-bit RSA keys

## Examples

### Basic Token Generation
```go
req := cjwt.JWTRequest{
    Issuer:    "my-app",
    Subject:   "user123",
    Audience:  []string{"my-api"},
    ExpiresAt: time.Now().Add(24 * time.Hour),
}

resp, err := jwtManager.GenerateToken(req)
```

### Token with Custom Claims
```go
req := cjwt.JWTRequest{
    Issuer:    "my-app",
    Subject:   "user123",
    Audience:  []string{"my-api"},
    ExpiresAt: time.Now().Add(24 * time.Hour),
    CustomClaims: map[string]interface{}{
        "role": "admin",
        "permissions": []string{"read", "write", "delete"},
        "department": "engineering",
    },
}

resp, err := jwtManager.GenerateToken(req)
```

### Token Verification
```go
verifyResp := jwtManager.VerifyToken(cjwt.VerifyRequest{
    Token: "your-jwt-token-here",
})

if verifyResp.Valid {
    fmt.Printf("Subject: %s\n", verifyResp.Subject)
    fmt.Printf("Custom claims: %+v\n", verifyResp.CustomClaims)
} else {
    fmt.Printf("Token invalid: %s\n", verifyResp.Error)
}
```

## Security Notes

- Always use strong RSA keys (2048-bit minimum)
- Store private keys securely
- Validate token expiration times
- Use HTTPS in production
- Consider token refresh mechanisms for long-lived applications

## License

MIT License
