# Token Maker

A unified token factory that allows you to create different types of tokens (JWT, Opaque) based on your requirements.

## Features

- **Unified Interface**: Single API for creating different token types
- **JWT Support**: Full JWT token support with RS256, ES256, HS256 signing
- **Opaque Token Support**: Stateful opaque tokens with revocation capabilities
- **Flexible Configuration**: Easy configuration for different token types
- **Type Safety**: Strong typing with Go structs

## Quick Start

```go
package main

import (
    "time"
    "cjwt"
    "cjwt/tokenmaker"
)

func main() {
    // Create token maker with JWT support
    privateKey, publicKey, _ := cjwt.DefaultRSAKeyPair()
    config := &tokenmaker.TokenMakerConfig{
        JWTPrivateKey: privateKey,
        JWTPublicKey:  publicKey,
    }
    
    tm, _ := tokenmaker.NewTokenMaker(config)
    
    // Generate JWT token
    jwtReq := tokenmaker.TokenRequest{
        Type:      tokenmaker.JWT,
        UserID:    "user123",
        ExpiresAt: time.Now().Add(24 * time.Hour),
        JWTConfig: &tokenmaker.JWTConfig{
            Issuer:  "my-app",
            Subject: "user123",
        },
    }
    
    jwtResp, _ := tm.GenerateToken(jwtReq)
    fmt.Printf("JWT Token: %s\n", jwtResp.Token)
    
    // Generate Opaque token
    opaqueReq := tokenmaker.TokenRequest{
        Type:      tokenmaker.Opaque,
        UserID:    "user456",
        ExpiresAt: time.Now().Add(12 * time.Hour),
    }
    
    opaqueResp, _ := tm.GenerateToken(opaqueReq)
    fmt.Printf("Opaque Token: %s\n", opaqueResp.Token)
}
```

## Token Types

### JWT Tokens
- **Stateless**: No server-side storage required
- **Self-contained**: All information is in the token
- **Multiple Signing Methods**: RS256, ES256, HS256
- **Standard Claims**: iss, sub, aud, exp, nbf, iat, jti
- **Custom Claims**: Add any custom data

### Opaque Tokens
- **Stateful**: Stored server-side for validation
- **Revocable**: Can be revoked before expiration
- **Secure**: Random token with server-side mapping
- **Flexible**: Custom length and prefix support

## Configuration

### JWT Configuration
```go
config := &tokenmaker.TokenMakerConfig{
    JWTPrivateKey: privateKey,        // *rsa.PrivateKey, *ecdsa.PrivateKey, or []byte
    JWTPublicKey:  publicKey,         // *rsa.PublicKey, *ecdsa.PublicKey, or nil for HMAC
    DefaultJWTSigningMethod: tokenmaker.RS256,
}
```

### Opaque Configuration
```go
config := &tokenmaker.TokenMakerConfig{
    DefaultOpaqueTokenLength: 32,
    DefaultOpaqueTokenPrefix: "op_",
}
```

## API Reference

### TokenRequest
```go
type TokenRequest struct {
    Type      TokenType              // "jwt" or "opaque"
    UserID    string                 // User identifier
    ClientID  string                 // Client identifier (optional)
    Scope     []string               // Token scope (optional)
    ExpiresAt time.Time              // Expiration time
    IssuedAt  *time.Time             // Issued time (optional)
    NotBefore *time.Time             // Not before time (optional)
    CustomData map[string]interface{} // Custom data
    JWTConfig *JWTConfig             // JWT-specific config
    OpaqueConfig *OpaqueConfig       // Opaque-specific config
}
```

### TokenResponse
```go
type TokenResponse struct {
    Type      TokenType              // Token type
    Token     string                 // The generated token
    TokenID   string                 // Unique token identifier
    UserID    string                 // User ID
    ClientID  string                 // Client ID
    Scope     []string               // Token scope
    ExpiresAt time.Time              // Expiration time
    IssuedAt  time.Time              // Issued time
    CustomData map[string]interface{} // Custom data
    JWTClaims map[string]interface{} // JWT claims (JWT only)
    OpaqueInfo *OpaqueTokenInfo      // Opaque info (Opaque only)
}
```

## Examples

See the `examples/` directory for comprehensive usage examples including:
- JWT token generation and validation
- Opaque token generation, validation, and revocation
- Different signing methods (RS256, ES256, HS256)
- Custom configurations

## Testing

```bash
go test ./tokenmaker -v
```

All tests pass with comprehensive coverage of:
- JWT token operations
- Opaque token operations
- Error handling
- Different signing methods
- Token validation and revocation
