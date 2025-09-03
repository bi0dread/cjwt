# cjwt - Clean JWT Library for Go

A comprehensive, production-ready JWT (JSON Web Token) and Opaque Token library for Go with advanced encryption, multi-signature support, and pluggable storage backends. Features enterprise-grade security with multiple signing algorithms, token encryption, and flexible token management.

## Features

### 🔐 JWT Token Management
- ✅ **Standard JWT Claims**: Support for all standard JWT claims (iss, sub, aud, exp, nbf, iat, jti)
- ✅ **Custom Claims**: Add any custom data to your JWT tokens
- ✅ **Multiple Signing Algorithms**: Support for RS256, ES256, and HS256
- ✅ **Token Verification**: Full token verification with public key validation
- ✅ **Token Parsing**: Parse tokens without verification for debugging
- ✅ **Key Rotation**: Automatic key rotation with grace period support
- ✅ **Token Metrics**: Built-in metrics tracking for monitoring
- ✅ **Audit Logging**: Comprehensive audit trail for all operations
- ✅ **Token Chunking**: Split large tokens into manageable chunks

### 🗄️ Opaque Token Management
- ✅ **Stateful Tokens**: Server-side token storage with full control
- ✅ **Pluggable Storage**: Memory, MySQL, PostgreSQL, or custom storage backends
- ✅ **Context Support**: Full context.Context integration for timeouts and cancellation
- ✅ **Token Lifecycle**: Generate, validate, revoke, and cleanup tokens
- ✅ **Advanced Filtering**: List tokens by user, client, status, and more
- ✅ **Automatic Cleanup**: Remove expired tokens automatically
- ✅ **Thread Safety**: Concurrent access with proper locking

### 🏭 Token Maker Factory
- ✅ **Unified Interface**: Single API for both JWT and Opaque tokens
- ✅ **Factory Pattern**: Easy token type switching
- ✅ **Configuration Management**: Flexible configuration for different token types
- ✅ **Manager Access**: Direct access to underlying managers

### 🔐 Token Encryption & Multi-Signature
- ✅ **Token Encryption**: AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC encryption
- ✅ **Multi-Signature**: RS256, ES256, HS256, Ed25519 signature algorithms
- ✅ **Signature Policies**: Threshold, Role-based, Weighted, All-signers policies
- ✅ **Key Management**: Automatic key generation, rotation, and lifecycle management
- ✅ **Secure Token Manager**: Combined encryption and multi-signature functionality
- ✅ **Additional Authenticated Data**: Support for authenticated encryption

### 🛠️ Developer Experience
- ✅ **Utility Functions**: Helper functions for common operations
- ✅ **Clean API**: Simple, intuitive API design
- ✅ **Type Safety**: Strong typing with Go structs
- ✅ **Comprehensive Testing**: 80+ tests with excellent coverage
- ✅ **Production Ready**: Database storage, connection pooling, error handling
- ✅ **Complete Documentation**: Detailed README files and examples for each package
- ✅ **Performance Optimized**: Efficient algorithms and memory management

## Installation

```bash
go get github.com/your-username/cjwt
```

## Package Structure

The library is organized into four main packages, each providing specialized functionality:

### 📦 `cjwt` - JWT Token Management
**Core JWT functionality with enterprise features:**
- Multiple signing algorithms (RS256, ES256, HS256)
- Standard and custom JWT claims support
- Token verification and parsing
- Key rotation with grace periods
- Built-in metrics and audit logging
- Token chunking for large payloads
- Utility functions for common operations

### 📦 `cjwt/opaque` - Opaque Token Management  
**Stateful token management with pluggable storage:**
- Server-side token storage and validation
- Multiple storage backends (Memory, MySQL, PostgreSQL)
- Context-aware operations with timeout support
- Advanced filtering and token lifecycle management
- Automatic cleanup of expired tokens
- Thread-safe concurrent access

### 📦 `cjwt/encryption` - Token Encryption & Multi-Signature
**Advanced security features for high-security applications:**
- Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC)
- Multi-signature support (RS256, ES256, HS256, Ed25519)
- Flexible signature policies (Threshold, Role-based, Weighted, All-signers)
- Automatic key management and rotation
- Additional Authenticated Data (AAD) support
- Secure token manager combining encryption and signatures

### 📦 `cjwt/tokenmaker` - Token Factory
**Unified interface for all token types:**
- Factory pattern for easy token type switching
- Single API for JWT and Opaque tokens
- Flexible configuration management
- Direct access to underlying managers
- Simplified token creation and management

## Key Features Overview

### 🔒 **Security First**
- **Enterprise-grade encryption** with multiple algorithms
- **Multi-signature support** for high-security scenarios
- **Key rotation** with automatic lifecycle management
- **Constant-time comparisons** to prevent timing attacks
- **Secure random generation** for all cryptographic operations

### 🚀 **Performance Optimized**
- **Efficient algorithms** with minimal overhead
- **Concurrent access** with proper locking mechanisms
- **Memory management** optimized for production use
- **Database connection pooling** for storage backends
- **Context-aware operations** with timeout support

### 🛠️ **Developer Friendly**
- **Clean, intuitive API** with strong typing
- **Comprehensive documentation** with examples
- **Extensive test coverage** (80+ tests)
- **Multiple storage backends** for flexibility
- **Factory pattern** for easy token type switching

### 📊 **Production Ready**
- **Built-in metrics** for monitoring and observability
- **Audit logging** for compliance and debugging
- **Automatic cleanup** of expired tokens
- **Error handling** with detailed error messages
- **Database migrations** and schema management

## Quick Start

### JWT Tokens

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

### Opaque Tokens

```go
package main

import (
    "fmt"
    "log"
    "time"
    "cjwt/opaque"
)

func main() {
    // Create opaque token manager with memory storage
    otm := opaque.NewOpaqueTokenManager()
    defer otm.Close()

    // Generate opaque token
    req := opaque.OpaqueTokenRequest{
        UserID:    "user123",
        ClientID:  "client456",
        Scope:     []string{"read", "write"},
        ExpiresAt: time.Now().Add(24 * time.Hour),
        CustomData: map[string]interface{}{
            "role": "admin",
        },
    }

    resp, err := otm.GenerateToken(req)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Generated opaque token: %s\n", resp.Token)

    // Validate token
    validateResp := otm.ValidateToken(opaque.ValidateRequest{Token: resp.Token})
    if validateResp.Valid {
        fmt.Printf("Token is valid! User: %s\n", validateResp.TokenInfo.UserID)
    }

    // Revoke token
    revokeResp := otm.RevokeToken(opaque.RevokeRequest{Token: resp.Token})
    if revokeResp.Success {
        fmt.Println("Token revoked successfully!")
    }
}
```

### Token Encryption & Multi-Signature

```go
package main

import (
    "fmt"
    "log"
    "time"
    "cjwt/encryption"
)

func main() {
    // Create secure token manager
    config := &encryption.KeyManagerConfig{
        DefaultEncryptionAlgorithm: encryption.AES256GCM,
        DefaultSignatureAlgorithm:  encryption.RS256,
    }
    
    stm, err := encryption.NewSecureTokenManager(config)
    if err != nil {
        log.Fatal(err)
    }
    defer stm.Close()
    
    // Create signers for multi-signature
    signers := []encryption.Signer{
        {
            ID:        "signer1",
            Algorithm: encryption.RS256,
            Role:      "approver",
            Weight:    1,
        },
        {
            ID:        "signer2",
            Algorithm: encryption.ES256,
            Role:      "auditor",
            Weight:    1,
        },
    }
    
    // Create signature policy
    policy := encryption.SignaturePolicy{
        Type:               encryption.ThresholdPolicy,
        RequiredSignatures: 2,
        RequiredRoles:      []string{"approver", "auditor"},
    }
    
    // Create secure token
    tokenData := []byte("Sensitive token data")
    req := encryption.SecureTokenRequest{
        TokenData:            tokenData,
        EncryptionAlgorithm:  encryption.AES256GCM,
        Signers:             signers,
        SignaturePolicy:     policy,
        ExpiresAt:           time.Now().Add(24 * time.Hour),
    }
    
    resp, err := stm.CreateSecureToken(req)
    if err != nil {
        log.Fatal(err)
    }
    
    if resp.Success {
        fmt.Printf("Created secure token: %s\n", resp.EncryptedToken.TokenID)
        
        // Verify token
        verifyReq := encryption.VerifySecureTokenRequest{
            EncryptedToken: resp.EncryptedToken,
        }
        
        verifyResp, err := stm.VerifySecureToken(verifyReq)
        if err != nil {
            log.Fatal(err)
        }
        
        if verifyResp.Valid {
            fmt.Printf("Verified token data: %s\n", string(verifyResp.TokenData))
        }
    }
}
```

### Token Maker (Unified Interface)

```go
package main

import (
    "fmt"
    "log"
    "time"
    "cjwt/tokenmaker"
)

func main() {
    // Create token maker with JWT configuration
    config := &tokenmaker.TokenMakerConfig{
        JWTConfig: &tokenmaker.JWTConfig{
            PrivateKey: privateKey,
            PublicKey:  publicKey,
        },
    }

    tm, err := tokenmaker.NewTokenMaker(config)
    if err != nil {
        log.Fatal(err)
    }

    // Generate JWT token
    jwtReq := tokenmaker.TokenRequest{
        Type:      tokenmaker.JWT,
        UserID:    "user123",
        ExpiresAt: time.Now().Add(24 * time.Hour),
        CustomData: map[string]interface{}{
            "role": "admin",
        },
    }

    jwtResp, err := tm.GenerateToken(jwtReq)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Generated JWT token: %s\n", jwtResp.Token)

    // Generate Opaque token
    opaqueReq := tokenmaker.TokenRequest{
        Type:      tokenmaker.Opaque,
        UserID:    "user456",
        ExpiresAt: time.Now().Add(12 * time.Hour),
        CustomData: map[string]interface{}{
            "role": "user",
        },
    }

    opaqueResp, err := tm.GenerateToken(opaqueReq)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Generated Opaque token: %s\n", opaqueResp.Token)
}
```

## Storage Backends

### Memory Storage (Default)
```go
otm := opaque.NewOpaqueTokenManager() // Uses memory storage by default
```

### MySQL Storage
```go
config := &opaque.StorageConfig{
    Type:     "mysql",
    Host:     "localhost",
    Port:     3306,
    Database: "token_db",
    Username: "root",
    Password: "password",
}

storage, err := opaque.NewMySQLStorage(config)
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

otm := opaque.NewOpaqueTokenManagerWithStorage(storage, 32, "mysql_")
```

### PostgreSQL Storage
```go
config := &opaque.StorageConfig{
    Type:     "postgresql",
    Host:     "localhost",
    Port:     5432,
    Database: "token_db",
    Username: "postgres",
    Password: "password",
}

storage, err := opaque.NewPostgreSQLStorage(config)
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

otm := opaque.NewOpaqueTokenManagerWithStorage(storage, 48, "pg_")
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

### Advanced Features

#### Multiple Signing Methods
```go
// RSA (default)
jwtManager := cjwt.NewJWTManager(privateKey, publicKey)

// ECDSA
ecdsaManager := cjwt.NewJWTManagerWithECDSA(ecdsaPrivateKey, ecdsaPublicKey)

// HMAC
hmacManager := cjwt.NewJWTManagerWithHMAC(hmacKey)
```

#### Key Rotation
```go
rotationReq := cjwt.KeyRotationRequest{
    Algorithm:   cjwt.RS256,
    GracePeriod: 24 * time.Hour,
}
rotationResp := jwtManager.RotateKey(rotationReq)
```

#### Token Metrics
```go
metrics := jwtManager.GetMetrics()
fmt.Printf("Generated tokens: %d\n", metrics.GeneratedTokens)
```

#### Audit Logging
```go
auditLogs := jwtManager.GetAuditLogs()
for _, log := range auditLogs {
    fmt.Printf("Action: %s, Success: %t\n", log.Action, log.Success)
}
```

#### Token Chunking
```go
chunkReq := cjwt.TokenChunkRequest{
    Token:       largeToken,
    MaxChunkSize: 1000,
}
chunks := jwtManager.ChunkToken(chunkReq)

// Reassemble
reassembleReq := cjwt.TokenReassembleRequest{
    Chunks:  chunks.Chunks,
    ChunkID: chunks.ChunkID,
}
reassembled := jwtManager.ReassembleToken(reassembleReq)
```

### Utility Functions

- `IsValidJWTFormat(token string) bool` - Check if string has JWT format
- `IsTokenExpired(token string) (bool, error)` - Check if token is expired
- `GetTokenExpirationTime(token string) (*time.Time, error)` - Get expiration time
- `GetTokenSubject(token string) (string, error)` - Get subject claim
- `GenerateRandomToken(length int) (string, error)` - Generate random token
- `HashSHA256(input string) string` - Create SHA256 hash
- `GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error)` - Generate RSA keys
- `DefaultRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error)` - Generate 2048-bit RSA keys
- `GenerateECDSAKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)` - Generate ECDSA keys
- `GenerateHMACKey(size int) ([]byte, error)` - Generate HMAC key
- `DefaultHMACKey() ([]byte, error)` - Generate 256-bit HMAC key

## API Reference

### JWT Package (`cjwt`)

#### Core Functions
- `NewJWTManager(privateKey, publicKey)` - Create JWT manager with RSA keys
- `NewJWTManagerWithECDSA(privateKey, publicKey)` - Create JWT manager with ECDSA keys
- `NewJWTManagerWithHMAC(key)` - Create JWT manager with HMAC key
- `GenerateToken(request)` - Generate JWT token
- `VerifyToken(request)` - Verify JWT token
- `ParseToken(request)` - Parse JWT token without verification

#### Advanced Features
- `GetMetrics()` - Get token operation metrics
- `ResetMetrics()` - Reset metrics counters
- `GetAuditLogs()` - Get audit log entries
- `ClearAuditLogs()` - Clear audit logs
- `RotateKey(request)` - Rotate signing keys
- `GetKeyInfo()` - Get key information
- `ChunkToken(request)` - Split token into chunks
- `ReassembleToken(request)` - Reassemble token from chunks

### Opaque Package (`cjwt/opaque`)

#### Core Functions
- `NewOpaqueTokenManager()` - Create manager with memory storage
- `NewOpaqueTokenManagerWithStorage(storage)` - Create manager with custom storage
- `GenerateToken(request)` - Generate opaque token
- `ValidateToken(request)` - Validate opaque token
- `RevokeToken(request)` - Revoke opaque token
- `ListTokens(request)` - List tokens with filtering
- `CleanupExpiredTokens()` - Remove expired tokens

#### Storage Interface
- `TokenStorage` - Interface for pluggable storage backends
- `NewMemoryStorage()` - In-memory storage implementation
- `NewMySQLStorage(config)` - MySQL storage implementation
- `NewPostgreSQLStorage(config)` - PostgreSQL storage implementation

### Encryption Package (`cjwt/encryption`)

#### Core Functions
- `NewEncryptionManager(config)` - Create encryption manager
- `NewMultiSignatureManager(config)` - Create multi-signature manager
- `NewSecureTokenManager(config)` - Create secure token manager
- `EncryptToken(request)` - Encrypt token data
- `DecryptToken(request)` - Decrypt token data
- `CreateMultiSignature(request)` - Create multi-signature
- `VerifyMultiSignature(request)` - Verify multi-signature
- `CreateSecureToken(request)` - Create encrypted token with optional signatures
- `VerifySecureToken(request)` - Verify encrypted token

#### Encryption Algorithms
- `AES256GCM` - AES-256 in Galois/Counter Mode (recommended)
- `ChaCha20Poly1305` - ChaCha20 stream cipher with Poly1305 MAC
- `AES256CBC` - AES-256 in Cipher Block Chaining mode

#### Signature Algorithms
- `RS256` - RSA with SHA-256
- `ES256` - ECDSA with P-256 and SHA-256
- `HS256` - HMAC with SHA-256
- `Ed25519` - Ed25519 digital signature algorithm

#### Signature Policies
- `ThresholdPolicy` - Requires minimum number of signatures
- `RoleBasedPolicy` - Requires specific roles to sign
- `WeightedPolicy` - Uses weighted signatures with minimum weight
- `AllSignersPolicy` - Requires all signers to sign

### TokenMaker Package (`cjwt/tokenmaker`)

#### Core Functions
- `NewTokenMaker(config)` - Create token maker factory
- `GenerateToken(request)` - Generate token (JWT or Opaque)
- `ValidateToken(request)` - Validate token
- `GetJWTManager()` - Get underlying JWT manager
- `GetOpaqueManager()` - Get underlying opaque manager

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

### Encryption Examples

#### Basic Token Encryption
```go
package main

import (
    "fmt"
    "log"
    "cjwt/encryption"
)

func main() {
    // Create encryption manager
    config := &encryption.KeyManagerConfig{
        DefaultEncryptionAlgorithm: encryption.AES256GCM,
    }
    
    em, err := encryption.NewEncryptionManager(config)
    if err != nil {
        log.Fatal(err)
    }
    defer em.Close()
    
    // Encrypt sensitive data
    tokenData := []byte("Sensitive token data")
    encryptReq := encryption.EncryptedTokenRequest{
        TokenData: tokenData,
        Algorithm: encryption.AES256GCM,
    }
    
    encryptResp, err := em.EncryptToken(encryptReq)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Encrypted with key: %s\n", encryptResp.KeyID)
    
    // Decrypt data
    decryptReq := encryption.DecryptTokenRequest{
        EncryptedData: encryptResp.EncryptedData,
        Nonce:         encryptResp.Nonce,
        Tag:           encryptResp.Tag,
        Algorithm:     encryptResp.Algorithm,
        KeyID:         encryptResp.KeyID,
    }
    
    decryptResp, err := em.DecryptToken(decryptReq)
    if err != nil {
        log.Fatal(err)
    }
    
    if decryptResp.Success {
        fmt.Printf("Decrypted: %s\n", string(decryptResp.TokenData))
    }
}
```

#### Multi-Signature Example
```go
package main

import (
    "fmt"
    "log"
    "cjwt/encryption"
)

func main() {
    // Create multi-signature manager
    config := &encryption.KeyManagerConfig{
        DefaultSignatureAlgorithm: encryption.RS256,
    }
    
    msm, err := encryption.NewMultiSignatureManager(config)
    if err != nil {
        log.Fatal(err)
    }
    defer msm.Close()
    
    // Create signers
    signers := []encryption.Signer{
        {
            ID:        "approver",
            Algorithm: encryption.RS256,
            Role:      "approver",
            Weight:    1,
        },
        {
            ID:        "auditor",
            Algorithm: encryption.ES256,
            Role:      "auditor",
            Weight:    1,
        },
    }
    
    // Create signature policy
    policy := encryption.SignaturePolicy{
        Type:               encryption.ThresholdPolicy,
        RequiredSignatures: 2,
        RequiredRoles:      []string{"approver", "auditor"},
    }
    
    // Create multi-signature
    data := []byte("Transaction data to be signed")
    req := encryption.MultiSignatureRequest{
        Data:    data,
        Signers: signers,
        Policy:  policy,
    }
    
    resp, err := msm.CreateMultiSignature(req)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Created multi-signature with %d signatures\n", len(resp.Signatures))
    
    // Verify multi-signature
    verifyReq := encryption.VerifyMultiSignatureRequest{
        Data:        data,
        Signatures:  resp.Signatures,
        Policy:      resp.Policy,
        SignatureID: resp.SignatureID,
    }
    
    verifyResp, err := msm.VerifyMultiSignature(verifyReq)
    if err != nil {
        log.Fatal(err)
    }
    
    if verifyResp.Valid {
        fmt.Println("Multi-signature verification successful!")
        for _, result := range verifyResp.SignatureResults {
            fmt.Printf("Signer %s: %s\n", result.SignerID, 
                map[bool]string{true: "Valid", false: "Invalid"}[result.Valid])
        }
    }
}
```

#### Secure Token Manager Example
```go
package main

import (
    "fmt"
    "log"
    "time"
    "cjwt/encryption"
)

func main() {
    // Create secure token manager
    config := &encryption.KeyManagerConfig{
        DefaultEncryptionAlgorithm: encryption.AES256GCM,
        DefaultSignatureAlgorithm:  encryption.RS256,
    }
    
    stm, err := encryption.NewSecureTokenManager(config)
    if err != nil {
        log.Fatal(err)
    }
    defer stm.Close()
    
    // Create signers for multi-signature
    signers := []encryption.Signer{
        {
            ID:        "signer1",
            Algorithm: encryption.RS256,
            Role:      "approver",
            Weight:    1,
        },
    }
    
    // Create signature policy
    policy := encryption.SignaturePolicy{
        Type:               encryption.ThresholdPolicy,
        RequiredSignatures: 1,
    }
    
    // Create secure token
    tokenData := []byte("Sensitive token data")
    req := encryption.SecureTokenRequest{
        TokenData:           tokenData,
        EncryptionAlgorithm: encryption.AES256GCM,
        Signers:             signers,
        SignaturePolicy:     policy,
        ExpiresAt:           time.Now().Add(24 * time.Hour),
    }
    
    resp, err := stm.CreateSecureToken(req)
    if err != nil {
        log.Fatal(err)
    }
    
    if resp.Success {
        fmt.Printf("Created secure token: %s\n", resp.EncryptedToken.TokenID)
        
        // Verify token
        verifyReq := encryption.VerifySecureTokenRequest{
            EncryptedToken: resp.EncryptedToken,
        }
        
        verifyResp, err := stm.VerifySecureToken(verifyReq)
        if err != nil {
            log.Fatal(err)
        }
        
        if verifyResp.Valid {
            fmt.Printf("Verified token data: %s\n", string(verifyResp.TokenData))
        }
    }
}
```

## Testing

The library includes comprehensive test coverage with 80+ tests across all packages:

### Running Tests
```bash
# Run all tests
go test ./... -v

# Run tests with coverage
go test ./... -cover

# Run specific package tests
go test ./cjwt -v
go test ./opaque -v
go test ./encryption -v
go test ./tokenmaker -v
```

### Test Coverage
- **JWT Package**: 21 tests covering all JWT functionality
- **Opaque Package**: 35 tests covering storage interface and token management
- **Encryption Package**: 15 tests covering encryption and multi-signature functionality
- **TokenMaker Package**: 11 tests covering factory pattern and unified interface
- **Overall Coverage**: 80+ tests with excellent coverage across all packages

### Test Categories
- **Unit Tests**: Individual function testing
- **Integration Tests**: Cross-package functionality
- **Concurrency Tests**: Thread safety verification
- **Context Tests**: Timeout and cancellation handling
- **Error Handling Tests**: Comprehensive error scenarios
- **Storage Tests**: Memory, MySQL, PostgreSQL storage backends
- **Encryption Tests**: Multiple encryption algorithms and key management
- **Multi-Signature Tests**: Signature policies and verification
- **Security Tests**: Cryptographic operations and key rotation

## Performance

### Benchmarks
```bash
# Run benchmarks
go test -bench=. ./...

# Memory allocation benchmarks
go test -benchmem -bench=. ./...
```

### Production Considerations
- **Connection Pooling**: Database storage includes configurable connection pools
- **Context Support**: All operations support context for timeouts and cancellation
- **Thread Safety**: All storage implementations are thread-safe
- **Memory Management**: Efficient memory usage with proper cleanup
- **Error Handling**: Comprehensive error handling with structured error types

## Security Notes

### JWT Security
- Always use strong RSA keys (2048-bit minimum)
- Store private keys securely
- Validate token expiration times
- Use HTTPS in production
- Consider token refresh mechanisms for long-lived applications

### Opaque Token Security
- Use cryptographically secure random token generation
- Implement proper token revocation mechanisms
- Store tokens securely in database
- Use connection encryption for database storage
- Implement proper access controls

### Encryption & Multi-Signature Security
- Use AES-256-GCM for new implementations (recommended)
- Implement proper key rotation policies
- Store encryption keys securely (consider HSM integration)
- Use Additional Authenticated Data (AAD) when possible
- Choose appropriate signature policies for your use case
- Implement proper key management for signers
- Consider using different algorithms for different signers
- Validate signature policies before accepting tokens

### General Security
- Validate all input data
- Use context timeouts to prevent resource exhaustion
- Implement proper logging and monitoring
- Regular security audits and updates

## Use Cases

### 🔐 **Authentication & Authorization**
- **JWT Tokens**: Stateless authentication for web APIs and microservices
- **Opaque Tokens**: Stateful session management with server-side control
- **Multi-Signature**: High-security authentication requiring multiple approvals
- **Token Encryption**: Sensitive data protection in transit and at rest

### 🏢 **Enterprise Applications**
- **Financial Systems**: Multi-signature transactions and audit trails
- **Healthcare**: HIPAA-compliant token management with encryption
- **Government**: High-security applications with role-based access
- **E-commerce**: Secure payment processing and user session management

### 🚀 **Microservices Architecture**
- **Service-to-Service**: JWT tokens for inter-service communication
- **API Gateway**: Centralized token validation and management
- **Distributed Systems**: Consistent token handling across services
- **Event-Driven**: Token-based event authentication and authorization

### 🔒 **High-Security Scenarios**
- **Blockchain**: Multi-signature wallet operations
- **Cryptocurrency**: Secure transaction signing and validation
- **Military/Defense**: Classified data access with multiple approvals
- **Critical Infrastructure**: Industrial control systems with audit trails

### 📊 **Monitoring & Compliance**
- **Audit Logging**: Comprehensive operation tracking for compliance
- **Metrics**: Real-time monitoring of token operations
- **Key Rotation**: Automated security key lifecycle management
- **Token Chunking**: Large payload handling for complex systems

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License
