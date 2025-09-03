# Encryption Package

The `encryption` package provides comprehensive token encryption and multi-signature functionality for the CJWT library. It offers secure token encryption with multiple algorithms and multi-signature support for enhanced security.

## Features

### 🔐 Token Encryption
- **Multiple Encryption Algorithms**: AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC
- **Key Management**: Automatic key generation, rotation, and lifecycle management
- **Additional Authenticated Data (AAD)**: Support for authenticated encryption
- **Secure Key Storage**: In-memory key storage with configurable expiration

### ✍️ Multi-Signature Support
- **Multiple Signature Algorithms**: RS256, ES256, HS256, Ed25519
- **Flexible Signature Policies**: Threshold, Role-based, Weighted, All-signers
- **Individual Signature Verification**: Verify each signature independently
- **Policy Compliance**: Automatic policy validation and compliance checking

### 🛡️ Security Features
- **Constant Time Comparisons**: Prevents timing attacks
- **Secure Random Generation**: Cryptographically secure random number generation
- **Key Rotation**: Automatic and manual key rotation support
- **Expiration Handling**: Token expiration validation

## Quick Start

### Basic Encryption

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
    
    // Encrypt data
    testData := []byte("Sensitive token data")
    encryptReq := encryption.EncryptedTokenRequest{
        TokenData: testData,
        Algorithm: encryption.AES256GCM,
    }
    
    encryptResp, err := em.EncryptToken(encryptReq)
    if err != nil {
        log.Fatal(err)
    }
    
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

### Multi-Signature

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
    
    // Create multi-signature
    testData := []byte("Data to be signed")
    req := encryption.MultiSignatureRequest{
        Data:   testData,
        Signers: signers,
        Policy: policy,
    }
    
    resp, err := msm.CreateMultiSignature(req)
    if err != nil {
        log.Fatal(err)
    }
    
    // Verify multi-signature
    verifyReq := encryption.VerifyMultiSignatureRequest{
        Data:        testData,
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
    }
}
```

### Secure Token Manager

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
    
    // Create secure token with multi-signature
    tokenData := []byte("Sensitive token data")
    signers := []encryption.Signer{
        {ID: "signer1", Algorithm: encryption.RS256, Role: "approver", Weight: 1},
    }
    
    policy := encryption.SignaturePolicy{
        Type:               encryption.ThresholdPolicy,
        RequiredSignatures: 1,
    }
    
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

## API Reference

### Encryption Manager

#### `NewEncryptionManager(config *KeyManagerConfig) (*EncryptionManager, error)`
Creates a new encryption manager with the specified configuration.

#### `EncryptToken(req EncryptedTokenRequest) (*EncryptedTokenResponse, error)`
Encrypts token data using the specified algorithm.

#### `DecryptToken(req DecryptTokenRequest) (*DecryptTokenResponse, error)`
Decrypts token data using the specified key and algorithm.

#### `GetKeyInfo() map[string]interface{}`
Returns information about all encryption keys.

#### `RotateKeys() error`
Rotates all encryption keys.

### Multi-Signature Manager

#### `NewMultiSignatureManager(config *KeyManagerConfig) (*MultiSignatureManager, error)`
Creates a new multi-signature manager with the specified configuration.

#### `CreateMultiSignature(req MultiSignatureRequest) (*MultiSignatureResponse, error)`
Creates a multi-signature for the specified data and signers.

#### `VerifyMultiSignature(req VerifyMultiSignatureRequest) (*VerifyMultiSignatureResponse, error)`
Verifies a multi-signature against the specified policy.

#### `GetKeyInfo() map[string]interface{}`
Returns information about all signature keys.

### Secure Token Manager

#### `NewSecureTokenManager(config *KeyManagerConfig) (*SecureTokenManager, error)`
Creates a new secure token manager that combines encryption and multi-signature.

#### `CreateSecureToken(req SecureTokenRequest) (*SecureTokenResponse, error)`
Creates a secure token with encryption and optional multi-signature.

#### `VerifySecureToken(req VerifySecureTokenRequest) (*VerifySecureTokenResponse, error)`
Verifies a secure token including decryption and signature validation.

## Configuration

### KeyManagerConfig

```go
type KeyManagerConfig struct {
    // Default encryption algorithm
    DefaultEncryptionAlgorithm EncryptionAlgorithm
    
    // Default signature algorithm
    DefaultSignatureAlgorithm SignatureAlgorithm
    
    // Key rotation interval
    KeyRotationInterval time.Duration
    
    // Maximum key age
    MaxKeyAge time.Duration
    
    // Key storage configuration
    KeyStorage KeyStorageConfig
}
```

### Encryption Algorithms

- **AES256GCM**: AES-256 in Galois/Counter Mode (recommended)
- **ChaCha20Poly1305**: ChaCha20 stream cipher with Poly1305 MAC
- **AES256CBC**: AES-256 in Cipher Block Chaining mode

### Signature Algorithms

- **RS256**: RSA with SHA-256
- **ES256**: ECDSA with P-256 and SHA-256
- **HS256**: HMAC with SHA-256
- **Ed25519**: Ed25519 digital signature algorithm

### Signature Policies

#### Threshold Policy
Requires a minimum number of signatures.

```go
policy := SignaturePolicy{
    Type:               ThresholdPolicy,
    RequiredSignatures: 2,
}
```

#### Role-Based Policy
Requires specific roles to sign.

```go
policy := SignaturePolicy{
    Type:          RoleBasedPolicy,
    RequiredRoles: []string{"approver", "auditor"},
}
```

#### Weighted Policy
Uses weighted signatures with minimum weight requirement.

```go
policy := SignaturePolicy{
    Type:          WeightedPolicy,
    MinimumWeight: 5,
}
```

#### All Signers Policy
Requires all signers to sign.

```go
policy := SignaturePolicy{
    Type: AllSignersPolicy,
}
```

## Security Considerations

### Encryption
- Use AES-256-GCM for new implementations (recommended)
- Implement proper key rotation policies
- Store keys securely (consider HSM integration)
- Use Additional Authenticated Data (AAD) when possible

### Multi-Signature
- Choose appropriate signature policies for your use case
- Implement proper key management for signers
- Consider using different algorithms for different signers
- Validate signature policies before accepting tokens

### General
- Always validate token expiration
- Implement proper error handling
- Use constant time comparisons for security-critical operations
- Consider implementing rate limiting for signature operations

## Testing

Run the test suite:

```bash
go test ./encryption/... -v
```

Run specific tests:

```bash
go test ./encryption/... -v -run "TestEncryptionManager"
go test ./encryption/... -v -run "TestMultiSignatureManager"
go test ./encryption/... -v -run "TestSecureTokenManager"
```

## Examples

See the `examples/` directory for complete working examples:

- `examples/main.go`: Comprehensive examples of all features
- Basic encryption and decryption
- Multi-signature creation and verification
- Different encryption algorithms
- Key management operations

## Performance

The encryption package is optimized for performance:

- **Encryption**: ~1-5ms per operation (depending on algorithm and data size)
- **Multi-Signature**: ~10-50ms per signature (depending on algorithm)
- **Key Management**: Minimal overhead with in-memory storage

## Dependencies

- `golang.org/x/crypto`: For ChaCha20-Poly1305 and cryptographic utilities
- `github.com/google/uuid`: For unique key and signature IDs
- Standard library: `crypto/*` packages for core cryptographic operations

## License

This package is part of the CJWT library and follows the same license terms.
