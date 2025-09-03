package cjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IsValidJWTFormat checks if a string has the basic JWT format (3 parts separated by dots)
func IsValidJWTFormat(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3
}

// IsTokenExpired checks if a JWT token is expired based on its exp claim
func IsTokenExpired(token string) (bool, error) {
	// Parse without verification to get claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return false, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return false, errors.New("invalid claims format")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return false, errors.New("exp claim not found or invalid")
	}

	expTime := time.Unix(int64(exp), 0)
	return time.Now().After(expTime), nil
}

// GetTokenExpirationTime extracts the expiration time from a JWT token
func GetTokenExpirationTime(token string) (*time.Time, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims format")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("exp claim not found or invalid")
	}

	expTime := time.Unix(int64(exp), 0)
	return &expTime, nil
}

// GetTokenSubject extracts the subject from a JWT token
func GetTokenSubject(token string) (string, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims format")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("sub claim not found or invalid")
	}

	return sub, nil
}

// GenerateRandomToken generates a random token string
func GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// HashSHA256 creates a SHA256 hash of the input string
func HashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// GenerateRSAKeyPair generates a new RSA key pair for JWT signing
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// DefaultRSAKeyPair generates a 2048-bit RSA key pair (recommended for JWT)
func DefaultRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	return GenerateRSAKeyPair(2048)
}

// GenerateECDSAKeyPair generates a new ECDSA key pair for JWT signing
func GenerateECDSAKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// GenerateHMACKey generates a new HMAC key for JWT signing
func GenerateHMACKey(size int) ([]byte, error) {
	if size <= 0 {
		size = 32 // Default 256-bit key
	}
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// DefaultHMACKey generates a 256-bit HMAC key
func DefaultHMACKey() ([]byte, error) {
	return GenerateHMACKey(32)
}
