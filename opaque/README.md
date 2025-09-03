# Opaque Token Manager with Storage Interface

The `OpaqueTokenManager` now supports pluggable storage backends through a clean interface design. You can use memory, MySQL, PostgreSQL, or implement your own custom storage.

## 🏗️ **Architecture Overview**

### **Storage Interface**
```go
type TokenStorage interface {
    Store(ctx context.Context, token string, info *OpaqueTokenInfo) error
    Get(ctx context.Context, token string) (*OpaqueTokenInfo, error)
    Update(ctx context.Context, token string, info *OpaqueTokenInfo) error
    Delete(ctx context.Context, token string) error
    List(ctx context.Context, filters *ListFilters) ([]*OpaqueTokenInfo, error)
    CleanupExpired(ctx context.Context) (int, error)
    Close() error
}
```

### **Supported Storage Types**
- **Memory**: In-memory map storage (default)
- **MySQL**: MySQL database storage
- **PostgreSQL**: PostgreSQL database storage
- **Custom**: Implement your own storage backend

## 🚀 **Quick Start**

### **1. Memory Storage (Default)**
```go
// Create manager with default memory storage
otm := opaque.NewOpaqueTokenManager()
defer otm.Close()

// Generate token
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

fmt.Printf("Generated token: %s\n", resp.Token)
```

### **2. MySQL Storage**
```go
// MySQL configuration
config := &opaque.StorageConfig{
    Type:     "mysql",
    Host:     "localhost",
    Port:     3306,
    Database: "token_db",
    Username: "root",
    Password: "password",
    TableName: "opaque_tokens",
    MaxOpenConns: 10,
    MaxIdleConns: 5,
    ConnMaxLifetime: 30 * time.Minute,
}

// Create storage
storage, err := opaque.NewMySQLStorage(config)
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

// Create manager with MySQL storage
otm := opaque.NewOpaqueTokenManagerWithStorage(storage, 32, "mysql_")

// Use with context
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

resp, err := otm.GenerateTokenWithContext(ctx, req)
```

### **3. PostgreSQL Storage**
```go
// PostgreSQL configuration
config := &opaque.StorageConfig{
    Type:     "postgresql",
    Host:     "localhost",
    Port:     5432,
    Database: "token_db",
    Username: "postgres",
    Password: "password",
    TableName: "opaque_tokens",
    MaxOpenConns: 10,
    MaxIdleConns: 5,
    ConnMaxLifetime: 30 * time.Minute,
}

// Create storage
storage, err := opaque.NewPostgreSQLStorage(config)
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

// Create manager with PostgreSQL storage
otm := opaque.NewOpaqueTokenManagerWithStorage(storage, 48, "pg_")
```

### **4. Storage Factory**
```go
// Create storage factory
factory := &opaque.StorageFactory{}

// Create storage based on configuration
config := &opaque.StorageConfig{
    Type:     "mysql",
    Host:     "localhost",
    Port:     3306,
    Database: "token_db",
    Username: "root",
    Password: "password",
}

storage, err := factory.NewStorage(config)
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

// Create manager
otm := opaque.NewOpaqueTokenManagerWithStorage(storage, 32, "factory_")
```

## 🗄️ **Database Schema**

### **MySQL Table**
```sql
CREATE TABLE opaque_tokens (
    token VARCHAR(255) PRIMARY KEY,
    token_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    scope JSON,
    expires_at TIMESTAMP NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    not_before TIMESTAMP NULL,
    custom_data JSON,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_client_id (client_id),
    INDEX idx_expires_at (expires_at),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### **PostgreSQL Table**
```sql
CREATE TABLE opaque_tokens (
    token VARCHAR(255) PRIMARY KEY,
    token_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    scope JSONB,
    expires_at TIMESTAMP NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    not_before TIMESTAMP NULL,
    custom_data JSONB,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_opaque_tokens_user_id ON opaque_tokens (user_id);
CREATE INDEX idx_opaque_tokens_client_id ON opaque_tokens (client_id);
CREATE INDEX idx_opaque_tokens_expires_at ON opaque_tokens (expires_at);
CREATE INDEX idx_opaque_tokens_is_active ON opaque_tokens (is_active);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_opaque_tokens_updated_at
    BEFORE UPDATE ON opaque_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

## 🔧 **Custom Storage Implementation**

You can implement your own storage backend by implementing the `TokenStorage` interface:

```go
type CustomStorage struct {
    // Your storage implementation
}

func (cs *CustomStorage) Store(ctx context.Context, token string, info *OpaqueTokenInfo) error {
    // Implement storage logic
    return nil
}

func (cs *CustomStorage) Get(ctx context.Context, token string) (*OpaqueTokenInfo, error) {
    // Implement retrieval logic
    return nil, nil
}

func (cs *CustomStorage) Update(ctx context.Context, token string, info *OpaqueTokenInfo) error {
    // Implement update logic
    return nil
}

func (cs *CustomStorage) Delete(ctx context.Context, token string) error {
    // Implement deletion logic
    return nil
}

func (cs *CustomStorage) List(ctx context.Context, filters *ListFilters) ([]*OpaqueTokenInfo, error) {
    // Implement listing logic
    return nil, nil
}

func (cs *CustomStorage) CleanupExpired(ctx context.Context) (int, error) {
    // Implement cleanup logic
    return 0, nil
}

func (cs *CustomStorage) Close() error {
    // Implement cleanup logic
    return nil
}

// Use custom storage
customStorage := &CustomStorage{}
otm := opaque.NewOpaqueTokenManagerWithStorage(customStorage, 32, "custom_")
```

## 📊 **API Reference**

### **Constructor Functions**
```go
// Default memory storage
func NewOpaqueTokenManager() *OpaqueTokenManager

// Memory storage with custom config
func NewOpaqueTokenManagerWithConfig(tokenLength int, tokenPrefix string) *OpaqueTokenManager

// Custom storage
func NewOpaqueTokenManagerWithStorage(storage TokenStorage, tokenLength int, tokenPrefix string) *OpaqueTokenManager
```

### **Token Operations**
```go
// Generate token
func (otm *OpaqueTokenManager) GenerateToken(req OpaqueTokenRequest) (*OpaqueTokenResponse, error)
func (otm *OpaqueTokenManager) GenerateTokenWithContext(ctx context.Context, req OpaqueTokenRequest) (*OpaqueTokenResponse, error)

// Validate token
func (otm *OpaqueTokenManager) ValidateToken(req ValidateRequest) *ValidateResponse
func (otm *OpaqueTokenManager) ValidateTokenWithContext(ctx context.Context, req ValidateRequest) *ValidateResponse

// Revoke token
func (otm *OpaqueTokenManager) RevokeToken(req RevokeRequest) *RevokeResponse
func (otm *OpaqueTokenManager) RevokeTokenWithContext(ctx context.Context, req RevokeRequest) *RevokeResponse

// List tokens
func (otm *OpaqueTokenManager) ListTokens(req ListTokensRequest) *ListTokensResponse
func (otm *OpaqueTokenManager) ListTokensWithContext(ctx context.Context, req ListTokensRequest) *ListTokensResponse

// Cleanup expired tokens
func (otm *OpaqueTokenManager) CleanupExpiredTokens() int
func (otm *OpaqueTokenManager) CleanupExpiredTokensWithContext(ctx context.Context) int

// Get token count
func (otm *OpaqueTokenManager) GetTokenCount() int
func (otm *OpaqueTokenManager) GetTokenCountWithContext(ctx context.Context) int
```

### **Storage Management**
```go
// Close storage connection
func (otm *OpaqueTokenManager) Close() error

// Get storage interface
func (otm *OpaqueTokenManager) GetStorage() TokenStorage
```

## 🔍 **Configuration Options**

### **StorageConfig**
```go
type StorageConfig struct {
    // Storage type
    Type string // "memory", "mysql", "postgresql"
    
    // Database connection
    Host     string
    Port     int
    Database string
    Username string
    Password string
    
    // Connection pool
    MaxOpenConns    int
    MaxIdleConns    int
    ConnMaxLifetime time.Duration
    
    // Table/collection name
    TableName string
    
    // Additional options
    Options map[string]interface{}
}
```

### **ListFilters**
```go
type ListFilters struct {
    UserID   string
    ClientID string
    Active   *bool
    Limit    int
    Offset   int
}
```

## 🚨 **Error Handling**

The storage system uses structured error handling:

```go
type StorageError struct {
    Type    string
    Message string
    Err     error
}

// Error types
// - CONNECTION_ERROR
// - TABLE_CREATION_ERROR
// - STORE_ERROR
// - GET_ERROR
// - UPDATE_ERROR
// - DELETE_ERROR
// - LIST_ERROR
// - CLEANUP_ERROR
// - TOKEN_NOT_FOUND
// - UNSUPPORTED_STORAGE_TYPE
```

## 🔒 **Security Considerations**

1. **Connection Security**: Use SSL/TLS for database connections in production
2. **Credential Management**: Store database credentials securely (environment variables, secrets management)
3. **Token Security**: Opaque tokens are cryptographically secure random strings
4. **Access Control**: Implement proper database access controls
5. **Audit Logging**: Consider implementing audit logging for token operations

## 📈 **Performance Tips**

1. **Connection Pooling**: Configure appropriate connection pool sizes
2. **Indexing**: Ensure proper database indexes are created
3. **Cleanup**: Regularly clean up expired tokens
4. **Context Usage**: Use context for timeout and cancellation
5. **Batch Operations**: Consider implementing batch operations for high-volume scenarios

## 🧪 **Testing**

```go
// Test with memory storage
otm := opaque.NewOpaqueTokenManager()
defer otm.Close()

// Test with custom storage
testStorage := &TestStorage{}
otm := opaque.NewOpaqueTokenManagerWithStorage(testStorage, 32, "test_")
```

## 📝 **Examples**

See the `examples/` directory for comprehensive usage examples:
- Memory storage usage
- MySQL storage setup
- PostgreSQL storage setup
- Storage factory usage
- Custom storage implementation

## 🔄 **Migration**

To migrate from the old in-memory implementation:

1. **No API Changes**: The public API remains the same
2. **Add Storage**: Configure your preferred storage backend
3. **Update Constructor**: Use `NewOpaqueTokenManagerWithStorage()` instead of the old constructor
4. **Add Context**: Use context-aware methods for better control

The storage interface provides a clean, extensible way to manage opaque tokens with any backend you choose!

## 🧪 Testing

The opaque package includes comprehensive test coverage with 35+ tests:

### Test Coverage
- **Memory Storage**: 88-100% coverage of all operations
- **Storage Interface**: 100% coverage of interface compliance
- **Context Operations**: Full context support testing
- **Error Handling**: Comprehensive error scenario testing
- **Concurrency**: Thread safety verification
- **Custom Storage**: Example implementation and testing

### Running Tests
```bash
# Run opaque package tests
go test ./opaque -v

# Run with coverage
go test ./opaque -cover

# Run specific test categories
go test ./opaque -run TestMemoryStorage -v
go test ./opaque -run TestContext -v
go test ./opaque -run TestStorage -v
```

### Test Categories
- **Storage Tests**: All storage operations (store, get, update, delete, list, cleanup)
- **Context Tests**: Context cancellation, timeout, and concurrent operations
- **Error Tests**: Storage errors, not found scenarios, validation failures
- **Integration Tests**: OpaqueTokenManager with different storage backends
- **Custom Storage Tests**: Example custom storage implementation

### Test Files
- `opaque_test.go` - Core OpaqueTokenManager functionality
- `storage_test.go` - Storage interface and memory storage tests
- `context_test.go` - Context-aware operations and concurrency tests

## 🚀 Performance

### Benchmarks
```bash
# Run benchmarks
go test -bench=. ./opaque

# Memory allocation benchmarks
go test -benchmem -bench=. ./opaque
```

### Production Performance
- **Memory Storage**: O(1) operations with in-memory map
- **Database Storage**: Optimized queries with proper indexing
- **Connection Pooling**: Configurable connection pools for database storage
- **Context Support**: Efficient timeout and cancellation handling
- **Thread Safety**: Minimal locking overhead with RWMutex

## 🔒 Security

### Token Security
- **Cryptographically Secure**: Random token generation using crypto/rand
- **No Sensitive Data**: Tokens contain no sensitive information
- **Immediate Revocation**: Can revoke tokens instantly
- **Expiration Handling**: Automatic cleanup of expired tokens

### Storage Security
- **Connection Encryption**: Use SSL/TLS for database connections
- **Credential Management**: Store database credentials securely
- **Access Control**: Implement proper database access controls
- **Audit Logging**: Consider implementing audit logging for token operations

## 📊 Monitoring

### Storage Statistics
```go
// Get storage statistics
stats := storage.GetStats()
fmt.Printf("Storage type: %s\n", stats["storage_type"])
fmt.Printf("Total tokens: %v\n", stats["total_tokens"])
fmt.Printf("Active tokens: %v\n", stats["active_tokens"])
```

### Token Metrics
```go
// Get token count
count := otm.GetTokenCount()
fmt.Printf("Total tokens: %d\n", count)

// Cleanup expired tokens
removedCount := otm.CleanupExpiredTokens()
fmt.Printf("Removed %d expired tokens\n", removedCount)
```

## 🔧 Troubleshooting

### Common Issues

#### Database Connection Errors
```go
// Check connection configuration
config := &StorageConfig{
    Type:     "mysql",
    Host:     "localhost",
    Port:     3306,
    Database: "token_db",
    Username: "root",
    Password: "password",
}

// Test connection
storage, err := NewMySQLStorage(config)
if err != nil {
    log.Printf("Connection failed: %v", err)
}
```

#### Context Timeout Issues
```go
// Use appropriate timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

resp, err := otm.GenerateTokenWithContext(ctx, req)
if err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        log.Println("Operation timed out")
    }
}
```

#### Token Not Found Errors
```go
// Check if token exists before operations
validateResp := otm.ValidateToken(ValidateRequest{Token: token})
if !validateResp.Valid {
    log.Printf("Token validation failed: %s", validateResp.Error)
}
```

## 📚 Examples

See the `examples/` directory for comprehensive usage examples:
- Memory storage usage
- MySQL storage setup and configuration
- PostgreSQL storage setup and configuration
- Storage factory usage
- Custom storage implementation
- Context-aware operations
- Error handling patterns
