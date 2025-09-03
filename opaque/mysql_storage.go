package opaque

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLStorage implements TokenStorage using MySQL database
type MySQLStorage struct {
	db        *sql.DB
	tableName string
}

// NewMySQLStorage creates a new MySQL storage instance
func NewMySQLStorage(config *StorageConfig) (*MySQLStorage, error) {
	// Build connection string
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.Username,
		config.Password,
		config.Host,
		config.Port,
		config.Database,
	)

	// Open database connection
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, &StorageError{
			Type:    "CONNECTION_ERROR",
			Message: "failed to open MySQL connection",
			Err:     err,
		}
	}

	// Configure connection pool
	if config.MaxOpenConns > 0 {
		db.SetMaxOpenConns(config.MaxOpenConns)
	}
	if config.MaxIdleConns > 0 {
		db.SetMaxIdleConns(config.MaxIdleConns)
	}
	if config.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(config.ConnMaxLifetime)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, &StorageError{
			Type:    "CONNECTION_ERROR",
			Message: "failed to ping MySQL database",
			Err:     err,
		}
	}

	tableName := "opaque_tokens"
	if config.TableName != "" {
		tableName = config.TableName
	}

	storage := &MySQLStorage{
		db:        db,
		tableName: tableName,
	}

	// Create table if it doesn't exist
	if err := storage.createTable(); err != nil {
		return nil, err
	}

	return storage, nil
}

// createTable creates the tokens table if it doesn't exist
func (ms *MySQLStorage) createTable() error {
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
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
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
	`, ms.tableName)

	_, err := ms.db.Exec(query)
	if err != nil {
		return &StorageError{
			Type:    "TABLE_CREATION_ERROR",
			Message: "failed to create tokens table",
			Err:     err,
		}
	}

	return nil
}

// Store stores a token with its information
func (ms *MySQLStorage) Store(ctx context.Context, token string, info *OpaqueTokenInfo) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (token, token_id, user_id, client_id, scope, expires_at, issued_at, not_before, custom_data, is_active, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			token_id = VALUES(token_id),
			user_id = VALUES(user_id),
			client_id = VALUES(client_id),
			scope = VALUES(scope),
			expires_at = VALUES(expires_at),
			issued_at = VALUES(issued_at),
			not_before = VALUES(not_before),
			custom_data = VALUES(custom_data),
			is_active = VALUES(is_active),
			updated_at = CURRENT_TIMESTAMP
	`, ms.tableName)

	_, err := ms.db.ExecContext(ctx, query,
		token,
		info.TokenID,
		info.UserID,
		info.ClientID,
		info.Scope,
		info.ExpiresAt,
		info.IssuedAt,
		info.NotBefore,
		info.CustomData,
		info.IsActive,
		info.CreatedAt,
	)

	if err != nil {
		return &StorageError{
			Type:    "STORE_ERROR",
			Message: "failed to store token",
			Err:     err,
		}
	}

	return nil
}

// Get retrieves token information by token string
func (ms *MySQLStorage) Get(ctx context.Context, token string) (*OpaqueTokenInfo, error) {
	query := fmt.Sprintf(`
		SELECT token_id, user_id, client_id, scope, expires_at, issued_at, not_before, custom_data, is_active, created_at
		FROM %s
		WHERE token = ?
	`, ms.tableName)

	var info OpaqueTokenInfo
	var scopeJSON []byte
	var customDataJSON []byte

	err := ms.db.QueryRowContext(ctx, query, token).Scan(
		&info.TokenID,
		&info.UserID,
		&info.ClientID,
		&scopeJSON,
		&info.ExpiresAt,
		&info.IssuedAt,
		&info.NotBefore,
		&customDataJSON,
		&info.IsActive,
		&info.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, &StorageError{
				Type:    "TOKEN_NOT_FOUND",
				Message: "token not found",
			}
		}
		return nil, &StorageError{
			Type:    "GET_ERROR",
			Message: "failed to get token",
			Err:     err,
		}
	}

	// Parse JSON fields
	if err := parseJSONField(scopeJSON, &info.Scope); err != nil {
		return nil, &StorageError{
			Type:    "PARSE_ERROR",
			Message: "failed to parse scope JSON",
			Err:     err,
		}
	}

	if err := parseJSONField(customDataJSON, &info.CustomData); err != nil {
		return nil, &StorageError{
			Type:    "PARSE_ERROR",
			Message: "failed to parse custom_data JSON",
			Err:     err,
		}
	}

	return &info, nil
}

// Update updates an existing token's information
func (ms *MySQLStorage) Update(ctx context.Context, token string, info *OpaqueTokenInfo) error {
	query := fmt.Sprintf(`
		UPDATE %s
		SET token_id = ?, user_id = ?, client_id = ?, scope = ?, expires_at = ?, issued_at = ?, not_before = ?, custom_data = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP
		WHERE token = ?
	`, ms.tableName)

	result, err := ms.db.ExecContext(ctx, query,
		info.TokenID,
		info.UserID,
		info.ClientID,
		info.Scope,
		info.ExpiresAt,
		info.IssuedAt,
		info.NotBefore,
		info.CustomData,
		info.IsActive,
		token,
	)

	if err != nil {
		return &StorageError{
			Type:    "UPDATE_ERROR",
			Message: "failed to update token",
			Err:     err,
		}
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return &StorageError{
			Type:    "UPDATE_ERROR",
			Message: "failed to get rows affected",
			Err:     err,
		}
	}

	if rowsAffected == 0 {
		return &StorageError{
			Type:    "TOKEN_NOT_FOUND",
			Message: "token not found",
		}
	}

	return nil
}

// Delete removes a token from storage
func (ms *MySQLStorage) Delete(ctx context.Context, token string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE token = ?`, ms.tableName)

	result, err := ms.db.ExecContext(ctx, query, token)
	if err != nil {
		return &StorageError{
			Type:    "DELETE_ERROR",
			Message: "failed to delete token",
			Err:     err,
		}
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return &StorageError{
			Type:    "DELETE_ERROR",
			Message: "failed to get rows affected",
			Err:     err,
		}
	}

	if rowsAffected == 0 {
		return &StorageError{
			Type:    "TOKEN_NOT_FOUND",
			Message: "token not found",
		}
	}

	return nil
}

// List retrieves tokens based on filters
func (ms *MySQLStorage) List(ctx context.Context, filters *ListFilters) ([]*OpaqueTokenInfo, error) {
	query := fmt.Sprintf(`
		SELECT token_id, user_id, client_id, scope, expires_at, issued_at, not_before, custom_data, is_active, created_at
		FROM %s
		WHERE 1=1
	`, ms.tableName)

	args := []interface{}{}

	if filters.UserID != "" {
		query += " AND user_id = ?"
		args = append(args, filters.UserID)
	}

	if filters.ClientID != "" {
		query += " AND client_id = ?"
		args = append(args, filters.ClientID)
	}

	if filters.Active != nil {
		query += " AND is_active = ?"
		args = append(args, *filters.Active)
	}

	query += " ORDER BY created_at DESC"

	if filters.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filters.Limit)
	}

	if filters.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filters.Offset)
	}

	rows, err := ms.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, &StorageError{
			Type:    "LIST_ERROR",
			Message: "failed to list tokens",
			Err:     err,
		}
	}
	defer rows.Close()

	var results []*OpaqueTokenInfo

	for rows.Next() {
		var info OpaqueTokenInfo
		var scopeJSON []byte
		var customDataJSON []byte

		err := rows.Scan(
			&info.TokenID,
			&info.UserID,
			&info.ClientID,
			&scopeJSON,
			&info.ExpiresAt,
			&info.IssuedAt,
			&info.NotBefore,
			&customDataJSON,
			&info.IsActive,
			&info.CreatedAt,
		)

		if err != nil {
			return nil, &StorageError{
				Type:    "SCAN_ERROR",
				Message: "failed to scan token row",
				Err:     err,
			}
		}

		// Parse JSON fields
		if err := parseJSONField(scopeJSON, &info.Scope); err != nil {
			return nil, &StorageError{
				Type:    "PARSE_ERROR",
				Message: "failed to parse scope JSON",
				Err:     err,
			}
		}

		if err := parseJSONField(customDataJSON, &info.CustomData); err != nil {
			return nil, &StorageError{
				Type:    "PARSE_ERROR",
				Message: "failed to parse custom_data JSON",
				Err:     err,
			}
		}

		results = append(results, &info)
	}

	if err := rows.Err(); err != nil {
		return nil, &StorageError{
			Type:    "LIST_ERROR",
			Message: "failed to iterate token rows",
			Err:     err,
		}
	}

	return results, nil
}

// CleanupExpired removes expired tokens from storage
func (ms *MySQLStorage) CleanupExpired(ctx context.Context) (int, error) {
	query := fmt.Sprintf(`DELETE FROM %s WHERE expires_at < NOW()`, ms.tableName)

	result, err := ms.db.ExecContext(ctx, query)
	if err != nil {
		return 0, &StorageError{
			Type:    "CLEANUP_ERROR",
			Message: "failed to cleanup expired tokens",
			Err:     err,
		}
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, &StorageError{
			Type:    "CLEANUP_ERROR",
			Message: "failed to get rows affected",
			Err:     err,
		}
	}

	return int(rowsAffected), nil
}

// Close closes the storage connection
func (ms *MySQLStorage) Close() error {
	if ms.db != nil {
		return ms.db.Close()
	}
	return nil
}

// GetStats returns storage statistics
func (ms *MySQLStorage) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"storage_type": "mysql",
		"table_name":   ms.tableName,
	}

	// Get connection stats
	if ms.db != nil {
		stats["max_open_conns"] = ms.db.Stats().MaxOpenConnections
		stats["open_conns"] = ms.db.Stats().OpenConnections
		stats["in_use"] = ms.db.Stats().InUse
		stats["idle"] = ms.db.Stats().Idle
	}

	return stats
}
