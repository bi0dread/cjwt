package opaque

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// PostgreSQLStorage implements TokenStorage using PostgreSQL database
type PostgreSQLStorage struct {
	db        *sql.DB
	tableName string
}

// NewPostgreSQLStorage creates a new PostgreSQL storage instance
func NewPostgreSQLStorage(config *StorageConfig) (*PostgreSQLStorage, error) {
	// Build connection string
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.Host,
		config.Port,
		config.Username,
		config.Password,
		config.Database,
	)

	// Open database connection
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, &StorageError{
			Type:    "CONNECTION_ERROR",
			Message: "failed to open PostgreSQL connection",
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
			Message: "failed to ping PostgreSQL database",
			Err:     err,
		}
	}

	tableName := "opaque_tokens"
	if config.TableName != "" {
		tableName = config.TableName
	}

	storage := &PostgreSQLStorage{
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
func (ps *PostgreSQLStorage) createTable() error {
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
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
		)
	`, ps.tableName)

	_, err := ps.db.Exec(query)
	if err != nil {
		return &StorageError{
			Type:    "TABLE_CREATION_ERROR",
			Message: "failed to create tokens table",
			Err:     err,
		}
	}

	// Create indexes
	indexes := []string{
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_user_id ON %s (user_id)", ps.tableName, ps.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_client_id ON %s (client_id)", ps.tableName, ps.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_expires_at ON %s (expires_at)", ps.tableName, ps.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_is_active ON %s (is_active)", ps.tableName, ps.tableName),
	}

	for _, indexQuery := range indexes {
		if _, err := ps.db.Exec(indexQuery); err != nil {
			return &StorageError{
				Type:    "INDEX_CREATION_ERROR",
				Message: "failed to create index",
				Err:     err,
			}
		}
	}

	// Create trigger for updated_at
	triggerQuery := fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION update_updated_at_column()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = CURRENT_TIMESTAMP;
			RETURN NEW;
		END;
		$$ language 'plpgsql';
		
		DROP TRIGGER IF EXISTS update_%s_updated_at ON %s;
		CREATE TRIGGER update_%s_updated_at
			BEFORE UPDATE ON %s
			FOR EACH ROW
			EXECUTE FUNCTION update_updated_at_column();
	`, ps.tableName, ps.tableName, ps.tableName, ps.tableName)

	if _, err := ps.db.Exec(triggerQuery); err != nil {
		return &StorageError{
			Type:    "TRIGGER_CREATION_ERROR",
			Message: "failed to create updated_at trigger",
			Err:     err,
		}
	}

	return nil
}

// Store stores a token with its information
func (ps *PostgreSQLStorage) Store(ctx context.Context, token string, info *OpaqueTokenInfo) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (token, token_id, user_id, client_id, scope, expires_at, issued_at, not_before, custom_data, is_active, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (token) DO UPDATE SET
			token_id = EXCLUDED.token_id,
			user_id = EXCLUDED.user_id,
			client_id = EXCLUDED.client_id,
			scope = EXCLUDED.scope,
			expires_at = EXCLUDED.expires_at,
			issued_at = EXCLUDED.issued_at,
			not_before = EXCLUDED.not_before,
			custom_data = EXCLUDED.custom_data,
			is_active = EXCLUDED.is_active,
			updated_at = CURRENT_TIMESTAMP
	`, ps.tableName)

	_, err := ps.db.ExecContext(ctx, query,
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
func (ps *PostgreSQLStorage) Get(ctx context.Context, token string) (*OpaqueTokenInfo, error) {
	query := fmt.Sprintf(`
		SELECT token_id, user_id, client_id, scope, expires_at, issued_at, not_before, custom_data, is_active, created_at
		FROM %s
		WHERE token = $1
	`, ps.tableName)

	var info OpaqueTokenInfo
	var scopeJSON []byte
	var customDataJSON []byte

	err := ps.db.QueryRowContext(ctx, query, token).Scan(
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
func (ps *PostgreSQLStorage) Update(ctx context.Context, token string, info *OpaqueTokenInfo) error {
	query := fmt.Sprintf(`
		UPDATE %s
		SET token_id = $1, user_id = $2, client_id = $3, scope = $4, expires_at = $5, issued_at = $6, not_before = $7, custom_data = $8, is_active = $9
		WHERE token = $10
	`, ps.tableName)

	result, err := ps.db.ExecContext(ctx, query,
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
func (ps *PostgreSQLStorage) Delete(ctx context.Context, token string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE token = $1`, ps.tableName)

	result, err := ps.db.ExecContext(ctx, query, token)
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
func (ps *PostgreSQLStorage) List(ctx context.Context, filters *ListFilters) ([]*OpaqueTokenInfo, error) {
	query := fmt.Sprintf(`
		SELECT token_id, user_id, client_id, scope, expires_at, issued_at, not_before, custom_data, is_active, created_at
		FROM %s
		WHERE 1=1
	`, ps.tableName)

	args := []interface{}{}
	argIndex := 1

	if filters.UserID != "" {
		query += fmt.Sprintf(" AND user_id = $%d", argIndex)
		args = append(args, filters.UserID)
		argIndex++
	}

	if filters.ClientID != "" {
		query += fmt.Sprintf(" AND client_id = $%d", argIndex)
		args = append(args, filters.ClientID)
		argIndex++
	}

	if filters.Active != nil {
		query += fmt.Sprintf(" AND is_active = $%d", argIndex)
		args = append(args, *filters.Active)
		argIndex++
	}

	query += " ORDER BY created_at DESC"

	if filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filters.Limit)
		argIndex++
	}

	if filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filters.Offset)
	}

	rows, err := ps.db.QueryContext(ctx, query, args...)
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
func (ps *PostgreSQLStorage) CleanupExpired(ctx context.Context) (int, error) {
	query := fmt.Sprintf(`DELETE FROM %s WHERE expires_at < NOW()`, ps.tableName)

	result, err := ps.db.ExecContext(ctx, query)
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
func (ps *PostgreSQLStorage) Close() error {
	if ps.db != nil {
		return ps.db.Close()
	}
	return nil
}

// GetStats returns storage statistics
func (ps *PostgreSQLStorage) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"storage_type": "postgresql",
		"table_name":   ps.tableName,
	}

	// Get connection stats
	if ps.db != nil {
		stats["max_open_conns"] = ps.db.Stats().MaxOpenConnections
		stats["open_conns"] = ps.db.Stats().OpenConnections
		stats["in_use"] = ps.db.Stats().InUse
		stats["idle"] = ps.db.Stats().Idle
	}

	return stats
}
