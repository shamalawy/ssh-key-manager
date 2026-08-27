package store

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// DefaultTenantID matches the tenant seeded by the initial migration. Every
// single-tenant install uses it.
var DefaultTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// isUniqueViolation reports whether err is a PostgreSQL unique constraint
// failure, so callers can turn it into ErrConflict rather than a 500.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	// Some paths wrap the error as text before it reaches here.
	return strings.Contains(err.Error(), "SQLSTATE 23505")
}

// isForeignKeyViolation reports whether err is a referenced-row failure.
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23503"
	}
	return strings.Contains(err.Error(), "SQLSTATE 23503")
}
