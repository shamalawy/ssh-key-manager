// Package api exposes SKM over HTTP.
//
// Handlers stay thin: parse, authorise via the service layer, encode. All
// business logic lives in internal/service, so the same operations are
// reachable from the CLI and the job workers without going through HTTP.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/backup"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/consumers"
	"github.com/hamalawy/ssh-key-manager/backend/internal/service"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// ErrorBody is the uniform error shape every failure returns.
type ErrorBody struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// writeJSON encodes a successful response.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("encoding response", "error", err)
	}
}

// writeError maps a domain error onto an HTTP status.
//
// The mapping lives in one place so a new handler cannot accidentally turn a
// permission denial into a 500 — or worse, leak an internal message as one.
func writeError(w http.ResponseWriter, err error) {
	status, code := http.StatusInternalServerError, "internal_error"
	message := "an internal error occurred"

	switch {
	case errors.Is(err, authz.ErrDenied):
		status, code, message = http.StatusForbidden, "permission_denied", err.Error()
	case errors.Is(err, authz.ErrMFARequired):
		status, code, message = http.StatusForbidden, "mfa_required", err.Error()
	case errors.Is(err, authz.ErrOutOfScope):
		status, code, message = http.StatusForbidden, "out_of_scope", err.Error()
	case errors.Is(err, service.ErrSessionInvalid):
		status, code, message = http.StatusUnauthorized, "unauthenticated", err.Error()
	case errors.Is(err, service.ErrPasswordChangeRequired):
		status, code, message = http.StatusForbidden, "password_change_required", err.Error()
	case errors.Is(err, service.ErrInvalidCredentials):
		status, code, message = http.StatusUnauthorized, "invalid_credentials", err.Error()
	case errors.Is(err, service.ErrMFARequired):
		status, code, message = http.StatusUnauthorized, "mfa_required", err.Error()
	case errors.Is(err, service.ErrAccountLocked):
		status, code, message = http.StatusTooManyRequests, "account_locked", err.Error()
	case errors.Is(err, store.ErrNotFound):
		status, code, message = http.StatusNotFound, "not_found", err.Error()
	case errors.Is(err, store.ErrConflict):
		status, code, message = http.StatusConflict, "conflict", err.Error()
	case errors.Is(err, vault.ErrSealed):
		status, code, message = http.StatusServiceUnavailable, "vault_sealed",
			"the vault is sealed; unseal it before performing key operations"
	case errors.Is(err, connectors.ErrWouldLockOut):
		status, code, message = http.StatusConflict, "would_lock_out", err.Error()
	case errors.Is(err, connectors.ErrDeviceRejected):
		// The device answered, and its answer was no. 422 rather than 500: the
		// server worked correctly, and the message carries what the device said.
		status, code, message = http.StatusUnprocessableEntity, "device_rejected", err.Error()
	case errors.Is(err, connectors.ErrUnsupported):
		status, code, message = http.StatusBadRequest, "unsupported", err.Error()
	case errors.Is(err, service.ErrBadUser):
		// Every one of these is something the administrator can correct: a
		// short password, an unknown role, or a guard refusing to remove the
		// last administrator. None of them is a server fault.
		status, code, message = http.StatusBadRequest, "invalid_request", err.Error()
	case errors.Is(err, service.ErrKeyDeployed):
		status, code, message = http.StatusConflict, "key_in_use", err.Error()
	case errors.Is(err, service.ErrBadRotation):
		status, code, message = http.StatusConflict, "invalid_rotation", err.Error()
	case errors.Is(err, backup.ErrWrongPassphrase):
		// Not a 500: the operator typed the wrong passphrase, and telling them
		// so is the whole point. The message deliberately does not distinguish
		// a wrong passphrase from a corrupt archive, because AES-GCM cannot.
		status, code, message = http.StatusBadRequest, "wrong_passphrase", err.Error()
	case errors.Is(err, backup.ErrNotAnArchive):
		status, code, message = http.StatusBadRequest, "not_an_archive", err.Error()
	case errors.Is(err, backup.ErrUnsupportedVersion):
		status, code, message = http.StatusBadRequest, "unsupported_archive", err.Error()
	case errors.Is(err, consumers.ErrDelivery):
		// Same reasoning as a device rejection: the destination answered, and
		// its answer was no. A 500 here would hide the one useful sentence.
		status, code, message = http.StatusUnprocessableEntity, "delivery_failed", err.Error()
	case errors.Is(err, consumers.ErrConfig), errors.Is(err, consumers.ErrUnsupported):
		status, code, message = http.StatusBadRequest, "invalid_consumer", err.Error()
	case errors.Is(err, errBadRequest):
		status, code = http.StatusBadRequest, "bad_request"
		// Strip the sentinel prefix so the client sees only the explanation.
		message = strings.TrimPrefix(err.Error(), errBadRequest.Error()+": ")
	case errors.Is(err, context.Canceled):
		// The client gave up. Nothing is wrong here, and there is nobody left
		// to read the response; 499 is the conventional code for it.
		status, code, message = 499, "client_closed_request", "the client closed the request"
	case errors.Is(err, context.DeadlineExceeded):
		status, code, message = http.StatusGatewayTimeout, "timeout", "the operation timed out"
	default:
		// Unmapped errors are logged in full but reported opaquely, so an
		// internal message never becomes part of the public API.
		slog.Error("unhandled error", "error", err)
	}

	writeJSON(w, status, ErrorBody{Error: message, Code: code})
}

// errBadRequest marks input-validation failures.
var errBadRequest = errors.New("bad request")

// badRequest wraps a message as a client error.
func badRequest(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errBadRequest, fmt.Sprintf(format, args...))
}

// decodeJSON reads a request body, rejecting unknown fields so a typo in a
// client payload is reported rather than silently ignored.
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return badRequest("could not parse the request body: %v", err)
	}
	return nil
}

// pathUUID extracts and parses a UUID path parameter.
func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	raw := r.PathValue(name)
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, badRequest("%s is not a valid identifier", name)
	}
	return id, nil
}

// queryInt reads an integer query parameter.
func queryInt(r *http.Request, name string, def int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

// queryList reads a repeated or comma-separated query parameter.
func queryList(r *http.Request, name string) []string {
	values := r.URL.Query()[name]
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// listResponse is the envelope for collections.
type listResponse[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

// wrapList builds a collection envelope, normalising nil to an empty array so
// clients never have to distinguish null from [].
func wrapList[T any](items []T, total int) listResponse[T] {
	if items == nil {
		items = []T{}
	}
	return listResponse[T]{Items: items, Total: total}
}
