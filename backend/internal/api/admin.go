package api

import (
	"net/http"

	"github.com/shamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/shamalawy/ssh-key-manager/backend/internal/service"
)

// ------------------------------------------------------------------ users ---

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.UserAdmin.List(r.Context(), subjectFrom(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(users, len(users)))
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	user, err := s.UserAdmin.Get(r.Context(), subjectFrom(r.Context()), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req service.CreateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	user, err := s.UserAdmin.Create(r.Context(), subjectFrom(r.Context()), req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req service.UpdateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	user, err := s.UserAdmin.Update(r.Context(), subjectFrom(r.Context()), id, req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.UserAdmin.Delete(r.Context(), subjectFrom(r.Context()), id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		Password        string `json:"password"`
		MustChange      bool   `json:"must_change_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	if err := s.UserAdmin.SetPassword(r.Context(), subjectFrom(r.Context()), id,
		req.CurrentPassword, req.Password, req.MustChange); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleResetUserTOTP(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.UserAdmin.ResetTOTP(r.Context(), subjectFrom(r.Context()), id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.UserAdmin.ListRoles(r.Context(), subjectFrom(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(roles, len(roles)))
}

// handleListPermissions publishes the permission vocabulary.
//
// Without it the token screen would have to ship a hard-coded copy of the
// permission list, which would drift from the server's the first time one was
// added. The server knows; let it say.
func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	perms := authz.All
	out := make([]map[string]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, map[string]string{
			"name":  string(p),
			"group": authz.Group(p),
		})
	}
	writeJSON(w, http.StatusOK, wrapList(out, len(out)))
}

// ------------------------------------------------------------- api tokens ---

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.UserAdmin.ListTokens(r.Context(), subjectFrom(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}

	// Status is derived, so it is attached here rather than stored.
	out := make([]map[string]any, 0, len(tokens))
	for i := range tokens {
		t := tokens[i]
		out = append(out, map[string]any{
			"id": t.ID, "name": t.Name, "prefix": t.Prefix, "username": t.Username,
			"permissions": t.Permissions, "scopes": t.Scopes,
			"expires_at": t.ExpiresAt, "last_used_at": t.LastUsedAt,
			"revoked_at": t.RevokedAt, "created_at": t.CreatedAt,
			"status": t.Status(),
		})
	}
	writeJSON(w, http.StatusOK, wrapList(out, len(out)))
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req service.CreateTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	token, plaintext, err := s.UserAdmin.CreateToken(r.Context(), subjectFrom(r.Context()), req)
	if err != nil {
		writeError(w, err)
		return
	}

	// The only time the plaintext exists outside the caller's memory.
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":  token,
		"secret": plaintext,
		"notice": "This is the only time the token is shown. Store it now.",
	})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.UserAdmin.RevokeToken(r.Context(), subjectFrom(r.Context()), id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.UserAdmin.DeleteToken(r.Context(), subjectFrom(r.Context()), id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------- second factor ---

func (s *Server) handleRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TOTPCode string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	codes, err := s.Auth.RegenerateRecoveryCodes(r.Context(), subjectFrom(r.Context()), req.TOTPCode)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (s *Server) handleDisableTOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TOTPCode string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := s.Auth.DisableTOTP(r.Context(), subjectFrom(r.Context()), req.TOTPCode); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

// handleChangeOwnPassword is the self-service path.
//
// It is separate from the administrative reset because the two have different
// rules: this one demands the current password and does not set the
// change-at-next-sign-in flag, since you have just chosen the value yourself.
func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())

	var req struct {
		CurrentPassword string `json:"current_password"`
		Password        string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	if err := s.UserAdmin.SetPassword(r.Context(), subject, subject.UserID,
		req.CurrentPassword, req.Password, false); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
