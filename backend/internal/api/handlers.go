package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
	"github.com/hamalawy/ssh-key-manager/backend/internal/service"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// ------------------------------------------------------------------- auth ---

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	session, err := s.Auth.Login(r.Context(), store.DefaultTenantID, service.LoginRequest{
		Username:  req.Username,
		Password:  req.Password,
		TOTPCode:  req.TOTPCode,
		IPAddress: clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeError(w, err)
		return
	}

	// The SPA uses an HttpOnly cookie so the token is never reachable from
	// JavaScript; API clients use the token from the body instead.
	http.SetCookie(w, &http.Cookie{
		Name:     "skm_session",
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt,
	})

	writeJSON(w, http.StatusOK, session)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.Auth.Logout(r.Context(), subjectFrom(r.Context()), tokenFrom(r.Context())); err != nil {
		writeError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "skm_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())

	user, err := s.Users.Get(r.Context(), subject.TenantID, subject.UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	roles, err := s.Users.RoleNamesFor(r.Context(), subject.UserID)
	if err != nil {
		writeError(w, err)
		return
	}

	user.PasswordHash = ""
	user.TOTPSecret = ""
	user.RecoveryCodes = nil

	scopes := subject.Scopes
	if scopes == nil {
		scopes = []string{} // unrestricted reads as an empty list, not null
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":         user,
		"roles":        roles,
		"permissions":  subject.Permissions(),
		"scopes":       scopes,
		"mfa_verified": !subject.MFAVerifiedAt.IsZero(),
		"is_admin":     subject.IsAdmin(),
	})
}

func (s *Server) handleStepUp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TOTPCode string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	if err := s.Auth.VerifyStepUp(r.Context(), subjectFrom(r.Context()), tokenFrom(r.Context()), req.TOTPCode); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "verified",
		"valid_until": time.Now().Add(service.MFAWindow),
	})
}

func (s *Server) handleTOTPEnrol(w http.ResponseWriter, r *http.Request) {
	issuer := s.Issuer
	if issuer == "" {
		issuer = "SKM"
	}

	enrolment, err := s.Auth.EnrolTOTPWithQR(r.Context(), subjectFrom(r.Context()), issuer)
	if err != nil {
		writeError(w, err)
		return
	}

	// Shown exactly once. Enrolment is not complete until confirmed, so a user
	// who closes this page before scanning has lost nothing but the codes.
	writeJSON(w, http.StatusOK, enrolment)
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TOTPCode string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := s.Auth.ConfirmTOTP(r.Context(), subjectFrom(r.Context()), req.TOTPCode); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "enrolled"})
}

// ------------------------------------------------------------------- keys ---

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())

	filter := store.KeyFilter{
		Statuses: queryList(r, "status"),
		Classes:  queryList(r, "class"),
		Tags:     queryList(r, "tag"),
		Search:   r.URL.Query().Get("q"),
		Limit:    queryInt(r, "limit", 100),
		Offset:   queryInt(r, "offset", 0),
	}
	if days := queryInt(r, "expiring_in_days", 0); days > 0 {
		filter.ExpiringIn = time.Duration(days) * 24 * time.Hour
	}

	items, err := s.Keys.List(r.Context(), subject, filter)
	if err != nil {
		writeError(w, err)
		return
	}
	// Total reflects this page rather than the whole collection; the GUI pages
	// with limit/offset and does not yet need a full count.
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Algorithm   string   `json:"algorithm"`
		Comment     string   `json:"comment"`
		Tags        []string `json:"tags"`
		KeyClass    string   `json:"key_class"`
		ValidDays   int      `json:"valid_days"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Name == "" {
		writeError(w, badRequest("a key name is required"))
		return
	}

	genReq := service.GenerateRequest{
		Name:        req.Name,
		Description: req.Description,
		Algorithm:   req.Algorithm,
		Comment:     req.Comment,
		Tags:        req.Tags,
		KeyClass:    req.KeyClass,
	}
	if req.ValidDays > 0 {
		genReq.ValidFor = time.Duration(req.ValidDays) * 24 * time.Hour
	}

	key, err := s.Keys.Generate(r.Context(), subjectFrom(r.Context()), genReq)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, key)
}

func (s *Server) handleImportKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string   `json:"name"`
		PrivateKey string   `json:"private_key"`
		Passphrase string   `json:"passphrase"`
		Tags       []string `json:"tags"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Name == "" || req.PrivateKey == "" {
		writeError(w, badRequest("both a name and private_key are required"))
		return
	}

	material := []byte(req.PrivateKey)
	defer vault.Zero(material)

	key, err := s.Keys.Import(r.Context(), subjectFrom(r.Context()), req.Name, material, req.Passphrase, req.Tags)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, key)
}

func (s *Server) handleGetKey(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	key, err := s.Keys.Get(r.Context(), subjectFrom(r.Context()), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

func (s *Server) handleUpdateKey(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Name        string     `json:"name"`
		Description string     `json:"description"`
		Tags        []string   `json:"tags"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	key, err := s.Keys.Update(r.Context(), subjectFrom(r.Context()), id, req.Name, req.Description, req.Tags, req.ExpiresAt)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

// handleRevealKey returns private key material.
//
// A reason is required: the audit entry is far more useful with one, and asking
// for it makes the operator pause over an action that hands out a secret.
func (s *Server) handleRevealKey(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Reason == "" {
		writeError(w, badRequest("a reason is required to reveal a private key"))
		return
	}

	res, err := s.Keys.Reveal(r.Context(), subjectFrom(r.Context()), id, req.Reason)
	if err != nil {
		writeError(w, err)
		return
	}
	defer vault.Zero(res.PrivatePEM)

	writeJSON(w, http.StatusOK, map[string]any{
		"key":         res.Key,
		"private_key": string(res.PrivatePEM),
	})
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Compromised bool   `json:"compromised"`
		Reason      string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	key, err := s.Keys.Revoke(r.Context(), subjectFrom(r.Context()), id, req.Compromised, req.Reason)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

func (s *Server) handleSetKeyStatus(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	key, err := s.Keys.SetStatus(r.Context(), subjectFrom(r.Context()), id, req.Status)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

// ---------------------------------------------------------------- targets ---

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermTargetRead); err != nil {
		writeError(w, err)
		return
	}

	items, err := s.Targets.List(r.Context(), store.TargetFilter{
		TenantID:   subject.TenantID,
		Kinds:      queryList(r, "kind"),
		Tags:       queryList(r, "tag"),
		Health:     queryList(r, "health"),
		DriftState: queryList(r, "drift"),
		Search:     r.URL.Query().Get("q"),
		Limit:      queryInt(r, "limit", 200),
		Offset:     queryInt(r, "offset", 0),
	})
	if err != nil {
		writeError(w, err)
		return
	}

	// Tag scoping is applied after the query so a scoped user cannot infer the
	// existence of targets outside their scope from result counts.
	visible := make([]store.Target, 0, len(items))
	for _, t := range items {
		if subject.InScope(t.Tags) {
			visible = append(visible, t)
		}
	}
	writeJSON(w, http.StatusOK, wrapList(visible, len(visible)))
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermTargetWrite); err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Name         string         `json:"name"`
		Kind         string         `json:"kind"`
		Connector    string         `json:"connector"`
		Address      string         `json:"address"`
		Port         int            `json:"port"`
		Config       map[string]any `json:"config"`
		CredentialID *uuid.UUID     `json:"credential_id"`
		Tags         []string       `json:"tags"`
		IsCanary     bool           `json:"is_canary"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Name == "" || req.Address == "" {
		writeError(w, badRequest("both a name and address are required"))
		return
	}
	if req.Connector == "" {
		req.Connector = req.Kind
	}
	if _, err := s.Registry.Get(req.Connector); err != nil {
		writeError(w, badRequest("unknown connector %q; available: %v", req.Connector, s.Registry.Kinds()))
		return
	}

	target, err := s.Targets.Create(r.Context(), &store.Target{
		TenantID: subject.TenantID, Name: req.Name, Kind: req.Kind,
		Connector: req.Connector, Address: req.Address, Port: req.Port,
		Config: req.Config, CredentialID: req.CredentialID, Tags: req.Tags,
		Enabled: true, IsCanary: req.IsCanary, CreatedBy: &subject.UserID,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	s.auditSimple(r, subject, audit.ActionTargetCreate, "target", &target.ID, target.Name,
		map[string]any{"kind": target.Kind, "address": target.Address})
	writeJSON(w, http.StatusCreated, target)
}

func (s *Server) handleGetTarget(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermTargetRead); err != nil {
		writeError(w, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	target, err := s.Targets.Get(r.Context(), subject.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	if !subject.InScope(target.Tags) {
		writeError(w, authz.ErrOutOfScope)
		return
	}
	writeJSON(w, http.StatusOK, target)
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermTargetDelete); err != nil {
		writeError(w, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.Targets.Delete(r.Context(), subject.TenantID, id); err != nil {
		writeError(w, err)
		return
	}

	s.auditSimple(r, subject, audit.ActionTargetDelete, "target", &id, "", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleProbeTarget(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	res, err := s.Deploy.Probe(r.Context(), subjectFrom(r.Context()), id)
	if err != nil {
		// A probe failure is a legitimate answer, not a server error: report
		// the outcome with a 200 so the UI can show why it is unreachable.
		writeJSON(w, http.StatusOK, map[string]any{
			"reachable": false,
			"message":   err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListPrincipals(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermTargetRead); err != nil {
		writeError(w, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	items, err := s.Targets.ListPrincipals(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleCreatePrincipal(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermTargetWrite); err != nil {
		writeError(w, err)
		return
	}
	targetID, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Username           string `json:"username"`
		AuthorizedKeysPath string `json:"authorized_keys_path"`
		UseSudo            bool   `json:"use_sudo"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Username == "" {
		writeError(w, badRequest("a username is required"))
		return
	}

	principal, err := s.Targets.CreatePrincipal(r.Context(), &store.Principal{
		TargetID: targetID, Username: req.Username,
		AuthorizedKeysPath: req.AuthorizedKeysPath, UseSudo: req.UseSudo, Enabled: true,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, principal)
}

func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermTargetRead); err != nil {
		writeError(w, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	items, err := s.Snapshots.ListForTarget(r.Context(), subject.TenantID, id, queryInt(r, "limit", 50))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

// ------------------------------------------------------------ assignments ---

func (s *Server) handleListAssignments(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermKeyRead); err != nil {
		writeError(w, err)
		return
	}

	filter := store.AssignmentFilter{
		TenantID:    subject.TenantID,
		OnlyDrifted: r.URL.Query().Get("drifted") == "true",
		Limit:       queryInt(r, "limit", 500),
		Offset:      queryInt(r, "offset", 0),
	}
	if raw := r.URL.Query().Get("key_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, badRequest("key_id is not a valid identifier"))
			return
		}
		filter.KeyID = &id
	}
	if raw := r.URL.Query().Get("target_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, badRequest("target_id is not a valid identifier"))
			return
		}
		filter.TargetID = &id
	}

	items, err := s.Assignments.List(r.Context(), filter)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleCreateAssignment(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermKeyWrite); err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		KeyID       uuid.UUID `json:"key_id"`
		TargetID    uuid.UUID `json:"target_id"`
		PrincipalID uuid.UUID `json:"principal_id"`
		Options     []string  `json:"options"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.KeyID == uuid.Nil || req.TargetID == uuid.Nil || req.PrincipalID == uuid.Nil {
		writeError(w, badRequest("key_id, target_id, and principal_id are all required"))
		return
	}

	assignment, err := s.Assignments.Upsert(r.Context(), &store.Assignment{
		TenantID: subject.TenantID, KeyID: req.KeyID, TargetID: req.TargetID,
		PrincipalID: req.PrincipalID, Options: req.Options, CreatedBy: &subject.UserID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, assignment)
}

func (s *Server) handleDeleteAssignment(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermKeyWrite); err != nil {
		writeError(w, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.Assignments.Delete(r.Context(), subject.TenantID, id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ----------------------------------------------------------------- deploy ---

func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetID    uuid.UUID `json:"target_id"`
		PrincipalID uuid.UUID `json:"principal_id"`
		DryRun      bool      `json:"dry_run"`
		Prune       bool      `json:"prune"`
		VerifyAuth  bool      `json:"verify_auth"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.TargetID == uuid.Nil || req.PrincipalID == uuid.Nil {
		writeError(w, badRequest("both target_id and principal_id are required"))
		return
	}

	res, err := s.Deploy.Deploy(r.Context(), subjectFrom(r.Context()), req.TargetID, req.PrincipalID,
		service.DeployOptions{DryRun: req.DryRun, Prune: req.Prune, VerifyAuth: req.VerifyAuth})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "snapshotId")
	if err != nil {
		writeError(w, err)
		return
	}
	res, err := s.Deploy.Rollback(r.Context(), subjectFrom(r.Context()), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ------------------------------------------------------------ credentials ---

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermCredentialRead); err != nil {
		writeError(w, err)
		return
	}
	items, err := s.Credentials.List(r.Context(), subject.TenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermCredentialWrite); err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Name     string     `json:"name"`
		Kind     string     `json:"kind"`
		Username string     `json:"username"`
		Secret   string     `json:"secret"`
		KeyID    *uuid.UUID `json:"key_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Name == "" || req.Kind == "" {
		writeError(w, badRequest("both a name and kind are required"))
		return
	}
	if req.Secret == "" && req.KeyID == nil {
		writeError(w, badRequest("supply either a secret or a key_id"))
		return
	}

	id := uuid.New()
	var sealed *vault.Sealed
	if req.Secret != "" {
		secret := []byte(req.Secret)
		defer vault.Zero(secret)

		var err error
		sealed, err = s.Vault.Encrypt(secret, []byte(id.String()))
		if err != nil {
			writeError(w, err)
			return
		}
	}

	cred, err := s.Credentials.Create(r.Context(), &store.Credential{
		ID: id, TenantID: subject.TenantID, Name: req.Name, Kind: req.Kind,
		Username: req.Username, KeyID: req.KeyID, CreatedBy: &subject.UserID,
	}, sealed)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, cred)
}

// ------------------------------------------------------------------ audit ---

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermAuditRead); err != nil {
		writeError(w, err)
		return
	}

	filter := audit.Filter{
		TenantID:     subject.TenantID,
		Actions:      queryList(r, "action"),
		ResourceType: r.URL.Query().Get("resource_type"),
		Outcome:      audit.Outcome(r.URL.Query().Get("outcome")),
		Limit:        queryInt(r, "limit", 100),
		BeforeSeq:    int64(queryInt(r, "before_seq", 0)),
	}

	items, err := s.Audit.Query(r.Context(), filter)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermAuditVerify); err != nil {
		writeError(w, err)
		return
	}

	res, err := s.Audit.Verify(r.Context(), subject.TenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ------------------------------------------------------------------ vault ---

func (s *Server) handleVaultStatus(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermVaultStatus); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sealed":          s.Vault.IsSealed(),
		"current_version": s.Vault.CurrentVersion(),
		"known_versions":  s.Vault.Versions(),
	})
}

func (s *Server) handleRotateKEK(w http.ResponseWriter, r *http.Request) {
	count, err := s.Keys.RotateKEK(r.Context(), subjectFrom(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"keys_rewrapped": count,
		"kek_version":    s.Vault.CurrentVersion(),
	})
}

// ----------------------------------------------------------------- system ---

func (s *Server) handleListConnectors(w http.ResponseWriter, r *http.Request) {
	kinds := s.Registry.Kinds()

	out := make([]map[string]any, 0, len(kinds))
	for _, kind := range kinds {
		conn, err := s.Registry.Get(kind)
		if err != nil {
			continue
		}
		entry := map[string]any{
			"kind":         kind,
			"capabilities": conn.Capabilities(),
		}
		// A connector that describes its settings gets a real form in the
		// interface instead of a JSON text box.
		if documented, ok := conn.(connectors.Documented); ok {
			entry["settings"] = documented.Settings()
		}
		out = append(out, entry)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"connectors": out,
		"algorithms": keys.SupportedAlgorithms(),
	})
}

// handleDashboard returns the headline counters the landing page shows.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermKeyRead); err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()

	activeKeys, err := s.Keys.List(ctx, subject, store.KeyFilter{
		Statuses: []string{store.KeyStatusActive, store.KeyStatusStaged}, Limit: 500,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	expiring, err := s.Keys.List(ctx, subject, store.KeyFilter{
		ExpiringIn: 30 * 24 * time.Hour, Limit: 500,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	targets, err := s.Targets.List(ctx, store.TargetFilter{TenantID: subject.TenantID, Limit: 1000})
	if err != nil {
		writeError(w, err)
		return
	}

	drifted, err := s.Assignments.List(ctx, store.AssignmentFilter{
		TenantID: subject.TenantID, OnlyDrifted: true, Limit: 500,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	var unreachable, nonCompliant int
	for _, t := range targets {
		if t.Health == store.HealthUnreachable {
			unreachable++
		}
	}
	for _, k := range activeKeys {
		if !k.Compliant {
			nonCompliant++
		}
	}

	body := map[string]any{
		"active_keys":         len(activeKeys),
		"expiring_soon":       len(expiring),
		"targets":             len(targets),
		"unreachable_targets": unreachable,
		"drifted_assignments": len(drifted),
		"non_compliant_keys":  nonCompliant,
		"vault_sealed":        s.Vault.IsSealed(),
	}

	// The panels below are additive: a failure to read one counter should dim
	// that tile, not blank the whole dashboard.
	if running, err := s.Rotations.ListRotations(ctx, subject.TenantID, []string{
		store.RotationPlanned, store.RotationAwaiting, store.RotationStaging,
		store.RotationVerifying, store.RotationSoaking, store.RotationRetiring,
	}, 100); err == nil {
		body["active_rotations"] = len(running)

		var awaiting int
		for _, r := range running {
			if r.State == store.RotationAwaiting {
				awaiting++
			}
		}
		body["rotations_awaiting_approval"] = awaiting
	}

	if counts, err := s.Discovery.CountByState(ctx, subject.TenantID); err == nil {
		body["unmanaged_keys"] = counts[store.DiscoveredUnmanaged]
	}

	if stats, err := s.Jobs.Stats(ctx, subject.TenantID); err == nil {
		body["jobs_queued"] = stats[store.JobQueued]
		body["jobs_running"] = stats[store.JobRunning]
		body["jobs_dead"] = stats[store.JobDead]
	}

	if backups, err := s.Backups.List(ctx, subject.TenantID, 1); err == nil && len(backups) > 0 {
		body["last_backup_at"] = backups[0].CreatedAt
		body["last_backup_state"] = backups[0].State
	}

	body["scheduler_leader"] = s.Scheduler != nil && s.Scheduler.IsLeader()

	writeJSON(w, http.StatusOK, body)
}

// auditSimple records a straightforward create/update/delete.
func (s *Server) auditSimple(r *http.Request, subject *authz.Subject, action, resourceType string, resourceID *uuid.UUID, resourceName string, detail map[string]any) {
	_, _ = s.Audit.Log(r.Context(), audit.Event{
		TenantID:     subject.TenantID,
		ActorType:    audit.ActorUser,
		ActorID:      &subject.UserID,
		ActorName:    subject.Username,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Detail:       detail,
		IPAddress:    clientIP(r),
		UserAgent:    r.UserAgent(),
	})
}
