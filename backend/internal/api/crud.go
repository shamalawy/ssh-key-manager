package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/shamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/shamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/shamalawy/ssh-key-manager/backend/internal/store"
)

// The editing half of the API.
//
// Every screen in this product lists things, and for a while several of them
// could only create and destroy. That is a bad shape for an operations tool:
// renaming a target, correcting a port, or turning off auto-heal became
// "delete it and put it back", which throws away the row's history and its
// assignments along with the typo. These handlers close that gap.
//
// The recurring pattern is a partial update: every field is a pointer, nil
// means "leave it alone". One endpoint then serves a rename, a retag, and a
// disable without any of them clobbering the others, and a client that has not
// heard of a new field cannot blank it.

// ---------------------------------------------------------------- targets ---

func (s *Server) handleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Name          *string         `json:"name"`
		Address       *string         `json:"address"`
		Port          *int            `json:"port"`
		Connector     *string         `json:"connector"`
		Kind          *string         `json:"kind"`
		Config        *map[string]any `json:"config"`
		CredentialID  *uuid.UUID      `json:"credential_id"`
		ClearCred     bool            `json:"clear_credential"`
		Tags          *[]string       `json:"tags"`
		Enabled       *bool           `json:"enabled"`
		IsCanary      *bool           `json:"is_canary"`
		ReconcileMode *string         `json:"reconcile_mode"`
		ClearHostPin  bool            `json:"clear_host_key_pin"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	target, err := s.Targets.Get(r.Context(), subject.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := subject.RequireScoped(authz.PermTargetWrite, target.Tags); err != nil {
		writeError(w, err)
		return
	}

	if req.Name != nil {
		target.Name = *req.Name
	}
	if req.Address != nil {
		target.Address = *req.Address
	}
	if req.Port != nil {
		target.Port = *req.Port
	}
	if req.Kind != nil {
		target.Kind = *req.Kind
	}
	if req.Connector != nil {
		if _, err := s.Registry.Get(*req.Connector); err != nil {
			writeError(w, badRequest("unknown connector %q; available: %v", *req.Connector, s.Registry.Kinds()))
			return
		}
		target.Connector = *req.Connector
	}
	if req.Config != nil {
		target.Config = *req.Config
	}
	if req.ClearCred {
		target.CredentialID = nil
	} else if req.CredentialID != nil {
		target.CredentialID = req.CredentialID
	}
	if req.Tags != nil {
		target.Tags = *req.Tags
	}
	if req.Enabled != nil {
		target.Enabled = *req.Enabled
	}
	if req.IsCanary != nil {
		target.IsCanary = *req.IsCanary
	}
	if req.ReconcileMode != nil {
		switch *req.ReconcileMode {
		case store.ReconcileReportOnly, store.ReconcileAutoHeal, store.ReconcileDisabled:
			target.ReconcileMode = *req.ReconcileMode
		default:
			writeError(w, badRequest("reconcile_mode must be one of report_only, auto_heal, disabled"))
			return
		}
	}

	updated, err := s.Targets.Update(r.Context(), target)
	if err != nil {
		writeError(w, err)
		return
	}

	// Clearing the pin is separate from the rest of the update because it is
	// the one field where "changed by mistake" means trusting a host key you
	// have not seen before. It is only ever done on request.
	if req.ClearHostPin {
		if err := s.Targets.SetHostKeyPin(r.Context(), subject.TenantID, id, ""); err != nil {
			writeError(w, err)
			return
		}
		updated.HostKeyPin = ""
	}

	s.auditSimple(r, subject, audit.ActionTargetUpdate, "target", &updated.ID, updated.Name,
		map[string]any{"address": updated.Address, "enabled": updated.Enabled,
			"host_key_pin_cleared": req.ClearHostPin})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleUpdatePrincipal(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermTargetWrite); err != nil {
		writeError(w, err)
		return
	}
	principalID, err := pathUUID(r, "principalId")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Username           *string `json:"username"`
		AuthorizedKeysPath *string `json:"authorized_keys_path"`
		UseSudo            *bool   `json:"use_sudo"`
		Enabled            *bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	principal, err := s.Targets.GetPrincipal(r.Context(), principalID)
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.Targets.Get(r.Context(), subject.TenantID, principal.TargetID); err != nil {
		writeError(w, err)
		return
	}

	if req.Username != nil {
		principal.Username = *req.Username
	}
	if req.AuthorizedKeysPath != nil {
		principal.AuthorizedKeysPath = *req.AuthorizedKeysPath
	}
	if req.UseSudo != nil {
		principal.UseSudo = *req.UseSudo
	}
	if req.Enabled != nil {
		principal.Enabled = *req.Enabled
	}

	updated, err := s.Targets.UpdatePrincipal(r.Context(), principal)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeletePrincipal(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermTargetWrite); err != nil {
		writeError(w, err)
		return
	}
	principalID, err := pathUUID(r, "principalId")
	if err != nil {
		writeError(w, err)
		return
	}

	principal, err := s.Targets.GetPrincipal(r.Context(), principalID)
	if err != nil {
		writeError(w, err)
		return
	}
	target, err := s.Targets.Get(r.Context(), subject.TenantID, principal.TargetID)
	if err != nil {
		writeError(w, err)
		return
	}

	// Deleting the login removes SKM's record of it, not the keys on the host.
	// Saying so is the difference between an operator who runs a cleanup and
	// one who believes access was withdrawn when it was not.
	if err := s.Targets.DeletePrincipal(r.Context(), principalID); err != nil {
		writeError(w, err)
		return
	}

	s.auditSimple(r, subject, audit.ActionTargetUpdate, "principal", &principalID, principal.Username,
		map[string]any{"event": "principal_deleted", "target": target.Name})
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"notice": "SKM has stopped tracking this login. Keys already on the host were not touched.",
	})
}

// ------------------------------------------------------------------- keys ---

func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.Keys.Delete(r.Context(), subject, id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------ credentials ---

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermCredentialWrite); err != nil {
		writeError(w, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	// A credential still bound to a target is a foreign key away from a
	// deployment that fails at the worst moment. Name the targets instead of
	// returning a constraint violation.
	targets, err := s.Targets.List(r.Context(), store.TargetFilter{TenantID: subject.TenantID})
	if err != nil {
		writeError(w, err)
		return
	}
	var inUse []string
	for _, t := range targets {
		if t.CredentialID != nil && *t.CredentialID == id {
			inUse = append(inUse, t.Name)
		}
	}
	if len(inUse) > 0 {
		writeError(w, badRequest("still used by %d target(s): %v", len(inUse), inUse))
		return
	}

	if err := s.Credentials.Delete(r.Context(), subject.TenantID, id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// -------------------------------------------------------------- webhooks ---

func (s *Server) handleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermWebhookWrite); err != nil {
		writeError(w, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Enabled == nil {
		writeError(w, badRequest("nothing to change"))
		return
	}

	if err := s.Webhooks.SetEnabled(r.Context(), subject.TenantID, id, *req.Enabled); err != nil {
		writeError(w, err)
		return
	}
	hook, err := s.Webhooks.Get(r.Context(), subject.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hook)
}
