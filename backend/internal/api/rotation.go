package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/shamalawy/ssh-key-manager/backend/internal/cronx"
	"github.com/shamalawy/ssh-key-manager/backend/internal/service"
	"github.com/shamalawy/ssh-key-manager/backend/internal/store"
)

// --------------------------------------------------------------- rotations ---

func (s *Server) handleListRotations(w http.ResponseWriter, r *http.Request) {
	items, err := s.Rotation.List(r.Context(), subjectFrom(r.Context()),
		queryList(r, "state"), queryInt(r, "limit", 50))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleGetRotation(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	rotation, targets, err := s.Rotation.Get(r.Context(), subjectFrom(r.Context()), id)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"rotation": rotation,
		"targets":  targets,
	})
}

// handlePlanRotation resolves what a rotation would do without doing it.
func (s *Server) handlePlanRotation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		// A pointer so an explicit 0 ("no soak") is distinguishable from the
		// field being omitted ("use the default").
		SoakHours        *int `json:"soak_hours"`
		CanaryPercent    int  `json:"canary_percent"`
		FailureThreshold int  `json:"failure_threshold"`
		ApprovalRequired bool `json:"approval_required"`
		DryRun           bool `json:"dry_run"`
		// Start begins the rotation immediately after planning, which is what
		// the interface's one-click path uses.
		Start bool `json:"start"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	keyID, err := uuid.Parse(req.KeyID)
	if err != nil {
		writeError(w, badRequest("key_id must be a UUID"))
		return
	}

	var soak *time.Duration
	if req.SoakHours != nil {
		d := time.Duration(*req.SoakHours) * time.Hour
		soak = &d
	}

	subject := subjectFrom(r.Context())
	plan, err := s.Rotation.Plan(r.Context(), subject, service.PlanRequest{
		KeyID:            keyID,
		Trigger:          store.TriggerAPI,
		Algorithm:        req.Algorithm,
		SoakPeriod:       soak,
		CanaryPercent:    req.CanaryPercent,
		FailureThreshold: req.FailureThreshold,
		ApprovalRequired: req.ApprovalRequired,
		DryRun:           req.DryRun,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	if req.Start && !req.ApprovalRequired {
		started, err := s.Rotation.Start(r.Context(), subject, plan.Rotation.ID)
		if err != nil {
			writeError(w, err)
			return
		}
		plan.Rotation = started
	}

	writeJSON(w, http.StatusCreated, plan)
}

func (s *Server) handleStartRotation(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	rotation, err := s.Rotation.Start(r.Context(), subjectFrom(r.Context()), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, rotation)
}

func (s *Server) handleApproveRotation(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	rotation, err := s.Rotation.Approve(r.Context(), subjectFrom(r.Context()), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rotation)
}

func (s *Server) handleAbortRotation(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &req)

	rotation, err := s.Rotation.Abort(r.Context(), subjectFrom(r.Context()), id, req.Reason)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rotation)
}

// ---------------------------------------------------------------- policies ---

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permRotationRead); err != nil {
		writeError(w, err)
		return
	}

	items, err := s.Rotations.ListPolicies(r.Context(), subject.TenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permRotationWrite); err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Name             string   `json:"name"`
		Enabled          bool     `json:"enabled"`
		CronExpr         string   `json:"cron_expr"`
		MaxAgeDays       int      `json:"max_age_days"`
		Algorithm        string   `json:"algorithm"`
		SoakHours        int      `json:"soak_hours"`
		CanaryPercent    int      `json:"canary_percent"`
		FailureThreshold int      `json:"failure_threshold"`
		ApprovalRequired bool     `json:"approval_required"`
		KeyTags          []string `json:"key_tags"`
		TargetTags       []string `json:"target_tags"`
		KeyClass         string   `json:"key_class"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Name == "" {
		writeError(w, badRequest("a policy name is required"))
		return
	}

	// Validate the schedule here rather than discovering at 3am that the
	// policy has silently never fired.
	var nextRun *time.Time
	if req.CronExpr != "" {
		next, err := cronx.NextAfter(req.CronExpr, time.Now())
		if err != nil {
			writeError(w, badRequest("%v", err))
			return
		}
		nextRun = &next
	} else {
		next := time.Now().Add(time.Hour)
		nextRun = &next
	}

	soak := int64((time.Duration(req.SoakHours) * time.Hour).Seconds())
	if soak == 0 {
		soak = int64((24 * time.Hour).Seconds())
	}

	policy, err := s.Rotations.CreatePolicy(r.Context(), &store.RotationPolicy{
		TenantID:  subject.TenantID,
		Name:      req.Name,
		Enabled:   req.Enabled,
		CronExpr:  req.CronExpr,
		MaxAgeSec: int64(req.MaxAgeDays) * 24 * 3600,
		Algorithm: req.Algorithm,
		Selector: store.Selector{
			KeyTags: req.KeyTags, TargetTags: req.TargetTags, KeyClass: req.KeyClass,
		},
		SoakPeriodSec:    soak,
		CanaryPercent:    req.CanaryPercent,
		FailureThreshold: req.FailureThreshold,
		ApprovalRequired: req.ApprovalRequired,
		NextRunAt:        nextRun,
		CreatedBy:        &subject.UserID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, policy)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permRotationWrite); err != nil {
		writeError(w, err)
		return
	}

	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.Rotations.DeletePolicy(r.Context(), subject.TenantID, id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// handlePreviewSchedule answers "when would this fire?" for the policy editor.
func (s *Server) handlePreviewSchedule(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expr")
	if expr == "" {
		writeError(w, badRequest("an expr query parameter is required"))
		return
	}

	schedule, err := cronx.Parse(expr)
	if err != nil {
		writeError(w, badRequest("%v", err))
		return
	}

	next := make([]time.Time, 0, 5)
	at := time.Now()
	for i := 0; i < 5; i++ {
		at = schedule.Next(at)
		if at.IsZero() {
			break
		}
		next = append(next, at)
	}

	writeJSON(w, http.StatusOK, map[string]any{"expr": expr, "next_runs": next})
}
