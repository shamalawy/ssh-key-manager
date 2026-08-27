package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/shamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/shamalawy/ssh-key-manager/backend/internal/events"
	"github.com/shamalawy/ssh-key-manager/backend/internal/service"
	"github.com/shamalawy/ssh-key-manager/backend/internal/store"
)

// Permissions referenced by handlers in this file, aliased so the routing table
// reads without an import prefix on every line.
const (
	permRotationRead  = authz.PermRotationRead
	permRotationWrite = authz.PermRotationWrite
	permJobRead       = authz.PermJobRead
	permJobCancel     = authz.PermJobCancel
	permWebhookRead   = authz.PermWebhookRead
	permWebhookWrite  = authz.PermWebhookWrite
	permTargetRead    = authz.PermTargetRead
	permReconcileRun  = authz.PermReconcileRun
)

// ---------------------------------------------------------------- jobs ---

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permJobRead); err != nil {
		writeError(w, err)
		return
	}

	filter := store.JobFilter{
		TenantID: subject.TenantID,
		States:   queryList(r, "state"),
		Types:    queryList(r, "type"),
		Limit:    queryInt(r, "limit", 100),
	}
	if v := r.URL.Query().Get("rotation_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, badRequest("rotation_id must be a UUID"))
			return
		}
		filter.RotationID = &id
	}

	items, err := s.Jobs.List(r.Context(), filter)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permJobRead); err != nil {
		writeError(w, err)
		return
	}

	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	job, err := s.Jobs.Get(r.Context(), subject.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// handleJobLogs streams a job's progress lines forward from a cursor.
func (s *Server) handleJobLogs(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permJobRead); err != nil {
		writeError(w, err)
		return
	}

	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	after := int64(0)
	if v := r.URL.Query().Get("after"); v != "" {
		after, _ = strconv.ParseInt(v, 10, 64)
	}

	logs, err := s.Jobs.Logs(r.Context(), id, after, queryInt(r, "limit", 200))
	if err != nil {
		writeError(w, err)
		return
	}

	cursor := after
	if len(logs) > 0 {
		cursor = logs[len(logs)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": logs, "cursor": cursor})
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permJobCancel); err != nil {
		writeError(w, err)
		return
	}

	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.Jobs.Cancel(r.Context(), subject.TenantID, id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": id})
}

// --------------------------------------------------------------- reconcile ---

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())

	var req struct {
		TargetID string `json:"target_id"`
		Async    bool   `json:"async"`
	}
	_ = decodeJSON(r, &req)

	var targetID *uuid.UUID
	if req.TargetID != "" {
		id, err := uuid.Parse(req.TargetID)
		if err != nil {
			writeError(w, badRequest("target_id must be a UUID"))
			return
		}
		targetID = &id
	}

	// A fleet sweep is slow enough that doing it inside a request would time
	// out; queue it and hand back the job to watch.
	if req.Async || targetID == nil {
		job, err := s.Worker.EnqueueReconcile(r.Context(), subject, targetID)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, job)
		return
	}

	result, err := s.Reconcile.Reconcile(r.Context(), subject, *targetID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleListDiscovered(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())

	filter := store.DiscoveryFilter{
		States: queryList(r, "state"),
		Limit:  queryInt(r, "limit", 200),
	}
	if v := r.URL.Query().Get("target_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, badRequest("target_id must be a UUID"))
			return
		}
		filter.TargetID = &id
	}

	items, err := s.Reconcile.ListDiscovered(r.Context(), subject, filter)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleAdoptKey(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	_ = decodeJSON(r, &req)

	key, err := s.Reconcile.Adopt(r.Context(), subjectFrom(r.Context()), id, req.Name)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, key)
}

func (s *Server) handleIgnoreDiscovered(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	item, err := s.Reconcile.Ignore(r.Context(), subjectFrom(r.Context()), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// ---------------------------------------------------------------- backups ---

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	items, err := s.Backup.List(r.Context(), subjectFrom(r.Context()), queryInt(r, "limit", 50))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		Kind       string `json:"kind"`
		Passphrase string `json:"passphrase"`
		RetainDays int    `json:"retain_days"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	record, err := s.Backup.Create(r.Context(), subjectFrom(r.Context()), service.CreateRequest{
		Name:       req.Name,
		Kind:       req.Kind,
		Passphrase: req.Passphrase,
		RetainFor:  time.Duration(req.RetainDays) * 24 * time.Hour,
	})
	// The passphrase must not survive the request in any form.
	req.Passphrase = ""
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (s *Server) handleVerifyBackup(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	result, err := s.Backup.Verify(r.Context(), subjectFrom(r.Context()), id, req.Passphrase)
	req.Passphrase = ""
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BackupID   string `json:"backup_id"`
		Path       string `json:"path"`
		Passphrase string `json:"passphrase"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	subject := subjectFrom(r.Context())
	path := req.Path

	// Restoring by identifier is the normal path; an explicit path is for
	// restoring an archive copied in from elsewhere.
	if req.BackupID != "" {
		id, err := uuid.Parse(req.BackupID)
		if err != nil {
			writeError(w, badRequest("backup_id must be a UUID"))
			return
		}
		record, err := s.Backups.Get(r.Context(), subject.TenantID, id)
		if err != nil {
			writeError(w, err)
			return
		}
		path = record.Location
	}
	if path == "" {
		writeError(w, badRequest("either backup_id or path is required"))
		return
	}

	result, err := s.Backup.Restore(r.Context(), subject, path, req.Passphrase)
	req.Passphrase = ""
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.Backup.Delete(r.Context(), subjectFrom(r.Context()), id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// -------------------------------------------------------------- consumers ---

func (s *Server) handleListConsumers(w http.ResponseWriter, r *http.Request) {
	var keyID *uuid.UUID
	if v := r.URL.Query().Get("key_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, badRequest("key_id must be a UUID"))
			return
		}
		keyID = &id
	}

	items, err := s.Consumers.List(r.Context(), subjectFrom(r.Context()), keyID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleCreateConsumer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string         `json:"name"`
		Kind    string         `json:"kind"`
		KeyID   string         `json:"key_id"`
		Config  map[string]any `json:"config"`
		Enabled bool           `json:"enabled"`
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

	created, err := s.Consumers.Create(r.Context(), subjectFrom(r.Context()), &store.Consumer{
		Name: req.Name, Kind: req.Kind, KeyID: keyID,
		Config: req.Config, Enabled: req.Enabled,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleDeliverConsumer(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.Consumers.Redeliver(r.Context(), subjectFrom(r.Context()), id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"delivered": id})
}

// handleRebindConsumer points a client at a different key and delivers it.
// The delivery happens first: a client is never recorded as holding a key it
// was not actually given.
func (s *Server) handleRebindConsumer(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req struct {
		KeyID uuid.UUID `json:"key_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.KeyID == uuid.Nil {
		writeError(w, badRequest("key_id is required"))
		return
	}
	if err := s.Consumers.Rebind(r.Context(), subjectFrom(r.Context()), id, req.KeyID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"delivered": id, "key_id": req.KeyID})
}

func (s *Server) handleDeleteConsumer(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.Consumers.Delete(r.Context(), subjectFrom(r.Context()), id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// --------------------------------------------------------------- webhooks ---

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permWebhookRead); err != nil {
		writeError(w, err)
		return
	}

	items, err := s.Webhooks.List(r.Context(), subject.TenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permWebhookWrite); err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Name    string            `json:"name"`
		URL     string            `json:"url"`
		Events  []string          `json:"events"`
		Headers map[string]string `json:"headers"`
		Enabled bool              `json:"enabled"`
		Secret  string            `json:"secret"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Name == "" || req.URL == "" {
		writeError(w, badRequest("a webhook needs a name and a url"))
		return
	}

	// An unsigned webhook lets anything that can reach the endpoint forge SKM
	// events, so one is generated when the caller supplies none.
	secret := req.Secret
	generated := false
	if secret == "" {
		secret = events.NewSecret()
		generated = true
	}

	id := uuid.New()
	sealed, err := s.Vault.Encrypt([]byte(secret), []byte(id.String()))
	if err != nil {
		writeError(w, err)
		return
	}

	created, err := s.Webhooks.Create(r.Context(), &store.Webhook{
		ID: id, TenantID: subject.TenantID, Name: req.Name, URL: req.URL,
		Events: req.Events, Headers: req.Headers, Enabled: req.Enabled,
	}, sealed)
	if err != nil {
		writeError(w, err)
		return
	}

	body := map[string]any{"webhook": created}
	if generated {
		// Shown exactly once, at creation. It cannot be retrieved afterwards.
		body["secret"] = secret
		body["note"] = "store this signing secret now; it is not shown again"
	}
	writeJSON(w, http.StatusCreated, body)
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permWebhookWrite); err != nil {
		writeError(w, err)
		return
	}

	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.Webhooks.Delete(r.Context(), subject.TenantID, id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleListDeliveries(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permWebhookRead); err != nil {
		writeError(w, err)
		return
	}

	var webhookID *uuid.UUID
	if v := r.URL.Query().Get("webhook_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, badRequest("webhook_id must be a UUID"))
			return
		}
		webhookID = &id
	}

	items, err := s.Webhooks.ListDeliveries(r.Context(), subject.TenantID, webhookID, queryInt(r, "limit", 100))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wrapList(items, len(items)))
}

func (s *Server) handleReplayDelivery(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permWebhookWrite); err != nil {
		writeError(w, err)
		return
	}

	id, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.Webhooks.ReplayDelivery(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": id})
}

func (s *Server) handleListEventTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": events.All})
}

// --------------------------------------------------------------- SSE stream ---

// handleEventStream pushes events to the browser over Server-Sent Events.
//
// SSE rather than WebSockets: the traffic is one-directional, it survives
// proxies that mangle upgrades, and the browser reconnects on its own.
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermKeyRead); err != nil {
		writeError(w, err)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, fmt.Errorf("service: streaming is not supported by this server"))
		return
	}

	// The server's write timeout would otherwise cut a healthy stream off at
	// the same interval as a stalled request. A stream has no deadline.
	if rc := http.NewResponseController(w); rc != nil {
		if err := rc.SetWriteDeadline(time.Time{}); err != nil {
			s.Log.Debug("clearing the write deadline for an event stream", "error", err)
		}
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache, no-store")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	sub := s.Events.Bus().Subscribe(128)
	defer sub.Close()

	fmt.Fprint(w, "retry: 3000\n\n")
	flusher.Flush()

	// A heartbeat keeps intermediaries from closing an idle connection and
	// tells the browser the stream is alive rather than merely quiet.
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case <-heartbeat.C:
			fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()

		case ev, open := <-sub.C:
			if !open {
				return
			}
			if ev.TenantID != subject.TenantID {
				continue
			}

			payload, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\nid: %s\ndata: %s\n\n", ev.Type, ev.ID, payload)
			flusher.Flush()
		}
	}
}

// -------------------------------------------------------------- inventory ---

// handleAnsibleInventory renders a dynamic inventory for ansible-inventory.
//
// Groups come from target tags, which is the mapping that makes an existing
// tag scheme usable from Ansible without maintaining a second one.
func (s *Server) handleAnsibleInventory(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permTargetRead); err != nil {
		writeError(w, err)
		return
	}

	targets, err := s.Targets.List(r.Context(), store.TargetFilter{
		TenantID: subject.TenantID, Tags: queryList(r, "tag"), Limit: 5000,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	hostvars := map[string]any{}
	groups := map[string][]string{}
	all := []string{}

	for i := range targets {
		t := &targets[i]
		if !t.Enabled || !subject.InScope(t.Tags) {
			continue
		}

		principals, err := s.Targets.ListPrincipals(r.Context(), t.ID)
		if err != nil {
			continue
		}

		user := ""
		if len(principals) > 0 {
			user = principals[0].Username
		}

		vars := map[string]any{
			"ansible_host":    t.Address,
			"skm_target_id":   t.ID.String(),
			"skm_connector":   t.Connector,
			"skm_drift_state": t.DriftState,
			"skm_health":      t.Health,
		}
		if t.Port > 0 && t.Port != 22 {
			vars["ansible_port"] = t.Port
		}
		if user != "" {
			vars["ansible_user"] = user
		}

		hostvars[t.Name] = vars
		all = append(all, t.Name)

		for _, tag := range t.Tags {
			group := ansibleGroupName(tag)
			groups[group] = append(groups[group], t.Name)
		}
		groups[ansibleGroupName("connector_"+t.Connector)] = append(
			groups[ansibleGroupName("connector_"+t.Connector)], t.Name)
	}

	out := map[string]any{
		"_meta": map[string]any{"hostvars": hostvars},
		"all":   map[string]any{"hosts": all},
	}
	for name, hosts := range groups {
		out[name] = map[string]any{"hosts": hosts}
	}

	writeJSON(w, http.StatusOK, out)
}

// handleNornirInventory renders Nornir's SimpleInventory shape.
func (s *Server) handleNornirInventory(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permTargetRead); err != nil {
		writeError(w, err)
		return
	}

	targets, err := s.Targets.List(r.Context(), store.TargetFilter{
		TenantID: subject.TenantID, Tags: queryList(r, "tag"), Limit: 5000,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	hosts := map[string]any{}
	groups := map[string]any{}

	for i := range targets {
		t := &targets[i]
		if !t.Enabled || !subject.InScope(t.Tags) {
			continue
		}

		principals, err := s.Targets.ListPrincipals(r.Context(), t.ID)
		if err != nil {
			continue
		}
		username := ""
		if len(principals) > 0 {
			username = principals[0].Username
		}

		groupNames := make([]string, 0, len(t.Tags)+1)
		for _, tag := range t.Tags {
			name := ansibleGroupName(tag)
			groupNames = append(groupNames, name)
			groups[name] = map[string]any{}
		}
		platform := t.Connector
		if profile, ok := t.Config["profile"].(string); ok && profile != "" {
			platform = profile
		}

		hosts[t.Name] = map[string]any{
			"hostname": t.Address,
			"port":     orPort(t.Port),
			"username": username,
			"platform": platform,
			"groups":   groupNames,
			"data": map[string]any{
				"skm_target_id": t.ID.String(),
				"skm_tags":      t.Tags,
				"skm_drift":     t.DriftState,
			},
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts, "groups": groups})
}

// handleAuthorizedKeys renders a principal's desired authorized_keys file.
//
// This is the pull-based integration point: a host can fetch its own file with
// curl in a cron job, which covers machines SKM cannot reach inbound.
func (s *Server) handleAuthorizedKeys(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(permTargetRead); err != nil {
		writeError(w, err)
		return
	}

	targetID, err := pathUUID(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}

	target, err := s.Targets.Get(r.Context(), subject.TenantID, targetID)
	if err != nil {
		writeError(w, err)
		return
	}
	if !subject.InScope(target.Tags) {
		writeError(w, fmt.Errorf("%w: target %s", authz.ErrOutOfScope, target.Name))
		return
	}

	username := r.PathValue("username")
	principals, err := s.Targets.ListPrincipals(r.Context(), targetID)
	if err != nil {
		writeError(w, err)
		return
	}

	var principalID *uuid.UUID
	for i := range principals {
		if principals[i].Username == username {
			principalID = &principals[i].ID
			break
		}
	}
	if principalID == nil {
		writeError(w, badRequest("no principal named %q on %s", username, target.Name))
		return
	}

	assignments, err := s.Assignments.List(r.Context(), store.AssignmentFilter{
		TenantID: subject.TenantID, TargetID: &targetID, PrincipalID: principalID,
		DesiredState: store.StatePresent, Limit: 500,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "# managed by SKM — target %s, principal %s\n", target.Name, username)
	for _, a := range assignments {
		switch a.KeyStatus {
		case store.KeyStatusRevoked, store.KeyStatusCompromised, store.KeyStatusDestroyed:
			continue
		}
		key, err := s.Keys.Get(r.Context(), subject, a.KeyID)
		if err != nil {
			continue
		}
		if len(a.Options) > 0 {
			fmt.Fprintf(w, "%s ", joinOptions(a.Options))
		}
		fmt.Fprintln(w, key.PublicKey)
	}
}

// ------------------------------------------------------------ vault status ---

// handleSchedulerStatus reports whether this instance holds the scheduler lock,
// which is the first thing to check when scheduled work has stopped happening.
func (s *Server) handleSchedulerStatus(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	if err := subject.Require(authz.PermSettingsRead); err != nil {
		writeError(w, err)
		return
	}

	body := map[string]any{
		"scheduler_enabled": s.Scheduler != nil,
		"is_leader":         s.Scheduler != nil && s.Scheduler.IsLeader(),
		"vault_sealed":      s.Vault.IsSealed(),
		"kek_version":       s.Vault.CurrentVersion(),
		"connectors":        s.Registry.Kinds(),
	}
	if s.Events != nil {
		body["event_subscribers"] = s.Events.Bus().Subscribers()
	}
	if stats, err := s.Jobs.Stats(r.Context(), subject.TenantID); err == nil {
		body["jobs"] = stats
	}

	writeJSON(w, http.StatusOK, body)
}

func ansibleGroupName(tag string) string {
	out := make([]rune, 0, len(tag))
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+32)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "ungrouped"
	}
	return string(out)
}

func orPort(p int) int {
	if p <= 0 {
		return 22
	}
	return p
}

func joinOptions(opts []string) string {
	out := ""
	for i, o := range opts {
		if i > 0 {
			out += ","
		}
		out += o
	}
	return out
}
