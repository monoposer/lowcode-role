package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/postship/lowcode-role/internal/bundle"
	"github.com/postship/lowcode-role/internal/cache"
	"github.com/postship/lowcode-role/internal/lowcode"
	metricsx "github.com/postship/lowcode-role/internal/metrics"
	"github.com/postship/lowcode-role/internal/opa"
	"github.com/postship/lowcode-role/internal/revision"
)

type Server struct {
	Pool      *pgxpool.Pool
	Pub       *bundle.Publisher
	OPA       *opa.Client
	Rev       *revision.Holder
	Cache     *cache.DecisionTTL
	OPABin    string
	BundleDir string
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Logger, middleware.Recoverer, middleware.Timeout(30*time.Second))

	r.Handle("/metrics", promhttp.Handler())

	r.Route("/v1", func(r chi.Router) {
		r.Get("/releases/current", s.handleCurrentRelease)
		r.Post("/releases", s.handlePublish)

		r.Post("/roles", s.handleCreateRole)
		r.Get("/roles", s.handleListRoles)
		r.Route("/roles/{roleID}", func(r chi.Router) {
			r.Get("/", s.handleGetRole)
			r.Patch("/", s.handlePatchRole)
			r.Delete("/", s.handleDeleteRole)
			r.Post("/policies", s.handleAttachPolicy)
			r.Delete("/policies/{policyID}", s.handleDetachPolicy)
		})

		r.Post("/policies", s.handleCreatePolicy)
		r.Get("/policies", s.handleListPolicies)
		r.Route("/policies/{policyID}", func(r chi.Router) {
			r.Get("/", s.handleGetPolicy)
			r.Patch("/", s.handlePatchPolicy)
			r.Delete("/", s.handleDeletePolicy)
			r.Post("/compile", s.handleCompilePolicy)
		})

		r.Post("/principals/{ptype}/{pid}/roles", s.handleGrantRole)
		r.Delete("/principals/{ptype}/{pid}/roles/{roleID}", s.handleRevokeRole)
		r.Get("/principals/{ptype}/{pid}/roles", s.handleListPrincipalRoles)

		r.Post("/authorize", s.handleAuthorize)
	})
	return r
}

func (s *Server) audit(ctx context.Context, actor, action, entityType, entityID string, payload any) {
	b, _ := json.Marshal(payload)
	_, _ = s.Pool.Exec(ctx, `
		INSERT INTO audit_log (actor, action, entity_type, entity_id, payload)
		VALUES ($1,$2,$3,$4,$5::jsonb)
	`, actor, action, entityType, entityID, b)
}

func actor(r *http.Request) string {
	a := r.Header.Get("X-Actor")
	if a == "" {
		return "anonymous"
	}
	return a
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return false
	}
	return true
}

// --- releases ---

func (s *Server) handleCurrentRelease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var rev int64
	var dig string
	var at time.Time
	err := s.Pool.QueryRow(ctx, `
		SELECT revision, bundle_digest, published_at
		FROM policy_releases ORDER BY revision DESC LIMIT 1
	`).Scan(&rev, &dig, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, map[string]any{"revision": 0, "bundle_digest": "", "published_at": nil})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": rev, "bundle_digest": dig, "published_at": at})
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rev, dig, err := s.Pub.PublishAtomic(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.Rev.Set(rev)
	s.audit(ctx, actor(r), "publish", "release", strconv.FormatInt(rev, 10), map[string]any{"digest": dig})
	writeJSON(w, http.StatusCreated, map[string]any{"revision": rev, "bundle_digest": dig})
}

// --- roles ---

type roleCreate struct {
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	StaticPermissions   []string `json:"static_permissions"`
	Metadata            any      `json:"metadata"`
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var in roleCreate
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	ctx := r.Context()
	meta, _ := json.Marshal(in.Metadata)
	if len(meta) == 0 || string(meta) == "null" {
		meta = []byte("{}")
	}
	var id string
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO roles (name, description, metadata, static_permissions)
		VALUES ($1,$2,$3::jsonb,$4)
		RETURNING id::text
	`, in.Name, in.Description, meta, in.StaticPermissions).Scan(&id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit(ctx, actor(r), "create", "role", id, in)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Pool.Query(r.Context(), `
		SELECT id::text, name, description, static_permissions, metadata, created_at
		FROM roles ORDER BY name
	`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, desc string
		var perms []string
		var meta []byte
		var created time.Time
		if err := rows.Scan(&id, &name, &desc, &perms, &meta, &created); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, map[string]any{
			"id": id, "name": name, "description": desc,
			"static_permissions": perms, "metadata": json.RawMessage(meta), "created_at": created,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": out})
}

func (s *Server) handleGetRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "roleID")
	ctx := r.Context()
	var name, desc string
	var perms []string
	var meta []byte
	var created, updated time.Time
	err := s.Pool.QueryRow(ctx, `
		SELECT name, description, static_permissions, metadata, created_at, updated_at
		FROM roles WHERE id = $1::uuid
	`, id).Scan(&name, &desc, &perms, &meta, &created, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "name": name, "description": desc,
		"static_permissions": perms, "metadata": json.RawMessage(meta),
		"created_at": created, "updated_at": updated,
	})
}

type rolePatch struct {
	Description       *string  `json:"description"`
	StaticPermissions *[]string `json:"static_permissions"`
	Metadata          any      `json:"metadata"`
}

func (s *Server) handlePatchRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "roleID")
	var in rolePatch
	if !readJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	if in.Description != nil {
		_, err := s.Pool.Exec(ctx, `UPDATE roles SET description=$2, updated_at=now() WHERE id=$1::uuid`, id, *in.Description)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	if in.StaticPermissions != nil {
		_, err := s.Pool.Exec(ctx, `UPDATE roles SET static_permissions=$2, updated_at=now() WHERE id=$1::uuid`, id, *in.StaticPermissions)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	if in.Metadata != nil {
		b, _ := json.Marshal(in.Metadata)
		_, err := s.Pool.Exec(ctx, `UPDATE roles SET metadata=$2::jsonb, updated_at=now() WHERE id=$1::uuid`, id, b)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	s.audit(ctx, actor(r), "patch", "role", id, in)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "roleID")
	ctx := r.Context()
	ct, err := s.Pool.Exec(ctx, `DELETE FROM roles WHERE id=$1::uuid`, id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if ct.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	s.audit(ctx, actor(r), "delete", "role", id, nil)
	writeJSON(w, http.StatusNoContent, nil)
}

// --- policies ---

type policyCreate struct {
	Name          string          `json:"name"`
	Kind          string          `json:"kind"`
	Body          json.RawMessage `json:"body"`
	CompiledRego  *string         `json:"compiled_rego"`
	Status        string          `json:"status"`
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var in policyCreate
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" || (in.Kind != "rego" && in.Kind != "lowcode") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and kind (rego|lowcode) required"})
		return
	}
	if len(in.Body) == 0 {
		in.Body = []byte("{}")
	}
	st := in.Status
	if st == "" {
		st = "draft"
	}
	ctx := r.Context()
	var id string
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO policies (name, kind, body, compiled_rego, status)
		VALUES ($1,$2,$3::jsonb,$4,$5)
		RETURNING id::text
	`, in.Name, in.Kind, in.Body, in.CompiledRego, st).Scan(&id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit(ctx, actor(r), "create", "policy", id, in)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Pool.Query(r.Context(), `
		SELECT id::text, name, kind, body, compiled_rego, status, created_at
		FROM policies ORDER BY name
	`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, kind, status string
		var body []byte
		var compiled *string
		var created time.Time
		if err := rows.Scan(&id, &name, &kind, &body, &compiled, &status, &created); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, map[string]any{
			"id": id, "name": name, "kind": kind, "body": json.RawMessage(body),
			"compiled_rego": compiled, "status": status, "created_at": created,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": out})
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "policyID")
	ctx := r.Context()
	var name, kind, status string
	var body []byte
	var compiled *string
	var created, updated time.Time
	err := s.Pool.QueryRow(ctx, `
		SELECT name, kind, body, compiled_rego, status, created_at, updated_at
		FROM policies WHERE id=$1::uuid
	`, id).Scan(&name, &kind, &body, &compiled, &status, &created, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "name": name, "kind": kind, "body": json.RawMessage(body),
		"compiled_rego": compiled, "status": status, "created_at": created, "updated_at": updated,
	})
}

type policyPatch struct {
	Name           *string         `json:"name"`
	Body           json.RawMessage `json:"body"`
	CompiledRego   *string         `json:"compiled_rego"`
	Status         *string         `json:"status"`
}

func (s *Server) handlePatchPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "policyID")
	var in policyPatch
	if !readJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	if in.Name != nil {
		_, err := s.Pool.Exec(ctx, `UPDATE policies SET name=$2, updated_at=now() WHERE id=$1::uuid`, id, *in.Name)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	if len(in.Body) > 0 {
		_, err := s.Pool.Exec(ctx, `UPDATE policies SET body=$2::jsonb, updated_at=now() WHERE id=$1::uuid`, id, in.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	if in.CompiledRego != nil {
		_, err := s.Pool.Exec(ctx, `UPDATE policies SET compiled_rego=$2, updated_at=now() WHERE id=$1::uuid`, id, *in.CompiledRego)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	if in.Status != nil {
		_, err := s.Pool.Exec(ctx, `UPDATE policies SET status=$2, updated_at=now() WHERE id=$1::uuid`, id, *in.Status)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	s.audit(ctx, actor(r), "patch", "policy", id, in)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "policyID")
	ctx := r.Context()
	ct, err := s.Pool.Exec(ctx, `DELETE FROM policies WHERE id=$1::uuid`, id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if ct.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	s.audit(ctx, actor(r), "delete", "policy", id, nil)
	writeJSON(w, http.StatusNoContent, nil)
}

type attachPolicy struct {
	PolicyID string `json:"policy_id"`
	Priority int    `json:"priority"`
}

func (s *Server) handleAttachPolicy(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "roleID")
	var in attachPolicy
	if !readJSON(w, r, &in) {
		return
	}
	if in.PolicyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy_id required"})
		return
	}
	ctx := r.Context()
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO role_policies (role_id, policy_id, priority)
		VALUES ($1::uuid,$2::uuid,$3)
		ON CONFLICT (role_id, policy_id) DO UPDATE SET priority=EXCLUDED.priority
	`, roleID, in.PolicyID, in.Priority)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit(ctx, actor(r), "attach_policy", "role", roleID, in)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDetachPolicy(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "roleID")
	policyID := chi.URLParam(r, "policyID")
	ctx := r.Context()
	_, err := s.Pool.Exec(ctx, `DELETE FROM role_policies WHERE role_id=$1::uuid AND policy_id=$2::uuid`, roleID, policyID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit(ctx, actor(r), "detach_policy", "role", roleID, map[string]string{"policy_id": policyID})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleCompilePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "policyID")
	ctx := r.Context()
	var kind, bodyStr string
	err := s.Pool.QueryRow(ctx, `SELECT kind, body::text FROM policies WHERE id=$1::uuid`, id).Scan(&kind, &bodyStr)
	body := []byte(bodyStr)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if kind != "lowcode" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "compile only for lowcode policies"})
		return
	}
	roles, err := s.Pub.RoleNamesForPolicy(ctx, id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(roles) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy must be attached to at least one role before compile"})
		return
	}
	rego, err := lowcode.CompileModule(id, body, roles)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := opaCheckFragment(ctx, s.OPABin, rego); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_, err = s.Pool.Exec(ctx, `UPDATE policies SET compiled_rego=$2, updated_at=now() WHERE id=$1::uuid`, id, rego)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit(ctx, actor(r), "compile", "policy", id, nil)
	writeJSON(w, http.StatusOK, map[string]string{"compiled_rego": rego})
}

func opaCheckFragment(ctx context.Context, opaBin, rego string) error {
	if opaBin == "" {
		return nil
	}
	dir, err := os.MkdirTemp("", "opa-frag-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.MkdirAll(filepath.Join(dir, "authz"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "authz", "fragment.rego"), []byte(rego), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "role_grants.json"), []byte("{}"), 0o644); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, opaBin, "check", dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(string(out))
	}
	return nil
}

type grantRole struct {
	RoleID string `json:"role_id"`
}

func (s *Server) handleGrantRole(w http.ResponseWriter, r *http.Request) {
	ptype := chi.URLParam(r, "ptype")
	pid := chi.URLParam(r, "pid")
	var in grantRole
	if !readJSON(w, r, &in) {
		return
	}
	if in.RoleID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role_id required"})
		return
	}
	ctx := r.Context()
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO principal_roles (principal_type, principal_id, role_id)
		VALUES ($1,$2,$3::uuid)
		ON CONFLICT (principal_type, principal_id, role_id) DO NOTHING
	`, ptype, pid, in.RoleID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit(ctx, actor(r), "grant_role", "principal", ptype+":"+pid, in)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRevokeRole(w http.ResponseWriter, r *http.Request) {
	ptype := chi.URLParam(r, "ptype")
	pid := chi.URLParam(r, "pid")
	roleID := chi.URLParam(r, "roleID")
	ctx := r.Context()
	_, err := s.Pool.Exec(ctx, `
		DELETE FROM principal_roles
		WHERE principal_type=$1 AND principal_id=$2 AND role_id=$3::uuid
	`, ptype, pid, roleID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit(ctx, actor(r), "revoke_role", "principal", ptype+":"+pid, map[string]string{"role_id": roleID})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleListPrincipalRoles(w http.ResponseWriter, r *http.Request) {
	ptype := chi.URLParam(r, "ptype")
	pid := chi.URLParam(r, "pid")
	rows, err := s.Pool.Query(r.Context(), `
		SELECT r.id::text, r.name
		FROM principal_roles pr
		JOIN roles r ON r.id = pr.role_id
		WHERE pr.principal_type=$1 AND pr.principal_id=$2
		ORDER BY r.name
	`, ptype, pid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	var roles []map[string]string
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		roles = append(roles, map[string]string{"id": id, "name": name})
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

type authorizeInput struct {
	User    json.RawMessage `json:"user"`
	Request json.RawMessage `json:"request"`
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var in authorizeInput
	if !readJSON(w, r, &in) {
		return
	}
	var u any
	var req any
	if err := json.Unmarshal(in.User, &u); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user: " + err.Error()})
		return
	}
	if err := json.Unmarshal(in.Request, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request: " + err.Error()})
		return
	}
	input := map[string]any{"user": u, "request": req}

	hdrRev := r.Header.Get("X-Authz-Revision")
	var clientRev int64 = -1
	if hdrRev != "" {
		if v, err := strconv.ParseInt(hdrRev, 10, 64); err == nil {
			clientRev = v
		}
	}
	rev := s.Rev.Current()
	revisionMatch := clientRev < 0 || clientRev == rev
	useCache := revisionMatch

	if useCache {
		if ok, hit, err := s.Cache.Get(rev, input); err == nil && hit {
			metricsx.CacheHits.Inc()
			metricsx.AuthzLatency.WithLabelValues("hit").Observe(time.Since(start).Seconds())
			metricsx.AuthzRequests.WithLabelValues(boolLabel(ok)).Inc()
			writeJSON(w, http.StatusOK, map[string]any{"allow": ok, "cache": "hit", "revision": rev})
			return
		}
	}
	metricsx.CacheMisses.Inc()

	ctx := r.Context()
	allow, d, err := s.OPA.EvalAllow(ctx, input)
	if err != nil {
		metricsx.AuthzLatency.WithLabelValues("miss").Observe(time.Since(start).Seconds())
		metricsx.AuthzRequests.WithLabelValues("error").Inc()
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	metricsx.OPALatency.Observe(d.Seconds())
	if useCache {
		_ = s.Cache.Set(rev, input, allow)
	}
	metricsx.AuthzLatency.WithLabelValues("miss").Observe(time.Since(start).Seconds())
	metricsx.AuthzRequests.WithLabelValues(boolLabel(allow)).Inc()
	writeJSON(w, http.StatusOK, map[string]any{"allow": allow, "cache": "miss", "revision": rev})
}

func boolLabel(v bool) string {
	if v {
		return "allow"
	}
	return "deny"
}
