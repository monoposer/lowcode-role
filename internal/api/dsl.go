package api

import (
	"encoding/json"
	"net/http"

	"github.com/postship/lowcode-role/internal/lowcode"
)

func (s *Server) handleCompileDSLPreview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PolicyID  string          `json:"policy_id"`
		Body      json.RawMessage `json:"body"`
		RoleNames []string        `json:"role_names"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Body) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body required"})
		return
	}
	roles := in.RoleNames
	if in.PolicyID != "" && len(roles) == 0 {
		var err error
		roles, err = s.Pub.RoleNamesForPolicy(r.Context(), in.PolicyID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	if len(roles) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role_names or policy_id with bindings required"})
		return
	}
	pid := in.PolicyID
	if pid == "" {
		pid = "preview"
	}
	rego, err := lowcode.CompileModule(pid, in.Body, roles)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"compiled_rego": rego})
}
