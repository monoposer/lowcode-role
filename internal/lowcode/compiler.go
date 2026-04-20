package lowcode

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Document is a constrained low-code policy AST (v0).
type Document struct {
	Resources  []string    `json:"resources"`
	Actions    []string    `json:"actions"`
	Effect     string      `json:"effect"` // allow only in v0
	Conditions []Condition `json:"conditions"`
}

type Condition struct {
	Left  string `json:"left"`  // rego ref, e.g. input.request.resource.owner_id
	Op    string `json:"op"`    // eq, neq
	Right string `json:"right"` // rego ref, e.g. input.user.sub
}

func sanitizeID(id string) string {
	return strings.ReplaceAll(strings.ReplaceAll(id, "-", "_"), ".", "_")
}

// CompileModule returns a standalone Rego module (with package authz) for storage and opa check.
func CompileModule(policyID string, docJSON []byte, roleNames []string) (string, error) {
	body, err := CompileRules(policyID, docJSON, roleNames)
	if err != nil {
		return "", err
	}
	return "package authz\n\n" + body, nil
}

// CompileRules emits rules without a package declaration (for concatenation under one package).
func CompileRules(policyID string, docJSON []byte, roleNames []string) (string, error) {
	pid := sanitizeID(policyID)
	var doc Document
	if err := json.Unmarshal(docJSON, &doc); err != nil {
		return "", fmt.Errorf("parse lowcode json: %w", err)
	}
	if doc.Effect != "" && doc.Effect != "allow" {
		return "", errors.New("effect must be allow or empty")
	}
	if len(doc.Resources) == 0 || len(doc.Actions) == 0 {
		return "", errors.New("resources and actions required")
	}
	if len(roleNames) == 0 {
		return "", errors.New("at least one role name required")
	}

	var b strings.Builder
	for _, rt := range doc.Resources {
		rt = strings.ReplaceAll(rt, `"`, ``)
		b.WriteString(fmt.Sprintf("%s[rt] {\n\trt == %q\n}\n\n", helperTypes(pid), rt))
	}
	for _, a := range doc.Actions {
		a = strings.ReplaceAll(a, `"`, ``)
		b.WriteString(fmt.Sprintf("%s[act] {\n\tact == %q\n}\n\n", helperActions(pid), a))
	}

	b.WriteString(fmt.Sprintf("%s {\n", helperMatch(pid)))
	b.WriteString(fmt.Sprintf("\t%s[input.request.resource.type]\n", helperTypes(pid)))
	b.WriteString(fmt.Sprintf("\t%s[input.request.action]\n", helperActions(pid)))
	for _, c := range doc.Conditions {
		line, err := conditionLine(c)
		if err != nil {
			return "", err
		}
		b.WriteString("\t" + line + "\n")
	}
	b.WriteString("}\n\n")

	for _, rn := range roleNames {
		rn = strings.ReplaceAll(rn, `"`, ``)
		b.WriteString("allow {\n")
		b.WriteString(fmt.Sprintf("\tinput.user.roles[_] == %q\n", rn))
		b.WriteString(fmt.Sprintf("\t%s\n", helperMatch(pid)))
		b.WriteString("}\n\n")
	}
	return b.String(), nil
}

func helperMatch(pid string) string   { return fmt.Sprintf("lowcode_%s_match", pid) }
func helperTypes(pid string) string  { return fmt.Sprintf("lowcode_%s_types", pid) }
func helperActions(pid string) string { return fmt.Sprintf("lowcode_%s_actions", pid) }

func conditionLine(c Condition) (string, error) {
	switch c.Op {
	case "eq":
		return fmt.Sprintf("%s == %s", c.Left, c.Right), nil
	case "neq":
		return fmt.Sprintf("%s != %s", c.Left, c.Right), nil
	default:
		return "", fmt.Errorf("unsupported op %q", c.Op)
	}
}
