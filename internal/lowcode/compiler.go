package lowcode

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var validOps = map[string]struct{}{
	"select": {}, "insert": {}, "update": {}, "delete": {},
}

func sanitizeID(id string) string {
	return strings.ReplaceAll(strings.ReplaceAll(id, "-", "_"), ".", "_")
}

func CompileModule(policyID string, docJSON []byte, roleNames []string) (string, error) {
	body, err := CompileRules(policyID, docJSON, roleNames)
	if err != nil {
		return "", err
	}
	return "package authz\n\n" + body, nil
}

func CompileRules(policyID string, docJSON []byte, roleNames []string) (string, error) {
	pid := sanitizeID(policyID)
	var doc Document
	if err := json.Unmarshal(docJSON, &doc); err != nil {
		return "", fmt.Errorf("parse dsl json: %w", err)
	}
	if err := doc.normalize(); err != nil {
		return "", err
	}
	if len(roleNames) == 0 {
		return "", errors.New("at least one role name required")
	}

	var b strings.Builder

	for op, fields := range doc.fieldRulesByOp() {
		if len(fields) == 0 {
			continue
		}
		setName := fmt.Sprintf("dsl_%s_field_%s", pid, op)
		for field, allowed := range fields {
			if allowed {
				b.WriteString(fmt.Sprintf("%s[%q] {\n\ttrue\n}\n\n", setName, field))
			}
		}
		b.WriteString(fmt.Sprintf("dsl_%s_fields_%s_ok {\n", pid, op))
		b.WriteString("\tcount(input.request.resource.fields) == 0\n")
		b.WriteString("} else {\n")
		b.WriteString(fmt.Sprintf("\tnot dsl_%s_fields_%s_denied\n", pid, op))
		b.WriteString("}\n\n")
		b.WriteString(fmt.Sprintf("dsl_%s_fields_%s_denied {\n", pid, op))
		b.WriteString("\tsome f in input.request.resource.fields\n")
		b.WriteString(fmt.Sprintf("\tnot %s[f]\n", setName))
		b.WriteString("}\n\n")
	}

	for op, rule := range doc.operationRules() {
		matchName := fmt.Sprintf("dsl_%s_match_%s", pid, op)
		b.WriteString(fmt.Sprintf("%s {\n", matchName))
		for _, line := range doc.resourceMatchLines() {
			b.WriteString("\t" + line + "\n")
		}
		b.WriteString(fmt.Sprintf("\tinput.request.action == %q\n", op))
		for _, line := range ruleLines(op, rule) {
			b.WriteString("\t" + line + "\n")
		}
		if _, hasFields := doc.fieldRulesByOp()[op]; hasFields {
			b.WriteString(fmt.Sprintf("\tdsl_%s_fields_%s_ok\n", pid, op))
		}
		b.WriteString("}\n\n")
	}

	for _, rn := range roleNames {
		rn = strings.ReplaceAll(rn, `"`, ``)
		for op := range doc.operationRules() {
			b.WriteString("allow {\n")
			b.WriteString(fmt.Sprintf("\tinput.user.roles[_] == %q\n", rn))
			b.WriteString(fmt.Sprintf("\tdsl_%s_match_%s\n", pid, op))
			b.WriteString("}\n\n")
		}
	}

	return b.String(), nil
}

func (d *Document) normalize() error {
	if d.Version != 1 {
		return fmt.Errorf("unsupported dsl version %d (only version 1)", d.Version)
	}
	if d.Resource.Table == "" {
		return errors.New("resource.table required")
	}
	if d.Resource.Type == "" {
		d.Resource.Type = "db"
	}
	if d.Resource.Type == "db" && d.Resource.Schema == "" {
		d.Resource.Schema = "public"
	}
	if len(d.operationRules()) == 0 {
		return errors.New("at least one operation (select|insert|update|delete) required")
	}
	for op := range d.operationRules() {
		if _, ok := validOps[op]; !ok {
			return fmt.Errorf("unknown operation %q", op)
		}
	}
	return nil
}

func (d Document) resourceMatchLines() []string {
	if d.Resource.Type == "db" {
		return []string{
			`input.request.resource.type == "db"`,
			fmt.Sprintf(`input.request.resource.schema == %q`, d.Resource.Schema),
			fmt.Sprintf(`input.request.resource.table == %q`, d.Resource.Table),
		}
	}
	return []string{
		fmt.Sprintf(`input.request.resource.type == %q`, d.Resource.Table),
	}
}

func (d Document) operationRules() map[string]*OperationRule {
	out := map[string]*OperationRule{}
	if d.Operations.Select != nil {
		out["select"] = d.Operations.Select
	}
	if d.Operations.Insert != nil {
		out["insert"] = d.Operations.Insert
	}
	if d.Operations.Update != nil {
		out["update"] = d.Operations.Update
	}
	if d.Operations.Delete != nil {
		out["delete"] = d.Operations.Delete
	}
	return out
}

func (d Document) fieldRulesByOp() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	if len(d.Fields) == 0 {
		return out
	}
	for name, acl := range d.Fields {
		if acl.Select != nil {
			if out["select"] == nil {
				out["select"] = map[string]bool{}
			}
			out["select"][name] = *acl.Select
		}
		if acl.Insert != nil {
			if out["insert"] == nil {
				out["insert"] = map[string]bool{}
			}
			out["insert"][name] = *acl.Insert
		}
		if acl.Update != nil {
			if out["update"] == nil {
				out["update"] = map[string]bool{}
			}
			out["update"][name] = *acl.Update
		}
	}
	return out
}

func ruleLines(op string, rule *OperationRule) []string {
	var lines []string
	switch op {
	case "select", "delete":
		for _, c := range rule.When {
			if line, err := conditionLine(c); err == nil {
				lines = append(lines, line)
			}
		}
	case "insert":
		for _, c := range rule.Check {
			if line, err := conditionLine(c); err == nil {
				lines = append(lines, line)
			}
		}
	case "update":
		for _, c := range rule.When {
			if line, err := conditionLine(c); err == nil {
				lines = append(lines, line)
			}
		}
		for _, c := range rule.Check {
			if line, err := conditionLine(c); err == nil {
				lines = append(lines, line)
			}
		}
	}
	return lines
}

func conditionLine(c Condition) (string, error) {
	right, err := formatRight(c.Right)
	if err != nil {
		return "", err
	}
	switch c.Op {
	case "eq":
		return fmt.Sprintf("%s == %s", c.Left, right), nil
	case "neq":
		return fmt.Sprintf("%s != %s", c.Left, right), nil
	case "in":
		return fmt.Sprintf("%s == %s[_]", c.Left, right), nil
	default:
		return "", fmt.Errorf("unsupported op %q", c.Op)
	}
}

func formatRight(v any) (string, error) {
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, "input.") || strings.HasPrefix(t, "data.") {
			return t, nil
		}
		return fmt.Sprintf("%q", t), nil
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t)), nil
		}
		return fmt.Sprintf("%v", t), nil
	case bool:
		return fmt.Sprintf("%t", t), nil
	case nil:
		return "null", nil
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			s, err := formatRight(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return fmt.Sprintf("[%s]", strings.Join(parts, ", ")), nil
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}
