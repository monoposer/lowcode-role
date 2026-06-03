package lowcode

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompileModule_OwnerSelect(t *testing.T) {
	trueVal := true
	falseVal := false
	doc := Document{
		Version: 1,
		Resource: Resource{Type: "db", Schema: "public", Table: "orders"},
		Operations: OperationSet{
			Select: &OperationRule{
				When: []Condition{{
					Left:  "input.request.resource.row.user_id",
					Op:    "eq",
					Right: "input.user.sub",
				}},
			},
		},
		Fields: map[string]FieldACL{
			"amount":  {Select: &trueVal},
			"user_id": {Select: &trueVal},
			"secret":  {Select: &falseVal},
		},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	mod, err := CompileModule("abc-123", body, []string{"authenticated"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"package role",
		`input.request.resource.table == "orders"`,
		`input.user.roles[_] == "authenticated"`,
		`dsl_abc_123_field_select["amount"]`,
		`dsl_abc_123_match_select`,
	} {
		if !strings.Contains(mod, want) {
			t.Errorf("missing %q in:\n%s", want, mod)
		}
	}
}

func TestCompileModule_InsertCheck(t *testing.T) {
	doc := Document{
		Version:  1,
		Resource: Resource{Table: "profiles"},
		Operations: OperationSet{
			Insert: &OperationRule{
				Check: []Condition{{
					Left:  "input.request.resource.row.id",
					Op:    "eq",
					Right: "input.user.sub",
				}},
			},
		},
	}
	body, _ := json.Marshal(doc)
	mod, err := CompileModule("p1", body, []string{"authenticated"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mod, `input.request.action == "insert"`) {
		t.Fatalf("expected insert rule:\n%s", mod)
	}
}

func TestCompileModule_VersionRequired(t *testing.T) {
	_, err := CompileModule("x", []byte(`{"version":0,"resource":{"table":"t"},"operations":{"select":{}}}`), []string{"r"})
	if err == nil {
		t.Fatal("expected version error")
	}
}
