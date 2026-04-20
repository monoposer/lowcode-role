package lowcode

import (
	"strings"
	"testing"
)

func TestCompileModule(t *testing.T) {
	doc := `{
	  "resources": ["orders"],
	  "actions": ["read"],
	  "conditions": [
	    {"left": "input.request.resource.owner_id", "op": "eq", "right": "input.user.sub"}
	  ]
	}`
	mod, err := CompileModule("550e8400-e29b-41d4-a716-446655440000", []byte(doc), []string{"editor"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mod, "package authz") {
		t.Fatalf("missing package: %s", mod)
	}
	if !strings.Contains(mod, `input.user.roles[_] == "editor"`) {
		t.Fatalf("missing role guard: %s", mod)
	}
}
