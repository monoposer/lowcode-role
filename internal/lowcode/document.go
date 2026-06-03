package lowcode

// Document is the unified policy DSL (v1 only). Configured via API, compiled to Rego for OPA.
type Document struct {
	Version    int                  `json:"version"`
	Resource   Resource             `json:"resource"`
	Operations OperationSet         `json:"operations"`
	Fields     map[string]FieldACL  `json:"fields,omitempty"`
}

type Resource struct {
	Type   string `json:"type"`             // default "db"
	Schema string `json:"schema,omitempty"` // default "public" when type=db
	Table  string `json:"table"`
}

// OperationSet maps CRUD operations to row-level rules.
type OperationSet struct {
	Select *OperationRule `json:"select,omitempty"`
	Insert *OperationRule `json:"insert,omitempty"`
	Update *OperationRule `json:"update,omitempty"`
	Delete *OperationRule `json:"delete,omitempty"`
}

// OperationRule: select/delete use when; insert uses check; update uses both.
type OperationRule struct {
	When  []Condition `json:"when,omitempty"`
	Check []Condition `json:"check,omitempty"`
}

type Condition struct {
	Left  string `json:"left"`
	Op    string `json:"op"` // eq, neq, in
	Right any    `json:"right"`
}

// FieldACL controls per-column access per CRUD operation.
type FieldACL struct {
	Select *bool `json:"select,omitempty"`
	Insert *bool `json:"insert,omitempty"`
	Update *bool `json:"update,omitempty"`
}
