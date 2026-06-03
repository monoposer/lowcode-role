# lowcode-role DSL v1 Specification

Policy body JSON Schema for `kind: "dsl"` policies.

## Schema file

- **[v1.schema.json](./v1.schema.json)** — JSON Schema Draft 2020-12

## HTTP

```bash
GET /v1/dsl/schema
```

Returns the schema document (same as `v1.schema.json`).

## Quick reference

```json
{
  "version": 1,
  "resource": {
    "type": "db",
    "schema": "public",
    "table": "orders"
  },
  "operations": {
    "select": { "when": [ { "left": "...", "op": "eq", "right": "..." } ] },
    "insert": { "check": [ ... ] },
    "update": { "when": [ ... ], "check": [ ... ] },
    "delete": { "when": [ ... ] }
  },
  "fields": {
    "column_name": { "select": true, "insert": false, "update": false }
  }
}
```

## Authorize input (companion contract)

DSL policies with `resource.type = "db"` expect:

```json
{
  "user": { "sub": "string", "roles": ["role-name"] },
  "request": {
    "action": "select | insert | update | delete",
    "resource": {
      "type": "db",
      "schema": "public",
      "table": "orders",
      "row": { },
      "fields": ["col1", "col2"]
    }
  }
}
```

## Lifecycle

1. `POST /v1/policies` with `kind: "dsl"` and body matching this schema
2. Attach to role → `POST /v1/roles/{id}/policies`
3. `PATCH` status to `published`
4. `POST /v1/releases` — compile to OPA bundle

## Condition operators

| `op`   | Rego emitted        |
|--------|---------------------|
| `eq`   | `left == right`     |
| `neq`  | `left != right`     |
| `in`   | `left == right[_]`  |

`right` as string starting with `input.` or `data.` is treated as a Rego reference; otherwise a literal.
