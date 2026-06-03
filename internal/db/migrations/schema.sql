-- RBAC metadata + DSL policies + policy releases + audit

CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    metadata    JSONB NOT NULL DEFAULT '{}',
    static_permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'dsl' CHECK (kind IN ('dsl')),
    body            JSONB NOT NULL DEFAULT '{}',
    compiled_rego   TEXT,
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS role_policies (
    role_id    UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    policy_id  UUID NOT NULL REFERENCES policies (id) ON DELETE CASCADE,
    priority   INT NOT NULL DEFAULT 0,
    PRIMARY KEY (role_id, policy_id)
);

CREATE INDEX IF NOT EXISTS role_policies_policy_id_idx ON role_policies (policy_id);

CREATE TABLE IF NOT EXISTS principal_roles (
    principal_type TEXT NOT NULL,
    principal_id    TEXT NOT NULL,
    role_id         UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_type, principal_id, role_id)
);

CREATE INDEX IF NOT EXISTS principal_roles_principal_idx ON principal_roles (principal_type, principal_id);

CREATE TABLE IF NOT EXISTS policy_releases (
    id             BIGSERIAL PRIMARY KEY,
    revision       BIGINT NOT NULL UNIQUE,
    bundle_digest  TEXT NOT NULL,
    published_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_by   TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id           BIGSERIAL PRIMARY KEY,
    actor        TEXT,
    action       TEXT NOT NULL,
    entity_type  TEXT NOT NULL,
    entity_id    TEXT,
    payload      JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_created_at_idx ON audit_log (created_at DESC);

INSERT INTO roles (name, description, static_permissions)
VALUES
    ('admin', 'Bootstrap administrator', ARRAY['*:*']::TEXT[]),
    ('authenticated', 'Logged-in users', ARRAY[]::TEXT[]),
    ('anon', 'Anonymous users', ARRAY[]::TEXT[])
ON CONFLICT (name) DO NOTHING;
