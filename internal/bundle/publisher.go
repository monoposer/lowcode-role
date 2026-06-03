package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/postship/lowcode-role/internal/lowcode"
)

// Publish snapshots published policies + role static grants into an OPA loadable directory:
//
//	<out>/role/main.rego
//	<out>/role/generated.rego
//	<out>/role_grants.json  -> data.role_grants
type Publisher struct {
	Pool     *pgxpool.Pool
	OutDir   string
	BaseRego string
	OPABin   string
}

type roleGrant struct {
	Permissions []string `json:"permissions"`
}

func (p *Publisher) Publish(ctx context.Context) (revision int64, digest string, err error) {
	digest, err = p.writeBundle(ctx, p.OutDir)
	if err != nil {
		return 0, "", err
	}
	rev, err := p.insertRelease(ctx, digest)
	if err != nil {
		return 0, "", err
	}
	return rev, digest, nil
}

// writeBundle materializes bundle files into dir (caller ensures dir exists or is empty).
func (p *Publisher) writeBundle(ctx context.Context, dir string) (digest string, err error) {
	if err := os.MkdirAll(filepath.Join(dir, "role"), 0o755); err != nil {
		return "", err
	}

	rows, err := p.Pool.Query(ctx, `
		SELECT name, static_permissions FROM roles ORDER BY name
	`)
	if err != nil {
		return "", err
	}
	grants := map[string]roleGrant{}
	for rows.Next() {
		var name string
		var perms []string
		if err := rows.Scan(&name, &perms); err != nil {
			rows.Close()
			return "", err
		}
		grants[name] = roleGrant{Permissions: perms}
	}
	rows.Close()

	roleGrantsPath := filepath.Join(dir, "role_grants.json")
	b, err := json.MarshalIndent(grants, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(roleGrantsPath, b, 0o644); err != nil {
		return "", err
	}

	mainPath := filepath.Join(dir, "role", "main.rego")
	if err := os.WriteFile(mainPath, []byte(p.BaseRego), 0o644); err != nil {
		return "", err
	}

	gen, err := p.buildGenerated(ctx)
	if err != nil {
		return "", err
	}
	genPath := filepath.Join(dir, "role", "generated.rego")
	if err := os.WriteFile(genPath, []byte(gen), 0o644); err != nil {
		return "", err
	}

	if p.OPABin != "" {
		cmd := exec.CommandContext(ctx, p.OPABin, "check", dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("opa check: %w: %s", err, string(out))
		}
	}

	return hashDir(dir)
}

func (p *Publisher) insertRelease(ctx context.Context, digest string) (int64, error) {
	var rev int64
	err := p.Pool.QueryRow(ctx, `
		WITH next AS (
			SELECT COALESCE(MAX(revision), 0) + 1 AS r FROM policy_releases
		)
		INSERT INTO policy_releases (revision, bundle_digest, published_by)
		SELECT r, $1, 'publisher' FROM next
		RETURNING revision
	`, digest).Scan(&rev)
	return rev, err
}

func (p *Publisher) buildGenerated(ctx context.Context) (string, error) {
	rows, err := p.Pool.Query(ctx, `
		SELECT id::text, kind, body::text, compiled_rego
		FROM policies
		WHERE status = 'published'
		  AND EXISTS (SELECT 1 FROM role_policies rp WHERE rp.policy_id = policies.id)
		ORDER BY name
	`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	type pol struct {
		id   string
		kind string
		body string
	}
	var policies []pol
	for rows.Next() {
		var r pol
		var compiled *string
		if err := rows.Scan(&r.id, &r.kind, &r.body, &compiled); err != nil {
			return "", err
		}
		policies = append(policies, r)
	}

	var blocks []string
	for _, pol := range policies {
		if pol.kind != "dsl" {
			return "", fmt.Errorf("unknown kind %s", pol.kind)
		}
		roleNames, err := p.roleNamesForPolicy(ctx, pol.id)
		if err != nil {
			return "", err
		}
		rego, err := lowcode.CompileRules(pol.id, []byte(pol.body), roleNames)
		if err != nil {
			return "", fmt.Errorf("policy %s: %w", pol.id, err)
		}
		blocks = append(blocks, fmt.Sprintf("# dsl policy %s\n%s", pol.id, rego))
	}
	if len(blocks) == 0 {
		return "package role\n\n# no published policies with role bindings\n", nil
	}
	return "package role\n\n" + strings.Join(blocks, "\n\n") + "\n", nil
}

func (p *Publisher) RoleNamesForPolicy(ctx context.Context, policyID string) ([]string, error) {
	return p.roleNamesForPolicy(ctx, policyID)
}

func (p *Publisher) roleNamesForPolicy(ctx context.Context, policyID string) ([]string, error) {
	rows, err := p.Pool.Query(ctx, `
		SELECT r.name
		FROM role_policies rp
		JOIN roles r ON r.id = rp.role_id
		WHERE rp.policy_id = $1::uuid
		ORDER BY r.name
	`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return uniqueSorted(names), rows.Err()
}

func uniqueSorted(in []string) []string {
	m := map[string]struct{}{}
	for _, s := range in {
		m[s] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func hashDir(root string) (string, error) {
	h := sha256.New()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".rego") && !strings.HasSuffix(path, ".json") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.WriteString(h, path); err != nil {
			return err
		}
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
