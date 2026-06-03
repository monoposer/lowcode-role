package bundle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// LoadBaseRego reads the canonical base policy from disk.
func LoadBaseRego(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DefaultBaseRegoPath is relative to the module root at runtime.
func DefaultBaseRegoPath() string {
	return filepath.Join("rego", "role", "main.rego")
}

// PublishAtomic writes to a temp directory, validates with opa check, swaps into OutDir, then records release.
func (p *Publisher) PublishAtomic(ctx context.Context) (revision int64, digest string, err error) {
	next := p.OutDir + ".next"
	if err := os.RemoveAll(next); err != nil {
		return 0, "", err
	}
	digest, err = p.writeBundle(ctx, next)
	if err != nil {
		_ = os.RemoveAll(next)
		return 0, "", err
	}
	if err := os.RemoveAll(p.OutDir); err != nil {
		return 0, "", fmt.Errorf("remove active bundle: %w", err)
	}
	if err := os.Rename(next, p.OutDir); err != nil {
		return 0, "", fmt.Errorf("activate bundle: %w", err)
	}
	rev, err := p.insertRelease(ctx, digest)
	if err != nil {
		return 0, "", err
	}
	return rev, digest, nil
}
