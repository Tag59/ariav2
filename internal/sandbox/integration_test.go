package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestDockerRunIntegration exercises a real container run. It is skipped unless a
// Docker daemon is reachable, so the unit suite still passes on machines (or CI
// stages) without Docker.
func TestDockerRunIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	r, err := NewDockerRunner(DockerConfig{})
	if err != nil {
		t.Fatalf("NewDockerRunner: %v", err)
	}
	if err := r.Available(ctx); err != nil {
		t.Skipf("Docker not available, skipping: %v", err)
	}

	t.Run("echo with no network", func(t *testing.T) {
		res, err := r.Run(ctx, Spec{
			Image:   "alpine:3",
			Argv:    []string{"echo", "aria-sandbox-ok"},
			Timeout: 60 * time.Second,
		})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("exit=%d stderr=%s", res.ExitCode, res.Stderr)
		}
		if !strings.Contains(string(res.Stdout), "aria-sandbox-ok") {
			t.Errorf("unexpected stdout: %q", res.Stdout)
		}
	})

	t.Run("no network really means no network", func(t *testing.T) {
		// With --network none, an outbound connection must fail: the container has
		// only a loopback interface. wget should return a non-zero exit code.
		res, err := r.Run(ctx, Spec{
			Image:   "alpine:3",
			Argv:    []string{"wget", "-q", "-T", "3", "-O", "-", "http://example.com"},
			Network: NetworkPolicy{Mode: NetNone},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.ExitCode == 0 {
			t.Errorf("expected outbound network to fail under --network none, got exit 0")
		}
	})

	t.Run("nonzero exit is reported, not errored", func(t *testing.T) {
		res, err := r.Run(ctx, Spec{
			Image:   "alpine:3",
			Argv:    []string{"sh", "-c", "exit 7"},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Run returned error for a nonzero exit: %v", err)
		}
		if res.ExitCode != 7 {
			t.Errorf("ExitCode = %d, want 7", res.ExitCode)
		}
	})
}
