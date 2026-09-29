package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestDockerRunIntegration exécute un vrai conteneur. Il est ignoré si aucun démon
// Docker n'est joignable, pour que la suite unitaire passe quand même sur les
// machines (ou étapes de CI) sans Docker.
func TestDockerRunIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("ignoré en mode -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	r, err := NewDockerRunner(DockerConfig{})
	if err != nil {
		t.Fatalf("NewDockerRunner : %v", err)
	}
	if err := r.Available(ctx); err != nil {
		t.Skipf("Docker indisponible, test ignoré : %v", err)
	}

	t.Run("echo sans réseau", func(t *testing.T) {
		res, err := r.Run(ctx, Spec{
			Image:   "alpine:3",
			Argv:    []string{"echo", "aria-sandbox-ok"},
			Timeout: 60 * time.Second,
		})
		if err != nil {
			t.Fatalf("Run : %v", err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("exit=%d stderr=%s", res.ExitCode, res.Stderr)
		}
		if !strings.Contains(string(res.Stdout), "aria-sandbox-ok") {
			t.Errorf("stdout inattendu : %q", res.Stdout)
		}
	})

	t.Run("sans réseau = vraiment sans réseau", func(t *testing.T) {
		// Avec --network none, une connexion sortante doit échouer : le conteneur
		// n'a qu'une interface loopback. wget doit renvoyer un code non nul.
		res, err := r.Run(ctx, Spec{
			Image:   "alpine:3",
			Argv:    []string{"wget", "-q", "-T", "3", "-O", "-", "http://example.com"},
			Network: NetworkPolicy{Mode: NetNone},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Run : %v", err)
		}
		if res.ExitCode == 0 {
			t.Errorf("la connexion sortante aurait dû échouer sous --network none, exit 0 obtenu")
		}
	})

	t.Run("un exit non nul est reporté, pas erré", func(t *testing.T) {
		res, err := r.Run(ctx, Spec{
			Image:   "alpine:3",
			Argv:    []string{"sh", "-c", "exit 7"},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Run a renvoyé une erreur pour un exit non nul : %v", err)
		}
		if res.ExitCode != 7 {
			t.Errorf("ExitCode = %d, attendu 7", res.ExitCode)
		}
	})
}
