package sandbox

import (
	"runtime"
	"testing"
)

func newTestRunner(t *testing.T) *DockerRunner {
	t.Helper()
	r, err := NewDockerRunner(DockerConfig{})
	if err != nil {
		t.Fatalf("NewDockerRunner : %v", err)
	}
	return r
}

// contains indique si args contient x.
func contains(args []string, x string) bool {
	for _, a := range args {
		if a == x {
			return true
		}
	}
	return false
}

// containsPair indique si args contient flag immédiatement suivi de value.
func containsPair(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func indexOf(args []string, x string) int {
	for i, a := range args {
		if a == x {
			return i
		}
	}
	return -1
}

func TestBuildArgsHardening(t *testing.T) {
	r := newTestRunner(t)
	args, err := r.buildArgs(Spec{Image: "alpine:3", Argv: []string{"echo", "hi"}})
	if err != nil {
		t.Fatalf("buildArgs : %v", err)
	}

	if !contains(args, "--rm") {
		t.Error("--rm manquant")
	}
	if !containsPair(args, "--cap-drop", "ALL") {
		t.Error("--cap-drop ALL manquant")
	}
	if !containsPair(args, "--security-opt", "no-new-privileges") {
		t.Error("no-new-privileges manquant")
	}
	if !contains(args, "--read-only") {
		t.Error("--read-only manquant")
	}
	if !containsPair(args, "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m") {
		t.Error("tmpfs /tmp durci manquant")
	}
	if !containsPair(args, "--network", "none") {
		t.Error("le réseau par défaut doit être none")
	}
	if !containsPair(args, "--pids-limit", "256") {
		t.Error("pids-limit par défaut manquant")
	}

	if contains(args, "--privileged") {
		t.Error("--privileged ne doit jamais être émis")
	}
	if containsPair(args, "--network", "host") {
		t.Error("le réseau host ne doit jamais être utilisé")
	}

	img := indexOf(args, "alpine:3")
	if img < 0 {
		t.Fatal("image introuvable dans les arguments")
	}
	if img+2 >= len(args) || args[img+1] != "echo" || args[img+2] != "hi" {
		t.Errorf("argv non passé tel quel après l'image : %v", args[img:])
	}
	if contains(args[img:], "--") {
		t.Error("un séparateur -- ne doit pas être injecté dans l'argv du conteneur")
	}
}

func TestBuildArgsRejections(t *testing.T) {
	r := newTestRunner(t)
	cases := map[string]Spec{
		"image vide":            {Argv: []string{"echo"}},
		"argv vide":             {Image: "alpine"},
		"workdir relatif":       {Image: "alpine", Argv: []string{"x"}, WorkdirMount: "relative/dir"},
		"capability interdite":  {Image: "alpine", Argv: []string{"x"}, ExtraCapAdd: []string{"SYS_ADMIN"}},
		"isolé sans nom":        {Image: "alpine", Argv: []string{"x"}, Network: NetworkPolicy{Mode: NetIsolated}},
		"réseau host via isolé": {Image: "alpine", Argv: []string{"x"}, Network: NetworkPolicy{Mode: NetIsolated, NetworkName: "host"}},
		"mode réseau inconnu":   {Image: "alpine", Argv: []string{"x"}, Network: NetworkPolicy{Mode: "wide-open"}},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := r.buildArgs(spec); err == nil {
				t.Errorf("erreur attendue pour %q, obtenu nil", name)
			}
		})
	}
}

func TestCapabilityAllowlistNormalization(t *testing.T) {
	r := newTestRunner(t)
	args, err := r.buildArgs(Spec{
		Image:       "alpine",
		Argv:        []string{"nmap"},
		ExtraCapAdd: []string{"cap_net_raw"},
	})
	if err != nil {
		t.Fatalf("buildArgs : %v", err)
	}
	if !containsPair(args, "--cap-add", "NET_RAW") {
		t.Errorf("attendu --cap-add NET_RAW normalisé, obtenu %v", args)
	}
}

func TestWorkdirMountAndNetwork(t *testing.T) {
	r, err := NewDockerRunner(DockerConfig{
		DefaultNetwork: NetworkPolicy{Mode: NetIsolated, NetworkName: "aria-lab"},
	})
	if err != nil {
		t.Fatalf("NewDockerRunner : %v", err)
	}
	abs := "/tmp/ws"
	if runtime.GOOS == "windows" {
		abs = `C:\ws`
	}
	args, err := r.buildArgs(Spec{Image: "alpine", Argv: []string{"x"}, WorkdirMount: abs})
	if err != nil {
		t.Fatalf("buildArgs : %v", err)
	}
	if !containsPair(args, "--network", "aria-lab") {
		t.Error("nom du réseau isolé non appliqué")
	}
	if !containsPair(args, "-v", abs+":/work:rw") {
		t.Errorf("montage du workdir non appliqué : %v", args)
	}
	if !containsPair(args, "-w", "/work") {
		t.Error("workdir non positionné sur /work")
	}
}

func TestNewDockerRunnerDefaultsAndRejections(t *testing.T) {
	r := newTestRunner(t)
	if r.cfg.Binary != "docker" || r.cfg.DefaultNetwork.Mode != NetNone {
		t.Errorf("défauts non appliqués : %+v", r.cfg)
	}
	if _, err := NewDockerRunner(DockerConfig{SeccompProfile: "unconfined"}); err == nil {
		t.Error("seccomp=unconfined doit être refusé")
	}
	if _, err := NewDockerRunner(DockerConfig{DefaultNetwork: NetworkPolicy{Mode: NetIsolated}}); err == nil {
		t.Error("réseau isolé par défaut sans nom doit être refusé")
	}
}
