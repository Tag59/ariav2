package sandbox

import (
	"runtime"
	"testing"
)

func newTestRunner(t *testing.T) *DockerRunner {
	t.Helper()
	r, err := NewDockerRunner(DockerConfig{})
	if err != nil {
		t.Fatalf("NewDockerRunner: %v", err)
	}
	return r
}

// contains reports whether args contains x.
func contains(args []string, x string) bool {
	for _, a := range args {
		if a == x {
			return true
		}
	}
	return false
}

// containsPair reports whether args contains flag immediately followed by value.
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
		t.Fatalf("buildArgs: %v", err)
	}

	if !contains(args, "--rm") {
		t.Error("missing --rm")
	}
	if !containsPair(args, "--cap-drop", "ALL") {
		t.Error("missing --cap-drop ALL")
	}
	if !containsPair(args, "--security-opt", "no-new-privileges") {
		t.Error("missing no-new-privileges")
	}
	if !contains(args, "--read-only") {
		t.Error("missing --read-only")
	}
	if !containsPair(args, "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m") {
		t.Error("missing hardened /tmp tmpfs")
	}
	if !containsPair(args, "--network", "none") {
		t.Error("default network must be none")
	}
	if !containsPair(args, "--pids-limit", "256") {
		t.Error("missing default pids-limit")
	}

	if contains(args, "--privileged") {
		t.Error("--privileged must never be emitted")
	}
	if containsPair(args, "--network", "host") {
		t.Error("host network must never be used")
	}

	img := indexOf(args, "alpine:3")
	if img < 0 {
		t.Fatal("image not found in args")
	}
	if img+2 >= len(args) || args[img+1] != "echo" || args[img+2] != "hi" {
		t.Errorf("argv not passed verbatim after image: %v", args[img:])
	}
	if contains(args[img:], "--") {
		t.Error("a bare -- separator must not be injected into the container argv")
	}
}

func TestBuildArgsRejections(t *testing.T) {
	r := newTestRunner(t)
	cases := map[string]Spec{
		"empty image":               {Argv: []string{"echo"}},
		"empty argv":                {Image: "alpine"},
		"relative workdir":          {Image: "alpine", Argv: []string{"x"}, WorkdirMount: "relative/dir"},
		"bad capability":            {Image: "alpine", Argv: []string{"x"}, ExtraCapAdd: []string{"SYS_ADMIN"}},
		"isolated without name":     {Image: "alpine", Argv: []string{"x"}, Network: NetworkPolicy{Mode: NetIsolated}},
		"host network via isolated": {Image: "alpine", Argv: []string{"x"}, Network: NetworkPolicy{Mode: NetIsolated, NetworkName: "host"}},
		"unknown network mode":      {Image: "alpine", Argv: []string{"x"}, Network: NetworkPolicy{Mode: "wide-open"}},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := r.buildArgs(spec); err == nil {
				t.Errorf("expected error for %q, got nil", name)
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
		t.Fatalf("buildArgs: %v", err)
	}
	if !containsPair(args, "--cap-add", "NET_RAW") {
		t.Errorf("expected normalized --cap-add NET_RAW, got %v", args)
	}
}

func TestWorkdirMountAndNetwork(t *testing.T) {
	r, err := NewDockerRunner(DockerConfig{
		DefaultNetwork: NetworkPolicy{Mode: NetIsolated, NetworkName: "aria-lab"},
	})
	if err != nil {
		t.Fatalf("NewDockerRunner: %v", err)
	}
	abs := "/tmp/ws"
	if runtime.GOOS == "windows" {
		abs = `C:\ws`
	}
	args, err := r.buildArgs(Spec{Image: "alpine", Argv: []string{"x"}, WorkdirMount: abs})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	if !containsPair(args, "--network", "aria-lab") {
		t.Error("isolated network name not applied")
	}
	if !containsPair(args, "-v", abs+":/work:rw") {
		t.Errorf("workdir mount not applied: %v", args)
	}
	if !containsPair(args, "-w", "/work") {
		t.Error("workdir not set to /work")
	}
}

func TestNewDockerRunnerDefaultsAndRejections(t *testing.T) {
	r := newTestRunner(t)
	if r.cfg.Binary != "docker" || r.cfg.DefaultNetwork.Mode != NetNone {
		t.Errorf("defaults not applied: %+v", r.cfg)
	}
	if _, err := NewDockerRunner(DockerConfig{SeccompProfile: "unconfined"}); err == nil {
		t.Error("seccomp=unconfined must be rejected")
	}
	if _, err := NewDockerRunner(DockerConfig{DefaultNetwork: NetworkPolicy{Mode: NetIsolated}}); err == nil {
		t.Error("isolated default network without a name must be rejected")
	}
}
