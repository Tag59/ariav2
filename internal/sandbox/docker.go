package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds any run whose Spec does not set one.
const DefaultTimeout = 5 * time.Minute

// allowedCaps is the vetted allowlist of Linux capabilities an adapter may add
// on top of a full --cap-drop=ALL. Anything outside this set is refused: the
// point of the sandbox is that no run can quietly grant itself dangerous powers.
var allowedCaps = map[string]bool{
	"NET_RAW":          true, // raw sockets, e.g. nmap -sS
	"NET_BIND_SERVICE": true, // bind ports < 1024 (rarely needed)
}

// DockerConfig configures a hardened DockerRunner.
type DockerConfig struct {
	// Binary is the container CLI to invoke. Defaults to "docker"; "podman" works
	// too as it is CLI-compatible for the flags used here.
	Binary string
	// DefaultNetwork is applied to runs whose Spec leaves Network.Mode empty.
	// Defaults to NetNone (no network) — fail safe.
	DefaultNetwork NetworkPolicy
	// SeccompProfile is a path to a seccomp JSON profile. Empty keeps Docker's
	// default profile (already restrictive). "unconfined" is rejected.
	SeccompProfile string
	// Resource limits. Empty/zero values fall back to conservative defaults.
	CPUs      string // e.g. "1.0"
	Memory    string // e.g. "512m"
	PidsLimit int    // e.g. 256
	// RunAsUser sets --user (e.g. "1000:1000") to avoid running as root inside the
	// container. Empty leaves the image default (many hardened images are non-root).
	RunAsUser string
	// DefaultTimeout overrides DefaultTimeout for this runner when > 0.
	DefaultTimeout time.Duration
}

// DockerRunner is a Runner backed by a hardened `docker run` invocation.
//
// Every run is: --rm (ephemeral), --cap-drop=ALL, --security-opt
// no-new-privileges, --read-only rootfs with a noexec tmpfs for /tmp, resource
// limited, and never --privileged nor --network host.
type DockerRunner struct {
	cfg DockerConfig
}

// NewDockerRunner builds a DockerRunner, applying safe defaults and rejecting an
// unsafe configuration up front.
func NewDockerRunner(cfg DockerConfig) (*DockerRunner, error) {
	if cfg.Binary == "" {
		cfg.Binary = "docker"
	}
	if cfg.DefaultNetwork.Mode == "" {
		cfg.DefaultNetwork.Mode = NetNone
	}
	if cfg.CPUs == "" {
		cfg.CPUs = "1.0"
	}
	if cfg.Memory == "" {
		cfg.Memory = "512m"
	}
	if cfg.PidsLimit == 0 {
		cfg.PidsLimit = 256
	}
	if cfg.DefaultTimeout == 0 {
		cfg.DefaultTimeout = DefaultTimeout
	}
	if strings.EqualFold(cfg.SeccompProfile, "unconfined") {
		return nil, errors.New("sandbox: seccomp=unconfined is not allowed")
	}
	if err := validateNetwork(cfg.DefaultNetwork); err != nil {
		return nil, err
	}
	return &DockerRunner{cfg: cfg}, nil
}

// Available reports whether the Docker daemon is reachable.
func (r *DockerRunner) Available(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, r.cfg.Binary, "version", "--format", "{{.Server.Version}}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sandbox: %s not available: %v: %s", r.cfg.Binary, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Run executes spec in a hardened container.
func (r *DockerRunner) Run(ctx context.Context, spec Spec) (Result, error) {
	args, err := r.buildArgs(spec)
	if err != nil {
		return Result{}, err
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = r.cfg.DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, r.cfg.Binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)

	res := Result{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: dur,
	}

	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
		return res, nil
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			// A non-zero container exit is a normal outcome, not a runner error.
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		// The command could not be started/run at all.
		return res, fmt.Errorf("sandbox: run failed: %w: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	res.ExitCode = 0
	return res, nil
}

// buildArgs constructs the hardened `docker run ...` argument vector for spec,
// validating everything security-relevant before returning.
func (r *DockerRunner) buildArgs(spec Spec) ([]string, error) {
	if strings.TrimSpace(spec.Image) == "" {
		return nil, errors.New("sandbox: spec.Image is required")
	}
	if len(spec.Argv) == 0 {
		return nil, errors.New("sandbox: spec.Argv is required (no shell entrypoint)")
	}

	net := spec.Network
	if net.Mode == "" {
		net = r.cfg.DefaultNetwork
	}
	if err := validateNetwork(net); err != nil {
		return nil, err
	}

	args := []string{
		"run", "--rm",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
	}

	// Never privileged. (Documented invariant: --privileged is never emitted.)
	if r.cfg.SeccompProfile != "" {
		args = append(args, "--security-opt", "seccomp="+r.cfg.SeccompProfile)
	}

	// Read-only root filesystem, with a locked-down writable /tmp.
	args = append(args,
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
	)

	// Resource limits.
	args = append(args,
		"--memory", r.cfg.Memory,
		"--cpus", r.cfg.CPUs,
		"--pids-limit", fmt.Sprintf("%d", r.cfg.PidsLimit),
	)

	if r.cfg.RunAsUser != "" {
		args = append(args, "--user", r.cfg.RunAsUser)
	}

	// Network.
	switch net.Mode {
	case NetNone:
		args = append(args, "--network", "none")
	case NetIsolated:
		args = append(args, "--network", net.NetworkName)
	}

	// Vetted capability additions only.
	for _, c := range spec.ExtraCapAdd {
		norm := strings.ToUpper(strings.TrimSpace(c))
		norm = strings.TrimPrefix(norm, "CAP_")
		if !allowedCaps[norm] {
			return nil, fmt.Errorf("sandbox: capability %q is not in the vetted allowlist", c)
		}
		args = append(args, "--cap-add", norm)
	}

	// Scoped workspace mount.
	if spec.WorkdirMount != "" {
		if !isAbs(spec.WorkdirMount) {
			return nil, fmt.Errorf("sandbox: WorkdirMount must be an absolute path, got %q", spec.WorkdirMount)
		}
		args = append(args, "-v", spec.WorkdirMount+":/work:rw", "-w", "/work")
	}

	// Environment.
	for _, e := range spec.Env {
		args = append(args, "--env", e)
	}

	// Image, then the argv. Docker stops parsing options at the image name, so
	// everything after it is passed to the container verbatim (no shell, no flag
	// reinterpretation of the argv).
	args = append(args, spec.Image)
	args = append(args, spec.Argv...)
	return args, nil
}

func validateNetwork(n NetworkPolicy) error {
	switch n.Mode {
	case NetNone:
		return nil
	case NetIsolated:
		name := strings.TrimSpace(n.NetworkName)
		if name == "" {
			return errors.New("sandbox: NetIsolated requires a NetworkName")
		}
		if strings.EqualFold(name, "host") || strings.EqualFold(name, "bridge") {
			return fmt.Errorf("sandbox: network %q is not an isolated network", name)
		}
		return nil
	case "":
		return errors.New("sandbox: empty network mode")
	default:
		return fmt.Errorf("sandbox: unknown network mode %q", n.Mode)
	}
}

// isAbs reports whether p is an absolute path on either Unix or Windows, so a
// Windows dev host and a Linux lab host are both handled.
func isAbs(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	// Windows drive path, e.g. C:\ or C:/
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	// UNC path
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	return false
}
