// Package sandbox runs tool adapters in an isolated, disposable container.
//
// The sandbox is a defense-in-depth layer beneath the scope engine: even though
// every action is already checked against engagement.InScope before it runs, the
// container that actually executes a tool is hardened, ephemeral, and — when it
// needs the network at all — attached only to an isolated network dedicated to
// the lab, never to the host network.
//
// The runtime is abstracted behind Runner so it can be swapped (a hardened
// Docker runner ships now; a gVisor/runsc or Podman backend can be added later
// without touching the adapters).
package sandbox

import (
	"context"
	"time"
)

// NetMode selects the network exposure of a run.
type NetMode string

const (
	// NetNone gives the container no network at all (--network none). This is the
	// default and the right choice for tools that only process local input.
	NetNone NetMode = "none"
	// NetIsolated attaches the container to a pre-created, isolated Docker network
	// (NetworkName) dedicated to the lab. Host-side egress filtering to the
	// authorized scope is applied out of band (see docs); the container never gets
	// the host network.
	NetIsolated NetMode = "isolated"
)

// NetworkPolicy describes how a run may reach the network.
type NetworkPolicy struct {
	Mode NetMode
	// NetworkName is the name of the isolated Docker network to attach to when
	// Mode is NetIsolated. It must already exist (created at lab setup).
	NetworkName string
}

// Spec is a single, fully-specified execution request. The argv is built by the
// tool adapter from typed, bounded parameters — never by the LLM, and never a
// shell string. There is no shell in the container's entrypoint.
type Spec struct {
	// Image is the container image to run. Should be pinned (a digest is best).
	Image string
	// Argv is the entrypoint command and its arguments, passed verbatim to the
	// container with no shell interpretation.
	Argv []string
	// Env are additional environment variables, "KEY=value".
	Env []string
	// WorkdirMount, if set, is a host directory bind-mounted read-write at /work
	// as the container's scoped workspace (for tool output). It must be an
	// absolute path the caller controls.
	WorkdirMount string
	// Network overrides the runner's default network policy for this run.
	// The zero value (empty Mode) means "use the runner default".
	Network NetworkPolicy
	// ExtraCapAdd lists Linux capabilities to add on top of a full cap-drop.
	// Only a vetted allowlist is accepted (e.g. NET_RAW for SYN scans).
	ExtraCapAdd []string
	// Timeout bounds the run. Zero means the runner's default timeout.
	Timeout time.Duration
}

// Result is the raw outcome of a run. Adapters PARSE Stdout/Stderr into
// structured objects; nothing here is handed to the LLM as instructions.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	Duration time.Duration
	// TimedOut is true when the run was killed because it exceeded its timeout.
	TimedOut bool
}

// Runner executes a Spec in an isolated environment.
type Runner interface {
	// Available returns nil if the runtime is usable right now (binary present
	// and daemon reachable), or an error explaining why not.
	Available(ctx context.Context) error
	// Run executes the spec and returns its result. A non-zero container exit
	// code is reported in Result.ExitCode, not as an error; err is non-nil only
	// when the run could not be carried out or a policy check failed.
	Run(ctx context.Context, spec Spec) (Result, error)
}
