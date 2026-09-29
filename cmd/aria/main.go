// Command aria is the ARIA CLI/TUI entrypoint.
//
// ARIA is a methodological pentest COPILOT: it assists a human operator, it does
// not replace them. This step-0 entrypoint only demonstrates the first
// non-negotiable guardrail: ARIA refuses to start without a valid, signed
// engagement, and offers a scope check against that engagement's perimeter.
//
// USAGE ONLY on systems you own or are authorized IN WRITING to test.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Tag59/aria/internal/engagement"
)

func main() {
	engPath := flag.String("engagement", "", "path to engagement.yaml (required)")
	check := flag.String("check", "", "optional: print whether a target is in scope, then exit")
	flag.Parse()

	if *engPath == "" {
		fmt.Fprintln(os.Stderr, "aria: --engagement <engagement.yaml> is required; ARIA will not start without a valid authorization")
		os.Exit(2)
	}

	eng, err := engagement.Load(*engPath)
	if err != nil {
		// No valid engagement => ARIA does not start.
		fmt.Fprintf(os.Stderr, "aria: refusing to start: %v\n", err)
		os.Exit(1)
	}

	if !eng.Authorization.IsActive(time.Now()) {
		fmt.Fprintln(os.Stderr, "aria: refusing to start: the authorization window is not currently active")
		os.Exit(1)
	}

	in, out := eng.ScopeStrings()
	fmt.Printf("ARIA — engagement %q loaded and validated.\n", eng.Name)
	fmt.Printf("  authorized by : %s (ref %s)\n", eng.Authorization.AuthorizedBy, eng.Authorization.Reference)
	fmt.Printf("  in scope      : %v\n", in)
	fmt.Printf("  out of scope  : %v\n", out)
	fmt.Printf("  RoE categories: %v\n", eng.RoE.AllowedCategories)

	if *check != "" {
		ok, err := eng.InScope(*check)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aria: cannot evaluate target %q: %v\n", *check, err)
			os.Exit(1)
		}
		if ok {
			fmt.Printf("IN SCOPE: %s\n", *check)
		} else {
			fmt.Printf("OUT OF SCOPE (refused): %s\n", *check)
		}
		return
	}

	fmt.Println("\n(step 0) Orchestrator, profiler, tools, sandbox, LLM and reporting are not wired yet.")
}
