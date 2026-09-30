// Command aria est le point d'entrée CLI/TUI d'ARIA.
//
// ARIA est un COPILOTE de pentest méthodologique : il assiste un opérateur humain,
// il ne le remplace pas. La CLI applique le premier garde-fou non négociable —
// ARIA refuse de démarrer sans un engagement valide et signé — puis permet :
//   - de vérifier si une cible est dans le périmètre (-check) ;
//   - de lancer une boucle de reconnaissance assistée par le LLM (-recon).
//
// USAGE UNIQUEMENT sur des systèmes que l'on possède ou que l'on est autorisé PAR
// ÉCRIT à tester.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Tag59/aria/internal/agent"
	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/llm"
	"github.com/Tag59/aria/internal/profiler"
	"github.com/Tag59/aria/internal/sandbox"
	"github.com/Tag59/aria/internal/tools"
)

func main() {
	engPath := flag.String("engagement", "", "chemin vers engagement.yaml (obligatoire)")
	check := flag.String("check", "", "vérifie si une cible est dans le scope, puis quitte")
	recon := flag.Bool("recon", false, "lance la boucle de reconnaissance assistée par le LLM")
	model := flag.String("model", "qwen3:8b", "modèle Ollama à utiliser pour le LLM")
	network := flag.String("network", "", "réseau Docker isolé pour le scan (ex. aria-lab) ; vide = aucun réseau")
	image := flag.String("image", "aria/nmap:latest", "image conteneur pour port_scan")
	maxSteps := flag.Int("max-steps", 8, "nombre maximum d'actions de reconnaissance")
	flag.Parse()

	if *engPath == "" {
		fmt.Fprintln(os.Stderr, "aria : --engagement <engagement.yaml> est obligatoire ; ARIA ne démarre pas sans autorisation valide")
		os.Exit(2)
	}

	// Garde-fou n°1 : pas d'engagement valide => ARIA ne démarre pas.
	eng, err := engagement.Load(*engPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aria : refus de démarrer : %v\n", err)
		os.Exit(1)
	}
	if !eng.Authorization.IsActive(time.Now()) {
		fmt.Fprintln(os.Stderr, "aria : refus de démarrer : la fenêtre d'autorisation n'est pas active actuellement")
		os.Exit(1)
	}

	afficherEngagement(eng)

	// Mode 1 : simple vérification de scope.
	if *check != "" {
		verifierCible(eng, *check)
		return
	}

	// Mode 2 : boucle de reconnaissance.
	if *recon {
		if err := lancerRecon(eng, *model, *network, *image, *maxSteps); err != nil {
			fmt.Fprintf(os.Stderr, "aria : %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Println("\nRien à faire de plus. Utilise -check <cible> ou -recon.")
}

// afficherEngagement résume l'engagement chargé.
func afficherEngagement(eng *engagement.Engagement) {
	in, out := eng.ScopeStrings()
	fmt.Printf("ARIA — engagement %q chargé et validé.\n", eng.Name)
	fmt.Printf("  autorisé par  : %s (réf %s)\n", eng.Authorization.AuthorizedBy, eng.Authorization.Reference)
	fmt.Printf("  dans le scope : %v\n", in)
	fmt.Printf("  hors scope    : %v\n", out)
	fmt.Printf("  catégories RoE: %v\n", eng.RoE.AllowedCategories)
}

// verifierCible affiche si une cible est dans le périmètre.
func verifierCible(eng *engagement.Engagement, cible string) {
	ok, err := eng.InScope(cible)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aria : impossible d'évaluer la cible %q : %v\n", cible, err)
		os.Exit(1)
	}
	if ok {
		fmt.Printf("DANS LE SCOPE : %s\n", cible)
	} else {
		fmt.Printf("HORS SCOPE (refusé) : %s\n", cible)
	}
}

// lancerRecon assemble tous les composants et exécute la boucle recon + analyse.
func lancerRecon(eng *engagement.Engagement, model, network, image string, maxSteps int) error {
	ctx := context.Background()

	// Politique réseau du bac à sable : aucun réseau par défaut (sûr), ou un
	// réseau isolé dédié au lab si -network est fourni.
	netPol := sandbox.NetworkPolicy{Mode: sandbox.NetNone}
	if network != "" {
		netPol = sandbox.NetworkPolicy{Mode: sandbox.NetIsolated, NetworkName: network}
	} else {
		fmt.Println("\n⚠ Aucun -network fourni : le scan n'aura pas d'accès réseau et ne trouvera rien.")
	}

	runner, err := sandbox.NewDockerRunner(sandbox.DockerConfig{DefaultNetwork: netPol})
	if err != nil {
		return err
	}
	if err := runner.Available(ctx); err != nil {
		return fmt.Errorf("Docker requis pour la reconnaissance : %w", err)
	}

	// Registre d'outils : pour l'instant, port_scan.
	reg := tools.NewRegistry()
	if err := reg.Register(tools.NewPortScan(image, netPol)); err != nil {
		return err
	}

	store := graph.NewStore()
	client := llm.NewOllamaClient(model)

	fmt.Printf("\n→ Reconnaissance (modèle %s, max %d étapes)...\n", model, maxSteps)
	planner := agent.NewPlanner(client, reg, eng)
	steps, err := planner.RunRecon(ctx, store, runner, maxSteps)
	if err != nil {
		return fmt.Errorf("reconnaissance : %w", err)
	}
	for _, s := range steps {
		fmt.Printf("  • %s %v (exit %d, %d hôte(s)) — %s\n", s.Action, s.Targets, s.ExitCode, s.HostsFound, s.Rationale)
	}

	fmt.Println("\n→ Profilage des hôtes...")
	for _, prof := range profiler.ClassifyStore(store) {
		fmt.Printf("  • %s\n", prof)
		for _, r := range prof.Reasons {
			fmt.Printf("      - %s\n", r)
		}
	}

	fmt.Println("\n→ Analyse des services découverts...")
	analyst := agent.NewAnalyst(client)
	if err := analyst.AnalyzeStore(ctx, store); err != nil {
		return fmt.Errorf("analyse : %w", err)
	}

	afficherGraph(store)
	return nil
}

// afficherGraph imprime les hôtes/services et les findings accumulés.
func afficherGraph(store *graph.Store) {
	sum := store.Summary()
	fmt.Printf("\n=== Résultats : %d hôte(s), %d service(s), %d finding(s) ===\n", sum.Hosts, sum.Services, sum.Findings)

	for _, h := range store.Hosts() {
		fmt.Printf("\nHôte %s", h.Address)
		if len(h.Hostnames) > 0 {
			fmt.Printf(" (%v)", h.Hostnames)
		}
		fmt.Println()
		for _, s := range h.Services {
			fmt.Printf("  %d/%s %s %s %s\n", s.Port, s.Protocol, s.Name, s.Product, s.Version)
		}
	}

	findings := store.Findings()
	if len(findings) > 0 {
		fmt.Println("\n--- Vulnérabilités candidates (à valider par l'opérateur) ---")
		for _, f := range findings {
			fmt.Printf("  [%s] %s (%s:%d)\n", f.Severity, f.Title, f.Host, f.Port)
			if f.Remediation != "" {
				fmt.Printf("      remédiation : %s\n", f.Remediation)
			}
		}
	}
}
