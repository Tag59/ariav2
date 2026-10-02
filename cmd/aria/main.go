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
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Tag59/aria/internal/agent"
	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/llm"
	"github.com/Tag59/aria/internal/playbook"
	"github.com/Tag59/aria/internal/profiler"
	"github.com/Tag59/aria/internal/report"
	"github.com/Tag59/aria/internal/sandbox"
	"github.com/Tag59/aria/internal/tools"
	"github.com/Tag59/aria/internal/tui"
)

func main() {
	engPath := flag.String("engagement", "", "chemin vers engagement.yaml (obligatoire)")
	check := flag.String("check", "", "vérifie si une cible est dans le scope, puis quitte")
	recon := flag.Bool("recon", false, "lance la boucle de reconnaissance assistée par le LLM")
	tuiMode := flag.Bool("tui", false, "lance la mission dans l'interface terminal (TUI)")
	model := flag.String("model", "qwen3:8b", "modèle Ollama à utiliser pour le LLM")
	network := flag.String("network", "", "réseau Docker isolé pour le scan (ex. aria-lab) ; vide = aucun réseau")
	image := flag.String("image", "aria/nmap:latest", "image conteneur pour port_scan / smb_enum")
	nucleiImage := flag.String("nuclei-image", "aria/nuclei:latest", "image conteneur pour nuclei_scan")
	sqlmapImage := flag.String("sqlmap-image", "aria/sqlmap:latest", "image conteneur pour sqli_probe")
	maxSteps := flag.Int("max-steps", 8, "nombre maximum d'actions de reconnaissance")
	playbooksDir := flag.String("playbooks", "playbooks", "dossier des playbooks")
	reportDir := flag.String("report", "", "dossier où écrire le rapport (md/json/html) ; vide = pas de rapport")
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

	// Mode TUI : interface terminal (ne pas polluer l'écran avant l'altscreen).
	if *tuiMode {
		if err := lancerTUI(eng, *model, *network, *image, *nucleiImage, *sqlmapImage, *maxSteps, *playbooksDir, *reportDir); err != nil {
			fmt.Fprintf(os.Stderr, "aria : %v\n", err)
			os.Exit(1)
		}
		return
	}

	afficherEngagement(eng)

	// Mode 1 : simple vérification de scope.
	if *check != "" {
		verifierCible(eng, *check)
		return
	}

	// Mode 2 : boucle de reconnaissance.
	if *recon {
		if err := lancerRecon(eng, *model, *network, *image, *nucleiImage, *sqlmapImage, *maxSteps, *playbooksDir, *reportDir); err != nil {
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

// construireExecution bâtit le runner (bac à sable Docker) et le registre d'outils
// à partir des options. Partagé par le mode CLI et le mode TUI.
func construireExecution(ctx context.Context, network, image, nucleiImage, sqlmapImage string) (sandbox.Runner, *tools.Registry, error) {
	netPol := sandbox.NetworkPolicy{Mode: sandbox.NetNone}
	if network != "" {
		netPol = sandbox.NetworkPolicy{Mode: sandbox.NetIsolated, NetworkName: network}
	}
	runner, err := sandbox.NewDockerRunner(sandbox.DockerConfig{DefaultNetwork: netPol})
	if err != nil {
		return nil, nil, err
	}
	if err := runner.Available(ctx); err != nil {
		return nil, nil, fmt.Errorf("Docker requis : %w", err)
	}
	reg := tools.NewRegistry()
	for _, t := range []tools.Tool{
		tools.NewPortScan(image, netPol),
		tools.NewNucleiScan(nucleiImage, netPol),
		tools.NewSMBEnum(image, netPol),
		tools.NewSQLiProbe(sqlmapImage, netPol),
	} {
		if err := reg.Register(t); err != nil {
			return nil, nil, err
		}
	}
	return runner, reg, nil
}

// lancerTUI lance la mission dans l'interface terminal.
func lancerTUI(eng *engagement.Engagement, model, network, image, nucleiImage, sqlmapImage string, maxSteps int, playbooksDir, reportDir string) error {
	runner, reg, err := construireExecution(context.Background(), network, image, nucleiImage, sqlmapImage)
	if err != nil {
		return err
	}
	return tui.Run(tui.Config{
		Eng:          eng,
		Registry:     reg,
		Runner:       runner,
		Client:       llm.NewOllamaClient(model),
		PlaybooksDir: playbooksDir,
		MaxSteps:     maxSteps,
		ReportDir:    reportDir,
	})
}

// lancerRecon assemble tous les composants et exécute la boucle recon + analyse.
func lancerRecon(eng *engagement.Engagement, model, network, image, nucleiImage, sqlmapImage string, maxSteps int, playbooksDir, reportDir string) error {
	ctx := context.Background()

	if network == "" {
		fmt.Println("\n⚠ Aucun -network fourni : le scan n'aura pas d'accès réseau et ne trouvera rien.")
	}
	runner, reg, err := construireExecution(ctx, network, image, nucleiImage, sqlmapImage)
	if err != nil {
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

	fmt.Println("\n→ Profilage, plan et exécution autonome...")
	executor := agent.NewExecutor(reg, eng, runner, &approbateurCLI{in: bufio.NewReader(os.Stdin)})
	execSteps := profilerPlanifierExecuter(ctx, store, eng, executor, playbooksDir)

	fmt.Println("\n→ Analyse des services découverts...")
	analyst := agent.NewAnalyst(client)
	if err := analyst.AnalyzeStore(ctx, store); err != nil {
		return fmt.Errorf("analyse : %w", err)
	}

	afficherGraph(store)

	if reportDir != "" {
		if err := ecrireRapport(eng, store, append(steps, execSteps...), reportDir); err != nil {
			return fmt.Errorf("rapport : %w", err)
		}
	}
	return nil
}

// ecrireRapport construit le modèle de rapport et l'écrit (md/json/html).
func ecrireRapport(eng *engagement.Engagement, store *graph.Store, steps []agent.Step, dir string) error {
	actions := make([]report.Action, 0, len(steps))
	for _, s := range steps {
		statut := s.Status
		if statut == "" {
			statut = "exécuté"
		}
		actions = append(actions, report.Action{Name: s.Action, Targets: s.Targets, Status: statut})
	}
	ecrits, err := report.WriteAll(dir, report.BuildModel(eng, store, actions))
	if err != nil {
		return err
	}
	fmt.Printf("\n→ Rapport écrit :\n")
	for _, p := range ecrits {
		fmt.Printf("   %s\n", p)
	}
	return nil
}

// profilerPlanifierExecuter classe chaque hôte, affiche le plan méthodologique
// applicable (via le playbook recommandé), puis EXÉCUTE automatiquement les steps
// applicables et outillés (sauf ceux exigeant une approbation).
func profilerPlanifierExecuter(ctx context.Context, store *graph.Store, eng *engagement.Engagement, executor *agent.Executor, playbooksDir string) []agent.Step {
	cache := map[string]*playbook.Playbook{}
	var tous []agent.Step
	for _, prof := range profiler.ClassifyStore(store) {
		fmt.Printf("  • %s\n", prof)
		for _, r := range prof.Reasons {
			fmt.Printf("      - %s\n", r)
		}
		if prof.Playbook == "" {
			continue
		}
		pb := cache[prof.Playbook]
		if pb == nil {
			loaded, err := playbook.Load(filepath.Join(playbooksDir, prof.Playbook))
			if err != nil {
				fmt.Printf("      (playbook %s non chargé : %v)\n", prof.Playbook, err)
				continue
			}
			pb = loaded
			cache[prof.Playbook] = pb
		}
		host, ok := store.Host(prof.Host)
		if !ok {
			continue
		}

		// Plan (ce que le playbook suggère, adapté aux découvertes et aux RoE).
		plan := playbook.NewEngine(pb, eng.RoE).PlanForHost(host)
		for _, ph := range plan {
			fmt.Printf("      Phase « %s » :\n", ph.Name)
			for _, st := range ph.Steps {
				marque := ""
				if st.RequiresApproval {
					marque = " [approbation requise — ignoré en auto]"
				}
				fmt.Printf("        - %s%s\n", st.Action, marque)
			}
		}

		// Exécution autonome des steps applicables et outillés.
		steps, err := executor.ExecutePlaybook(ctx, store, host, pb)
		if err != nil {
			fmt.Printf("      exécution interrompue : %v\n", err)
			continue
		}
		if len(steps) == 0 {
			fmt.Println("      (aucun step exécutable automatiquement pour l'instant)")
			continue
		}
		fmt.Println("      Résultat :")
		for _, s := range steps {
			if s.Status == "refusé" {
				fmt.Printf("        ✗ %s %v — refusé (non approuvé)\n", s.Action, s.Targets)
			} else {
				fmt.Printf("        ✓ %s %v (exit %d)\n", s.Action, s.Targets, s.ExitCode)
			}
		}
		tous = append(tous, steps...)
	}
	return tous
}

// approbateurCLI demande à l'opérateur de valider une action intrusive, en
// affichant un dry-run complet (garde-fou n°4). En entrée non interactive (pas de
// terminal), la lecture échoue et l'action est REFUSÉE (fail-closed).
type approbateurCLI struct {
	in *bufio.Reader
}

func (a *approbateurCLI) Approve(dr agent.DryRun) (bool, error) {
	fmt.Println("\n  ┌─ VALIDATION REQUISE — action intrusive ─────────────────────")
	fmt.Printf("  │ action   : %s (%s)\n", dr.Action, dr.Category)
	fmt.Printf("  │ cible(s) : %v\n", dr.Targets)
	fmt.Printf("  │ pourquoi : %s\n", dr.Rationale)
	fmt.Printf("  │ commande : %s\n", strings.Join(dr.Command, " "))
	fmt.Print("  └ Exécuter cette action ? [y/N] ")

	line, err := a.in.ReadString('\n')
	if err != nil {
		fmt.Println("(pas d'entrée interactive → refus par défaut)")
		return false, nil
	}
	rep := strings.TrimSpace(strings.ToLower(line))
	return rep == "y" || rep == "yes" || rep == "o" || rep == "oui", nil
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
