// Command ariabench compare plusieurs modèles LLM locaux (Ollama) sur les tâches
// d'ARIA (Planner et Analyst), avec des métriques objectives et reproductibles.
//
// Prérequis : Ollama lancé, avec les modèles à comparer déjà récupérés.
// Exemple : ariabench -models qwen3:8b,llama3.1,qwen2.5-coder:14b -runs 5 -out bench.md
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/eval"
	"github.com/Tag59/aria/internal/sandbox"
	"github.com/Tag59/aria/internal/tools"
)

func main() {
	modelsFlag := flag.String("models", "", "modèles Ollama à comparer, séparés par des virgules")
	runs := flag.Int("runs", 3, "répétitions par scénario et par modèle")
	out := flag.String("out", "", "fichier Markdown de sortie (optionnel)")
	flag.Parse()

	models := decouper(*modelsFlag)
	if len(models) == 0 {
		fmt.Fprintln(os.Stderr, "ariabench : -models est requis (ex. -models qwen3:8b,llama3.1)")
		os.Exit(2)
	}

	eng, err := engagementBench()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ariabench : %v\n", err)
		os.Exit(1)
	}
	reg, err := registreBench()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ariabench : %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Banc d'évaluation : %s (%d runs chacun)\n", strings.Join(models, ", "), *runs)
	res := eval.Run(eval.Config{
		Models:   models,
		Runs:     *runs,
		Eng:      eng,
		Registry: reg,
		Progress: func(s string) { fmt.Fprintf(os.Stderr, "  … %-50s\r", s) },
	})
	fmt.Fprintln(os.Stderr)

	fmt.Print(eval.Console(res))

	if *out != "" {
		if err := os.WriteFile(*out, []byte(eval.Markdown(res)), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "ariabench : écriture %q : %v\n", *out, err)
			os.Exit(1)
		}
		fmt.Printf("\nMarkdown écrit : %s\n", *out)
	}
}

func decouper(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// engagementBench fournit un engagement de test (toutes catégories activées) pour
// que le Planner puisse proposer ses actions et que Prepare valide les paramètres.
func engagementBench() (*engagement.Engagement, error) {
	const yml = `
name: "Banc d'évaluation ARIA"
authorization: {reference: BENCH, authorized_by: bench, signed: true, valid_from: "2026-01-01", valid_until: "2030-12-31"}
scope: {in: ["10.0.0.0/8"]}
rules_of_engagement: {allowed_categories: [recon, enumeration, vuln_scan, exploitation]}
`
	return engagement.ParseAndValidate([]byte(yml))
}

// registreBench enregistre les adapters (les images/réseau importent peu : le banc
// n'exécute aucun outil, il n'évalue que les décisions du LLM).
func registreBench() (*tools.Registry, error) {
	reg := tools.NewRegistry()
	np := sandbox.NetworkPolicy{Mode: sandbox.NetNone}
	for _, t := range []tools.Tool{
		tools.NewPortScan("", np),
		tools.NewNucleiScan("", np),
		tools.NewSMBEnum("", np),
		tools.NewSQLiProbe("", np),
	} {
		if err := reg.Register(t); err != nil {
			return nil, err
		}
	}
	return reg, nil
}
