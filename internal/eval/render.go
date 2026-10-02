package eval

import (
	"fmt"
	"strings"
)

// frac formate un compte sur le nombre de runs (ex. "3/3").
func frac(n, total int) string { return fmt.Sprintf("%d/%d", n, total) }

// Console rend les résultats en tableau texte simple pour le terminal.
func Console(results []ModelResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-22s %-10s %-10s %-10s %-10s %-10s %-10s %-10s\n",
		"Modèle", "Décision", "Attendue", "Params", "Analyse", "Findings", "Lat.Plan", "Lat.Anal")
	b.WriteString(strings.Repeat("-", 96) + "\n")
	for _, r := range results {
		fmt.Fprintf(&b, "%-22s %-10s %-10s %-10s %-10s %-10s %-10s %-10s\n",
			r.Model,
			frac(r.PlannerValid, r.Runs),
			frac(r.PlannerExpected, r.Runs),
			frac(r.ParamsValid, r.Runs),
			frac(r.AnalystValid, r.Runs),
			frac(r.AnalystFindings, r.Runs),
			r.AvgPlanner().Round(100000000).String(),
			r.AvgAnalyst().Round(100000000).String(),
		)
	}
	return b.String()
}

// Markdown rend les résultats en tableau Markdown (pour la doc / le rapport).
func Markdown(results []ModelResult) string {
	var b strings.Builder
	b.WriteString("# Banc d'évaluation multi-modèles ARIA\n\n")
	b.WriteString("Métriques par modèle (sur N runs). Décision = sortie Planner valide ; ")
	b.WriteString("Attendue = action pertinente choisie ; Params = paramètres acceptés par Prepare ; ")
	b.WriteString("Analyse = sortie Analyst valide ; Findings = au moins un finding produit.\n\n")
	b.WriteString("| Modèle | Décision | Attendue | Params | Analyse | Findings | Lat. Planner | Lat. Analyst |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, r := range results {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			r.Model,
			frac(r.PlannerValid, r.Runs),
			frac(r.PlannerExpected, r.Runs),
			frac(r.ParamsValid, r.Runs),
			frac(r.AnalystValid, r.Runs),
			frac(r.AnalystFindings, r.Runs),
			r.AvgPlanner().Round(100000000).String(),
			r.AvgAnalyst().Round(100000000).String(),
		)
	}
	return b.String()
}
