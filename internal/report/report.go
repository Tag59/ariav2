// Package report génère un rapport de mission à partir du knowledge graph :
// Markdown (versionnable), JSON (exploitable par d'autres outils) et HTML (artefact
// visuel, imprimable en PDF).
//
// Les contenus issus de la cible (descriptions, preuves) sont échappés dans le
// rendu HTML (html/template) : une preuve piégée ne peut pas injecter de code dans
// le rapport.
package report

import (
	"sort"
	"time"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
)

// Action résume une action menée pendant la mission (pour la traçabilité).
type Action struct {
	Name    string
	Targets []string
	Status  string // "exécuté" / "refusé"
}

// Model est le modèle de données du rapport, prêt à être rendu.
type Model struct {
	Title          string
	EngagementName string
	Client         string
	AuthRef        string
	GeneratedAt    time.Time
	ScopeIn        []string
	ScopeOut       []string
	Categories     []string
	Summary        graph.Summary
	SeverityCounts map[string]int
	Hosts          []graph.Host
	Findings       []graph.Finding // triés par sévérité décroissante
	Actions        []Action
}

// ordreSeverite classe les sévérités de la plus grave à la moins grave.
var ordreSeverite = map[string]int{
	"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
}

func rangSeverite(s string) int { return ordreSeverite[s] }

// severitesConnues liste les niveaux dans l'ordre d'affichage.
var severitesConnues = []string{"critical", "high", "medium", "low", "info"}

// BuildModel assemble le modèle du rapport depuis l'engagement, le graph et la
// liste des actions menées.
func BuildModel(eng *engagement.Engagement, store *graph.Store, actions []Action) Model {
	in, out := eng.ScopeStrings()
	cats := make([]string, 0, len(eng.RoE.AllowedCategories))
	for _, c := range eng.RoE.AllowedCategories {
		cats = append(cats, string(c))
	}

	findings := store.Findings()
	sort.SliceStable(findings, func(i, j int) bool {
		return rangSeverite(findings[i].Severity) > rangSeverite(findings[j].Severity)
	})

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	return Model{
		Title:          "Rapport de mission ARIA",
		EngagementName: eng.Name,
		Client:         eng.Client,
		AuthRef:        eng.Authorization.Reference,
		GeneratedAt:    time.Now(),
		ScopeIn:        in,
		ScopeOut:       out,
		Categories:     cats,
		Summary:        store.Summary(),
		SeverityCounts: counts,
		Hosts:          store.Hosts(),
		Findings:       findings,
		Actions:        actions,
	}
}
