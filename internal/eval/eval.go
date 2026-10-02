// Package eval compare plusieurs modèles LLM locaux sur les tâches réellement
// utilisées par ARIA (Planner et Analyst), de façon reproductible et hors ligne.
//
// Les métriques sont objectives (pas de jugement humain ni de LLM-juge) :
//   - décision valide : la sortie du Planner respecte le schéma et l'action est
//     dans la liste autorisée (Planner.Next ne renvoie pas d'erreur) ;
//   - action attendue : le Planner choisit l'action pertinente du scénario ;
//   - paramètres valides : les paramètres proposés passent Tool.Prepare ;
//   - analyse valide : la sortie de l'Analyst respecte le schéma (sévérités
//     bornées) ;
//   - findings produits : l'Analyst remonte au moins un finding ;
//   - latence moyenne par rôle.
package eval

import (
	"context"
	"fmt"
	"time"

	"github.com/Tag59/aria/internal/agent"
	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/llm"
	"github.com/Tag59/aria/internal/tools"
)

// Config paramètre un banc d'évaluation.
type Config struct {
	Models   []string
	Runs     int
	Eng      *engagement.Engagement
	Registry *tools.Registry
	// NewClient fabrique un client LLM pour un modèle. Injectable pour les tests ;
	// par défaut, un client Ollama local.
	NewClient func(model string) llm.Client
	// Progress, s'il est défini, reçoit des messages d'avancement.
	Progress func(string)
}

// ModelResult agrège les métriques d'un modèle sur l'ensemble des runs.
type ModelResult struct {
	Model           string
	Runs            int
	PlannerValid    int
	PlannerExpected int
	ParamsValid     int
	AnalystValid    int
	AnalystFindings int
	Errors          int

	plannerLatency time.Duration
	analystLatency time.Duration
}

// AvgPlanner renvoie la latence moyenne d'un appel Planner (Next).
func (r ModelResult) AvgPlanner() time.Duration {
	if r.Runs == 0 {
		return 0
	}
	return r.plannerLatency / time.Duration(r.Runs)
}

// AvgAnalyst renvoie la latence moyenne d'un appel Analyst.
func (r ModelResult) AvgAnalyst() time.Duration {
	if r.Runs == 0 {
		return 0
	}
	return r.analystLatency / time.Duration(r.Runs)
}

// expectedPlannerActions : au départ (graph vide), la seule action de recon
// pertinente est un scan de ports ; répondre "stop" serait prématuré.
var expectedPlannerActions = map[string]bool{"port_scan": true}

// analystHost est le scénario d'analyse : un service web avec une version précise,
// pour lequel un bon modèle doit proposer au moins un finding candidat.
func analystHost() graph.Host {
	return graph.Host{
		Address: "10.0.0.10",
		Services: []graph.Service{
			{Port: 80, Protocol: "tcp", State: "open", Name: "http", Product: "nginx", Version: "1.18.0"},
		},
	}
}

// Run exécute le banc sur tous les modèles et renvoie les résultats agrégés.
func Run(cfg Config) []ModelResult {
	if cfg.Runs <= 0 {
		cfg.Runs = 3
	}
	if cfg.NewClient == nil {
		cfg.NewClient = func(m string) llm.Client { return llm.NewOllamaClient(m) }
	}
	ctx := context.Background()

	var results []ModelResult
	for _, mdl := range cfg.Models {
		client := cfg.NewClient(mdl)
		planner := agent.NewPlanner(client, cfg.Registry, cfg.Eng)
		analyst := agent.NewAnalyst(client)
		r := ModelResult{Model: mdl, Runs: cfg.Runs}

		// Préchauffage (non chronométré) : charge le modèle en VRAM pour que la
		// première latence mesurée ne soit pas faussée par le temps de chargement.
		if cfg.Progress != nil {
			cfg.Progress(mdl + " — préchauffage")
		}
		_, _ = planner.Next(ctx, graph.NewStore())

		for i := 0; i < cfg.Runs; i++ {
			if cfg.Progress != nil {
				cfg.Progress(fmt.Sprintf("%s — run %d/%d", mdl, i+1, cfg.Runs))
			}

			// Scénario Planner : graph vide, quelle première action ?
			store := graph.NewStore()
			t0 := time.Now()
			d, err := planner.Next(ctx, store)
			r.plannerLatency += time.Since(t0)
			if err != nil {
				r.Errors++
			} else {
				r.PlannerValid++
				if expectedPlannerActions[d.Action] {
					r.PlannerExpected++
				}
				if d.Action != "stop" {
					if tool, ok := cfg.Registry.Get(d.Action); ok {
						if params, perr := planner.Params(ctx, tool, store); perr == nil {
							if _, prep := tool.Prepare(params); prep == nil {
								r.ParamsValid++
							}
						}
					}
				}
			}

			// Scénario Analyst : interpréter un service web connu.
			t1 := time.Now()
			fs, aerr := analyst.Analyze(ctx, analystHost())
			r.analystLatency += time.Since(t1)
			if aerr != nil {
				r.Errors++
			} else {
				r.AnalystValid++
				if len(fs) > 0 {
					r.AnalystFindings++
				}
			}
		}
		results = append(results, r)
	}
	return results
}
