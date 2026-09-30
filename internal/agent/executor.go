package agent

import (
	"context"
	"fmt"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/playbook"
	"github.com/Tag59/aria/internal/sandbox"
	"github.com/Tag59/aria/internal/tools"
)

// Executor exécute AUTONOMEMENT le plan d'un playbook contre un hôte : il enchaîne
// les steps applicables (condition `when` satisfaite ET catégorie autorisée par
// les RoE) dont l'outil est disponible et qui n'exigent pas d'approbation.
//
// Les steps intrusifs (requires_approval) sont volontairement IGNORÉS ici : ils
// passeront par les tiers d'approbation (dry-run + validation humaine), étape
// ultérieure. Les steps sans adapter enregistré sont sautés (la méthodologie du
// playbook est plus large que l'outillage disponible).
type Executor struct {
	tools    *tools.Registry
	eng      *engagement.Engagement
	runner   sandbox.Runner
	approver Approver
}

// NewExecutor assemble un Executor. Si approver est nil, toute action nécessitant
// une approbation est refusée (fail-closed).
func NewExecutor(reg *tools.Registry, eng *engagement.Engagement, runner sandbox.Runner, approver Approver) *Executor {
	if approver == nil {
		approver = AutoDeny{}
	}
	return &Executor{tools: reg, eng: eng, runner: runner, approver: approver}
}

// ExecutePlaybook exécute le plan de pb contre l'hôte h et ingère les résultats
// dans store. Renvoie les steps réellement exécutés.
func (e *Executor) ExecutePlaybook(ctx context.Context, store *graph.Store, h graph.Host, pb *playbook.Playbook) ([]Step, error) {
	var steps []Step
	plan := playbook.NewEngine(pb, e.eng.RoE).PlanForHost(h)

	for _, ph := range plan {
		for _, st := range ph.Steps {
			tool, ok := e.tools.Get(st.Action)
			if !ok {
				continue // pas d'adapter pour cette action : on saute
			}

			params := contextParams(st, h)
			inv, err := tool.Prepare(params)
			if err != nil {
				return steps, fmt.Errorf("agent : paramètres invalides pour %q : %w", st.Action, err)
			}
			// Contrôle de périmètre AVANT toute approbation : on ne propose jamais
			// d'approuver une action hors scope.
			if err := tools.EnforceScope(e.eng, inv); err != nil {
				return steps, err
			}

			// Tiers d'approbation : une action intrusive (marquée requires_approval,
			// ou de catégorie exploitation/post_exploit) exige une validation humaine
			// avec dry-run. Le reste (recon/énumération/vuln_scan) est automatique.
			if besoinApprobation(st, tool) {
				ok, err := e.approver.Approve(DryRun{
					Action:    st.Action,
					Category:  string(tool.Category()),
					Targets:   inv.Targets,
					Command:   inv.Spec.Argv,
					Rationale: st.Rationale,
				})
				if err != nil {
					return steps, fmt.Errorf("agent : approbation de %q : %w", st.Action, err)
				}
				if !ok {
					steps = append(steps, Step{
						Action:    st.Action,
						Targets:   inv.Targets,
						Rationale: st.Rationale,
						Status:    "refusé",
					})
					continue // non approuvé : on n'exécute pas
				}
			}

			res, err := e.runner.Run(ctx, inv.Spec)
			if err != nil {
				return steps, fmt.Errorf("agent : exécution de %q : %w", st.Action, err)
			}
			out, err := tool.Parse(res)
			if err != nil {
				return steps, fmt.Errorf("agent : lecture de la sortie de %q : %w", st.Action, err)
			}
			// Rattache les findings sans hôte/port à l'hôte courant (certains outils,
			// comme sqlmap, ne connaissent pas l'adresse dans leur sortie).
			for i := range out.Findings {
				if out.Findings[i].Host == "" {
					out.Findings[i].Host = h.Address
				}
				if out.Findings[i].Port == 0 {
					if p, _ := webEndpoint(h); p != 0 {
						out.Findings[i].Port = p
					}
				}
			}
			store.Merge(out.Hosts)
			store.MergeFindings(out.Findings)

			steps = append(steps, Step{
				Action:     st.Action,
				Targets:    inv.Targets,
				Rationale:  st.Rationale,
				ExitCode:   res.ExitCode,
				HostsFound: len(out.Hosts),
				Status:     "exécuté",
			})
		}
	}
	return steps, nil
}

// besoinApprobation indique si une action exige une validation humaine : marquée
// requires_approval (playbook ou adapter), ou de catégorie intrusive
// (exploitation / post_exploit).
func besoinApprobation(st playbook.Step, tool tools.Tool) bool {
	if st.RequiresApproval || tool.RequiresApproval() {
		return true
	}
	switch tool.Category() {
	case engagement.CatExploitation, engagement.CatPostExploit:
		return true
	}
	return false
}

// contextParams part des paramètres du step et y injecte le contexte de l'hôte
// (cible, et pour le web port/scheme), sans écraser une valeur déjà fournie. La
// cible est TOUJOURS l'hôte courant : en exécution autonome, ce n'est pas le LLM
// qui choisit la cible.
func contextParams(st playbook.Step, h graph.Host) map[string]any {
	p := map[string]any{}
	for k, v := range st.Params {
		p[k] = v
	}
	p["target"] = h.Address
	if port, scheme := webEndpoint(h); port != 0 {
		if _, ok := p["port"]; !ok {
			p["port"] = port
		}
		if _, ok := p["scheme"]; !ok {
			p["scheme"] = scheme
		}
	}
	return p
}

// webEndpoint choisit un service web représentatif de l'hôte (HTTPS prioritaire).
func webEndpoint(h graph.Host) (int, string) {
	for _, s := range h.Services {
		if s.Name == "https" || s.Port == 443 || s.Port == 8443 {
			return s.Port, "https"
		}
	}
	for _, s := range h.Services {
		if s.Name == "http" || s.Port == 80 || s.Port == 8080 || s.Port == 8000 || s.Port == 3000 {
			return s.Port, "http"
		}
	}
	return 0, ""
}
