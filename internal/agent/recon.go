package agent

import (
	"context"
	"fmt"

	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/sandbox"
	"github.com/Tag59/aria/internal/tools"
)

// Step consigne une action tentée, pour l'inspection et (plus tard) le journal
// d'audit.
type Step struct {
	Action     string
	Targets    []string
	Rationale  string
	ExitCode   int
	HostsFound int
	Status     string // "exécuté" ou "refusé" (par l'opérateur / faute d'approbateur)
}

// RunRecon fait tourner la boucle de reconnaissance : le Planner propose une
// action, on la valide (périmètre, RoE), on l'exécute dans le bac à sable, on
// parse la sortie et on l'accumule dans le graph — jusqu'à ce que le Planner dise
// "stop" ou qu'on atteigne maxSteps (garde-fou contre une boucle sans fin).
//
// La reconnaissance est automatique : aucune de ces actions n'exige d'approbation
// humaine (ce sera le cas des actions intrusives, à une étape ultérieure).
func (p *Planner) RunRecon(ctx context.Context, store *graph.Store, runner sandbox.Runner, maxSteps int) ([]Step, error) {
	var steps []Step

	for i := 0; i < maxSteps; i++ {
		d, err := p.Next(ctx, store)
		if err != nil {
			return steps, err
		}
		if d.Action == actionStop {
			return steps, nil
		}

		tool, ok := p.tools.Get(d.Action)
		if !ok {
			// Ne devrait pas arriver : Next a déjà validé l'action.
			return steps, fmt.Errorf("agent : outil inconnu %q", d.Action)
		}

		// Second appel au LLM : les paramètres, contraints par le schéma de l'outil.
		params, err := p.Params(ctx, tool, store)
		if err != nil {
			return steps, fmt.Errorf("agent : obtention des paramètres pour %q : %w", d.Action, err)
		}

		// Prepare valide et borne les paramètres proposés par le LLM.
		inv, err := tool.Prepare(params)
		if err != nil {
			return steps, fmt.Errorf("agent : paramètres invalides pour %q : %w", d.Action, err)
		}

		// Contrôle de périmètre : toute cible hors scope stoppe net.
		if err := tools.EnforceScope(p.eng, inv); err != nil {
			return steps, err
		}

		res, err := runner.Run(ctx, inv.Spec)
		if err != nil {
			return steps, fmt.Errorf("agent : exécution de %q : %w", d.Action, err)
		}

		out, err := tool.Parse(res)
		if err != nil {
			return steps, fmt.Errorf("agent : lecture de la sortie de %q : %w", d.Action, err)
		}
		store.Merge(out.Hosts)

		st := Step{
			Action:     d.Action,
			Targets:    inv.Targets,
			Rationale:  d.Rationale,
			ExitCode:   res.ExitCode,
			HostsFound: len(out.Hosts),
			Status:     "exécuté",
		}
		steps = append(steps, st)
		if p.OnStep != nil {
			p.OnStep(st)
		}
	}

	return steps, nil
}
