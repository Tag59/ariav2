package playbook

import (
	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
)

// Engine calcule, à partir d'un playbook et de l'état connu d'un hôte, le plan
// méthodologique applicable : quels steps ont leur condition `when` satisfaite ET
// dont la catégorie est autorisée par les RoE.
//
// C'est le « cadre » dans lequel le Planner raisonnera : le moteur détermine ce
// qui est pertinent et permis ; il ne décide pas seul d'exécuter (l'humain et les
// tiers d'approbation gardent la main sur l'intrusif).
type Engine struct {
	pb  *Playbook
	roe engagement.RoE
}

// NewEngine crée un moteur pour un playbook et des règles d'engagement données.
func NewEngine(pb *Playbook, roe engagement.RoE) *Engine {
	return &Engine{pb: pb, roe: roe}
}

// PlannedPhase est une phase avec seulement ses steps applicables pour un hôte.
type PlannedPhase struct {
	ID    string
	Name  string
	Steps []Step
}

// PlanForHost renvoie, phase par phase, les steps applicables à un hôte. Les
// phases sans aucun step applicable sont omises.
func (e *Engine) PlanForHost(h graph.Host) []PlannedPhase {
	facts := FactsForHost(h)
	var plan []PlannedPhase
	for _, ph := range e.pb.Phases {
		var steps []Step
		for _, st := range ph.Steps {
			if e.stepApplicable(st, facts) {
				steps = append(steps, st)
			}
		}
		if len(steps) > 0 {
			plan = append(plan, PlannedPhase{ID: ph.ID, Name: ph.Name, Steps: steps})
		}
	}
	return plan
}

// stepApplicable : la catégorie du gate RoE doit être autorisée, et la condition
// `when` satisfaite.
func (e *Engine) stepApplicable(st Step, facts Facts) bool {
	if st.GatedByRoE != "" && !e.roe.Allows(engagement.Category(st.GatedByRoE)) {
		return false
	}
	return EvalWhen(st.When, facts)
}

// FactsForHost dérive les faits d'un hôte à partir de ses services (ports/noms),
// pour l'évaluation des conditions `when`.
func FactsForHost(h graph.Host) Facts {
	ports := make(map[int]bool)
	names := make(map[string]bool)
	for _, s := range h.Services {
		ports[s.Port] = true
		if s.Name != "" {
			names[s.Name] = true
		}
	}
	any := func(ps []int, ns []string) bool {
		for _, p := range ps {
			if ports[p] {
				return true
			}
		}
		for _, n := range ns {
			if names[n] {
				return true
			}
		}
		return false
	}

	bools := map[string]bool{
		"service.http":       any([]int{80, 8080, 8000, 3000}, []string{"http", "http-alt", "http-proxy"}),
		"service.https":      any([]int{443, 8443}, []string{"https", "ssl/http"}),
		"service.smb":        any([]int{445, 139}, []string{"microsoft-ds", "netbios-ssn", "smb"}),
		"service.ssh":        any([]int{22}, []string{"ssh"}),
		"service.snmp":       any([]int{161}, []string{"snmp"}),
		"service.ftp":        any([]int{21}, []string{"ftp"}),
		"target.is_hostname": len(h.Hostnames) > 0,
	}
	return Facts{Bools: bools, Strs: map[string]string{}}
}
