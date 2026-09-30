package agent

// DryRun décrit une action intrusive PROPOSÉE, présentée à l'opérateur avant toute
// exécution. C'est le cœur du garde-fou n°4 (tiers d'approbation) : on montre
// exactement quoi sera fait, sur quelle cible, avec quelle commande, et pourquoi —
// puis un humain décide.
type DryRun struct {
	Action    string
	Category  string
	Targets   []string
	Command   []string // argv exact qui sera exécuté dans le bac à sable
	Rationale string
}

// Approver décide si une action intrusive peut être exécutée. L'implémentation CLI
// interroge l'opérateur ; les tests fournissent un approbateur scriptable.
//
// Règle de sécurité : en l'absence d'approbateur, une action nécessitant une
// approbation est REFUSÉE (fail-closed) — voir Executor.
type Approver interface {
	Approve(dr DryRun) (bool, error)
}

// AutoDeny refuse tout. C'est le comportement par défaut si aucun approbateur n'est
// fourni : rien d'intrusif ne s'exécute sans validation explicite.
type AutoDeny struct{}

func (AutoDeny) Approve(DryRun) (bool, error) { return false, nil }
