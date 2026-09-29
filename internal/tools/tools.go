// Package tools définit le catalogue d'actions typées que l'agent peut exécuter.
//
// Principe central d'ARIA : le LLM ne fabrique jamais une commande shell. Il
// choisit un outil par son nom et fournit des paramètres, que l'adapter valide et
// borne avant de construire la commande réelle. Chaque outil sait aussi quels
// hôtes il va toucher (pour la vérification de scope) et comment transformer sa
// sortie brute en objets structurés.
package tools

import (
	"fmt"
	"sort"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/sandbox"
)

// Invocation est une action prête à être vérifiée puis exécutée. C'est le
// résultat de Tool.Prepare : les paramètres bruts ont été validés, la cible est
// connue, et la commande à lancer dans le bac à sable est fixée.
type Invocation struct {
	// Targets liste les hôtes/domaines que l'action va contacter. L'orchestrateur
	// vérifie CHAQUE cible avec engagement.InScope avant de lancer quoi que ce soit.
	Targets []string
	// Spec est la commande sandboxée à exécuter (image + argv bornés).
	Spec sandbox.Spec
}

// Output regroupe la sortie structurée d'un outil après parsing. Pour l'instant
// on ne remonte que des hôtes ; on enrichira (findings, preuves) plus tard.
type Output struct {
	Hosts []graph.Host
}

// Tool est l'interface que tout adapter d'outil implémente.
type Tool interface {
	// Name est l'identifiant stable utilisé par le Planner et les playbooks.
	Name() string
	// Category sert au filtrage par les règles d'engagement (RoE).
	Category() engagement.Category
	// RequiresApproval indique si l'action est intrusive et exige une validation
	// humaine (avec dry-run) avant exécution.
	RequiresApproval() bool
	// Prepare valide/borne les paramètres et renvoie l'action à exécuter.
	Prepare(params map[string]any) (Invocation, error)
	// Parse transforme la sortie brute du bac à sable en objets structurés.
	Parse(res sandbox.Result) (Output, error)
}

// Registry est le catalogue des outils disponibles.
type Registry struct {
	tools map[string]Tool
}

// NewRegistry crée un registre vide.
func NewRegistry() *Registry {
	return &Registry{tools: make(map[string]Tool)}
}

// Register ajoute un outil. Un nom vide ou déjà pris est une erreur : on veut un
// catalogue sans ambiguïté.
func (r *Registry) Register(t Tool) error {
	name := t.Name()
	if name == "" {
		return fmt.Errorf("tools: nom d'outil vide")
	}
	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("tools: outil %q déjà enregistré", name)
	}
	r.tools[name] = t
	return nil
}

// Get renvoie un outil par son nom.
func (r *Registry) Get(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// List renvoie les outils triés par nom (ordre stable pour l'affichage et les tests).
func (r *Registry) List() []Tool {
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Tool, 0, len(names))
	for _, n := range names {
		out = append(out, r.tools[n])
	}
	return out
}

// EnforceScope vérifie que toutes les cibles d'une invocation sont dans le
// périmètre autorisé. C'est le point de contrôle que l'orchestrateur appelle
// avant d'exécuter une action ; hors scope = refus net.
func EnforceScope(eng *engagement.Engagement, inv Invocation) error {
	if len(inv.Targets) == 0 {
		return fmt.Errorf("tools: invocation sans cible, refus par précaution")
	}
	for _, t := range inv.Targets {
		ok, err := eng.InScope(t)
		if err != nil {
			return fmt.Errorf("tools: cible %q invalide : %w", t, err)
		}
		if !ok {
			return fmt.Errorf("tools: cible %q HORS SCOPE, action refusée", t)
		}
	}
	return nil
}
