package tools

import (
	"testing"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/sandbox"
)

// outilBidon est un Tool minimal pour tester le registre.
type outilBidon struct{ nom string }

func (o outilBidon) Name() string                               { return o.nom }
func (o outilBidon) Description() string                        { return "outil de test" }
func (o outilBidon) Category() engagement.Category              { return engagement.CatRecon }
func (o outilBidon) RequiresApproval() bool                     { return false }
func (o outilBidon) Prepare(map[string]any) (Invocation, error) { return Invocation{}, nil }
func (o outilBidon) Parse(sandbox.Result) (Output, error)       { return Output{}, nil }

func TestRegistry(t *testing.T) {
	r := NewRegistry()

	if err := r.Register(outilBidon{nom: "a"}); err != nil {
		t.Fatalf("Register a: %v", err)
	}
	if err := r.Register(outilBidon{nom: "a"}); err == nil {
		t.Error("un doublon doit être refusé")
	}
	if err := r.Register(outilBidon{nom: ""}); err == nil {
		t.Error("un nom vide doit être refusé")
	}
	if err := r.Register(outilBidon{nom: "b"}); err != nil {
		t.Fatalf("Register b: %v", err)
	}

	if _, ok := r.Get("a"); !ok {
		t.Error("outil 'a' introuvable")
	}
	if _, ok := r.Get("inconnu"); ok {
		t.Error("Get d'un outil inexistant devrait renvoyer false")
	}

	list := r.List()
	if len(list) != 2 || list[0].Name() != "a" || list[1].Name() != "b" {
		t.Errorf("List devrait être triée [a b], obtenu %v", nomsDe(list))
	}
}

func nomsDe(ts []Tool) []string {
	var n []string
	for _, t := range ts {
		n = append(n, t.Name())
	}
	return n
}

// engagementTest construit un engagement valide (scope 192.168.56.0/24).
func engagementTest(t *testing.T) *engagement.Engagement {
	t.Helper()
	const yml = `
name: test
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: ["192.168.56.0/24"], out: ["192.168.56.1"]}
rules_of_engagement: {allowed_categories: [recon]}
`
	eng, err := engagement.ParseAndValidate([]byte(yml))
	if err != nil {
		t.Fatalf("engagement invalide : %v", err)
	}
	return eng
}

func TestEnforceScope(t *testing.T) {
	eng := engagementTest(t)

	// Cible dans le scope : OK.
	if err := EnforceScope(eng, Invocation{Targets: []string{"192.168.56.10"}}); err != nil {
		t.Errorf("cible dans le scope refusée : %v", err)
	}
	// Cible hors scope : refus.
	if err := EnforceScope(eng, Invocation{Targets: []string{"8.8.8.8"}}); err == nil {
		t.Error("cible hors scope acceptée, refus attendu")
	}
	// Cible exclue : refus.
	if err := EnforceScope(eng, Invocation{Targets: []string{"192.168.56.1"}}); err == nil {
		t.Error("cible exclue acceptée, refus attendu")
	}
	// Aucune cible : refus par précaution.
	if err := EnforceScope(eng, Invocation{}); err == nil {
		t.Error("invocation sans cible acceptée, refus attendu")
	}
}

// Vérifie que l'adapter port_scan respecte bien l'interface Tool.
var _ Tool = (*PortScan)(nil)
