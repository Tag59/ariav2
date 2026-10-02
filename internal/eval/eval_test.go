package eval

import (
	"context"
	"strings"
	"testing"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/llm"
	"github.com/Tag59/aria/internal/sandbox"
	"github.com/Tag59/aria/internal/tools"
)

// fakeClient renvoie une réponse préparée selon le rôle (déduit du prompt).
type fakeClient struct {
	action  string
	params  string
	analyst string
}

func (f fakeClient) Generate(_ context.Context, p llm.Prompt) ([]byte, error) {
	switch {
	case strings.Contains(p.System, "Analyst"):
		return []byte(f.analyst), nil
	case strings.Contains(p.User, "Fournis les paramètres"):
		return []byte(f.params), nil
	default:
		return []byte(f.action), nil
	}
}

func setup(t *testing.T) (*engagement.Engagement, *tools.Registry) {
	t.Helper()
	const yml = `
name: bench
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: ["10.0.0.0/8"]}
rules_of_engagement: {allowed_categories: [recon, enumeration, vuln_scan, exploitation]}
`
	eng, err := engagement.ParseAndValidate([]byte(yml))
	if err != nil {
		t.Fatalf("engagement : %v", err)
	}
	reg := tools.NewRegistry()
	np := sandbox.NetworkPolicy{Mode: sandbox.NetNone}
	for _, tl := range []tools.Tool{
		tools.NewPortScan("", np), tools.NewNucleiScan("", np),
		tools.NewSMBEnum("", np), tools.NewSQLiProbe("", np),
	} {
		if err := reg.Register(tl); err != nil {
			t.Fatalf("register : %v", err)
		}
	}
	return eng, reg
}

func TestRunBonModele(t *testing.T) {
	eng, reg := setup(t)
	good := fakeClient{
		action:  `{"action":"port_scan","rationale":"scan initial"}`,
		params:  `{"target":"10.0.0.10"}`,
		analyst: `{"findings":[{"title":"nginx obsolète","severity":"high","port":80,"description":"d"}]}`,
	}
	res := Run(Config{
		Models: []string{"good"}, Runs: 2, Eng: eng, Registry: reg,
		NewClient: func(string) llm.Client { return good },
	})
	if len(res) != 1 {
		t.Fatalf("attendu 1 résultat, obtenu %d", len(res))
	}
	r := res[0]
	if r.PlannerValid != 2 || r.PlannerExpected != 2 || r.ParamsValid != 2 ||
		r.AnalystValid != 2 || r.AnalystFindings != 2 || r.Errors != 0 {
		t.Errorf("bon modèle mal scoré : %+v", r)
	}
}

func TestRunMauvaisModele(t *testing.T) {
	eng, reg := setup(t)
	bad := fakeClient{
		action:  `{"action":"stop","rationale":"rien à faire"}`, // valide mais prématuré
		params:  `{}`,
		analyst: `{"findings":[{"title":"x","severity":"BOGUS","description":"d"}]}`, // sévérité invalide
	}
	res := Run(Config{
		Models: []string{"bad"}, Runs: 2, Eng: eng, Registry: reg,
		NewClient: func(string) llm.Client { return bad },
	})
	r := res[0]
	if r.PlannerValid != 2 {
		t.Errorf("'stop' est une décision valide : PlannerValid=%d", r.PlannerValid)
	}
	if r.PlannerExpected != 0 {
		t.Errorf("'stop' n'est pas l'action attendue : PlannerExpected=%d", r.PlannerExpected)
	}
	if r.ParamsValid != 0 {
		t.Errorf("pas de params pour 'stop' : ParamsValid=%d", r.ParamsValid)
	}
	if r.AnalystValid != 0 || r.Errors != 2 {
		t.Errorf("sévérité invalide => analyse en erreur : AnalystValid=%d Errors=%d", r.AnalystValid, r.Errors)
	}
}

func TestRendu(t *testing.T) {
	res := []ModelResult{{Model: "qwen3:8b", Runs: 3, PlannerValid: 3}}
	if !strings.Contains(Console(res), "qwen3:8b") {
		t.Error("Console doit contenir le nom du modèle")
	}
	if !strings.Contains(Markdown(res), "| qwen3:8b |") {
		t.Error("Markdown doit contenir une ligne pour le modèle")
	}
}
