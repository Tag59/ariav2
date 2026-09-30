package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/playbook"
	"github.com/Tag59/aria/internal/sandbox"
	"github.com/Tag59/aria/internal/tools"
)

// fakeTool est un outil de test : sa cible vient de params["target"], et Parse
// renvoie des findings préparés.
type fakeTool struct {
	nom      string
	cat      engagement.Category
	approval bool
	findings []graph.Finding
}

func (f fakeTool) Name() string                  { return f.nom }
func (f fakeTool) Description() string           { return "fake" }
func (f fakeTool) ParamsSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (f fakeTool) Category() engagement.Category { return f.cat }
func (f fakeTool) RequiresApproval() bool        { return f.approval }
func (f fakeTool) Prepare(params map[string]any) (tools.Invocation, error) {
	target, _ := params["target"].(string)
	return tools.Invocation{
		Targets: []string{target},
		Spec:    sandbox.Spec{Image: "x", Argv: []string{"x"}},
	}, nil
}
func (f fakeTool) Parse(_ sandbox.Result) (tools.Output, error) {
	return tools.Output{Findings: f.findings}, nil
}

func engagementScope(t *testing.T, in string) *engagement.Engagement {
	t.Helper()
	yml := `
name: test
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: ["` + in + `"]}
rules_of_engagement: {allowed_categories: [recon, enumeration, vuln_scan]}
`
	eng, err := engagement.ParseAndValidate([]byte(yml))
	if err != nil {
		t.Fatalf("engagement : %v", err)
	}
	return eng
}

func playbookExec() *playbook.Playbook {
	return &playbook.Playbook{
		Name: "t", TargetType: "web-app",
		Phases: []playbook.Phase{
			{ID: "vuln", Name: "Vuln", Steps: []playbook.Step{
				{ID: "n", Action: "nuclei_scan", GatedByRoE: "vuln_scan", When: "service.http == true"},
				{ID: "app", Action: "nuclei_scan", GatedByRoE: "vuln_scan", When: "service.http == true", RequiresApproval: true},
				{ID: "abs", Action: "outil_inexistant", GatedByRoE: "vuln_scan", When: "service.http == true"},
			}},
		},
	}
}

func hostHTTP() graph.Host {
	return graph.Host{Address: "10.0.0.5", Services: []graph.Service{{Port: 3000, Name: "http"}}}
}

func TestExecutePlaybook(t *testing.T) {
	eng := engagementScope(t, "10.0.0.0/24")
	reg := tools.NewRegistry()
	_ = reg.Register(fakeTool{
		nom: "nuclei_scan", cat: engagement.CatVulnScan,
		findings: []graph.Finding{{Host: "10.0.0.5", Port: 3000, Title: "XSS", Severity: "medium"}},
	})
	store := graph.NewStore()
	exec := NewExecutor(reg, eng, &fakeRunner{})

	steps, err := exec.ExecutePlaybook(context.Background(), store, hostHTTP(), playbookExec())
	if err != nil {
		t.Fatalf("ExecutePlaybook : %v", err)
	}
	// Un seul step exécuté : le step intrusif (requires_approval) et le step sans
	// adapter sont ignorés.
	if len(steps) != 1 || steps[0].Action != "nuclei_scan" {
		t.Fatalf("attendu 1 step (nuclei_scan), obtenu %+v", steps)
	}
	if store.Summary().Findings != 1 {
		t.Errorf("attendu 1 finding ingéré, obtenu %d", store.Summary().Findings)
	}
}

func TestExecutePlaybookRefuseHorsScope(t *testing.T) {
	// L'hôte 10.0.0.5 n'est PAS dans le périmètre 192.168.0.0/24.
	eng := engagementScope(t, "192.168.0.0/24")
	reg := tools.NewRegistry()
	_ = reg.Register(fakeTool{nom: "nuclei_scan", cat: engagement.CatVulnScan})
	store := graph.NewStore()
	exec := NewExecutor(reg, eng, &fakeRunner{})

	if _, err := exec.ExecutePlaybook(context.Background(), store, hostHTTP(), playbookExec()); err == nil {
		t.Error("attendu un refus de scope pour un hôte hors périmètre")
	}
}
