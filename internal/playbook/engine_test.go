package playbook

import (
	"testing"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
)

func playbookTest() *Playbook {
	return &Playbook{
		Name:       "test",
		TargetType: "web-app",
		Phases: []Phase{
			{ID: "recon", Name: "Recon", Steps: []Step{
				{ID: "http_probe", Action: "http_probe", GatedByRoE: "recon", When: "service.http == true"},
				{ID: "tls_scan", Action: "tls_scan", GatedByRoE: "recon", When: "service.https == true"},
			}},
			{ID: "vuln", Name: "Vuln", Steps: []Step{
				{ID: "nuclei", Action: "nuclei_scan", GatedByRoE: "vuln_scan", When: "service.http == true"},
			}},
			{ID: "expl", Name: "Exploitation", Steps: []Step{
				{ID: "sqli", Action: "sqli_probe", GatedByRoE: "exploitation", When: "service.http == true"},
			}},
		},
	}
}

func TestPlanForHost(t *testing.T) {
	// Hôte web (port 3000/http), sans HTTPS.
	host := graph.Host{
		Address:  "10.0.0.1",
		Services: []graph.Service{{Port: 3000, Protocol: "tcp", Name: "http"}},
	}
	// RoE : recon + vuln_scan autorisés, mais PAS exploitation.
	roe := engagement.RoE{AllowedCategories: []engagement.Category{
		engagement.CatRecon, engagement.CatVulnScan,
	}}

	plan := NewEngine(playbookTest(), roe).PlanForHost(host)

	// Attendu : phase recon (http_probe seul, tls_scan filtré car pas d'HTTPS) et
	// phase vuln (nuclei). La phase exploitation est filtrée par les RoE.
	if len(plan) != 2 {
		t.Fatalf("attendu 2 phases applicables, obtenu %d : %+v", len(plan), plan)
	}
	if plan[0].ID != "recon" || len(plan[0].Steps) != 1 || plan[0].Steps[0].ID != "http_probe" {
		t.Errorf("phase recon inattendue : %+v", plan[0])
	}
	if plan[1].ID != "vuln" || len(plan[1].Steps) != 1 {
		t.Errorf("phase vuln inattendue : %+v", plan[1])
	}
}

func TestPlanForHostExploitationActivee(t *testing.T) {
	host := graph.Host{Address: "10.0.0.1", Services: []graph.Service{{Port: 80, Name: "http"}}}
	// Exploitation autorisée : la phase exploitation doit apparaître.
	roe := engagement.RoE{AllowedCategories: []engagement.Category{
		engagement.CatRecon, engagement.CatVulnScan, engagement.CatExploitation,
	}}
	plan := NewEngine(playbookTest(), roe).PlanForHost(host)
	if len(plan) != 3 {
		t.Fatalf("attendu 3 phases (dont exploitation), obtenu %d", len(plan))
	}
}

func TestFactsForHost(t *testing.T) {
	h := graph.Host{
		Address:   "10.0.0.1",
		Hostnames: []string{"web.lab.local"},
		Services: []graph.Service{
			{Port: 3000, Name: "http"},
			{Port: 22, Name: "ssh"},
		},
	}
	f := FactsForHost(h)
	if !f.Bools["service.http"] || !f.Bools["service.ssh"] || !f.Bools["target.is_hostname"] {
		t.Errorf("faits attendus manquants : %+v", f.Bools)
	}
	if f.Bools["service.smb"] || f.Bools["service.https"] {
		t.Errorf("faits inattendus présents : %+v", f.Bools)
	}
}
