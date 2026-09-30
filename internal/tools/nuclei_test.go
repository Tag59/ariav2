package tools

import (
	"strings"
	"testing"

	"github.com/Tag59/aria/internal/sandbox"
)

func TestNucleiPrepareDefaut(t *testing.T) {
	ns := NewNucleiScan("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	inv, err := ns.Prepare(map[string]any{"target": "172.28.0.10"})
	if err != nil {
		t.Fatalf("Prepare : %v", err)
	}
	got := strings.Join(inv.Spec.Argv, " ")
	if !strings.Contains(got, "-u http://172.28.0.10:80") {
		t.Errorf("URL par défaut attendue http://172.28.0.10:80, argv=%q", got)
	}
	if !strings.Contains(got, "-t /nuclei-templates") || !strings.Contains(got, "-jsonl") {
		t.Errorf("flags essentiels manquants : %q", got)
	}
	if inv.Spec.Image != imageNucleiParDefaut {
		t.Errorf("image = %q", inv.Spec.Image)
	}
	if len(inv.Targets) != 1 || inv.Targets[0] != "172.28.0.10" {
		t.Errorf("Targets = %v", inv.Targets)
	}
}

func TestNucleiPreparePortScheme(t *testing.T) {
	ns := NewNucleiScan("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	inv, err := ns.Prepare(map[string]any{"target": "web.lab", "scheme": "https", "port": float64(8443)})
	if err != nil {
		t.Fatalf("Prepare : %v", err)
	}
	if !strings.Contains(strings.Join(inv.Spec.Argv, " "), "https://web.lab:8443") {
		t.Errorf("URL attendue https://web.lab:8443, argv=%v", inv.Spec.Argv)
	}
}

func TestNucleiPrepareRejets(t *testing.T) {
	ns := NewNucleiScan("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	cas := map[string]map[string]any{
		"cible manquante": {},
		"cible CIDR":      {"target": "10.0.0.0/24"},
		"scheme invalide": {"target": "x", "scheme": "ftp"},
	}
	for nom, p := range cas {
		if _, err := ns.Prepare(p); err == nil {
			t.Errorf("erreur attendue pour %q", nom)
		}
	}
}

func TestNucleiParse(t *testing.T) {
	jsonl := `{"template-id":"swagger-api","host":"172.28.0.10","port":"3000","matched-at":"http://172.28.0.10:3000/api-docs","info":{"name":"Public Swagger API","severity":"info","description":"detected","reference":["https://swagger.io/"]}}
pas du json
{"template-id":"x","host":"172.28.0.10","port":"3000","matched-at":"http://172.28.0.10:3000/","info":{"name":"Header manquant","severity":"medium","reference":"https://ex"}}`

	ns := NewNucleiScan("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	out, err := ns.Parse(sandbox.Result{Stdout: []byte(jsonl)})
	if err != nil {
		t.Fatalf("Parse : %v", err)
	}
	if len(out.Findings) != 2 {
		t.Fatalf("attendu 2 findings (ligne non-JSON ignorée), obtenu %d", len(out.Findings))
	}
	f0 := out.Findings[0]
	if f0.Title != "Public Swagger API" || f0.Severity != "info" || f0.Port != 3000 || f0.Host != "172.28.0.10" {
		t.Errorf("finding 0 mal parsé : %+v", f0)
	}
	if len(f0.Refs) != 1 || f0.Refs[0] != "https://swagger.io/" {
		t.Errorf("refs (liste) mal parsées : %v", f0.Refs)
	}
	// reference sous forme de chaîne unique doit aussi marcher (flexStrings).
	if len(out.Findings[1].Refs) != 1 || out.Findings[1].Refs[0] != "https://ex" {
		t.Errorf("refs (chaîne) mal parsées : %v", out.Findings[1].Refs)
	}
}
