package tools

import (
	"strings"
	"testing"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/sandbox"
)

func TestSQLiProbeMetadonnees(t *testing.T) {
	s := NewSQLiProbe("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	if s.Category() != engagement.CatExploitation {
		t.Errorf("catégorie attendue exploitation, obtenu %q", s.Category())
	}
	if !s.RequiresApproval() {
		t.Error("sqli_probe doit exiger une approbation")
	}
}

func TestSQLiProbePrepare(t *testing.T) {
	s := NewSQLiProbe("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	inv, err := s.Prepare(map[string]any{
		"target": "172.28.0.10", "port": float64(3000),
		"path": "/rest/user/login", "data": `{"email":"a","password":"b"}`,
	})
	if err != nil {
		t.Fatalf("Prepare : %v", err)
	}
	got := strings.Join(inv.Spec.Argv, " ")
	if !strings.Contains(got, "-u http://172.28.0.10:3000/rest/user/login") {
		t.Errorf("URL attendue, argv=%q", got)
	}
	if !strings.Contains(got, "--batch") || strings.Contains(got, "--dump") {
		t.Errorf("attendu --batch et PAS --dump : %q", got)
	}
	if !strings.Contains(got, "--data") || !strings.Contains(got, "Content-Type: application/json") {
		t.Errorf("données POST JSON mal gérées : %q", got)
	}
}

func TestSQLiProbeCrawlGenerique(t *testing.T) {
	s := NewSQLiProbe("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	// Sans path ni data : mode générique (découverte par crawl).
	inv, err := s.Prepare(map[string]any{"target": "10.0.0.5"})
	if err != nil {
		t.Fatalf("Prepare : %v", err)
	}
	got := strings.Join(inv.Spec.Argv, " ")
	if !strings.Contains(got, "--crawl=2") || !strings.Contains(got, "--forms") {
		t.Errorf("mode générique attendu (--crawl/--forms) : %q", got)
	}
	if !strings.Contains(got, "-u http://10.0.0.5:80/") {
		t.Errorf("URL racine attendue : %q", got)
	}
	if strings.Contains(got, "--data") {
		t.Error("pas de --data en mode découverte")
	}
}

func TestSQLiProbeRejets(t *testing.T) {
	s := NewSQLiProbe("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	cas := map[string]map[string]any{
		"cible manquante": {},
		"cible CIDR":      {"target": "10.0.0.0/24"},
		"scheme invalide": {"target": "x", "scheme": "ftp"},
	}
	for nom, p := range cas {
		if _, err := s.Prepare(p); err == nil {
			t.Errorf("erreur attendue pour %q", nom)
		}
	}
}

func TestSQLiProbeParse(t *testing.T) {
	s := NewSQLiProbe("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})

	// Sortie avec injection confirmée.
	vuln := `[*] starting
sqlmap identified the following injection point(s):
Parameter: email (JSON)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"email":"a' AND 1=1-- -","password":"b"}
[*] done`
	out, err := s.Parse(sandbox.Result{Stdout: []byte(vuln)})
	if err != nil {
		t.Fatalf("Parse : %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("attendu 1 finding, obtenu %d", len(out.Findings))
	}
	f := out.Findings[0]
	if f.Severity != "high" || !strings.Contains(f.Evidence, "email") {
		t.Errorf("finding mal formé : %+v", f)
	}

	// Sortie sans injection : aucun finding.
	out2, _ := s.Parse(sandbox.Result{Stdout: []byte("[*] all tested parameters do not appear to be injectable")})
	if len(out2.Findings) != 0 {
		t.Errorf("attendu 0 finding, obtenu %d", len(out2.Findings))
	}
}
