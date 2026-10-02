package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
)

func modeleTest(t *testing.T) Model {
	t.Helper()
	const yml = `
name: "Mission test"
client: "Client test"
authorization: {reference: REF-1, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: ["10.0.0.0/24"], out: ["10.0.0.1"]}
rules_of_engagement: {allowed_categories: [recon, vuln_scan]}
`
	eng, err := engagement.ParseAndValidate([]byte(yml))
	if err != nil {
		t.Fatalf("engagement : %v", err)
	}
	store := graph.NewStore()
	store.Merge([]graph.Host{{Address: "10.0.0.10", Services: []graph.Service{{Port: 80, Protocol: "tcp", Name: "http"}}}})
	store.MergeFindings([]graph.Finding{
		{Host: "10.0.0.10", Port: 80, Title: "Info banale", Severity: "info"},
		{Host: "10.0.0.10", Port: 80, Title: "Injection SQL", Severity: "high", Evidence: "param email"},
	})
	actions := []Action{{Name: "nuclei_scan", Targets: []string{"10.0.0.10"}, Status: "exécuté"}}
	return BuildModel(eng, store, actions)
}

func TestBuildModelTriEtComptes(t *testing.T) {
	m := modeleTest(t)
	if len(m.Findings) != 2 {
		t.Fatalf("attendu 2 findings, obtenu %d", len(m.Findings))
	}
	// Tri par sévérité : high avant info.
	if m.Findings[0].Severity != "high" {
		t.Errorf("findings mal triés : %s en premier", m.Findings[0].Severity)
	}
	if m.SeverityCounts["high"] != 1 || m.SeverityCounts["info"] != 1 {
		t.Errorf("comptes de sévérité inattendus : %+v", m.SeverityCounts)
	}
}

func TestMarkdownEtJSON(t *testing.T) {
	m := modeleTest(t)

	md := Markdown(m)
	for _, attendu := range []string{"Rapport de mission ARIA", "Mission test", "Injection SQL", "10.0.0.10", "## Synthèse"} {
		if !strings.Contains(md, attendu) {
			t.Errorf("Markdown : %q manquant", attendu)
		}
	}

	js, err := JSON(m)
	if err != nil {
		t.Fatalf("JSON : %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(js, &round); err != nil {
		t.Fatalf("JSON invalide : %v", err)
	}
}

func TestHTMLEchappe(t *testing.T) {
	store := graph.NewStore()
	store.MergeFindings([]graph.Finding{
		{Host: "10.0.0.10", Port: 80, Title: "XSS", Severity: "medium", Evidence: "<script>alert(1)</script>"},
	})
	const yml = `
name: t
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: ["10.0.0.0/24"]}
rules_of_engagement: {allowed_categories: [recon]}
`
	eng, _ := engagement.ParseAndValidate([]byte(yml))
	h, err := HTML(BuildModel(eng, store, nil))
	if err != nil {
		t.Fatalf("HTML : %v", err)
	}
	if strings.Contains(h, "<script>alert(1)</script>") {
		t.Error("la preuve issue de la cible n'a pas été échappée (risque d'injection dans le rapport)")
	}
	if !strings.Contains(h, "&lt;script&gt;") {
		t.Error("échappement HTML attendu de la preuve")
	}
}

func TestWriteAll(t *testing.T) {
	dir := t.TempDir()
	ecrits, err := WriteAll(dir, modeleTest(t))
	if err != nil {
		t.Fatalf("WriteAll : %v", err)
	}
	if len(ecrits) != 3 {
		t.Fatalf("attendu 3 fichiers, obtenu %d", len(ecrits))
	}
	for _, nom := range []string{"report.md", "report.json", "report.html"} {
		if _, err := os.Stat(filepath.Join(dir, nom)); err != nil {
			t.Errorf("fichier %s manquant : %v", nom, err)
		}
	}
}
