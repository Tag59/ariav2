package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/Tag59/aria/internal/graph"
)

func hoteExemple() graph.Host {
	return graph.Host{
		Address: "192.168.56.10",
		Services: []graph.Service{
			{Port: 80, Protocol: "tcp", State: "open", Name: "http", Product: "nginx", Version: "1.18.0"},
		},
	}
}

func TestAnalyzeCheminNominal(t *testing.T) {
	fake := &fakeLLM{responses: [][]byte{
		[]byte(`{"findings":[{"title":"nginx obsolète","severity":"medium","port":80,"description":"version ancienne","impact":"exposition","remediation":"mettre à jour","refs":["CVE-2021-23017"]}]}`),
	}}
	a := NewAnalyst(fake)

	findings, err := a.Analyze(context.Background(), hoteExemple())
	if err != nil {
		t.Fatalf("Analyze : %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("attendu 1 finding, obtenu %d", len(findings))
	}
	f := findings[0]
	if f.Host != "192.168.56.10" || f.Port != 80 || f.Severity != "medium" {
		t.Errorf("finding mal rattaché : %+v", f)
	}
	// L'evidence doit être reconstruite depuis le service du port.
	if !strings.Contains(f.Evidence, "nginx") || !strings.Contains(f.Evidence, "1.18.0") {
		t.Errorf("evidence inattendue : %q", f.Evidence)
	}
}

func TestAnalyzeSansService(t *testing.T) {
	// Aucun service : pas d'appel au LLM, pas de finding.
	fake := &fakeLLM{} // aucune réponse préparée : s'il est appelé, ce sera une erreur
	a := NewAnalyst(fake)
	findings, err := a.Analyze(context.Background(), graph.Host{Address: "10.0.0.1"})
	if err != nil {
		t.Fatalf("Analyze : %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("attendu 0 finding, obtenu %d", len(findings))
	}
}

func TestAnalyzeSeveriteInvalide(t *testing.T) {
	fake := &fakeLLM{responses: [][]byte{
		[]byte(`{"findings":[{"title":"x","severity":"catastrophique","description":"y"}]}`),
	}}
	a := NewAnalyst(fake)
	if _, err := a.Analyze(context.Background(), hoteExemple()); err == nil {
		t.Error("une sévérité hors échelle aurait dû être rejetée")
	}
}

func TestAnalyzeCleInconnue(t *testing.T) {
	fake := &fakeLLM{responses: [][]byte{
		[]byte(`{"findings":[],"injection":"ignore-moi"}`),
	}}
	a := NewAnalyst(fake)
	if _, err := a.Analyze(context.Background(), hoteExemple()); err == nil {
		t.Error("une sortie avec une clé inconnue aurait dû être rejetée")
	}
}

func TestAnalyzePortFallback(t *testing.T) {
	// Le LLM omet le port (0), mais l'hôte n'a qu'un seul service : le finding
	// doit être rattaché à ce service (port 80).
	fake := &fakeLLM{responses: [][]byte{
		[]byte(`{"findings":[{"title":"x","severity":"low","port":0,"description":"d"}]}`),
	}}
	a := NewAnalyst(fake)
	findings, err := a.Analyze(context.Background(), hoteExemple())
	if err != nil {
		t.Fatalf("Analyze : %v", err)
	}
	if len(findings) != 1 || findings[0].Port != 80 {
		t.Errorf("port attendu 80 (repli sur le seul service), obtenu %+v", findings)
	}
}

func TestAnalyzeStore(t *testing.T) {
	store := graph.NewStore()
	store.Merge([]graph.Host{hoteExemple()})

	fake := &fakeLLM{responses: [][]byte{
		[]byte(`{"findings":[{"title":"nginx obsolète","severity":"low","port":80,"description":"d"}]}`),
	}}
	a := NewAnalyst(fake)

	if err := a.AnalyzeStore(context.Background(), store); err != nil {
		t.Fatalf("AnalyzeStore : %v", err)
	}
	if got := store.Summary().Findings; got != 1 {
		t.Errorf("attendu 1 finding dans le graph, obtenu %d", got)
	}
}
