package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Tag59/aria/internal/agent"
	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
)

func engTest(t *testing.T) *engagement.Engagement {
	t.Helper()
	const yml = `
name: "Mission TUI"
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: ["10.0.0.0/24"]}
rules_of_engagement: {allowed_categories: [recon, exploitation]}
`
	e, err := engagement.ParseAndValidate([]byte(yml))
	if err != nil {
		t.Fatalf("engagement : %v", err)
	}
	return e
}

func TestModelRenduEtRefresh(t *testing.T) {
	store := graph.NewStore()
	store.Merge([]graph.Host{{Address: "10.0.0.10", Services: []graph.Service{{Port: 3000, Protocol: "tcp", Name: "http"}}}})
	store.MergeFindings([]graph.Finding{{Host: "10.0.0.10", Port: 3000, Title: "Injection SQL", Severity: "high"}})

	m := model{cfg: Config{Eng: engTest(t)}, store: store, phase: "Reconnaissance", width: 100, height: 30}
	m2, _ := m.Update(refreshMsg{})
	m = m2.(model)

	v := m.View()
	for _, attendu := range []string{"Mission TUI", "10.0.0.10", "Injection SQL", "Reconnaissance"} {
		if !strings.Contains(v, attendu) {
			t.Errorf("vue : %q manquant", attendu)
		}
	}
}

func TestModelApprobation(t *testing.T) {
	m := model{cfg: Config{Eng: engTest(t)}, store: graph.NewStore(), width: 100, height: 30}

	// L'approbateur envoie une demande ; la modale doit s'afficher.
	reply := make(chan bool, 1)
	m2, _ := m.Update(approvalMsg{
		dr:    agent.DryRun{Action: "sqli_probe", Category: "exploitation", Targets: []string{"10.0.0.10"}, Command: []string{"sqlmap", "-u", "x"}},
		reply: reply,
	})
	m = m2.(model)
	if m.pending == nil {
		t.Fatal("la modale d'approbation devrait être active")
	}
	if !strings.Contains(m.View(), "VALIDATION REQUISE") {
		t.Error("la vue devrait afficher la modale d'approbation")
	}

	// Appui sur 'y' => la décision true revient par le canal, la modale se ferme.
	m3, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	m = m3.(model)
	select {
	case got := <-reply:
		if !got {
			t.Error("attendu une approbation (true)")
		}
	default:
		t.Error("aucune décision envoyée sur le canal")
	}
	if m.pending != nil {
		t.Error("la modale devrait être fermée après décision")
	}
}

func TestModelRefus(t *testing.T) {
	m := model{cfg: Config{Eng: engTest(t)}, store: graph.NewStore(), width: 100, height: 30}
	reply := make(chan bool, 1)
	m2, _ := m.Update(approvalMsg{dr: agent.DryRun{Action: "sqli_probe"}, reply: reply})
	m = m2.(model)

	m3, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = m3.(model)
	select {
	case got := <-reply:
		if got {
			t.Error("Échap devait refuser (false)")
		}
	default:
		t.Error("aucune décision envoyée")
	}
}
