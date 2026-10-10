package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Tag59/aria/internal/agent"
	"github.com/Tag59/aria/internal/graph"
)

type fakeAppr struct{ ok bool }

func (f fakeAppr) Approve(agent.DryRun) (bool, error) { return f.ok, nil }

func TestJournalEtRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	j := New(&buf)
	j.now = func() time.Time { return time.Date(2026, 10, 11, 14, 30, 0, 0, time.UTC) }

	j.MissionStart("Mission test", []string{"10.0.0.0/24"})
	j.Phase("Reconnaissance")
	j.Step(agent.Step{Action: "port_scan", Targets: []string{"10.0.0.10"}, Status: "exécuté"})
	j.Finding(graph.Finding{Host: "10.0.0.10", Port: 80, Severity: "high", Title: "Injection SQL"})
	j.MissionEnd("terminé")

	ev := j.Events()
	if len(ev) != 5 {
		t.Fatalf("attendu 5 événements, obtenu %d", len(ev))
	}

	// Round-trip JSONL : relire ce qui a été écrit au fil de l'eau.
	relus, err := Load(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Load : %v", err)
	}
	if len(relus) != 5 || relus[0].Kind != KindMissionStart || relus[2].Action != "port_scan" {
		t.Errorf("round-trip incorrect : %+v", relus)
	}

	// Rendu lisible.
	r := j.Render()
	for _, attendu := range []string{"mission_start", "port_scan", "Injection SQL"} {
		if !strings.Contains(r, attendu) {
			t.Errorf("Render : %q manquant", attendu)
		}
	}
}

func TestWrapApprover(t *testing.T) {
	j := New(nil)

	// Approbation accordée : journalise demande + décision, renvoie la vraie réponse.
	appr := WrapApprover(fakeAppr{ok: true}, j)
	ok, err := appr.Approve(agent.DryRun{Action: "sqli_probe", Targets: []string{"10.0.0.10"}})
	if err != nil || !ok {
		t.Fatalf("Approve = %v,%v ; attendu true,nil", ok, err)
	}
	ev := j.Events()
	if len(ev) != 2 || ev[0].Kind != KindApprovalReq || ev[1].Kind != KindApprovalOK {
		t.Errorf("événements d'approbation inattendus : %+v", ev)
	}

	// Refus.
	j2 := New(nil)
	appr2 := WrapApprover(fakeAppr{ok: false}, j2)
	if ok, _ := appr2.Approve(agent.DryRun{Action: "sqli_probe"}); ok {
		t.Error("attendu un refus")
	}
	if j2.Events()[1].Kind != KindApprovalNo {
		t.Errorf("attendu approval_denied, obtenu %s", j2.Events()[1].Kind)
	}
}
