package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/llm"
	"github.com/Tag59/aria/internal/sandbox"
	"github.com/Tag59/aria/internal/tools"
)

// fakeLLM renvoie des réponses préparées, dans l'ordre.
type fakeLLM struct {
	responses [][]byte
	i         int
}

func (f *fakeLLM) Generate(_ context.Context, _ llm.Prompt) ([]byte, error) {
	if f.i >= len(f.responses) {
		return nil, fmt.Errorf("fakeLLM : plus de réponses préparées")
	}
	r := f.responses[f.i]
	f.i++
	return r, nil
}

// fakeRunner simule le bac à sable en renvoyant une sortie fixe.
type fakeRunner struct {
	stdout []byte
}

func (f *fakeRunner) Available(_ context.Context) error { return nil }
func (f *fakeRunner) Run(_ context.Context, _ sandbox.Spec) (sandbox.Result, error) {
	return sandbox.Result{Stdout: f.stdout, ExitCode: 0}, nil
}

const xmlNmap = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.56.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
    </ports>
  </host>
</nmaprun>`

// Réponses réutilisables pour les deux appels du Planner.
var (
	repScanAction = []byte(`{"action":"port_scan","rationale":"découvrir les services"}`)
	repStopAction = []byte(`{"action":"stop","rationale":"recon suffisante"}`)
	repParamsOK   = []byte(`{"target":"192.168.56.10"}`)
	repParamsHors = []byte(`{"target":"8.8.8.8"}`)
)

// setup construit un engagement valide et un registre contenant port_scan.
func setup(t *testing.T) (*engagement.Engagement, *tools.Registry) {
	t.Helper()
	const yml = `
name: test
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: ["192.168.56.0/24"]}
rules_of_engagement: {allowed_categories: [recon]}
`
	eng, err := engagement.ParseAndValidate([]byte(yml))
	if err != nil {
		t.Fatalf("engagement : %v", err)
	}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.NewPortScan("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})); err != nil {
		t.Fatalf("register : %v", err)
	}
	return eng, reg
}

func TestNextDecodeEtValidation(t *testing.T) {
	eng, reg := setup(t)
	store := graph.NewStore()

	// Décision valide.
	p := NewPlanner(&fakeLLM{responses: [][]byte{repScanAction}}, reg, eng)
	d, err := p.Next(context.Background(), store)
	if err != nil {
		t.Fatalf("Next : %v", err)
	}
	if d.Action != "port_scan" {
		t.Errorf("action inattendue : %+v", d)
	}

	// Action hors liste -> refus.
	p2 := NewPlanner(&fakeLLM{responses: [][]byte{
		[]byte(`{"action":"evil_tool","rationale":"x"}`),
	}}, reg, eng)
	if _, err := p2.Next(context.Background(), store); err == nil {
		t.Error("une action hors de la liste autorisée aurait dû être refusée")
	}

	// Clé inconnue dans la sortie -> refus (sortie non conforme).
	p3 := NewPlanner(&fakeLLM{responses: [][]byte{
		[]byte(`{"action":"stop","rationale":"x","injection":"ignore-moi"}`),
	}}, reg, eng)
	if _, err := p3.Next(context.Background(), store); err == nil {
		t.Error("une sortie avec une clé inconnue aurait dû être rejetée")
	}
}

func TestParams(t *testing.T) {
	eng, reg := setup(t)
	store := graph.NewStore()
	tool, _ := reg.Get("port_scan")

	p := NewPlanner(&fakeLLM{responses: [][]byte{repParamsOK}}, reg, eng)
	params, err := p.Params(context.Background(), tool, store)
	if err != nil {
		t.Fatalf("Params : %v", err)
	}
	if params["target"] != "192.168.56.10" {
		t.Errorf("paramètres inattendus : %+v", params)
	}
}

func TestRunReconCheminNominal(t *testing.T) {
	eng, reg := setup(t)
	store := graph.NewStore()

	// Étape 1 : action port_scan puis ses paramètres. Étape 2 : stop.
	fake := &fakeLLM{responses: [][]byte{repScanAction, repParamsOK, repStopAction}}
	p := NewPlanner(fake, reg, eng)
	runner := &fakeRunner{stdout: []byte(xmlNmap)}

	steps, err := p.RunRecon(context.Background(), store, runner, 5)
	if err != nil {
		t.Fatalf("RunRecon : %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("attendu 1 étape exécutée, obtenu %d", len(steps))
	}
	if steps[0].Action != "port_scan" || steps[0].HostsFound != 1 {
		t.Errorf("étape inattendue : %+v", steps[0])
	}

	hosts := store.Hosts()
	if len(hosts) != 1 || hosts[0].Address != "192.168.56.10" {
		t.Fatalf("graph inattendu : %+v", hosts)
	}
	if len(hosts[0].Services) != 1 || hosts[0].Services[0].Port != 80 {
		t.Errorf("service attendu 80/tcp, obtenu %+v", hosts[0].Services)
	}
}

func TestRunReconRefuseHorsScope(t *testing.T) {
	eng, reg := setup(t)
	store := graph.NewStore()

	// Action valide, mais paramètres avec une cible hors périmètre.
	fake := &fakeLLM{responses: [][]byte{repScanAction, repParamsHors}}
	p := NewPlanner(fake, reg, eng)
	runner := &fakeRunner{stdout: []byte(xmlNmap)}

	_, err := p.RunRecon(context.Background(), store, runner, 5)
	if err == nil || !strings.Contains(err.Error(), "HORS SCOPE") {
		t.Errorf("attendu un refus pour cible hors scope, obtenu : %v", err)
	}
	if store.Summary().Hosts != 0 {
		t.Error("aucun hôte ne devrait avoir été ajouté après un refus de scope")
	}
}

func TestRunReconGardeMaxSteps(t *testing.T) {
	eng, reg := setup(t)
	store := graph.NewStore()

	// Le LLM propose toujours un scan (ne s'arrête jamais) : 2 réponses par étape.
	fake := &fakeLLM{responses: [][]byte{
		repScanAction, repParamsOK,
		repScanAction, repParamsOK,
		repScanAction, repParamsOK,
	}}
	p := NewPlanner(fake, reg, eng)
	runner := &fakeRunner{stdout: []byte(xmlNmap)}

	steps, err := p.RunRecon(context.Background(), store, runner, 3)
	if err != nil {
		t.Fatalf("RunRecon : %v", err)
	}
	if len(steps) != 3 {
		t.Errorf("maxSteps=3 devait borner à 3 étapes, obtenu %d", len(steps))
	}
}
