// Package tui fournit une interface terminal (Bubble Tea) qui déroule une mission
// ARIA en direct : phases, hôtes/services découverts, findings colorés par
// sévérité, et une modale d'approbation pour les actions intrusives.
//
// La mission tourne dans une goroutine qui communique avec l'interface uniquement
// par messages (p.Send) ; l'état partagé (le knowledge graph) est protégé par un
// mutex côté store.
package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Tag59/aria/internal/agent"
	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/llm"
	"github.com/Tag59/aria/internal/playbook"
	"github.com/Tag59/aria/internal/profiler"
	"github.com/Tag59/aria/internal/report"
	"github.com/Tag59/aria/internal/sandbox"
	"github.com/Tag59/aria/internal/tools"
)

// Config regroupe ce dont la TUI a besoin pour mener la mission.
type Config struct {
	Eng          *engagement.Engagement
	Registry     *tools.Registry
	Runner       sandbox.Runner
	Client       llm.Client
	PlaybooksDir string
	MaxSteps     int
	ReportDir    string
}

// Run lance l'interface et la mission. Bloque jusqu'à ce que l'opérateur quitte.
func Run(cfg Config) error {
	store := graph.NewStore()
	m := model{cfg: cfg, store: store, phase: "Initialisation"}
	p := tea.NewProgram(m, tea.WithAltScreen())

	appr := &approver{p: p}
	planner := agent.NewPlanner(cfg.Client, cfg.Registry, cfg.Eng)
	planner.OnStep = func(s agent.Step) { p.Send(stepMsg(s)) }
	executor := agent.NewExecutor(cfg.Registry, cfg.Eng, cfg.Runner, appr)
	executor.OnStep = func(s agent.Step) { p.Send(stepMsg(s)) }
	analyst := agent.NewAnalyst(cfg.Client)

	go runMission(p, cfg, store, planner, executor, analyst)

	_, err := p.Run()
	return err
}

// --- messages ---

type phaseMsg string
type logMsg string
type stepMsg agent.Step
type refreshMsg struct{}
type approvalMsg struct {
	dr    agent.DryRun
	reply chan bool
}
type doneMsg struct {
	err     error
	reports []string
}
type tickMsg struct{}

func tick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

// runMission déroule recon → profil/exécution → analyse → rapport, en poussant des
// messages vers l'interface.
func runMission(p *tea.Program, cfg Config, store *graph.Store, planner *agent.Planner, executor *agent.Executor, analyst *agent.Analyst) {
	ctx := context.Background()
	var toutes []agent.Step

	p.Send(phaseMsg("Reconnaissance"))
	reconSteps, err := planner.RunRecon(ctx, store, cfg.Runner, cfg.MaxSteps)
	if err != nil {
		p.Send(doneMsg{err: err})
		return
	}
	toutes = append(toutes, reconSteps...)
	p.Send(refreshMsg{})

	p.Send(phaseMsg("Profilage & exécution du plan"))
	cache := map[string]*playbook.Playbook{}
	for _, prof := range profiler.ClassifyStore(store) {
		p.Send(logMsg("profil : " + prof.String()))
		if prof.Playbook == "" {
			continue
		}
		pb := cache[prof.Playbook]
		if pb == nil {
			loaded, err := playbook.Load(filepath.Join(cfg.PlaybooksDir, prof.Playbook))
			if err != nil {
				p.Send(logMsg("playbook non chargé : " + err.Error()))
				continue
			}
			pb = loaded
			cache[prof.Playbook] = pb
		}
		host, ok := store.Host(prof.Host)
		if !ok {
			continue
		}
		steps, err := executor.ExecutePlaybook(ctx, store, host, pb)
		if err != nil {
			p.Send(logMsg("exécution : " + err.Error()))
		}
		toutes = append(toutes, steps...)
		p.Send(refreshMsg{})
	}

	p.Send(phaseMsg("Analyse"))
	if err := analyst.AnalyzeStore(ctx, store); err != nil {
		p.Send(logMsg("analyse : " + err.Error()))
	}
	p.Send(refreshMsg{})

	var reports []string
	if cfg.ReportDir != "" {
		actions := make([]report.Action, 0, len(toutes))
		for _, s := range toutes {
			statut := s.Status
			if statut == "" {
				statut = "exécuté"
			}
			actions = append(actions, report.Action{Name: s.Action, Targets: s.Targets, Status: statut})
		}
		reports, _ = report.WriteAll(cfg.ReportDir, report.BuildModel(cfg.Eng, store, actions))
	}
	p.Send(doneMsg{reports: reports})
}

// --- modèle ---

type model struct {
	cfg   Config
	store *graph.Store

	phase    string
	logs     []string
	hosts    []graph.Host
	findings []graph.Finding

	pending *agent.DryRun
	reply   chan bool

	done    bool
	err     error
	reports []string

	frame         int
	width, height int
}

func (m model) Init() tea.Cmd { return tick() }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case tea.KeyMsg:
		// En attente d'approbation : seules les touches de décision comptent.
		if m.pending != nil {
			switch strings.ToLower(msg.String()) {
			case "y", "o":
				m.reply <- true
				m.pending, m.reply = nil, nil
			case "n", "esc", "enter":
				m.reply <- false
				m.pending, m.reply = nil, nil
			}
			return m, nil
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}

	case tickMsg:
		m.frame++
		if !m.done {
			return m, tick()
		}

	case phaseMsg:
		m.phase = string(msg)
		m.logs = appendLog(m.logs, "▸ "+string(msg))

	case logMsg:
		m.logs = appendLog(m.logs, string(msg))

	case stepMsg:
		s := agent.Step(msg)
		icon := "✓"
		if s.Status == "refusé" {
			icon = "✗"
		}
		m.logs = appendLog(m.logs, fmt.Sprintf("%s %s %s", icon, s.Action, strings.Join(s.Targets, ",")))

	case refreshMsg:
		m.hosts = m.store.Hosts()
		m.findings = triFindings(m.store.Findings())

	case approvalMsg:
		dr := msg.dr
		m.pending = &dr
		m.reply = msg.reply

	case doneMsg:
		m.done = true
		m.err = msg.err
		m.reports = msg.reports
		m.hosts = m.store.Hosts()
		m.findings = triFindings(m.store.Findings())
	}
	return m, nil
}

// --- utilitaires ---

func appendLog(logs []string, line string) []string {
	logs = append(logs, line)
	const max = 10
	if len(logs) > max {
		logs = logs[len(logs)-max:]
	}
	return logs
}

var rangSeverite = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

func triFindings(fs []graph.Finding) []graph.Finding {
	sort.SliceStable(fs, func(i, j int) bool {
		return rangSeverite[fs[i].Severity] > rangSeverite[fs[j].Severity]
	})
	return fs
}
