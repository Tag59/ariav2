// Package audit est le journal de mission horodaté et rejouable (garde-fou n°6).
//
// Chaque décision, action, approbation et finding est consigné sous forme
// d'événement ordonné et daté. Le journal s'écrit au fil de l'eau en JSONL
// (append-only), ce qui le rend relisable et vérifiable a posteriori : on peut
// reconstituer toute la mission, y compris qui a approuvé quoi et quand.
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Tag59/aria/internal/agent"
	"github.com/Tag59/aria/internal/graph"
)

// Kind énumère les types d'événements.
const (
	KindMissionStart = "mission_start"
	KindPhase        = "phase"
	KindStep         = "step"
	KindApprovalReq  = "approval_request"
	KindApprovalOK   = "approval_granted"
	KindApprovalNo   = "approval_denied"
	KindFinding      = "finding"
	KindError        = "error"
	KindMissionEnd   = "mission_end"
)

// Event est une entrée du journal. Les champs vides sont omis à la sérialisation.
type Event struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	Message  string    `json:"message,omitempty"`
	Action   string    `json:"action,omitempty"`
	Targets  []string  `json:"targets,omitempty"`
	Command  []string  `json:"command,omitempty"`
	Status   string    `json:"status,omitempty"`
	ExitCode int       `json:"exit_code,omitempty"`
	Host     string    `json:"host,omitempty"`
	Port     int       `json:"port,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Title    string    `json:"title,omitempty"`
}

// Journal accumule les événements et, si un writer est fourni, les écrit au fil de
// l'eau en JSONL. Sûr pour un usage concurrent (la boucle de l'agent peut écrire
// depuis plusieurs goroutines).
type Journal struct {
	mu     sync.Mutex
	events []Event
	w      io.Writer
	now    func() time.Time // injectable pour les tests
}

// New crée un journal. Si w n'est pas nil, chaque événement y est aussi écrit
// immédiatement en JSONL (append-only).
func New(w io.Writer) *Journal {
	return &Journal{w: w, now: time.Now}
}

func (j *Journal) record(e Event) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e.Time = j.now()
	j.events = append(j.events, e)
	if j.w != nil {
		if b, err := json.Marshal(e); err == nil {
			j.w.Write(b)
			j.w.Write([]byte("\n"))
		}
	}
}

// --- méthodes de consignation ---

func (j *Journal) MissionStart(engagement string, scopeIn []string) {
	j.record(Event{Kind: KindMissionStart, Message: engagement, Targets: scopeIn})
}

func (j *Journal) Phase(name string) { j.record(Event{Kind: KindPhase, Message: name}) }

func (j *Journal) Step(s agent.Step) {
	j.record(Event{Kind: KindStep, Action: s.Action, Targets: s.Targets, Status: s.Status, ExitCode: s.ExitCode})
}

func (j *Journal) ApprovalRequest(dr agent.DryRun) {
	j.record(Event{Kind: KindApprovalReq, Action: dr.Action, Targets: dr.Targets, Command: dr.Command})
}

func (j *Journal) ApprovalDecision(action string, granted bool) {
	k := KindApprovalNo
	if granted {
		k = KindApprovalOK
	}
	j.record(Event{Kind: k, Action: action})
}

func (j *Journal) Finding(f graph.Finding) {
	j.record(Event{Kind: KindFinding, Host: f.Host, Port: f.Port, Severity: f.Severity, Title: f.Title})
}

func (j *Journal) Errorf(format string, args ...any) {
	j.record(Event{Kind: KindError, Message: fmt.Sprintf(format, args...)})
}

func (j *Journal) MissionEnd(message string) {
	j.record(Event{Kind: KindMissionEnd, Message: message})
}

// Events renvoie une copie des événements consignés.
func (j *Journal) Events() []Event {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Event, len(j.events))
	copy(out, j.events)
	return out
}

// WriteFile écrit tout le journal en JSONL dans path (utile si aucun writer live
// n'a été fourni, ou pour une copie).
func (j *Journal) WriteFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("audit : création %q : %w", path, err)
	}
	defer f.Close()
	bw := bufio.NewWriter(f)
	for _, e := range j.Events() {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		bw.Write(b)
		bw.WriteByte('\n')
	}
	return bw.Flush()
}

// Render produit une chronologie lisible (pour l'affichage ou une relecture rapide).
func (j *Journal) Render() string {
	var b strings.Builder
	for _, e := range j.Events() {
		fmt.Fprintf(&b, "%s  %-16s %s\n", e.Time.Format("15:04:05"), e.Kind, resume(e))
	}
	return b.String()
}

func resume(e Event) string {
	switch e.Kind {
	case KindMissionStart:
		return fmt.Sprintf("%s (scope %s)", e.Message, strings.Join(e.Targets, ", "))
	case KindStep:
		return fmt.Sprintf("%s %s [%s]", e.Action, strings.Join(e.Targets, ","), e.Status)
	case KindApprovalReq:
		return fmt.Sprintf("%s %s", e.Action, strings.Join(e.Targets, ","))
	case KindApprovalOK, KindApprovalNo:
		return e.Action
	case KindFinding:
		return fmt.Sprintf("[%s] %s (%s:%d)", e.Severity, e.Title, e.Host, e.Port)
	default:
		return e.Message
	}
}

// Load relit un journal JSONL (pour une relecture / vérification hors ligne).
func Load(r io.Reader) ([]Event, error) {
	var events []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("audit : ligne JSONL illisible : %w", err)
		}
		events = append(events, e)
	}
	return events, sc.Err()
}

// --- wrapper d'approbateur traçant les décisions ---

// WrapApprover enveloppe un approbateur pour journaliser chaque demande et chaque
// décision (traçabilité des validations humaines).
func WrapApprover(real agent.Approver, j *Journal) agent.Approver {
	return auditApprover{real: real, j: j}
}

type auditApprover struct {
	real agent.Approver
	j    *Journal
}

func (a auditApprover) Approve(dr agent.DryRun) (bool, error) {
	a.j.ApprovalRequest(dr)
	ok, err := a.real.Approve(dr)
	a.j.ApprovalDecision(dr.Action, ok)
	return ok, err
}
