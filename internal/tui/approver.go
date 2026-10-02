package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/Tag59/aria/internal/agent"
)

// approver relie la demande d'approbation (côté goroutine de mission) à la modale
// de l'interface. Approve envoie un message à l'UI puis bloque jusqu'à ce que
// l'opérateur réponde (y/n), dont la décision revient par un canal.
type approver struct {
	p *tea.Program
}

func (a *approver) Approve(dr agent.DryRun) (bool, error) {
	reply := make(chan bool, 1)
	a.p.Send(approvalMsg{dr: dr, reply: reply})
	return <-reply, nil
}
