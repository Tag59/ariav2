package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("63")).Padding(0, 1)
	boxStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).Padding(0, 1)
	boxTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("111"))
	muted    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	okStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	errStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)

	sevBadge = map[string]lipgloss.Style{
		"critical": badge("196", "231"),
		"high":     badge("202", "231"),
		"medium":   badge("214", "232"),
		"low":      badge("34", "231"),
		"info":     badge("39", "231"),
	}
	modalStyle = lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("214")).Padding(1, 2)
)

func badge(bg, fg string) lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color(fg)).Background(lipgloss.Color(bg)).Padding(0, 1)
}

func (m model) View() string {
	w := m.width
	if w < 40 {
		w = 100
	}
	h := m.height
	if h < 10 {
		h = 30
	}

	// Modale d'approbation : prend tout l'écran pour une décision claire.
	if m.pending != nil {
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, m.renderModal())
	}

	header := titleStyle.Width(w - 2).Render("ARIA — " + m.cfg.Eng.Name)

	// Statut.
	var status string
	switch {
	case m.err != nil:
		status = errStyle.Render("✗ Erreur : " + m.err.Error())
	case m.done:
		status = okStyle.Render("✓ Mission terminée")
	default:
		status = frames[m.frame%len(frames)] + " " + m.phase + muted.Render(" …")
	}

	// Badges de synthèse.
	counts := map[string]int{}
	for _, f := range m.findings {
		counts[f.Severity]++
	}
	var bParts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		bParts = append(bParts, sevBadge[sev].Render(fmt.Sprintf("%s %d", sev, counts[sev])))
	}
	badges := strings.Join(bParts, " ")

	// Colonnes : findings (gauche) | hôtes (droite).
	left := w*58/100 - 2
	right := w - left - 6
	if left < 20 {
		left = 20
	}
	if right < 20 {
		right = 20
	}

	findingsBox := boxStyle.Width(left).Render(boxTitle.Render("Findings") + "\n" + m.renderFindings(left))
	hostsBox := boxStyle.Width(right).Render(boxTitle.Render("Hôtes & services") + "\n" + m.renderHosts(right))
	cols := lipgloss.JoinHorizontal(lipgloss.Top, findingsBox, " ", hostsBox)

	logBox := boxStyle.Width(w - 2).Render(boxTitle.Render("Journal") + "\n" + muted.Render(strings.Join(m.logs, "\n")))

	footer := muted.Render("q : quitter")
	if m.done && len(m.reports) > 0 {
		footer = muted.Render("Rapport : "+strings.Join(m.reports, ", ")) + "   " + footer
	}

	return lipgloss.JoinVertical(lipgloss.Left, header, "", status, badges, "", cols, logBox, footer)
}

func (m model) renderFindings(width int) string {
	if len(m.findings) == 0 {
		return muted.Render("(aucun pour l'instant)")
	}
	var lines []string
	for i, f := range m.findings {
		if i >= 12 {
			lines = append(lines, muted.Render(fmt.Sprintf("… +%d autres", len(m.findings)-12)))
			break
		}
		tag := sevBadge[f.Severity]
		titre := f.Title
		cible := f.Host
		if f.Port != 0 {
			cible = fmt.Sprintf("%s:%d", f.Host, f.Port)
		}
		max := width - 16
		if max > 8 && len(titre) > max {
			titre = titre[:max-1] + "…"
		}
		lines = append(lines, tag.Render(strings.ToUpper(f.Severity[:1]))+" "+titre+" "+muted.Render(cible))
	}
	return strings.Join(lines, "\n")
}

func (m model) renderHosts(width int) string {
	if len(m.hosts) == 0 {
		return muted.Render("(aucun pour l'instant)")
	}
	var lines []string
	for _, h := range m.hosts {
		lines = append(lines, lipgloss.NewStyle().Bold(true).Render(h.Address))
		for _, s := range h.Services {
			svc := fmt.Sprintf("  %d/%s", s.Port, s.Protocol)
			if s.Name != "" {
				svc += " " + s.Name
			}
			if s.Product != "" {
				svc += " " + s.Product
			}
			lines = append(lines, muted.Render(svc))
		}
	}
	return strings.Join(lines, "\n")
}

func (m model) renderModal() string {
	dr := m.pending
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214")).
		Render("⚠  VALIDATION REQUISE — action intrusive") + "\n\n")
	fmt.Fprintf(&b, "%s %s (%s)\n", muted.Render("action   :"), dr.Action, dr.Category)
	fmt.Fprintf(&b, "%s %s\n", muted.Render("cible(s) :"), strings.Join(dr.Targets, ", "))
	fmt.Fprintf(&b, "%s %s\n", muted.Render("pourquoi :"), dr.Rationale)
	fmt.Fprintf(&b, "%s\n%s\n\n", muted.Render("commande :"), wrap(strings.Join(dr.Command, " "), 70))
	b.WriteString(okStyle.Render("[y] exécuter") + "    " + errStyle.Render("[n] refuser"))
	return modalStyle.Render(b.String())
}

// wrap coupe une longue chaîne en lignes d'au plus n caractères.
func wrap(s string, n int) string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	out = append(out, s)
	return strings.Join(out, "\n")
}
