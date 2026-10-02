package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// JSON exporte le modèle en JSON indenté (pour exploitation par d'autres outils).
func JSON(m Model) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// Markdown rend le rapport en Markdown.
func Markdown(m Model) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# %s\n\n", m.Title)
	fmt.Fprintf(&b, "**Engagement :** %s", m.EngagementName)
	if m.Client != "" {
		fmt.Fprintf(&b, " — %s", m.Client)
	}
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "- Autorisation : %s\n", m.AuthRef)
	fmt.Fprintf(&b, "- Généré le : %s\n", m.GeneratedAt.Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, "- Périmètre : %s\n", strings.Join(m.ScopeIn, ", "))
	if len(m.ScopeOut) > 0 {
		fmt.Fprintf(&b, "- Exclusions : %s\n", strings.Join(m.ScopeOut, ", "))
	}
	fmt.Fprintf(&b, "- Catégories autorisées (RoE) : %s\n\n", strings.Join(m.Categories, ", "))

	b.WriteString("> Rapport généré par ARIA, copilote de pentest méthodologique. ")
	b.WriteString("Les vulnérabilités listées sont des findings à valider par l'opérateur. ")
	b.WriteString("Tests menés uniquement dans le périmètre autorisé.\n\n")

	// Synthèse.
	b.WriteString("## Synthèse\n\n")
	fmt.Fprintf(&b, "%d hôte(s), %d service(s), %d finding(s).\n\n", m.Summary.Hosts, m.Summary.Services, m.Summary.Findings)
	b.WriteString("| Sévérité | Nombre |\n|---|---|\n")
	for _, sev := range severitesConnues {
		fmt.Fprintf(&b, "| %s | %d |\n", sev, m.SeverityCounts[sev])
	}
	b.WriteString("\n")

	// Hôtes et services.
	b.WriteString("## Hôtes et services\n\n")
	for _, h := range m.Hosts {
		fmt.Fprintf(&b, "### %s", h.Address)
		if len(h.Hostnames) > 0 {
			fmt.Fprintf(&b, " (%s)", strings.Join(h.Hostnames, ", "))
		}
		b.WriteString("\n\n")
		if len(h.Services) == 0 {
			b.WriteString("Aucun service ouvert détecté.\n\n")
			continue
		}
		b.WriteString("| Port | Service | Produit | Version |\n|---|---|---|---|\n")
		for _, s := range h.Services {
			fmt.Fprintf(&b, "| %d/%s | %s | %s | %s |\n", s.Port, s.Protocol, s.Name, s.Product, s.Version)
		}
		b.WriteString("\n")
	}

	// Findings.
	b.WriteString("## Vulnérabilités candidates\n\n")
	if len(m.Findings) == 0 {
		b.WriteString("Aucun finding.\n\n")
	}
	for _, f := range m.Findings {
		fmt.Fprintf(&b, "### [%s] %s\n\n", strings.ToUpper(f.Severity), f.Title)
		cible := f.Host
		if f.Port != 0 {
			cible = fmt.Sprintf("%s:%d", f.Host, f.Port)
		}
		fmt.Fprintf(&b, "- Cible : %s\n", cible)
		if f.Description != "" {
			fmt.Fprintf(&b, "- Description : %s\n", f.Description)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "- Preuve : %s\n", f.Evidence)
		}
		if f.Impact != "" {
			fmt.Fprintf(&b, "- Impact : %s\n", f.Impact)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "- Remédiation : %s\n", f.Remediation)
		}
		if len(f.Refs) > 0 {
			fmt.Fprintf(&b, "- Références : %s\n", strings.Join(f.Refs, ", "))
		}
		b.WriteString("\n")
	}

	// Journal des actions.
	if len(m.Actions) > 0 {
		b.WriteString("## Journal des actions\n\n")
		b.WriteString("| Action | Cible(s) | Statut |\n|---|---|---|\n")
		for _, a := range m.Actions {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", a.Name, strings.Join(a.Targets, ", "), a.Status)
		}
		b.WriteString("\n")
	}

	return b.String()
}
