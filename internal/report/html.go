package report

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/Tag59/aria/internal/graph"
)

// HTML rend le rapport en page HTML autonome (CSS en ligne), imprimable en PDF.
// On utilise html/template : tout contenu issu de la cible est échappé.
func HTML(m Model) (string, error) {
	t, err := template.New("report").Funcs(template.FuncMap{
		"sevClass": func(s string) string { return "sev-" + s },
		"cible": func(f graph.Finding) string {
			if f.Port != 0 {
				return fmt.Sprintf("%s:%d", f.Host, f.Port)
			}
			return f.Host
		},
		"join":  strings.Join,
		"date":  func(t time.Time) string { return t.Format("2006-01-02 15:04") },
		"count": func(m map[string]int, k string) int { return m[k] },
	}).Parse(htmlTmpl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := t.Execute(&b, m); err != nil {
		return "", err
	}
	return b.String(), nil
}

const htmlTmpl = `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
  :root { --bg:#ffffff; --fg:#1a1a2e; --muted:#5b6472; --line:#e3e7ee; --card:#f7f9fc; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         color: var(--fg); background: var(--bg); margin: 0; padding: 32px; line-height: 1.5; }
  h1 { margin: 0 0 4px; font-size: 26px; }
  h2 { margin: 32px 0 12px; font-size: 20px; border-bottom: 2px solid var(--line); padding-bottom: 6px; }
  h3 { margin: 18px 0 6px; font-size: 16px; }
  .meta { color: var(--muted); font-size: 14px; }
  .meta ul { margin: 8px 0; padding-left: 18px; }
  .disclaimer { background: var(--card); border-left: 4px solid #0277bd; padding: 10px 14px;
                margin: 16px 0; font-size: 14px; color: var(--muted); }
  table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 14px; }
  th, td { border: 1px solid var(--line); padding: 6px 10px; text-align: left; }
  th { background: var(--card); }
  .badges { display: flex; gap: 8px; flex-wrap: wrap; margin: 8px 0 16px; }
  .badge { color: #fff; border-radius: 6px; padding: 4px 10px; font-size: 13px; font-weight: 600; }
  .sev-critical { background: #b00020; }
  .sev-high     { background: #e65100; }
  .sev-medium   { background: #f9a825; color:#1a1a2e; }
  .sev-low      { background: #2e7d32; }
  .sev-info     { background: #0277bd; }
  .finding { border: 1px solid var(--line); border-radius: 8px; padding: 12px 16px; margin: 12px 0; }
  .finding .tag { display:inline-block; vertical-align:middle; margin-right:8px; }
  .finding dl { margin: 8px 0 0; display: grid; grid-template-columns: 120px 1fr; gap: 4px 12px; font-size: 14px; }
  .finding dt { color: var(--muted); }
  .finding dd { margin: 0; word-break: break-word; }
  code, .mono { font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
  footer { margin-top: 32px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 10px; }
</style>
</head>
<body>
  <h1>{{.Title}}</h1>
  <div class="meta">
    <strong>{{.EngagementName}}</strong>{{if .Client}} — {{.Client}}{{end}}
    <ul>
      <li>Autorisation : {{.AuthRef}}</li>
      <li>Généré le : {{date .GeneratedAt}}</li>
      <li>Périmètre : {{join .ScopeIn ", "}}</li>
      {{if .ScopeOut}}<li>Exclusions : {{join .ScopeOut ", "}}</li>{{end}}
      <li>Catégories autorisées (RoE) : {{join .Categories ", "}}</li>
    </ul>
  </div>

  <div class="disclaimer">
    Rapport généré par ARIA, copilote de pentest méthodologique. Les vulnérabilités
    listées sont des findings à valider par l'opérateur. Tests menés uniquement dans
    le périmètre autorisé.
  </div>

  <h2>Synthèse</h2>
  <p>{{.Summary.Hosts}} hôte(s), {{.Summary.Services}} service(s), {{.Summary.Findings}} finding(s).</p>
  <div class="badges">
    <span class="badge sev-critical">critical : {{count .SeverityCounts "critical"}}</span>
    <span class="badge sev-high">high : {{count .SeverityCounts "high"}}</span>
    <span class="badge sev-medium">medium : {{count .SeverityCounts "medium"}}</span>
    <span class="badge sev-low">low : {{count .SeverityCounts "low"}}</span>
    <span class="badge sev-info">info : {{count .SeverityCounts "info"}}</span>
  </div>

  <h2>Hôtes et services</h2>
  {{range .Hosts}}
    <h3>{{.Address}}{{if .Hostnames}} ({{join .Hostnames ", "}}){{end}}</h3>
    {{if .Services}}
    <table>
      <tr><th>Port</th><th>Service</th><th>Produit</th><th>Version</th></tr>
      {{range .Services}}
      <tr><td class="mono">{{.Port}}/{{.Protocol}}</td><td>{{.Name}}</td><td>{{.Product}}</td><td>{{.Version}}</td></tr>
      {{end}}
    </table>
    {{else}}<p>Aucun service ouvert détecté.</p>{{end}}
  {{end}}

  <h2>Vulnérabilités candidates</h2>
  {{if not .Findings}}<p>Aucun finding.</p>{{end}}
  {{range .Findings}}
  <div class="finding">
    <span class="badge {{sevClass .Severity}} tag">{{.Severity}}</span><strong>{{.Title}}</strong>
    <dl>
      <dt>Cible</dt><dd class="mono">{{cible .}}</dd>
      {{if .Description}}<dt>Description</dt><dd>{{.Description}}</dd>{{end}}
      {{if .Evidence}}<dt>Preuve</dt><dd class="mono">{{.Evidence}}</dd>{{end}}
      {{if .Impact}}<dt>Impact</dt><dd>{{.Impact}}</dd>{{end}}
      {{if .Remediation}}<dt>Remédiation</dt><dd>{{.Remediation}}</dd>{{end}}
      {{if .Refs}}<dt>Références</dt><dd>{{join .Refs ", "}}</dd>{{end}}
    </dl>
  </div>
  {{end}}

  {{if .Actions}}
  <h2>Journal des actions</h2>
  <table>
    <tr><th>Action</th><th>Cible(s)</th><th>Statut</th></tr>
    {{range .Actions}}
    <tr><td class="mono">{{.Name}}</td><td class="mono">{{join .Targets ", "}}</td><td>{{.Status}}</td></tr>
    {{end}}
  </table>
  {{end}}

  <footer>ARIA — rapport généré automatiquement. À relire et valider par l'opérateur avant diffusion.</footer>
</body>
</html>
`
