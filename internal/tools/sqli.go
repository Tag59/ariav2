package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/sandbox"
)

const imageSQLMapParDefaut = "aria/sqlmap:latest"

// SQLiProbe confirme une injection SQL avec sqlmap, en DÉTECTION uniquement
// (--batch, ni --dump ni accès système) : on prouve l'existence de la faille, on
// n'exfiltre ni ne modifie de données.
//
// C'est une action de catégorie EXPLOITATION et RequiresApproval = true : elle ne
// s'exécute jamais sans validation humaine (dry-run + approbation).
type SQLiProbe struct {
	image string
	net   sandbox.NetworkPolicy
}

// NewSQLiProbe crée l'adapter. image vide => image sqlmap par défaut.
func NewSQLiProbe(image string, net sandbox.NetworkPolicy) *SQLiProbe {
	if strings.TrimSpace(image) == "" {
		image = imageSQLMapParDefaut
	}
	return &SQLiProbe{image: image, net: net}
}

func (s *SQLiProbe) Name() string                  { return "sqli_probe" }
func (s *SQLiProbe) Category() engagement.Category { return engagement.CatExploitation }
func (s *SQLiProbe) RequiresApproval() bool        { return true }

func (s *SQLiProbe) Description() string {
	return "Confirmation NON destructive d'une injection SQL (sqlmap, détection seule). " +
		"Paramètres : target (IP/hôte, obligatoire), port, scheme (http|https), path (défaut /), " +
		"data (corps POST optionnel, ex. JSON de login)."
}

func (s *SQLiProbe) ParamsSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {"type": "string"},
			"port": {"type": "integer"},
			"scheme": {"type": "string", "enum": ["http", "https"]},
			"path": {"type": "string"},
			"data": {"type": "string"}
		},
		"required": ["target"]
	}`)
}

// Prepare valide les paramètres et construit la commande sqlmap (détection seule).
func (s *SQLiProbe) Prepare(params map[string]any) (Invocation, error) {
	target, err := stringParam(params, "target", "")
	if err != nil {
		return Invocation{}, err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return Invocation{}, fmt.Errorf("sqli_probe: le paramètre 'target' est obligatoire")
	}
	if strings.Contains(target, "/") {
		return Invocation{}, fmt.Errorf("sqli_probe: 'target' doit être un hôte unique, pas un bloc CIDR (%q)", target)
	}

	scheme, err := stringParam(params, "scheme", "http")
	if err != nil {
		return Invocation{}, err
	}
	if scheme != "http" && scheme != "https" {
		return Invocation{}, fmt.Errorf("sqli_probe: scheme %q invalide (http|https)", scheme)
	}

	port, err := intParam(params, "port", 0)
	if err != nil {
		return Invocation{}, err
	}
	if port == 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	if port < 1 || port > 65535 {
		return Invocation{}, fmt.Errorf("sqli_probe: port %d hors bornes", port)
	}

	path, err := stringParam(params, "path", "/")
	if err != nil {
		return Invocation{}, err
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	data, err := stringParam(params, "data", "")
	if err != nil {
		return Invocation{}, err
	}

	url := fmt.Sprintf("%s://%s:%d%s", scheme, target, port, path)

	// Détection uniquement : pas de --dump, pas de --os-*. --batch = non interactif.
	argv := []string{
		"sqlmap", "-u", url,
		"--batch", "--level=1", "--risk=1", "--technique=BEU",
		"--smart", "--flush-session", "--disable-coloring",
		"--output-dir=/tmp/sqlmap", "-v", "0",
	}
	if data != "" {
		argv = append(argv, "--data", data)
		if strings.HasPrefix(strings.TrimSpace(data), "{") {
			argv = append(argv, "--headers", "Content-Type: application/json")
		}
	}

	inv := Invocation{
		Targets: []string{target},
		Spec: sandbox.Spec{
			Image:   s.image,
			Argv:    argv,
			Env:     []string{"HOME=/tmp"},
			Network: s.net,
			Timeout: 10 * time.Minute,
		},
	}
	return inv, nil
}

// Parse cherche dans la sortie de sqlmap la preuve d'une injection. Le finding
// n'a pas d'hôte (sqlmap ne le donne pas clairement) : l'appelant le rattache à
// l'hôte courant.
func (s *SQLiProbe) Parse(res sandbox.Result) (Output, error) {
	text := string(res.Stdout)
	if !injectionConfirmee(text) {
		return Output{}, nil // aucune injection confirmée
	}
	return Output{Findings: []graph.Finding{{
		Title:       "Injection SQL confirmée (sqlmap)",
		Severity:    "high",
		Description: "sqlmap a confirmé une injection SQL exploitable (détection non destructive).",
		Evidence:    extraitInjection(text),
		Refs:        []string{"CWE-89", "WSTG-INPV-05"},
	}}}, nil
}

// injectionConfirmee détecte les marqueurs de sqlmap indiquant une faille.
func injectionConfirmee(text string) bool {
	return strings.Contains(text, "identified the following injection point") ||
		strings.Contains(text, "is vulnerable")
}

// extraitInjection récupère les lignes décrivant le point d'injection.
func extraitInjection(text string) string {
	var lignes []string
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "Parameter:") || strings.HasPrefix(t, "Type:") ||
			strings.HasPrefix(t, "Title:") || strings.HasPrefix(t, "Payload:") {
			lignes = append(lignes, t)
		}
	}
	if len(lignes) == 0 {
		return "injection confirmée par sqlmap (voir sortie complète)"
	}
	return strings.Join(lignes, " | ")
}
