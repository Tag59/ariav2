package tools

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/sandbox"
)

const imageNucleiParDefaut = "aria/nuclei:latest"

// NucleiScan est l'adapter nuclei : un scanner de vulnérabilités web à base de
// templates. Il vise un service HTTP unique et renvoie des findings.
//
// Contraintes du bac à sable : le conteneur n'a pas Internet (réseau isolé), donc
// les templates sont embarqués dans l'image (dossier /nuclei-templates) et toute
// mise à jour / interaction OOB est désactivée. Le scan est borné à des templates
// non destructifs (on exclut dos/intrusive/fuzz).
type NucleiScan struct {
	image string
	net   sandbox.NetworkPolicy
}

// NewNucleiScan crée l'adapter. net est la politique réseau du bac à sable (le
// scan a besoin de joindre la cible, donc un réseau isolé du lab).
func NewNucleiScan(image string, net sandbox.NetworkPolicy) *NucleiScan {
	if strings.TrimSpace(image) == "" {
		image = imageNucleiParDefaut
	}
	return &NucleiScan{image: image, net: net}
}

func (n *NucleiScan) Name() string                  { return "nuclei_scan" }
func (n *NucleiScan) Category() engagement.Category { return engagement.CatVulnScan }
func (n *NucleiScan) RequiresApproval() bool        { return false }

func (n *NucleiScan) Description() string {
	return "Scan de vulnérabilités web (nuclei, templates non destructifs) sur un service HTTP. " +
		"Paramètres : target (IP ou hôte, obligatoire), port (défaut 80), scheme (http|https, défaut http)."
}

func (n *NucleiScan) ParamsSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {"type": "string", "description": "IP ou nom d'hôte unique (pas de CIDR)"},
			"port": {"type": "integer"},
			"scheme": {"type": "string", "enum": ["http", "https"]}
		},
		"required": ["target"]
	}`)
}

// Prepare valide les paramètres et construit la commande nuclei.
func (n *NucleiScan) Prepare(params map[string]any) (Invocation, error) {
	target, err := stringParam(params, "target", "")
	if err != nil {
		return Invocation{}, err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return Invocation{}, fmt.Errorf("nuclei_scan: le paramètre 'target' est obligatoire")
	}
	if strings.Contains(target, "/") {
		return Invocation{}, fmt.Errorf("nuclei_scan: 'target' doit être un hôte unique, pas un bloc CIDR (%q)", target)
	}

	scheme, err := stringParam(params, "scheme", "http")
	if err != nil {
		return Invocation{}, err
	}
	if scheme != "http" && scheme != "https" {
		return Invocation{}, fmt.Errorf("nuclei_scan: scheme %q invalide (http|https)", scheme)
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
		return Invocation{}, fmt.Errorf("nuclei_scan: port %d hors bornes", port)
	}

	url := fmt.Sprintf("%s://%s:%d", scheme, target, port)

	// Commande bornée :
	//   -jsonl -silent -nc : sortie JSON propre sur stdout
	//   -duc -ni           : pas de MAJ en ligne ni d'interaction OOB (réseau isolé)
	//   -t /nuclei-templates : templates embarqués dans l'image
	//   -pt http + -tags   : on cible le web, sur un jeu de templates pertinents
	//   -etags dos,intrusive,fuzz : on exclut le destructif/bruyant
	argv := []string{
		"nuclei", "-u", url,
		"-jsonl", "-silent", "-nc",
		"-duc", "-ni",
		"-t", "/nuclei-templates",
		"-pt", "http",
		"-tags", "cve,misconfig,exposure,default-login",
		"-etags", "dos,intrusive,fuzz",
		"-rl", "100", "-timeout", "5",
	}

	inv := Invocation{
		Targets: []string{target},
		Spec: sandbox.Spec{
			Image:   n.image,
			Argv:    argv,
			Env:     []string{"HOME=/tmp"}, // nuclei écrit son cache/config dans HOME (tmpfs)
			Network: n.net,
			Timeout: 10 * time.Minute,
		},
	}
	return inv, nil
}

// Parse lit la sortie JSONL de nuclei (un objet par ligne) en findings.
func (n *NucleiScan) Parse(res sandbox.Result) (Output, error) {
	var out Output
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var r nucleiResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue // ligne non conforme : on l'ignore plutôt que d'échouer
		}
		sev := strings.ToLower(r.Info.Severity)
		if sev == "" || sev == "unknown" {
			sev = "info"
		}
		port := 0
		if r.Port != "" {
			port, _ = strconv.Atoi(r.Port)
		}
		title := r.Info.Name
		if title == "" {
			title = r.TemplateID
		}
		out.Findings = append(out.Findings, graph.Finding{
			Host:        r.Host,
			Port:        port,
			Title:       title,
			Severity:    sev,
			Description: strings.TrimSpace(r.Info.Description),
			Evidence:    r.MatchedAt,
			Refs:        r.Info.Reference,
		})
	}
	return out, nil
}

// --- décodage du JSONL nuclei (sous-ensemble utile) ---

type nucleiResult struct {
	TemplateID string     `json:"template-id"`
	Host       string     `json:"host"`
	Port       string     `json:"port"` // nuclei émet le port en chaîne
	MatchedAt  string     `json:"matched-at"`
	Info       nucleiInfo `json:"info"`
}

type nucleiInfo struct {
	Name        string      `json:"name"`
	Severity    string      `json:"severity"`
	Description string      `json:"description"`
	Reference   flexStrings `json:"reference"`
}

// flexStrings accepte un champ JSON qui est soit une liste de chaînes, soit une
// chaîne unique, soit null — sans jamais faire échouer le décodage de la ligne.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var a []string
		if err := json.Unmarshal(b, &a); err == nil {
			*f = a
		}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil && s != "" {
		*f = []string{s}
	}
	return nil
}
