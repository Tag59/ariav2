package tools

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/Tag59/aria/internal/engagement"
	"github.com/Tag59/aria/internal/graph"
	"github.com/Tag59/aria/internal/sandbox"
)

// imageParDefaut est l'image conteneur utilisée si aucune n'est fournie.
// Voir docker/nmap.Dockerfile pour la construire : `docker build -t aria/nmap docker`.
const imageParDefaut = "aria/nmap:latest"

// PortScan est l'adapter nmap. Il fait un scan TCP "connect" (-sT), qui ne
// demande aucun privilège particulier dans le conteneur, et récupère la sortie
// au format XML pour un parsing fiable.
type PortScan struct {
	image string
	net   sandbox.NetworkPolicy
}

// NewPortScan crée l'adapter. image peut être vide (image par défaut) ; net est
// la politique réseau du bac à sable (le scan a besoin du réseau pour joindre la
// cible, donc typiquement un réseau isolé du lab).
func NewPortScan(image string, net sandbox.NetworkPolicy) *PortScan {
	if strings.TrimSpace(image) == "" {
		image = imageParDefaut
	}
	return &PortScan{image: image, net: net}
}

func (p *PortScan) Name() string                  { return "port_scan" }
func (p *PortScan) Category() engagement.Category { return engagement.CatRecon }
func (p *PortScan) RequiresApproval() bool        { return false }

func (p *PortScan) Description() string {
	return "Scan de ports TCP d'un hôte unique (nmap). Paramètres : target (IP ou nom d'hôte, obligatoire), " +
		"ports (top100|top1000|web|full, défaut top1000), timing (T2|T3|T4, défaut T3), " +
		"service_detection (bool, défaut true)."
}

// ParamsSchema contraint les paramètres acceptés. Seul target est obligatoire ;
// les autres ont des valeurs par défaut dans Prepare.
func (p *PortScan) ParamsSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {"type": "string", "description": "IP ou nom d'hôte unique (pas de CIDR)"},
			"ports": {"type": "string", "enum": ["top100", "top1000", "web", "full"]},
			"timing": {"type": "string", "enum": ["T2", "T3", "T4"]},
			"service_detection": {"type": "boolean"}
		},
		"required": ["target"]
	}`)
}

// presetsPorts associe un nom de preset aux arguments nmap correspondants.
// On borne volontairement le choix : le LLM ne peut pas passer une liste de ports
// arbitraire, seulement l'un de ces presets.
var presetsPorts = map[string][]string{
	"top100":  {"--top-ports", "100"},
	"top1000": {"--top-ports", "1000"},
	"web":     {"-p", "80,443,8080,8443,8000"},
	"full":    {"-p", "1-65535"},
}

// timingsAutorises borne le modèle de temporisation nmap (-T). On exclut T0/T1
// (trop lents) et T5 (agressif, risque de fausser/perturber la cible).
var timingsAutorises = map[string]bool{"T2": true, "T3": true, "T4": true}

// Prepare valide les paramètres et construit la commande nmap.
//
// Paramètres acceptés :
//   - target  (obligatoire) : hôte ou IP à scanner
//   - ports   (optionnel)   : preset parmi top100/top1000/web/full (défaut top1000)
//   - timing  (optionnel)   : T2, T3 ou T4 (défaut T3)
//   - service_detection (optionnel, bool) : détecter versions des services (défaut true)
func (p *PortScan) Prepare(params map[string]any) (Invocation, error) {
	target, err := stringParam(params, "target", "")
	if err != nil {
		return Invocation{}, err
	}
	if strings.TrimSpace(target) == "" {
		return Invocation{}, fmt.Errorf("port_scan: le paramètre 'target' est obligatoire")
	}
	// On refuse les CIDR ici : le contrôle de scope raisonne cible par cible, et un
	// bloc CIDR pourrait déborder du périmètre autorisé. Le balayage de sous-réseau
	// sera une fonctionnalité dédiée, vérifiée bloc par bloc.
	if strings.Contains(target, "/") {
		return Invocation{}, fmt.Errorf("port_scan: 'target' doit être un hôte unique, pas un bloc CIDR (%q)", target)
	}

	preset, err := stringParam(params, "ports", "top1000")
	if err != nil {
		return Invocation{}, err
	}
	portsArgs, ok := presetsPorts[preset]
	if !ok {
		return Invocation{}, fmt.Errorf("port_scan: preset de ports inconnu %q (attendu : top100, top1000, web ou full)", preset)
	}

	timing, err := stringParam(params, "timing", "T3")
	if err != nil {
		return Invocation{}, err
	}
	if !timingsAutorises[timing] {
		return Invocation{}, fmt.Errorf("port_scan: timing %q non autorisé (attendu : T2, T3 ou T4)", timing)
	}

	serviceDetection, err := boolParam(params, "service_detection", true)
	if err != nil {
		return Invocation{}, err
	}

	// Construction de la commande.
	//   -sT : scan TCP connect (pas besoin de NET_RAW)
	//   -Pn : ne pas "pinger" avant (les VMs de lab bloquent souvent l'ICMP)
	//   -oX - : sortie XML sur stdout, pour un parsing fiable
	argv := []string{"nmap", "-sT", "-Pn", "-" + timing}
	argv = append(argv, portsArgs...)
	if serviceDetection {
		argv = append(argv, "-sV")
	}
	argv = append(argv, "-oX", "-", target)

	inv := Invocation{
		Targets: []string{target},
		Spec: sandbox.Spec{
			Image:   p.image,
			Argv:    argv,
			Network: p.net,
		},
	}
	return inv, nil
}

// Parse lit la sortie XML de nmap et la convertit en hôtes/services.
func (p *PortScan) Parse(res sandbox.Result) (Output, error) {
	if len(res.Stdout) == 0 {
		return Output{}, fmt.Errorf("port_scan: sortie vide (stderr: %s)", strings.TrimSpace(string(res.Stderr)))
	}

	var run nmapRun
	if err := xml.Unmarshal(res.Stdout, &run); err != nil {
		return Output{}, fmt.Errorf("port_scan: XML nmap illisible : %w", err)
	}
	// Garde-fou : si la racine n'est pas <nmaprun>, la sortie n'est pas celle
	// attendue (autre XML, page d'erreur, etc.).
	if run.XMLName.Local != "nmaprun" {
		return Output{}, fmt.Errorf("port_scan: sortie inattendue, racine XML <nmaprun> absente")
	}

	var out Output
	for _, h := range run.Hosts {
		// On ignore les hôtes qui ne sont pas "up".
		if h.Status.State != "up" {
			continue
		}
		host := graph.Host{
			Address:   choisirAdresse(h.Addresses),
			Hostnames: nomsHotes(h.Hostnames),
		}
		for _, port := range h.Ports {
			// On ne garde que les ports ouverts.
			if port.State.State != "open" {
				continue
			}
			host.Services = append(host.Services, graph.Service{
				Port:     port.PortID,
				Protocol: port.Protocol,
				State:    port.State.State,
				Name:     nomService(port.Service),
				Product:  port.Service.Product,
				Version:  port.Service.Version,
			})
		}
		out.Hosts = append(out.Hosts, host)
	}
	return out, nil
}

// choisirAdresse préfère l'adresse IPv4, sinon prend la première disponible.
func choisirAdresse(addrs []nmapAddr) string {
	for _, a := range addrs {
		if a.Type == "ipv4" {
			return a.Addr
		}
	}
	if len(addrs) > 0 {
		return addrs[0].Addr
	}
	return ""
}

// nomService renvoie le nom du service. Repli : quand nmap n'a pas su classer le
// service (il laisse alors une empreinte brute servicefp) mais que cette empreinte
// est clairement une réponse HTTP, on classe le service en "http". On ne renvoie
// jamais l'empreinte brute au LLM (elle contient la réponse de la cible : surface
// d'injection) — on se contente d'un classement déterministe.
func nomService(s nmapService) string {
	if s.ServiceFP != "" && s.Name != "http" && strings.Contains(s.ServiceFP, "HTTP/") {
		return "http"
	}
	return s.Name
}

func nomsHotes(hn []nmapHostname) []string {
	var noms []string
	for _, h := range hn {
		if h.Name != "" {
			noms = append(noms, h.Name)
		}
	}
	return noms
}

// --- petits utilitaires d'extraction de paramètres ---

// stringParam lit un paramètre string. Absent -> valeur par défaut. Présent mais
// d'un autre type -> erreur (on ne devine pas).
func stringParam(params map[string]any, key, def string) (string, error) {
	v, ok := params[key]
	if !ok || v == nil {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("paramètre %q : chaîne attendue", key)
	}
	return s, nil
}

// boolParam lit un paramètre booléen, avec la même logique que stringParam.
func boolParam(params map[string]any, key string, def bool) (bool, error) {
	v, ok := params[key]
	if !ok || v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("paramètre %q : booléen attendu", key)
	}
	return b, nil
}

// --- structures de décodage du XML nmap (sous-ensemble utile) ---

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus     `xml:"status"`
	Addresses []nmapAddr     `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     []nmapPort     `xml:"ports>port"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddr struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ServiceFP string `xml:"servicefp,attr"` // empreinte brute quand -sV n'a pas su classer
}
