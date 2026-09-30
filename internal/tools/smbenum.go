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

// SMBEnum énumère un hôte via les scripts SMB de nmap (partages, OS, mode de
// sécurité). Il réutilise l'image nmap (aria/nmap) et transforme la sortie des
// scripts NSE en findings (informationnels : ce sont des observations à qualifier).
type SMBEnum struct {
	image string
	net   sandbox.NetworkPolicy
}

// NewSMBEnum crée l'adapter. image vide => image nmap par défaut.
func NewSMBEnum(image string, net sandbox.NetworkPolicy) *SMBEnum {
	if strings.TrimSpace(image) == "" {
		image = imageParDefaut // aria/nmap
	}
	return &SMBEnum{image: image, net: net}
}

func (s *SMBEnum) Name() string                  { return "smb_enum" }
func (s *SMBEnum) Category() engagement.Category { return engagement.CatEnumeration }
func (s *SMBEnum) RequiresApproval() bool        { return false }

func (s *SMBEnum) Description() string {
	return "Énumération SMB d'un hôte (nmap : partages, OS, mode de sécurité). Paramètre : target (IP ou hôte, obligatoire)."
}

func (s *SMBEnum) ParamsSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {"target": {"type": "string", "description": "IP ou nom d'hôte unique (pas de CIDR)"}},
		"required": ["target"]
	}`)
}

// Prepare construit la commande nmap avec les scripts SMB.
func (s *SMBEnum) Prepare(params map[string]any) (Invocation, error) {
	target, err := stringParam(params, "target", "")
	if err != nil {
		return Invocation{}, err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return Invocation{}, fmt.Errorf("smb_enum: le paramètre 'target' est obligatoire")
	}
	if strings.Contains(target, "/") {
		return Invocation{}, fmt.Errorf("smb_enum: 'target' doit être un hôte unique, pas un bloc CIDR (%q)", target)
	}

	argv := []string{
		"nmap", "-Pn", "-p", "445,139",
		"--script", "smb-os-discovery,smb-enum-shares,smb-security-mode",
		"-oX", "-", target,
	}

	inv := Invocation{
		Targets: []string{target},
		Spec: sandbox.Spec{
			Image:   s.image,
			Argv:    argv,
			Network: s.net,
		},
	}
	return inv, nil
}

// Parse transforme la sortie des scripts NSE (au niveau hôte et au niveau port) en
// findings informationnels. Sans cible SMB, la sortie est vide (aucun finding).
func (s *SMBEnum) Parse(res sandbox.Result) (Output, error) {
	if len(res.Stdout) == 0 {
		return Output{}, fmt.Errorf("smb_enum: sortie vide (stderr: %s)", strings.TrimSpace(string(res.Stderr)))
	}
	var run nmapRun
	if err := xml.Unmarshal(res.Stdout, &run); err != nil {
		return Output{}, fmt.Errorf("smb_enum: XML nmap illisible : %w", err)
	}
	if run.XMLName.Local != "nmaprun" {
		return Output{}, fmt.Errorf("smb_enum: sortie inattendue, racine <nmaprun> absente")
	}

	var out Output
	for _, h := range run.Hosts {
		addr := choisirAdresse(h.Addresses)
		ajoute := func(sc nmapScript, port int) {
			if strings.TrimSpace(sc.Output) == "" {
				return
			}
			out.Findings = append(out.Findings, graph.Finding{
				Host:        addr,
				Port:        port,
				Title:       "SMB : " + sc.ID,
				Severity:    "info",
				Description: "Résultat du script NSE " + sc.ID,
				Evidence:    strings.TrimSpace(sc.Output),
			})
		}
		for _, sc := range h.HostScripts {
			ajoute(sc, 0)
		}
		for _, p := range h.Ports {
			for _, sc := range p.Scripts {
				ajoute(sc, p.PortID)
			}
		}
	}
	return out, nil
}
