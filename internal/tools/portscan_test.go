package tools

import (
	"strings"
	"testing"

	"github.com/Tag59/aria/internal/sandbox"
)

func joinArgv(argv []string) string { return strings.Join(argv, " ") }

func TestPortScanPrepareDefaults(t *testing.T) {
	ps := NewPortScan("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	inv, err := ps.Prepare(map[string]any{"target": "192.168.56.10"})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	got := joinArgv(inv.Spec.Argv)
	want := "nmap -sT -Pn -T3 --top-ports 1000 -sV -oX - 192.168.56.10"
	if got != want {
		t.Errorf("argv =\n  %q\nattendu\n  %q", got, want)
	}
	if len(inv.Targets) != 1 || inv.Targets[0] != "192.168.56.10" {
		t.Errorf("Targets = %v", inv.Targets)
	}
	if inv.Spec.Image != imageParDefaut {
		t.Errorf("image = %q, attendu %q", inv.Spec.Image, imageParDefaut)
	}
}

func TestPortScanPrepareCustom(t *testing.T) {
	ps := NewPortScan("aria/nmap:test", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	inv, err := ps.Prepare(map[string]any{
		"target":            "web.lab.local",
		"ports":             "web",
		"timing":            "T4",
		"service_detection": false,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	got := joinArgv(inv.Spec.Argv)
	want := "nmap -sT -Pn -T4 -p 80,443,8080,8443,8000 -oX - web.lab.local"
	if got != want {
		t.Errorf("argv =\n  %q\nattendu\n  %q", got, want)
	}
	if strings.Contains(got, "-sV") {
		t.Error("-sV ne devrait pas être présent quand service_detection=false")
	}
	if inv.Spec.Image != "aria/nmap:test" {
		t.Errorf("image = %q", inv.Spec.Image)
	}
}

func TestPortScanPrepareRejections(t *testing.T) {
	ps := NewPortScan("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	cas := map[string]map[string]any{
		"cible manquante":    {},
		"cible vide":         {"target": "   "},
		"preset inconnu":     {"target": "x", "ports": "everything"},
		"timing interdit":    {"target": "x", "timing": "T5"},
		"cible mauvais type": {"target": 42},
		"bool mauvais type":  {"target": "x", "service_detection": "yes"},
	}
	for nom, params := range cas {
		t.Run(nom, func(t *testing.T) {
			if _, err := ps.Prepare(params); err == nil {
				t.Errorf("erreur attendue pour %q, obtenu nil", nom)
			}
		})
	}
}

const xmlNmapExemple = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.56.10" addrtype="ipv4"/>
    <hostnames><hostname name="web.lab.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.56.11" addrtype="ipv4"/>
  </host>
</nmaprun>`

func TestPortScanParse(t *testing.T) {
	ps := NewPortScan("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	out, err := ps.Parse(sandbox.Result{Stdout: []byte(xmlNmapExemple)})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out.Hosts) != 1 {
		t.Fatalf("attendu 1 hôte up, obtenu %d", len(out.Hosts))
	}
	h := out.Hosts[0]
	if h.Address != "192.168.56.10" {
		t.Errorf("adresse = %q", h.Address)
	}
	if len(h.Hostnames) != 1 || h.Hostnames[0] != "web.lab.local" {
		t.Errorf("hostnames = %v", h.Hostnames)
	}
	if len(h.Services) != 2 {
		t.Fatalf("attendu 2 services ouverts (443 fermé ignoré), obtenu %d", len(h.Services))
	}
	// Vérifie le service http détecté.
	var http bool
	for _, s := range h.Services {
		if s.Port == 80 {
			http = true
			if s.Name != "http" || s.Product != "nginx" || s.Version != "1.18.0" {
				t.Errorf("service 80 mal parsé : %+v", s)
			}
		}
	}
	if !http {
		t.Error("service sur le port 80 introuvable")
	}
}

func TestPortScanParseErreurs(t *testing.T) {
	ps := NewPortScan("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	if _, err := ps.Parse(sandbox.Result{Stdout: nil}); err == nil {
		t.Error("erreur attendue pour une sortie vide")
	}
	if _, err := ps.Parse(sandbox.Result{Stdout: []byte("pas du xml")}); err == nil {
		t.Error("erreur attendue pour un XML invalide")
	}
}
