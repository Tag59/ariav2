// Package profiler classe une cible à partir de la reconnaissance (les services
// découverts) et recommande le playbook adapté.
//
// La classification est DÉTERMINISTE (à base de règles sur les ports/services),
// pas confiée au LLM : c'est fiable, explicable, et sans surface d'injection.
package profiler

import (
	"fmt"

	"github.com/Tag59/aria/internal/graph"
)

// TargetType est le type de cible déduit.
type TargetType string

const (
	TypeWebApp      TargetType = "web-app"
	TypeAD          TargetType = "ad"
	TypeWindowsHost TargetType = "windows-host"
	TypeLinuxHost   TargetType = "linux-host"
	TypeNetworkHost TargetType = "network-host"
	TypeUnknown     TargetType = "unknown"
)

// Profile est le résultat de la classification d'un hôte.
type Profile struct {
	Host     string
	Type     TargetType
	Playbook string   // fichier playbook recommandé
	Reasons  []string // pourquoi cette classification (explicabilité)
}

// playbookParType associe un type de cible au playbook recommandé. Les types
// « hôte » partagent pour l'instant network-host.yaml ; un ad.yaml dédié pourra
// être ajouté plus tard.
var playbookParType = map[TargetType]string{
	TypeWebApp:      "web.yaml",
	TypeAD:          "network-host.yaml",
	TypeWindowsHost: "network-host.yaml",
	TypeLinuxHost:   "network-host.yaml",
	TypeNetworkHost: "network-host.yaml",
	TypeUnknown:     "",
}

// Classify déduit le type d'un hôte à partir de ses services.
//
// Ordre de priorité : AD > web-app > windows-host > linux-host > network-host.
// Un contrôleur de domaine est traité en priorité comme AD ; une machine qui
// expose du web est traitée comme web-app (surface d'attaque la plus riche), même
// si c'est par ailleurs un hôte Windows/Linux.
func Classify(h graph.Host) Profile {
	ports := make(map[int]bool)
	for _, s := range h.Services {
		ports[s.Port] = true
	}
	hasName := func(names ...string) bool {
		for _, s := range h.Services {
			for _, n := range names {
				if s.Name == n {
					return true
				}
			}
		}
		return false
	}

	p := Profile{Host: h.Address}

	web := ports[80] || ports[443] || ports[8080] || ports[8443] || ports[8000] || ports[3000] ||
		hasName("http", "https", "http-proxy", "http-alt")
	smb := ports[445] || ports[139] || hasName("microsoft-ds", "netbios-ssn")
	ldap := ports[389] || ports[636] || hasName("ldap", "ldapssl")
	kerberos := ports[88] || hasName("kerberos-sec", "kerberos")
	rdp := ports[3389] || hasName("ms-wbt-server", "rdp")
	ssh := ports[22] || hasName("ssh")

	switch {
	case (kerberos && ldap) || (ldap && smb):
		p.Type = TypeAD
		p.Reasons = append(p.Reasons, "signaux Active Directory (LDAP/Kerberos/SMB)")
	case web:
		p.Type = TypeWebApp
		p.Reasons = append(p.Reasons, "service web détecté (HTTP/HTTPS)")
	case smb || rdp:
		p.Type = TypeWindowsHost
		p.Reasons = append(p.Reasons, "services typiques Windows (SMB/RDP)")
	case ssh:
		p.Type = TypeLinuxHost
		p.Reasons = append(p.Reasons, "SSH détecté, pas de signal Windows/web")
	case len(h.Services) > 0:
		p.Type = TypeNetworkHost
		p.Reasons = append(p.Reasons, "services ouverts sans type clairement identifiable")
	default:
		p.Type = TypeUnknown
		p.Reasons = append(p.Reasons, "aucun service connu")
	}

	p.Playbook = playbookParType[p.Type]
	return p
}

// ClassifyStore classe tous les hôtes du graph.
func ClassifyStore(store *graph.Store) []Profile {
	hosts := store.Hosts()
	profiles := make([]Profile, 0, len(hosts))
	for _, h := range hosts {
		profiles = append(profiles, Classify(h))
	}
	return profiles
}

// String rend un profil lisible pour l'affichage.
func (p Profile) String() string {
	pb := p.Playbook
	if pb == "" {
		pb = "(aucun)"
	}
	return fmt.Sprintf("%s → %s (playbook : %s)", p.Host, p.Type, pb)
}
