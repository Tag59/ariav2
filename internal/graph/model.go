package graph

// Ce fichier définit le modèle de données du knowledge graph : les objets
// structurés que les adapters d'outils produisent et que le rapport consomme.
// Le "store" (accumulation, fusion, requêtes) viendra à l'étape dédiée ; ici on
// ne pose que les types.

// Host représente une machine découverte pendant la mission.
type Host struct {
	// Address est l'adresse IP (ou le nom d'hôte si l'IP est inconnue).
	Address string
	// Hostnames liste les noms DNS associés, s'il y en a.
	Hostnames []string
	// Services liste les ports/services ouverts trouvés sur cet hôte.
	Services []Service
}

// Service décrit un port ouvert et, si connu, le service qui écoute derrière.
type Service struct {
	Port     int    // numéro de port (1-65535)
	Protocol string // "tcp" ou "udp"
	State    string // état du port tel que rapporté par l'outil (ex. "open")
	Name     string // nom du service (ex. "http"), si détecté
	Product  string // logiciel (ex. "nginx"), si détecté
	Version  string // version (ex. "1.18.0"), si détectée
}

// Finding est une vulnérabilité CANDIDATE : une hypothèse produite par l'analyse
// (rôle Analyst), pas une preuve d'exploitation. L'opérateur reste seul juge.
type Finding struct {
	Host        string   // adresse de l'hôte concerné
	Port        int      // port concerné (0 si sans objet)
	Title       string   // intitulé court
	Severity    string   // sévérité qualitative : info, low, medium, high, critical
	Description string   // description du problème
	Evidence    string   // preuve/indice ayant mené au finding (donnée observée)
	Impact      string   // impact potentiel
	Remediation string   // remédiation conseillée
	Refs        []string // références (CVE, OWASP, MITRE...)
}
