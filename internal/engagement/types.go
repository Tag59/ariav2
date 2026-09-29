// Package engagement charge, valide et fait respecter les règles d'une mission de
// pentest décrite dans un fichier engagement.yaml.
//
// C'est la source de vérité unique de deux garde-fous d'ARIA :
//
//   - SCOPE : Engagement.InScope(target) est le contrôle central que toute action
//     visant un hôte ou un domaine doit passer. Ce qui n'est pas prouvé dans le
//     périmètre est refusé.
//   - RÈGLES D'ENGAGEMENT (RoE) : une liste blanche de catégories d'actions
//     activées par l'opérateur, avec des interdits DURS (déni de service,
//     destruction de données, exfiltration) qui ne peuvent jamais être activés,
//     quoi que proposent le LLM ou la config.
//
// Un engagement absent ou invalide est une erreur fatale : ARIA ne doit pas
// démarrer sans une autorisation valide et signée et un périmètre non vide.
package engagement

import "time"

// Category est une classe d'action, utilisée à la fois par la liste blanche des
// RoE et, plus tard, par le registre d'outils et les playbooks pour filtrer ce
// que l'agent a le droit de faire.
type Category string

const (
	CatRecon           Category = "recon"        // découverte passive/légère
	CatEnumeration     Category = "enumeration"  // énumération services & contenu
	CatVulnScan        Category = "vuln_scan"    // identification de vulnérabilités
	CatExploitation    Category = "exploitation" // intrusif, exige une approbation
	CatPostExploit     Category = "post_exploit" // lab uniquement, exige une approbation
	CatDenialOfService Category = "denial_of_service"
	CatDataDestruction Category = "data_destruction"
	CatExfiltration    Category = "exfiltration"
)

// selectableCategories sont les catégories qu'un opérateur peut activer dans les
// RoE. Tout ce qui n'est pas dans cet ensemble est soit inconnu, soit interdit dur.
var selectableCategories = map[Category]bool{
	CatRecon:        true,
	CatEnumeration:  true,
	CatVulnScan:     true,
	CatExploitation: true,
	CatPostExploit:  true,
}

// hardProhibited liste les catégories qui ne doivent JAMAIS s'exécuter, quelles
// que soient les RoE ou une suggestion du LLM. Elles ne peuvent jamais être activées.
var hardProhibited = map[Category]bool{
	CatDenialOfService: true,
	CatDataDestruction: true,
	CatExfiltration:    true,
}

// IsHardProhibited indique si une catégorie est un interdit dur, non négociable.
func IsHardProhibited(c Category) bool { return hardProhibited[c] }

// Engagement est l'engagement.yaml parsé et validé. Il n'est utilisable en toute
// sécurité qu'une fois produit par ParseAndValidate ou Load ; une valeur zéro n'a
// pas de scope compilé et tout appel à InScope échoue en mode fermé (fail-closed).
type Engagement struct {
	Name          string        `yaml:"name"`
	Client        string        `yaml:"client"`
	Authorization Authorization `yaml:"authorization"`
	Scope         ScopeConfig   `yaml:"scope"`
	RoE           RoE           `yaml:"rules_of_engagement"`

	// compiled est construit pendant la validation à partir de Scope. Il vaut nil
	// tant que ce n'est pas fait, donc InScope sur un Engagement non validé échoue
	// en mode fermé.
	compiled *Scope
}

// Authorization consigne l'autorisation écrite qui légitime la mission. ARIA
// refuse de tourner sans une autorisation complète et signée.
type Authorization struct {
	Reference    string `yaml:"reference"`     // réf. contrat / ordre de mission
	AuthorizedBy string `yaml:"authorized_by"` // qui a donné l'accord
	Signed       bool   `yaml:"signed"`        // doit être true
	ValidFrom    string `yaml:"valid_from"`    // AAAA-MM-JJ
	ValidUntil   string `yaml:"valid_until"`   // AAAA-MM-JJ
}

// ScopeConfig est le périmètre in/out brut tel qu'écrit en YAML. Chaque entrée
// peut être une adresse IPv4/IPv6, un bloc CIDR, un nom d'hôte exact, ou un
// wildcard de domaine de la forme "*.example.com".
type ScopeConfig struct {
	In  []string `yaml:"in"`
	Out []string `yaml:"out"`
}

// RoE regroupe les règles d'engagement : les catégories activées par l'opérateur.
type RoE struct {
	AllowedCategories []Category `yaml:"allowed_categories"`
}

// Allows indique si la catégorie donnée est activée par les RoE. Les interdits
// durs renvoient toujours false.
func (r RoE) Allows(c Category) bool {
	if hardProhibited[c] {
		return false
	}
	for _, a := range r.AllowedCategories {
		if a == c {
			return true
		}
	}
	return false
}

// dateLayout est le format de date accepté pour la fenêtre de validité.
const dateLayout = "2006-01-02"

// parsedWindow renvoie la fenêtre de validité de l'autorisation en time.Time.
func (a Authorization) parsedWindow() (from, until time.Time, err error) {
	from, err = time.Parse(dateLayout, a.ValidFrom)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	until, err = time.Parse(dateLayout, a.ValidUntil)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return from, until, nil
}

// IsActive indique si l'autorisation couvre l'instant at. La fenêtre est inclusive
// aux deux bornes (toute la journée valid_until compte comme autorisée).
func (a Authorization) IsActive(at time.Time) bool {
	from, until, err := a.parsedWindow()
	if err != nil {
		return false
	}
	until = until.Add(24*time.Hour - time.Nanosecond)
	return !at.Before(from) && !at.After(until)
}
