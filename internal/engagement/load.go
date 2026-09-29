package engagement

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load lit, parse et valide un engagement.yaml depuis le disque. Un Engagement
// renvoyé est garanti valide et interrogeable via InScope.
func Load(path string) (*Engagement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("engagement : lecture de %q : %w", path, err)
	}
	e, err := ParseAndValidate(data)
	if err != nil {
		return nil, fmt.Errorf("engagement %q : %w", path, err)
	}
	return e, nil
}

// ParseAndValidate parse du YAML brut et le valide. C'est le seul moyen supporté
// d'obtenir un Engagement utilisable.
func ParseAndValidate(data []byte) (*Engagement, error) {
	var e Engagement
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // rejette les clés inconnues : une faute de frappe dans un fichier de scope est dangereuse
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("parse : %w", err)
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return &e, nil
}

// Validate impose toutes les préconditions dont ARIA a besoin avant de tourner et,
// en cas de succès, construit le scope compilé utilisé par InScope. Elle échoue en
// mode fermé : le moindre doute est une erreur, jamais un passage silencieux.
func (e *Engagement) Validate() error {
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("validate : le nom de l'engagement est obligatoire")
	}
	if err := e.Authorization.validate(); err != nil {
		return fmt.Errorf("validate : authorization : %w", err)
	}
	if err := e.RoE.validate(); err != nil {
		return fmt.Errorf("validate : rules_of_engagement : %w", err)
	}
	compiled, err := compileScope(e.Scope)
	if err != nil {
		return fmt.Errorf("validate : scope : %w", err)
	}
	e.compiled = compiled
	return nil
}

// InScope est le contrôle de périmètre central que toute action doit passer. Il
// échoue en mode fermé si l'engagement n'a pas été validé.
func (e *Engagement) InScope(target string) (bool, error) {
	if e.compiled == nil {
		return false, fmt.Errorf("engagement non validé : refus de répondre à InScope")
	}
	return e.compiled.InScope(target)
}

// ScopeStrings renvoie les entrées in/out compilées sous forme lisible, pour les
// affichages en dry-run et le journal d'audit.
func (e *Engagement) ScopeStrings() (in, out []string) {
	if e.compiled == nil {
		return nil, nil
	}
	for _, m := range e.compiled.in {
		in = append(in, m.String())
	}
	for _, m := range e.compiled.out {
		out = append(out, m.String())
	}
	return in, out
}

func (a Authorization) validate() error {
	if strings.TrimSpace(a.Reference) == "" {
		return fmt.Errorf("reference est obligatoire (autorisation écrite)")
	}
	if strings.TrimSpace(a.AuthorizedBy) == "" {
		return fmt.Errorf("authorized_by est obligatoire")
	}
	if !a.Signed {
		return fmt.Errorf("l'autorisation doit être signée (signed: true)")
	}
	from, until, err := a.parsedWindow()
	if err != nil {
		return fmt.Errorf("valid_from/valid_until doivent être des dates (AAAA-MM-JJ) : %w", err)
	}
	if until.Before(from) {
		return fmt.Errorf("valid_until (%s) est antérieur à valid_from (%s)", a.ValidUntil, a.ValidFrom)
	}
	return nil
}

func (r RoE) validate() error {
	if len(r.AllowedCategories) == 0 {
		return fmt.Errorf("allowed_categories est vide : activez au moins une catégorie (ex. recon)")
	}
	for _, c := range r.AllowedCategories {
		if hardProhibited[c] {
			return fmt.Errorf("la catégorie %q est un interdit dur et ne peut jamais être activée", c)
		}
		if !selectableCategories[c] {
			return fmt.Errorf("catégorie inconnue %q", c)
		}
	}
	return nil
}
