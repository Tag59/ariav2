package playbook

import "strings"

// Facts regroupe les faits (booléens et textuels) dérivés de l'état courant,
// contre lesquels les conditions `when` des steps sont évaluées.
type Facts struct {
	Bools map[string]bool
	Strs  map[string]string
}

// EvalWhen évalue une condition `when` de step.
//
// Le langage est volontairement minuscule (c'est le MOTEUR qui évalue, jamais le
// LLM). Formes reconnues :
//   - ""                       -> toujours vrai (pas de condition)
//   - "clé"                    -> fait booléen `clé`
//   - "clé == true|false"      -> fait booléen (ou sa négation)
//   - "clé == 'valeur'"        -> égalité textuelle
//
// Toute condition non reconnue renvoie false (fail-closed : on ne suggère pas un
// step dont on ne sait pas vérifier la précondition).
func EvalWhen(cond string, f Facts) bool {
	c := strings.TrimSpace(cond)
	if c == "" {
		return true
	}

	// Sans opérateur : fait booléen nu.
	if !strings.Contains(c, "==") {
		return f.Bools[c]
	}

	parts := strings.SplitN(c, "==", 2)
	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])

	switch val {
	case "true":
		return f.Bools[key]
	case "false":
		return !f.Bools[key]
	}

	// Comparaison textuelle : la valeur doit être entre quotes.
	if len(val) >= 2 && (val[0] == '\'' || val[0] == '"') && val[len(val)-1] == val[0] {
		want := val[1 : len(val)-1]
		got, ok := f.Strs[key]
		return ok && got == want
	}

	return false
}
