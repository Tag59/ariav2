package playbook

import "testing"

func TestEvalWhen(t *testing.T) {
	f := Facts{
		Bools: map[string]bool{"service.http": true, "service.https": false},
		Strs:  map[string]string{"finding.candidate": "sql_injection"},
	}
	cas := []struct {
		cond string
		want bool
	}{
		{"", true},                                     // pas de condition
		{"service.http", true},                         // fait booléen nu
		{"service.https", false},                       // fait absent/false
		{"service.http == true", true},                 // == true
		{"service.https == false", true},               // == false (négation)
		{"service.http == false", false},               // == false alors que vrai
		{"finding.candidate == 'sql_injection'", true}, // égalité textuelle
		{"finding.candidate == 'xss'", false},          // texte différent
		{"machin.inconnu == true", false},              // clé inconnue
		{"n'importe quoi ~ bidon", false},              // syntaxe non reconnue
	}
	for _, c := range cas {
		if got := EvalWhen(c.cond, f); got != c.want {
			t.Errorf("EvalWhen(%q) = %v, attendu %v", c.cond, got, c.want)
		}
	}
}
