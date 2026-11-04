package llm

import "testing"

func TestBaseURLDepuisEnv(t *testing.T) {
	cas := map[string]string{
		"":                      "http://localhost:11434",
		"172.29.144.1:11434":    "http://172.29.144.1:11434", // schéma ajouté
		"localhost:11434":       "http://localhost:11434",
		"http://host:11434":     "http://host:11434",
		"https://host:443":      "https://host:443",
		"http://host:11434/":    "http://host:11434",         // slash final retiré
		"  172.29.144.1:11434 ": "http://172.29.144.1:11434", // trim
	}
	for in, want := range cas {
		if got := baseURLDepuisEnv(in); got != want {
			t.Errorf("baseURLDepuisEnv(%q) = %q, attendu %q", in, got, want)
		}
	}
}
