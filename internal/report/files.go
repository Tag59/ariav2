package report

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteAll écrit le rapport dans dir sous trois formats : report.md, report.json
// et report.html. Renvoie les chemins écrits.
func WriteAll(dir string, m Model) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("report : création du dossier %q : %w", dir, err)
	}

	js, err := JSON(m)
	if err != nil {
		return nil, fmt.Errorf("report : export JSON : %w", err)
	}
	htmlStr, err := HTML(m)
	if err != nil {
		return nil, fmt.Errorf("report : rendu HTML : %w", err)
	}

	fichiers := []struct {
		nom     string
		contenu []byte
	}{
		{"report.md", []byte(Markdown(m))},
		{"report.json", js},
		{"report.html", []byte(htmlStr)},
	}

	var ecrits []string
	for _, f := range fichiers {
		p := filepath.Join(dir, f.nom)
		if err := os.WriteFile(p, f.contenu, 0o644); err != nil {
			return ecrits, fmt.Errorf("report : écriture de %q : %w", p, err)
		}
		ecrits = append(ecrits, p)
	}
	return ecrits, nil
}
