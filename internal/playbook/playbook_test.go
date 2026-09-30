package playbook

import (
	"path/filepath"
	"testing"
)

const playbookValide = `
name: test
target_type: web-app
description: "un playbook de test"
phases:
  - id: recon
    name: "Recon"
    steps:
      - id: scan
        action: port_scan
        category: recon
        gated_by_roe: recon
        requires_approval: false
        rationale: "scanner"
`

func TestParseAndValidateValide(t *testing.T) {
	pb, err := ParseAndValidate([]byte(playbookValide))
	if err != nil {
		t.Fatalf("ParseAndValidate : %v", err)
	}
	if pb.Name != "test" || pb.TargetType != "web-app" {
		t.Errorf("champs inattendus : %+v", pb)
	}
	if len(pb.Phases) != 1 || len(pb.Phases[0].Steps) != 1 {
		t.Fatalf("structure inattendue : %+v", pb.Phases)
	}
	if pb.Phases[0].Steps[0].Action != "port_scan" {
		t.Errorf("action inattendue : %q", pb.Phases[0].Steps[0].Action)
	}
}

func TestParseAndValidateRejets(t *testing.T) {
	cas := map[string]string{
		"nom vide": `
target_type: web-app
phases: [{id: recon, steps: [{action: port_scan, category: recon}]}]
`,
		"target_type vide": `
name: t
phases: [{id: recon, steps: [{action: port_scan, category: recon}]}]
`,
		"sans phase": `
name: t
target_type: web-app
phases: []
`,
		"step sans action": `
name: t
target_type: web-app
phases: [{id: recon, steps: [{category: recon}]}]
`,
		"catégorie interdite": `
name: t
target_type: web-app
phases: [{id: recon, steps: [{action: x, category: denial_of_service}]}]
`,
		"catégorie inconnue": `
name: t
target_type: web-app
phases: [{id: recon, steps: [{action: x, category: teleportation}]}]
`,
		"clé inconnue": `
name: t
target_type: web-app
oops: true
phases: [{id: recon, steps: [{action: x, category: recon}]}]
`,
	}
	for nom, yml := range cas {
		t.Run(nom, func(t *testing.T) {
			if _, err := ParseAndValidate([]byte(yml)); err == nil {
				t.Errorf("erreur attendue pour %q", nom)
			}
		})
	}
}

// Vérifie que les playbooks réellement livrés dans le dépôt sont valides.
func TestPlaybooksLivresValides(t *testing.T) {
	for _, f := range []string{"web.yaml", "network-host.yaml"} {
		path := filepath.Join("..", "..", "playbooks", f)
		pb, err := Load(path)
		if err != nil {
			t.Errorf("%s invalide : %v", f, err)
			continue
		}
		if len(pb.Phases) == 0 {
			t.Errorf("%s : aucune phase", f)
		}
	}
}
