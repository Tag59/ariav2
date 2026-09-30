// Package playbook charge et valide les playbooks YAML déclaratifs.
//
// Un playbook encode la méthodologie (phases -> steps -> actions typées
// suggérées) pour un type de cible. Le Planner raisonne À L'INTÉRIEUR de ce cadre :
// il peut choisir, sauter, réordonner ou boucler sur des steps, mais chaque action
// reste soumise aux garde-fous (scope, RoE, approbation).
//
// Ici on fournit le chargement + la validation. Le moteur d'exécution (évaluation
// des conditions `when`, progression entre phases) viendra ensuite.
package playbook

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Tag59/aria/internal/engagement"
)

// Playbook est un playbook parsé et validé.
type Playbook struct {
	Name        string  `yaml:"name"`
	TargetType  string  `yaml:"target_type"`
	Description string  `yaml:"description"`
	Phases      []Phase `yaml:"phases"`
}

// Phase regroupe des steps d'une même étape méthodologique (recon, énumération...).
type Phase struct {
	ID    string `yaml:"id"`
	Name  string `yaml:"name"`
	Steps []Step `yaml:"steps"`
}

// Step est une action suggérée du playbook.
type Step struct {
	ID               string         `yaml:"id"`
	Action           string         `yaml:"action"`            // nom d'outil du registre
	Category         string         `yaml:"category"`          // catégorie de l'action
	GatedByRoE       string         `yaml:"gated_by_roe"`      // catégorie RoE requise
	RequiresApproval bool           `yaml:"requires_approval"` // validation humaine ?
	When             string         `yaml:"when"`              // condition (optionnelle)
	Params           map[string]any `yaml:"params"`            // paramètres suggérés
	Rationale        string         `yaml:"rationale"`         // pourquoi ce step
	Refs             []string       `yaml:"refs"`              // références WSTG/CVE...
}

// Load lit et valide un playbook depuis le disque.
func Load(path string) (*Playbook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("playbook : lecture de %q : %w", path, err)
	}
	pb, err := ParseAndValidate(data)
	if err != nil {
		return nil, fmt.Errorf("playbook %q : %w", path, err)
	}
	return pb, nil
}

// ParseAndValidate parse du YAML de playbook et le valide.
func ParseAndValidate(data []byte) (*Playbook, error) {
	var pb Playbook
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // rejette les clés inconnues (fautes de frappe)
	if err := dec.Decode(&pb); err != nil {
		return nil, fmt.Errorf("parse : %w", err)
	}
	if err := pb.validate(); err != nil {
		return nil, err
	}
	return &pb, nil
}

func (pb *Playbook) validate() error {
	if strings.TrimSpace(pb.Name) == "" {
		return fmt.Errorf("le nom du playbook est obligatoire")
	}
	if strings.TrimSpace(pb.TargetType) == "" {
		return fmt.Errorf("target_type est obligatoire")
	}
	if len(pb.Phases) == 0 {
		return fmt.Errorf("le playbook doit contenir au moins une phase")
	}
	for i, ph := range pb.Phases {
		if strings.TrimSpace(ph.ID) == "" {
			return fmt.Errorf("phase[%d] : id obligatoire", i)
		}
		for j, st := range ph.Steps {
			if err := st.validate(); err != nil {
				return fmt.Errorf("phase %q step[%d] : %w", ph.ID, j, err)
			}
		}
	}
	return nil
}

func (st Step) validate() error {
	if strings.TrimSpace(st.Action) == "" {
		return fmt.Errorf("action obligatoire")
	}
	// La catégorie et le gate RoE doivent être des catégories connues et jamais un
	// interdit dur (on ne peut pas encoder une action interdite dans un playbook).
	for _, c := range []string{st.Category, st.GatedByRoE} {
		if c == "" {
			continue
		}
		cat := engagement.Category(c)
		if engagement.IsHardProhibited(cat) {
			return fmt.Errorf("catégorie %q interdite (interdit dur)", c)
		}
		if !engagement.IsSelectableCategory(cat) {
			return fmt.Errorf("catégorie inconnue %q", c)
		}
	}
	return nil
}
