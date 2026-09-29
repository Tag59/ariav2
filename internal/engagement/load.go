package engagement

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads, parses and validates an engagement.yaml from disk. A returned
// Engagement is guaranteed valid and safe to query with InScope.
func Load(path string) (*Engagement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("engagement: reading %q: %w", path, err)
	}
	e, err := ParseAndValidate(data)
	if err != nil {
		return nil, fmt.Errorf("engagement %q: %w", path, err)
	}
	return e, nil
}

// ParseAndValidate parses raw YAML and validates it. It is the only supported way
// to obtain a usable Engagement.
func ParseAndValidate(data []byte) (*Engagement, error) {
	var e Engagement
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // reject unknown keys: typos in a scope file are dangerous
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return &e, nil
}

// Validate enforces every precondition ARIA needs before it may run, and on
// success builds the compiled scope used by InScope. It fails closed: any doubt
// is an error, never a silent pass.
func (e *Engagement) Validate() error {
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("validate: engagement name is required")
	}
	if err := e.Authorization.validate(); err != nil {
		return fmt.Errorf("validate: authorization: %w", err)
	}
	if err := e.RoE.validate(); err != nil {
		return fmt.Errorf("validate: rules_of_engagement: %w", err)
	}
	compiled, err := compileScope(e.Scope)
	if err != nil {
		return fmt.Errorf("validate: scope: %w", err)
	}
	e.compiled = compiled
	return nil
}

// InScope is the central perimeter check every action must pass. It fails closed
// if the engagement was not validated.
func (e *Engagement) InScope(target string) (bool, error) {
	if e.compiled == nil {
		return false, fmt.Errorf("engagement not validated: refusing to answer InScope")
	}
	return e.compiled.InScope(target)
}

// ScopeStrings returns the compiled in/out entries as human-readable strings, for
// dry-run displays and the audit log.
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
		return fmt.Errorf("reference is required (written authorization)")
	}
	if strings.TrimSpace(a.AuthorizedBy) == "" {
		return fmt.Errorf("authorized_by is required")
	}
	if !a.Signed {
		return fmt.Errorf("authorization must be signed (signed: true)")
	}
	from, until, err := a.parsedWindow()
	if err != nil {
		return fmt.Errorf("valid_from/valid_until must be dates (YYYY-MM-DD): %w", err)
	}
	if until.Before(from) {
		return fmt.Errorf("valid_until (%s) is before valid_from (%s)", a.ValidUntil, a.ValidFrom)
	}
	return nil
}

func (r RoE) validate() error {
	if len(r.AllowedCategories) == 0 {
		return fmt.Errorf("allowed_categories is empty: enable at least one category (e.g. recon)")
	}
	for _, c := range r.AllowedCategories {
		if hardProhibited[c] {
			return fmt.Errorf("category %q is a hard interdict and can never be enabled", c)
		}
		if !selectableCategories[c] {
			return fmt.Errorf("unknown category %q", c)
		}
	}
	return nil
}
