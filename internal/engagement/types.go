// Package engagement loads, validates and enforces the rules of a pentest
// engagement described by an engagement.yaml file.
//
// It is the single source of truth for two guardrails of ARIA:
//
//   - SCOPE ENFORCEMENT: Engagement.InScope(target) is the central check that
//     every action targeting a host or domain must pass. Anything not proven to
//     be in scope is refused.
//   - RULES OF ENGAGEMENT (RoE): a whitelist of action categories the operator
//     enabled, with a set of HARD prohibitions (denial of service, data
//     destruction, exfiltration) that can never be enabled, whatever the LLM or
//     the config proposes.
//
// A missing or invalid engagement is a hard failure: ARIA must not start without
// a valid, signed authorization and a non-empty scope.
package engagement

import "time"

// Category is a class of action, used both by the RoE whitelist and, later, by
// the tool registry and playbooks to gate what the agent may do.
type Category string

const (
	CatRecon          Category = "recon"           // passive/light discovery
	CatEnumeration    Category = "enumeration"     // service & content enumeration
	CatVulnScan       Category = "vuln_scan"       // vulnerability identification
	CatExploitation   Category = "exploitation"    // intrusive, requires approval
	CatPostExploit    Category = "post_exploit"    // lab-only, requires approval
	CatDenialOfService Category = "denial_of_service"
	CatDataDestruction Category = "data_destruction"
	CatExfiltration    Category = "exfiltration"
)

// selectableCategories are the categories an operator is allowed to enable in the
// RoE. Anything outside this set is either unknown or hard-prohibited.
var selectableCategories = map[Category]bool{
	CatRecon:        true,
	CatEnumeration:  true,
	CatVulnScan:     true,
	CatExploitation: true,
	CatPostExploit:  true,
}

// hardProhibited lists categories that MUST never run, regardless of the RoE or
// any suggestion made by the LLM. They can never be enabled.
var hardProhibited = map[Category]bool{
	CatDenialOfService: true,
	CatDataDestruction: true,
	CatExfiltration:    true,
}

// IsHardProhibited reports whether a category is a hard, non-negotiable interdict.
func IsHardProhibited(c Category) bool { return hardProhibited[c] }

// Engagement is the parsed, validated engagement.yaml. It is only safe to use
// once produced by ParseAndValidate or Load; a zero value has no compiled scope
// and every InScope call fails closed.
type Engagement struct {
	Name          string        `yaml:"name"`
	Client        string        `yaml:"client"`
	Authorization Authorization `yaml:"authorization"`
	Scope         ScopeConfig   `yaml:"scope"`
	RoE           RoE           `yaml:"rules_of_engagement"`

	// compiled is built during validation from Scope. It is nil until then, so
	// InScope on an unvalidated Engagement fails closed.
	compiled *Scope
}

// Authorization records the written authorization that legitimizes the mission.
// ARIA refuses to run without a complete, signed authorization.
type Authorization struct {
	Reference    string `yaml:"reference"`     // e.g. contract / mission order ref
	AuthorizedBy string `yaml:"authorized_by"` // who signed off
	Signed       bool   `yaml:"signed"`        // must be true
	ValidFrom    string `yaml:"valid_from"`    // YYYY-MM-DD
	ValidUntil   string `yaml:"valid_until"`   // YYYY-MM-DD
}

// ScopeConfig is the raw in/out scope as written in YAML. Each entry may be an
// IPv4/IPv6 address, a CIDR block, an exact hostname, or a domain wildcard of
// the form "*.example.com".
type ScopeConfig struct {
	In  []string `yaml:"in"`
	Out []string `yaml:"out"`
}

// RoE is the rules of engagement: the categories the operator enabled.
type RoE struct {
	AllowedCategories []Category `yaml:"allowed_categories"`
}

// Allows reports whether the given category is enabled by the RoE. Hard
// prohibitions always return false.
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

// dateLayout is the accepted date format for authorization validity dates.
const dateLayout = "2006-01-02"

// parsedWindow returns the authorization validity window as time.Time values.
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

// IsActive reports whether the authorization covers the instant at. The window is
// inclusive on both ends (the whole valid_until day counts as authorized).
func (a Authorization) IsActive(at time.Time) bool {
	from, until, err := a.parsedWindow()
	if err != nil {
		return false
	}
	until = until.Add(24*time.Hour - time.Nanosecond)
	return !at.Before(from) && !at.After(until)
}
