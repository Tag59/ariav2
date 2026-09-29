package engagement

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const validYAML = `
name: "Demo lab engagement"
client: "Internal lab"
authorization:
  reference: "MISSION-2026-001"
  authorized_by: "Lab owner"
  signed: true
  valid_from: "2026-01-01"
  valid_until: "2026-12-31"
scope:
  in:
    - 192.168.56.0/24
    - "*.lab.local"
  out:
    - 192.168.56.1
rules_of_engagement:
  allowed_categories:
    - recon
    - enumeration
    - vuln_scan
`

func TestParseAndValidateValid(t *testing.T) {
	e, err := ParseAndValidate([]byte(validYAML))
	if err != nil {
		t.Fatalf("ParseAndValidate valid config failed: %v", err)
	}
	if e.Name != "Demo lab engagement" {
		t.Errorf("Name = %q", e.Name)
	}
	if in, err := e.InScope("192.168.56.10"); err != nil || !in {
		t.Errorf("InScope(host in cidr) = %v,%v want true,nil", in, err)
	}
	if in, _ := e.InScope("192.168.56.1"); in {
		t.Error("excluded host reported in scope")
	}
	if !e.RoE.Allows(CatRecon) {
		t.Error("recon should be allowed")
	}
	if e.RoE.Allows(CatExploitation) {
		t.Error("exploitation should not be allowed")
	}
	if !e.Authorization.IsActive(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("authorization should be active mid-window")
	}
	if e.Authorization.IsActive(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("authorization should be inactive after window")
	}
}

func TestValidateRejections(t *testing.T) {
	cases := map[string]string{
		"empty scope.in": `
name: x
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: []}
rules_of_engagement: {allowed_categories: [recon]}
`,
		"missing authorization ref": `
name: x
authorization: {authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: [10.0.0.0/24]}
rules_of_engagement: {allowed_categories: [recon]}
`,
		"unsigned authorization": `
name: x
authorization: {reference: r, authorized_by: a, signed: false, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: [10.0.0.0/24]}
rules_of_engagement: {allowed_categories: [recon]}
`,
		"invalid CIDR": `
name: x
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: ["10.0.0.0/33"]}
rules_of_engagement: {allowed_categories: [recon]}
`,
		"hard-prohibited category": `
name: x
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: [10.0.0.0/24]}
rules_of_engagement: {allowed_categories: [recon, denial_of_service]}
`,
		"unknown category": `
name: x
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: [10.0.0.0/24]}
rules_of_engagement: {allowed_categories: [teleportation]}
`,
		"reversed date window": `
name: x
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-12-31", valid_until: "2026-01-01"}
scope: {in: [10.0.0.0/24]}
rules_of_engagement: {allowed_categories: [recon]}
`,
		"empty name": `
name: ""
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: [10.0.0.0/24]}
rules_of_engagement: {allowed_categories: [recon]}
`,
		"unknown field": `
name: x
authorization: {reference: r, authorized_by: a, signed: true, valid_from: "2026-01-01", valid_until: "2026-12-31"}
scope: {in: [10.0.0.0/24]}
rules_of_engagement: {allowed_categories: [recon]}
oops_typo: true
`,
	}
	for name, yml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAndValidate([]byte(yml)); err == nil {
				t.Errorf("expected validation error for %q, got nil", name)
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engagement.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if in, _ := e.InScope("web.lab.local"); !in {
		t.Error("expected web.lab.local in scope")
	}
}

func TestInScopeBeforeValidateFailsClosed(t *testing.T) {
	var e Engagement
	if in, err := e.InScope("10.0.0.1"); in || err == nil {
		t.Errorf("unvalidated Engagement.InScope = %v,%v; want false,error", in, err)
	}
}
