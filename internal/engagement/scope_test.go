package engagement

import "testing"

// buildScope compile un scope ou fait échouer le test.
func buildScope(t *testing.T, in, out []string) *Scope {
	t.Helper()
	s, err := compileScope(ScopeConfig{In: in, Out: out})
	if err != nil {
		t.Fatalf("compileScope(%v,%v) failed: %v", in, out, err)
	}
	return s
}

func TestInScope(t *testing.T) {
	s := buildScope(t,
		[]string{"10.0.0.0/24", "192.168.56.101", "*.lab.local", "target.example.com", "::1"},
		[]string{"10.0.0.5", "admin.lab.local", "10.0.0.128/25"},
	)

	cases := []struct {
		name   string
		target string
		want   bool
	}{
		{"ip inside cidr", "10.0.0.42", true},
		{"ip outside cidr", "10.0.1.42", false},
		{"exact ip in scope", "192.168.56.101", true},
		{"exact ip not in scope", "192.168.56.102", false},
		{"excluded single ip inside included cidr", "10.0.0.5", false},
		{"excluded subnet inside included cidr", "10.0.0.200", false},
		{"non-excluded ip in lower half", "10.0.0.100", true},
		{"wildcard subdomain", "web.lab.local", true},
		{"wildcard deep subdomain", "a.b.lab.local", true},
		{"wildcard apex not matched", "lab.local", false},
		{"excluded subdomain wins over wildcard", "admin.lab.local", false},
		{"exact hostname", "target.example.com", true},
		{"subdomain of exact host not matched", "sub.target.example.com", false},
		{"unrelated host", "evil.com", false},
		{"ipv6 loopback in scope", "::1", true},
		{"case-insensitive host", "WEB.LAB.LOCAL", true},
		{"host with port", "web.lab.local:8080", true},
		{"host with scheme and path", "https://web.lab.local/admin?x=1", true},
		{"ip with scheme and port", "http://10.0.0.42:80", true},
		{"excluded host with scheme", "https://admin.lab.local/", false},
		{"userinfo stripped", "user@web.lab.local", true},
		{"ipv6 with brackets and port", "[::1]:443", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := s.InScope(c.target)
			if err != nil {
				t.Fatalf("InScope(%q) unexpected error: %v", c.target, err)
			}
			if got != c.want {
				t.Errorf("InScope(%q) = %v, want %v", c.target, got, c.want)
			}
		})
	}
}

func TestInScopeInvalidTarget(t *testing.T) {
	s := buildScope(t, []string{"10.0.0.0/24"}, nil)
	for _, target := range []string{"", "   ", "not a host!", "http://", "999.999.999.999"} {
		got, err := s.InScope(target)
		if got {
			t.Errorf("InScope(%q) = true, want false for invalid target", target)
		}
		if err == nil && target != "999.999.999.999" {
			// "999.999.999.999" ressemble à un nom d'hôte syntaxiquement valide :
			// il se normalise mais ne correspond à rien ; les autres doivent errer.
			t.Errorf("InScope(%q) : une erreur était attendue pour une cible mal formée", target)
		}
	}
}

func TestCompileScopeRejectsEmptyIn(t *testing.T) {
	if _, err := compileScope(ScopeConfig{In: nil}); err == nil {
		t.Fatal("expected error for empty in-scope, got nil")
	}
}

func TestCompileEntryErrors(t *testing.T) {
	bad := []string{"", "10.0.0.0/33", "*.", "*.*.com", "*.bad_domain!", "just bad chars!!"}
	for _, e := range bad {
		if _, err := compileEntry(e); err == nil {
			t.Errorf("compileEntry(%q) expected error, got nil", e)
		}
	}
	good := []string{"10.0.0.0/24", "192.168.1.1", "*.example.com", "host.example.com", "::1", "2001:db8::/32"}
	for _, e := range good {
		if _, err := compileEntry(e); err != nil {
			t.Errorf("compileEntry(%q) unexpected error: %v", e, err)
		}
	}
}

// TestFailClosedZeroScope vérifie qu'un Scope à valeur zéro n'autorise jamais.
func TestFailClosedZeroScope(t *testing.T) {
	var s Scope
	got, err := s.InScope("10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("zero-value Scope authorized a target; must fail closed")
	}
}
