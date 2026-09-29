package engagement

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Scope is a compiled, ready-to-query representation of the in/out scope. Build
// it with compileScope; then InScope answers whether a target is authorized.
//
// Decision rule (fail-closed):
//  1. If the target matches any OUT entry  -> NOT in scope (exclusions win).
//  2. Else if it matches any IN entry      -> in scope.
//  3. Otherwise                            -> NOT in scope.
type Scope struct {
	in  []matcher
	out []matcher
}

// target is a normalized query: an IP-form target has ip set; a hostname target
// has ip nil and host set to the lowercase, port/scheme-stripped name.
type target struct {
	raw  string
	host string
	ip   net.IP
}

type matcher interface {
	matches(t target) bool
	fmt.Stringer
}

// InScope reports whether target is within the authorized perimeter. It fails
// closed: an unparsable target, or a target matching no in-scope entry, is out
// of scope. An error is returned only for a malformed target string so callers
// can log the reason; the boolean is always safe to trust on its own.
func (s *Scope) InScope(rawTarget string) (bool, error) {
	t, err := normalizeTarget(rawTarget)
	if err != nil {
		return false, err
	}
	for _, m := range s.out {
		if m.matches(t) {
			return false, nil
		}
	}
	for _, m := range s.in {
		if m.matches(t) {
			return true, nil
		}
	}
	return false, nil
}

// compileScope turns a raw ScopeConfig into a compiled Scope, validating every
// entry. An empty in-scope list is rejected: ARIA must never run with no target.
func compileScope(cfg ScopeConfig) (*Scope, error) {
	if len(cfg.In) == 0 {
		return nil, fmt.Errorf("scope.in is empty: an engagement must define at least one authorized target")
	}
	s := &Scope{}
	for i, raw := range cfg.In {
		m, err := compileEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("scope.in[%d] %q: %w", i, raw, err)
		}
		s.in = append(s.in, m)
	}
	for i, raw := range cfg.Out {
		m, err := compileEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("scope.out[%d] %q: %w", i, raw, err)
		}
		s.out = append(s.out, m)
	}
	return s, nil
}

// compileEntry classifies and compiles a single scope entry.
func compileEntry(raw string) (matcher, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return nil, fmt.Errorf("empty entry")
	}
	switch {
	case strings.Contains(s, "/"): // CIDR block
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %w", err)
		}
		return cidrMatcher{ipnet}, nil
	case strings.HasPrefix(s, "*."): // domain wildcard
		suffix := strings.TrimSuffix(s[2:], ".")
		if suffix == "" || strings.ContainsAny(suffix, "*") {
			return nil, fmt.Errorf("invalid wildcard: expected form *.example.com")
		}
		if !validHostname(suffix) {
			return nil, fmt.Errorf("invalid wildcard domain %q", suffix)
		}
		return wildcardMatcher{suffix}, nil
	default:
		if ip := net.ParseIP(s); ip != nil {
			return ipMatcher{ip}, nil
		}
		host := strings.TrimSuffix(s, ".")
		if !validHostname(host) {
			return nil, fmt.Errorf("not a valid IP, CIDR, wildcard or hostname")
		}
		return exactHostMatcher{host}, nil
	}
}

// --- matchers ---

type cidrMatcher struct{ net *net.IPNet }

func (m cidrMatcher) matches(t target) bool { return t.ip != nil && m.net.Contains(t.ip) }
func (m cidrMatcher) String() string        { return m.net.String() }

type ipMatcher struct{ ip net.IP }

func (m ipMatcher) matches(t target) bool { return t.ip != nil && t.ip.Equal(m.ip) }
func (m ipMatcher) String() string        { return m.ip.String() }

type exactHostMatcher struct{ host string }

func (m exactHostMatcher) matches(t target) bool { return t.ip == nil && t.host == m.host }
func (m exactHostMatcher) String() string        { return m.host }

// wildcardMatcher matches any strict subdomain of suffix. "*.example.com"
// matches "a.example.com" and "a.b.example.com" but NOT the apex "example.com".
type wildcardMatcher struct{ suffix string }

func (m wildcardMatcher) matches(t target) bool {
	return t.ip == nil && strings.HasSuffix(t.host, "."+m.suffix)
}
func (m wildcardMatcher) String() string { return "*." + m.suffix }

// --- target normalization ---

var hostnameRE = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	return hostnameRE.MatchString(s)
}

// normalizeTarget reduces an arbitrary target string (which may carry a scheme,
// userinfo, port or path) to a bare host or IP for matching.
func normalizeTarget(raw string) (target, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return target{}, fmt.Errorf("empty target")
	}
	if i := strings.Index(s, "://"); i >= 0 { // strip scheme
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 { // strip path/query/fragment
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 { // strip userinfo
		s = s[i+1:]
	}
	if h, _, err := net.SplitHostPort(s); err == nil { // strip port when present
		s = h
	}
	s = strings.Trim(s, "[]")   // unwrap bracketed IPv6
	s = strings.TrimSuffix(s, ".") // drop trailing dot on FQDN
	if s == "" {
		return target{}, fmt.Errorf("empty target after normalization: %q", raw)
	}
	t := target{raw: raw, host: s}
	if ip := net.ParseIP(s); ip != nil {
		t.ip = ip
		return t, nil
	}
	if !validHostname(s) {
		return target{}, fmt.Errorf("target %q is neither a valid IP nor hostname", raw)
	}
	return t, nil
}
