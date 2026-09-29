package engagement

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Scope est une représentation compilée et prête à interroger du périmètre
// in/out. On la construit avec compileScope ; ensuite InScope répond si une cible
// est autorisée.
//
// Règle de décision (fail-closed) :
//  1. Si la cible correspond à une entrée OUT -> HORS scope (les exclusions gagnent).
//  2. Sinon si elle correspond à une entrée IN -> dans le scope.
//  3. Sinon                                    -> HORS scope.
type Scope struct {
	in  []matcher
	out []matcher
}

// target est une requête normalisée : une cible sous forme d'IP a ip renseigné ;
// une cible nom d'hôte a ip nil et host mis au nom en minuscules, sans port ni schéma.
type target struct {
	raw  string
	host string
	ip   net.IP
}

type matcher interface {
	matches(t target) bool
	fmt.Stringer
}

// InScope indique si target est dans le périmètre autorisé. La fonction échoue en
// mode fermé : une cible illisible, ou une cible ne correspondant à aucune entrée
// IN, est hors scope. Une erreur n'est renvoyée que pour une chaîne de cible mal
// formée (pour pouvoir la journaliser) ; le booléen seul est toujours fiable.
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

// compileScope transforme un ScopeConfig brut en Scope compilé, en validant
// chaque entrée. Une liste in vide est rejetée : ARIA ne doit jamais tourner sans
// cible.
func compileScope(cfg ScopeConfig) (*Scope, error) {
	if len(cfg.In) == 0 {
		return nil, fmt.Errorf("scope.in est vide : un engagement doit définir au moins une cible autorisée")
	}
	s := &Scope{}
	for i, raw := range cfg.In {
		m, err := compileEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("scope.in[%d] %q : %w", i, raw, err)
		}
		s.in = append(s.in, m)
	}
	for i, raw := range cfg.Out {
		m, err := compileEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("scope.out[%d] %q : %w", i, raw, err)
		}
		s.out = append(s.out, m)
	}
	return s, nil
}

// compileEntry classe et compile une entrée de scope.
func compileEntry(raw string) (matcher, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return nil, fmt.Errorf("entrée vide")
	}
	switch {
	case strings.Contains(s, "/"): // bloc CIDR
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("CIDR invalide : %w", err)
		}
		return cidrMatcher{ipnet}, nil
	case strings.HasPrefix(s, "*."): // wildcard de domaine
		suffix := strings.TrimSuffix(s[2:], ".")
		if suffix == "" || strings.ContainsAny(suffix, "*") {
			return nil, fmt.Errorf("wildcard invalide : forme attendue *.example.com")
		}
		if !validHostname(suffix) {
			return nil, fmt.Errorf("domaine wildcard invalide %q", suffix)
		}
		return wildcardMatcher{suffix}, nil
	default:
		if ip := net.ParseIP(s); ip != nil {
			return ipMatcher{ip}, nil
		}
		host := strings.TrimSuffix(s, ".")
		if !validHostname(host) {
			return nil, fmt.Errorf("ni IP, ni CIDR, ni wildcard, ni nom d'hôte valide")
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

// wildcardMatcher correspond à tout sous-domaine strict de suffix. "*.example.com"
// correspond à "a.example.com" et "a.b.example.com" mais PAS à l'apex "example.com".
type wildcardMatcher struct{ suffix string }

func (m wildcardMatcher) matches(t target) bool {
	return t.ip == nil && strings.HasSuffix(t.host, "."+m.suffix)
}
func (m wildcardMatcher) String() string { return "*." + m.suffix }

// --- normalisation des cibles ---

var hostnameRE = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	return hostnameRE.MatchString(s)
}

// normalizeTarget réduit une chaîne de cible quelconque (qui peut porter un
// schéma, un userinfo, un port ou un chemin) à un simple hôte ou IP, pour le
// matching.
func normalizeTarget(raw string) (target, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return target{}, fmt.Errorf("cible vide")
	}
	if i := strings.Index(s, "://"); i >= 0 { // retire le schéma
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 { // retire chemin/query/fragment
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 { // retire le userinfo
		s = s[i+1:]
	}
	if h, _, err := net.SplitHostPort(s); err == nil { // retire le port s'il y en a
		s = h
	}
	s = strings.Trim(s, "[]")      // enlève les crochets d'une IPv6
	s = strings.TrimSuffix(s, ".") // enlève le point final d'un FQDN
	if s == "" {
		return target{}, fmt.Errorf("cible vide après normalisation : %q", raw)
	}
	t := target{raw: raw, host: s}
	if ip := net.ParseIP(s); ip != nil {
		t.ip = ip
		return t, nil
	}
	if !validHostname(s) {
		return target{}, fmt.Errorf("la cible %q n'est ni une IP ni un nom d'hôte valide", raw)
	}
	return t, nil
}
