package graph

import (
	"sort"
	"sync"
)

// Store accumule les hôtes et services découverts au fil de la mission.
//
// Son rôle principal est le DÉDOUBLONNAGE : réinjecter le résultat d'un scan met à
// jour les informations existantes (nouveaux ports, versions plus précises, noms
// d'hôte supplémentaires) au lieu de créer des doublons. Le store sert de contexte
// au raisonnement du Planner et de source au rapport.
//
// Il est sûr pour un usage concurrent : l'agent peut y écrire depuis plusieurs
// goroutines.
type Store struct {
	mu    sync.RWMutex
	hosts map[string]*Host // clé : adresse de l'hôte
}

// NewStore crée un store vide.
func NewStore() *Store {
	return &Store{hosts: make(map[string]*Host)}
}

// Merge intègre une liste d'hôtes (typiquement la sortie d'un outil) dans le store.
func (s *Store) Merge(hosts []Host) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range hosts {
		s.mergeHost(h)
	}
}

// mergeHost fusionne un hôte. Un hôte sans adresse est ignoré : on ne saurait pas
// le dédoublonner.
func (s *Store) mergeHost(h Host) {
	if h.Address == "" {
		return
	}
	existing, ok := s.hosts[h.Address]
	if !ok {
		// Première fois qu'on voit cet hôte : on en stocke une copie défensive
		// (pour que le store ne partage pas les slices de l'appelant).
		cp := Host{
			Address:   h.Address,
			Hostnames: append([]string(nil), h.Hostnames...),
			Services:  append([]Service(nil), h.Services...),
		}
		s.hosts[h.Address] = &cp
		return
	}
	// Hôte déjà connu : on enrichit.
	existing.Hostnames = unionStrings(existing.Hostnames, h.Hostnames)
	for _, svc := range h.Services {
		mergeService(existing, svc)
	}
}

// mergeService ajoute un service à un hôte, ou enrichit celui déjà présent sur le
// même port/protocole. Règle simple : la dernière information non vide l'emporte.
func mergeService(h *Host, svc Service) {
	for i := range h.Services {
		cur := &h.Services[i]
		if cur.Protocol == svc.Protocol && cur.Port == svc.Port {
			if svc.State != "" {
				cur.State = svc.State
			}
			if svc.Name != "" {
				cur.Name = svc.Name
			}
			if svc.Product != "" {
				cur.Product = svc.Product
			}
			if svc.Version != "" {
				cur.Version = svc.Version
			}
			return
		}
	}
	h.Services = append(h.Services, svc)
}

// Hosts renvoie une copie triée (par adresse) de tous les hôtes. Les copies
// évitent que l'appelant modifie l'état interne du store par mégarde.
func (s *Store) Hosts() []Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		out = append(out, copieTriee(h))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// Host renvoie une copie d'un hôte par son adresse.
func (s *Store) Host(addr string) (Host, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hosts[addr]
	if !ok {
		return Host{}, false
	}
	return copieTriee(h), true
}

// Summary est un décompte rapide du contenu du graph, pratique pour l'affichage.
type Summary struct {
	Hosts    int
	Services int
}

// Summary compte les hôtes et services accumulés.
func (s *Store) Summary() Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sum := Summary{Hosts: len(s.hosts)}
	for _, h := range s.hosts {
		sum.Services += len(h.Services)
	}
	return sum
}

// copieTriee renvoie une copie de l'hôte avec ses services triés (protocole puis
// port), pour un affichage stable.
func copieTriee(h *Host) Host {
	cp := Host{
		Address:   h.Address,
		Hostnames: append([]string(nil), h.Hostnames...),
		Services:  append([]Service(nil), h.Services...),
	}
	sort.Slice(cp.Services, func(i, j int) bool {
		if cp.Services[i].Protocol != cp.Services[j].Protocol {
			return cp.Services[i].Protocol < cp.Services[j].Protocol
		}
		return cp.Services[i].Port < cp.Services[j].Port
	})
	return cp
}

// unionStrings concatène deux listes en supprimant les doublons et les vides, tout
// en gardant l'ordre d'apparition.
func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, x := range a {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	for _, x := range b {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
