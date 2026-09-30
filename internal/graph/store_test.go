package graph

import (
	"sync"
	"testing"
)

func TestMergeDeduplique(t *testing.T) {
	s := NewStore()

	// Premier scan : un hôte avec deux ports.
	s.Merge([]Host{{
		Address:   "192.168.56.10",
		Hostnames: []string{"web.lab.local"},
		Services: []Service{
			{Port: 22, Protocol: "tcp", State: "open", Name: "ssh"},
			{Port: 80, Protocol: "tcp", State: "open", Name: "http"}, // sans version
		},
	}})

	// Second scan du MÊME hôte : nouveau nom d'hôte, version du port 80 précisée,
	// et un nouveau port 443.
	s.Merge([]Host{{
		Address:   "192.168.56.10",
		Hostnames: []string{"web.lab.local", "intranet.lab.local"},
		Services: []Service{
			{Port: 80, Protocol: "tcp", State: "open", Name: "http", Product: "nginx", Version: "1.18.0"},
			{Port: 443, Protocol: "tcp", State: "open", Name: "https"},
		},
	}})

	hosts := s.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("attendu 1 hôte (dédoublonné), obtenu %d", len(hosts))
	}
	h := hosts[0]

	// Noms d'hôte : union sans doublon.
	if len(h.Hostnames) != 2 {
		t.Errorf("hostnames = %v, attendu 2 uniques", h.Hostnames)
	}

	// Services : 3 ports distincts (22, 80, 443), pas de doublon sur 80.
	if len(h.Services) != 3 {
		t.Fatalf("attendu 3 services, obtenu %d : %+v", len(h.Services), h.Services)
	}

	// Le port 80 doit avoir été enrichi avec la version du second scan.
	var trouve bool
	for _, svc := range h.Services {
		if svc.Port == 80 {
			trouve = true
			if svc.Version != "1.18.0" || svc.Product != "nginx" {
				t.Errorf("port 80 non enrichi : %+v", svc)
			}
		}
	}
	if !trouve {
		t.Error("port 80 introuvable")
	}
}

func TestMergePlusieursHotesEtTri(t *testing.T) {
	s := NewStore()
	s.Merge([]Host{
		{Address: "192.168.56.20"},
		{Address: "192.168.56.10"},
	})
	hosts := s.Hosts()
	if len(hosts) != 2 {
		t.Fatalf("attendu 2 hôtes, obtenu %d", len(hosts))
	}
	// Hosts() doit trier par adresse.
	if hosts[0].Address != "192.168.56.10" || hosts[1].Address != "192.168.56.20" {
		t.Errorf("hôtes non triés : %s puis %s", hosts[0].Address, hosts[1].Address)
	}
}

func TestMergeIgnoreAdresseVide(t *testing.T) {
	s := NewStore()
	s.Merge([]Host{{Address: "", Hostnames: []string{"x"}}})
	if got := s.Summary().Hosts; got != 0 {
		t.Errorf("un hôte sans adresse ne doit pas être stocké, obtenu %d", got)
	}
}

func TestHostsRenvoieDesCopies(t *testing.T) {
	s := NewStore()
	s.Merge([]Host{{
		Address:  "192.168.56.10",
		Services: []Service{{Port: 80, Protocol: "tcp", State: "open"}},
	}})

	// On modifie la copie renvoyée...
	hosts := s.Hosts()
	hosts[0].Address = "modifié"
	hosts[0].Services[0].Port = 9999

	// ...le store ne doit pas avoir changé.
	again := s.Hosts()
	if again[0].Address != "192.168.56.10" || again[0].Services[0].Port != 80 {
		t.Error("Hosts() ne renvoie pas des copies : l'état interne a été modifié")
	}
}

func TestSummary(t *testing.T) {
	s := NewStore()
	s.Merge([]Host{
		{Address: "a", Services: []Service{{Port: 22, Protocol: "tcp"}, {Port: 80, Protocol: "tcp"}}},
		{Address: "b", Services: []Service{{Port: 443, Protocol: "tcp"}}},
	})
	sum := s.Summary()
	if sum.Hosts != 2 || sum.Services != 3 {
		t.Errorf("Summary = %+v, attendu {Hosts:2 Services:3}", sum)
	}
}

func TestMergeFindingsDeduplique(t *testing.T) {
	s := NewStore()
	f := Finding{Host: "192.168.56.10", Port: 80, Title: "nginx obsolète", Severity: "medium", Refs: []string{"CVE-1"}}

	// Le même finding injecté deux fois ne doit compter qu'une fois.
	s.MergeFindings([]Finding{f})
	s.MergeFindings([]Finding{f})
	// Un finding différent (autre titre) s'ajoute.
	s.MergeFindings([]Finding{{Host: "192.168.56.10", Port: 80, Title: "en-tête manquant", Severity: "low"}})

	got := s.Findings()
	if len(got) != 2 {
		t.Fatalf("attendu 2 findings uniques, obtenu %d", len(got))
	}
	if s.Summary().Findings != 2 {
		t.Errorf("Summary.Findings = %d, attendu 2", s.Summary().Findings)
	}

	// Findings() doit renvoyer des copies : modifier le retour ne change pas le store.
	got[0].Title = "modifié"
	if s.Findings()[0].Title == "modifié" {
		t.Error("Findings() ne renvoie pas des copies")
	}
}

// TestMergeConcurrent vérifie l'absence de course de données (à lancer avec -race).
func TestMergeConcurrent(t *testing.T) {
	s := NewStore()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Merge([]Host{{
				Address:  "192.168.56.10",
				Services: []Service{{Port: 80, Protocol: "tcp", State: "open"}},
			}})
		}()
	}
	wg.Wait()
	if s.Summary().Hosts != 1 {
		t.Errorf("attendu 1 hôte après merges concurrents, obtenu %d", s.Summary().Hosts)
	}
}
