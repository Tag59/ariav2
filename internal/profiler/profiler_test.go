package profiler

import (
	"testing"

	"github.com/Tag59/aria/internal/graph"
)

func hote(services ...graph.Service) graph.Host {
	return graph.Host{Address: "10.0.0.1", Services: services}
}

func svc(port int, name string) graph.Service {
	return graph.Service{Port: port, Protocol: "tcp", State: "open", Name: name}
}

func TestClassify(t *testing.T) {
	cas := []struct {
		nom      string
		host     graph.Host
		attendu  TargetType
		playbook string
	}{
		{"web par port 3000", hote(svc(3000, "http")), TypeWebApp, "web.yaml"},
		{"web par port 443", hote(svc(443, "https")), TypeWebApp, "web.yaml"},
		{"linux par ssh", hote(svc(22, "ssh")), TypeLinuxHost, "network-host.yaml"},
		{"windows par smb", hote(svc(445, "microsoft-ds")), TypeWindowsHost, "network-host.yaml"},
		{"windows par rdp", hote(svc(3389, "ms-wbt-server")), TypeWindowsHost, "network-host.yaml"},
		{"ad par ldap+smb", hote(svc(389, "ldap"), svc(445, "microsoft-ds")), TypeAD, "network-host.yaml"},
		{"ad par kerberos+ldap", hote(svc(88, "kerberos-sec"), svc(389, "ldap")), TypeAD, "network-host.yaml"},
		{"web prioritaire sur windows", hote(svc(80, "http"), svc(445, "microsoft-ds")), TypeWebApp, "web.yaml"},
		{"hote reseau generique", hote(svc(3306, "mysql")), TypeNetworkHost, "network-host.yaml"},
		{"inconnu sans service", hote(), TypeUnknown, ""},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			p := Classify(c.host)
			if p.Type != c.attendu {
				t.Errorf("type = %q, attendu %q", p.Type, c.attendu)
			}
			if p.Playbook != c.playbook {
				t.Errorf("playbook = %q, attendu %q", p.Playbook, c.playbook)
			}
			if len(p.Reasons) == 0 {
				t.Error("un profil devrait toujours porter au moins une raison")
			}
		})
	}
}

func TestClassifyStore(t *testing.T) {
	s := graph.NewStore()
	s.Merge([]graph.Host{
		{Address: "10.0.0.1", Services: []graph.Service{svc(80, "http")}},
		{Address: "10.0.0.2", Services: []graph.Service{svc(22, "ssh")}},
	})
	profils := ClassifyStore(s)
	if len(profils) != 2 {
		t.Fatalf("attendu 2 profils, obtenu %d", len(profils))
	}
}
