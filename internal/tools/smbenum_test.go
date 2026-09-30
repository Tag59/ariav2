package tools

import (
	"strings"
	"testing"

	"github.com/Tag59/aria/internal/sandbox"
)

func TestSMBEnumPrepare(t *testing.T) {
	s := NewSMBEnum("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	inv, err := s.Prepare(map[string]any{"target": "10.0.0.5"})
	if err != nil {
		t.Fatalf("Prepare : %v", err)
	}
	got := strings.Join(inv.Spec.Argv, " ")
	if !strings.Contains(got, "--script smb-os-discovery,smb-enum-shares,smb-security-mode") {
		t.Errorf("scripts SMB manquants : %q", got)
	}
	if !strings.Contains(got, "-p 445,139") {
		t.Errorf("ports SMB manquants : %q", got)
	}
	if inv.Spec.Image != imageParDefaut {
		t.Errorf("image = %q (attendu image nmap)", inv.Spec.Image)
	}
}

func TestSMBEnumParse(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostscript>
      <script id="smb-os-discovery" output="OS: Windows Server 2016"/>
    </hostscript>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <script id="smb-enum-shares" output="ADMIN$, C$, IPC$"/>
      </port>
    </ports>
  </host>
</nmaprun>`
	s := NewSMBEnum("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	out, err := s.Parse(sandbox.Result{Stdout: []byte(xml)})
	if err != nil {
		t.Fatalf("Parse : %v", err)
	}
	if len(out.Findings) != 2 {
		t.Fatalf("attendu 2 findings (hostscript + port script), obtenu %d", len(out.Findings))
	}
	// Vérifie le finding au niveau hôte.
	var osFinding bool
	for _, f := range out.Findings {
		if strings.Contains(f.Title, "smb-os-discovery") {
			osFinding = true
			if f.Host != "10.0.0.5" || !strings.Contains(f.Evidence, "Windows Server 2016") {
				t.Errorf("finding OS mal parsé : %+v", f)
			}
		}
	}
	if !osFinding {
		t.Error("finding smb-os-discovery introuvable")
	}
}

func TestSMBEnumParseVide(t *testing.T) {
	s := NewSMBEnum("", sandbox.NetworkPolicy{Mode: sandbox.NetNone})
	// Hôte sans script SMB (cas d'une cible non-Windows) : aucun finding, pas d'erreur.
	xml := `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/></host></nmaprun>`
	out, err := s.Parse(sandbox.Result{Stdout: []byte(xml)})
	if err != nil {
		t.Fatalf("Parse : %v", err)
	}
	if len(out.Findings) != 0 {
		t.Errorf("attendu 0 finding, obtenu %d", len(out.Findings))
	}
}
