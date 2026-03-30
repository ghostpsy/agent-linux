//go:build linux

package firewall

import "testing"

func TestPolicyFromFilterTableLines(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		lines  []string
		chain  string
		expect string
	}{
		{
			name:   "input drop",
			lines:  []string{"-P INPUT DROP", "-P FORWARD DROP", "-P OUTPUT ACCEPT"},
			chain:  "INPUT",
			expect: "DROP",
		},
		{
			name:   "output accept",
			lines:  []string{"-P INPUT DROP", "-P OUTPUT ACCEPT"},
			chain:  "OUTPUT",
			expect: "ACCEPT",
		},
		{
			name:   "missing chain",
			lines:  []string{"-A INPUT -j DROP"},
			chain:  "INPUT",
			expect: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := policyFromFilterTableLines(tc.lines, tc.chain)
			if got != tc.expect {
				t.Fatalf("got %q want %q", got, tc.expect)
			}
		})
	}
}

func TestFilterTableRulesForListenerClassificationOrderAndChains(t *testing.T) {
	t.Parallel()
	dump := []string{
		"-P INPUT DROP",
		"-A INPUT -j ufw-before-input",
		"-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A DOCKER-USER -j RETURN",
	}
	got := filterTableRulesForListenerClassification(dump)
	if len(got) != 3 {
		t.Fatalf("len %d want 3: %v", len(got), got)
	}
	if got[0] != "-A INPUT -j ufw-before-input" || got[1] != "-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT" || got[2] != "-A DOCKER-USER -j RETURN" {
		t.Fatalf("unexpected order: %v", got)
	}
}

func TestFilterTableRulesForListenerClassificationSkipsOutputForward(t *testing.T) {
	t.Parallel()
	dump := []string{
		"-P INPUT DROP",
		"-A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT",
		"-A INPUT -i lo -j ACCEPT",
		"-A FORWARD -j DROP",
		"-A ufw6-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
	}
	got := filterTableRulesForListenerClassification(dump)
	if len(got) != 2 {
		t.Fatalf("len %d want 2: %v", len(got), got)
	}
	if got[0] != "-A INPUT -i lo -j ACCEPT" || got[1] != "-A ufw6-user-input -p tcp -m tcp --dport 22 -j ACCEPT" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestFilterTableRulesLayerUfwBeforeDockerDespiteFileOrder(t *testing.T) {
	t.Parallel()
	dump := []string{
		"-P INPUT DROP",
		"-A DOCKER-USER -p tcp -m tcp --dport 22 -j DROP",
		"-A INPUT -j ufw-before-input",
		"-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
	}
	got := filterTableRulesForListenerClassification(dump)
	if len(got) != 3 {
		t.Fatalf("len %d want 3: %v", len(got), got)
	}
	if got[0] != "-A INPUT -j ufw-before-input" || got[1] != "-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT" || got[2] != "-A DOCKER-USER -p tcp -m tcp --dport 22 -j DROP" {
		t.Fatalf("INPUT+ufw must precede DOCKER so ACCEPT wins: %v", got)
	}
}
