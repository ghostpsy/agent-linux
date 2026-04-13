//go:build linux

package postgres

import (
	"strings"
)

const (
	maxHbaLinesScan   = 4096
	maxHbaRuleSamples = 48
	maxHbaLineLen     = 512
)

type hbaRule struct {
	rawLine string
	typ     string
	db      string
	user    string
	addr    string
	method  string
	broad   bool
}

func splitPgHbaFields(s string) []string {
	var fields []string
	var cur strings.Builder
	inDQuote := false
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '"' {
			if inDQuote && i+1 < len(runes) && runes[i+1] == '"' {
				cur.WriteRune('"')
				i++
				continue
			}
			inDQuote = !inDQuote
			continue
		}
		if !inDQuote && (r == ' ' || r == '\t') {
			if cur.Len() > 0 {
				fields = append(fields, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		fields = append(fields, cur.String())
	}
	return fields
}

func hbaAnalyze(content string) hbaOutcome {
	var o hbaOutcome
	var ordered []hbaRule
	linesSeen := 0
	for _, raw := range strings.Split(content, "\n") {
		if linesSeen >= maxHbaLinesScan {
			o.truncated = true
			break
		}
		line := stripHbaComment(raw)
		if line == "" {
			continue
		}
		linesSeen++
		parts := splitPgHbaFields(line)
		if len(parts) < 2 {
			continue
		}
		typ := strings.ToLower(parts[0])
		switch typ {
		case "local":
			if len(parts) < 4 {
				continue
			}
			db, user, method := normHbaToken(parts[1]), normHbaToken(parts[2]), strings.ToLower(strings.Trim(parts[3], `"'`))
			r := hbaRule{rawLine: truncHbaLine(line), typ: typ, db: db, user: user, method: method}
			o.applyRule(r, &ordered)
		case "host", "hostssl", "hostnossl":
			if len(parts) < 5 {
				continue
			}
			db, user, addr := normHbaToken(parts[1]), normHbaToken(parts[2]), normHbaToken(parts[3])
			method := strings.ToLower(strings.Trim(parts[4], `"'`))
			r := hbaRule{rawLine: truncHbaLine(line), typ: typ, db: db, user: user, addr: addr, method: method}
			r.broad = hbaIsBroadWildcard(db, user, addr)
			o.applyRule(r, &ordered)
		default:
			continue
		}
	}
	o.linesScanned = linesSeen
	o.computeOrderRisk(ordered)
	return o
}

func stripHbaComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func normHbaToken(s string) string {
	s = strings.Trim(s, `"'`)
	return strings.TrimSpace(s)
}

func truncHbaLine(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxHbaLineLen {
		return s
	}
	return s[:maxHbaLineLen]
}

func hbaIsBroadWildcard(db, user, addr string) bool {
	if !strings.EqualFold(db, "all") || !strings.EqualFold(user, "all") {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(addr))
	return a == "0.0.0.0/0" || a == "::/0"
}

type hbaOutcome struct {
	linesScanned int
	truncated    bool

	host, hostssl, hostnossl, localN int
	trustN, rejectN, md5N, scramN    int
	passwordCleartextN               int
	peerIdentN                       int

	trustLines             []string
	passwordCleartextLines []string
	wideOpenLines          []string
	ruleOrderRisk          bool
}

func (o *hbaOutcome) applyRule(r hbaRule, ordered *[]hbaRule) {
	*ordered = append(*ordered, r)
	switch r.typ {
	case "local":
		o.localN++
	case "host":
		o.host++
	case "hostssl":
		o.hostssl++
	case "hostnossl":
		o.hostnossl++
	}
	switch r.method {
	case "trust":
		o.trustN++
		if len(o.trustLines) < maxHbaRuleSamples {
			o.trustLines = append(o.trustLines, r.rawLine)
		}
	case "reject":
		o.rejectN++
	case "md5":
		o.md5N++
	case "scram-sha-256":
		o.scramN++
	case "password":
		o.passwordCleartextN++
		if len(o.passwordCleartextLines) < maxHbaRuleSamples {
			o.passwordCleartextLines = append(o.passwordCleartextLines, r.rawLine)
		}
	case "peer", "ident":
		o.peerIdentN++
	default:
		if strings.Contains(r.method, "-") || r.method == "" {
			// ldap, gss, etc. — ignore counts for password family
		}
	}
	if r.broad && (r.typ == "host" || r.typ == "hostssl" || r.typ == "hostnossl") {
		if len(o.wideOpenLines) < maxHbaRuleSamples {
			o.wideOpenLines = append(o.wideOpenLines, r.rawLine)
		}
	}
}

func (o *hbaOutcome) computeOrderRisk(rules []hbaRule) {
	var broadIdx []int
	var laterSpecific bool
	for i, r := range rules {
		if r.broad && (r.typ == "host" || r.typ == "hostssl" || r.typ == "hostnossl") {
			broadIdx = append(broadIdx, i)
		}
	}
	for i, r := range rules {
		if !hbaIsMoreSpecificThanBroad(r) {
			continue
		}
		for _, bi := range broadIdx {
			if bi < i {
				laterSpecific = true
				break
			}
		}
		if laterSpecific {
			break
		}
	}
	o.ruleOrderRisk = laterSpecific
}

func hbaIsMoreSpecificThanBroad(r hbaRule) bool {
	if r.typ != "host" && r.typ != "hostssl" && r.typ != "hostnossl" {
		return false
	}
	if hbaIsBroadWildcard(r.db, r.user, r.addr) {
		return false
	}
	if !strings.EqualFold(r.db, "all") || !strings.EqualFold(r.user, "all") {
		return true
	}
	a := strings.ToLower(strings.TrimSpace(r.addr))
	if a != "0.0.0.0/0" && a != "::/0" && a != "" {
		return true
	}
	return false
}
