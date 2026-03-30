//go:build linux

package firewall

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"ghostpsy/agent-linux/internal/payload"
)

var errNoNftInputChain = errors.New("nft: no filter INPUT chain")

type nftInputState struct {
	rules         []*nftables.Rule
	defaultPolicy string
}

func loadNftInputFilterState() (*nftInputState, error) {
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.CloseLasting() }()
	chains, err := c.ListChains()
	if err != nil {
		return nil, err
	}
	ch := pickFilterInputChain(chains)
	if ch == nil || ch.Table == nil {
		return nil, errNoNftInputChain
	}
	rules, err := c.GetRules(ch.Table, ch)
	if err != nil {
		return nil, err
	}
	pol := payload.FirewallRuleUnknown
	if ch.Policy != nil {
		if *ch.Policy == nftables.ChainPolicyAccept {
			pol = "ACCEPT"
		} else {
			pol = "DROP"
		}
	}
	return &nftInputState{rules: rules, defaultPolicy: pol}, nil
}

func pickFilterInputChain(chains []*nftables.Chain) *nftables.Chain {
	var inet, ip4, ip6 *nftables.Chain
	for _, ch := range chains {
		if ch.Table == nil || !isIptablesParityFilterTable(ch.Table) {
			continue
		}
		if ch.Type != nftables.ChainTypeFilter || ch.Hooknum == nil {
			continue
		}
		if *ch.Hooknum != *nftables.ChainHookInput {
			continue
		}
		switch ch.Table.Family {
		case nftables.TableFamilyINet:
			inet = ch
		case nftables.TableFamilyIPv4:
			ip4 = ch
		case nftables.TableFamilyIPv6:
			ip6 = ch
		}
	}
	if inet != nil {
		return inet
	}
	if ip4 != nil {
		return ip4
	}
	return ip6
}

func classifyFromNFTRules(rules []*nftables.Rule, defaultPolicy string, port uint16, v6 bool) string {
	policy := strings.TrimSpace(defaultPolicy)
	if policy == "" {
		policy = payload.FirewallRuleUnknown
	}
	if policy != payload.FirewallRuleUnknown {
		policy = strings.ToUpper(policy)
	}
	for _, r := range rules {
		if nftRuleEstablishedOnlySkip(r) {
			continue
		}
		if nftRuleMatchesTCPPort(r, port) {
			v := nftExtractVerdict(r)
			switch v {
			case "accept":
				if nftRuleHasRestrictedSource(r, v6) {
					return payload.FirewallRuleFiltered
				}
				return payload.FirewallRuleUnfiltered
			case "drop", "reject":
				return payload.FirewallRuleBlocked
			case "jump", "goto":
				return payload.FirewallRuleUnknown
			}
			continue
		}
		if nftRuleImplicitAll(r) {
			v := nftExtractVerdict(r)
			switch v {
			case "accept":
				return payload.FirewallRuleUnfiltered
			case "drop", "reject":
				return payload.FirewallRuleBlocked
			case "jump", "goto":
				return payload.FirewallRuleUnknown
			}
		}
	}
	if policy == "DROP" {
		return payload.FirewallRuleBlocked
	}
	if policy == payload.FirewallRuleUnknown {
		return payload.FirewallRuleUnknown
	}
	return payload.FirewallRuleUnfiltered
}

func nftRuleEstablishedOnlySkip(r *nftables.Rule) bool {
	hasCt := false
	hasDport := false
	for _, e := range r.Exprs {
		if ct, ok := e.(*expr.Ct); ok && ct.Key == expr.CtKeySTATE {
			hasCt = true
		}
		if pl, ok := e.(*expr.Payload); ok && pl.Base == expr.PayloadBaseTransportHeader && pl.Offset == 2 {
			hasDport = true
		}
	}
	return hasCt && !hasDport
}

func nftRuleMatchesTCPPort(r *nftables.Rule, want uint16) bool {
	ex := r.Exprs
	for i := 0; i < len(ex); i++ {
		pl, ok := ex[i].(*expr.Payload)
		if !ok || pl.Base != expr.PayloadBaseTransportHeader || pl.Offset != 2 || pl.Len != 2 {
			continue
		}
		for j := i + 1; j < len(ex) && j <= i+6; j++ {
			cmp, ok := ex[j].(*expr.Cmp)
			if !ok || cmp.Op != expr.CmpOpEq {
				continue
			}
			if len(cmp.Data) == 2 && binary.BigEndian.Uint16(cmp.Data) == uint16(want) {
				return true
			}
		}
	}
	return false
}

func nftRuleImplicitAll(r *nftables.Rule) bool {
	if nftExtractVerdict(r) == "" {
		return false
	}
	for _, e := range r.Exprs {
		if pl, ok := e.(*expr.Payload); ok && pl.Base == expr.PayloadBaseTransportHeader && pl.Offset == 2 {
			return false
		}
	}
	return true
}

func nftExtractVerdict(r *nftables.Rule) string {
	var last string
	for _, e := range r.Exprs {
		switch v := e.(type) {
		case *expr.Verdict:
			switch v.Kind {
			case expr.VerdictAccept:
				last = "accept"
			case expr.VerdictDrop:
				last = "drop"
			case expr.VerdictJump, expr.VerdictGoto:
				return "jump"
			}
		case *expr.Reject:
			last = "reject"
		}
	}
	return last
}

func nftRuleHasRestrictedSource(r *nftables.Rule, v6 bool) bool {
	if v6 {
		return nftRuleHasRestrictedSourceIPv6(r)
	}
	return nftRuleHasRestrictedSourceIPv4(r)
}

func nftRuleHasRestrictedSourceIPv4(r *nftables.Rule) bool {
	ex := r.Exprs
	for i := 0; i < len(ex); i++ {
		pl, ok := ex[i].(*expr.Payload)
		if !ok || pl.Base != expr.PayloadBaseNetworkHeader || pl.Offset != 12 || pl.Len != 4 {
			continue
		}
		for j := i + 1; j < len(ex) && j <= i+6; j++ {
			cmp, ok := ex[j].(*expr.Cmp)
			if !ok || cmp.Op != expr.CmpOpEq || len(cmp.Data) != 4 {
				continue
			}
			if cmp.Data[0] == 0 && cmp.Data[1] == 0 && cmp.Data[2] == 0 && cmp.Data[3] == 0 {
				return false
			}
			return true
		}
	}
	return false
}

func nftRuleHasRestrictedSourceIPv6(r *nftables.Rule) bool {
	ex := r.Exprs
	for i := 0; i < len(ex); i++ {
		pl, ok := ex[i].(*expr.Payload)
		if !ok || pl.Base != expr.PayloadBaseNetworkHeader || pl.Offset != 8 || pl.Len != 16 {
			continue
		}
		for j := i + 1; j < len(ex) && j <= i+6; j++ {
			cmp, ok := ex[j].(*expr.Cmp)
			if !ok || cmp.Op != expr.CmpOpEq || len(cmp.Data) != 16 {
				continue
			}
			allZero := true
			for _, b := range cmp.Data {
				if b != 0 {
					allZero = false
					break
				}
			}
			return !allZero
		}
	}
	return false
}
