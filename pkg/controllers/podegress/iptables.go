package podegress

import "github.com/coreos/go-iptables/iptables"

func iptablesChainExists(table string, chain string, it *iptables.IPTables) (bool, error) {
	chains, err := it.ListChains(table)
	if err != nil {
		return false, err
	}

	for _, c := range chains {
		if c == chain {
			return true, nil
		}
	}
	return false, nil
}

func iptablesEnsureChain(table string, chain string, it *iptables.IPTables) error {
	if exists, err := iptablesChainExists(table, chain, it); err != nil {
		return nil
	} else if !exists {
		return it.NewChain(table, chain)
	}
	return nil
}

func iptablesEnsureRuleAtPosition(table, chain string, position int, it *iptables.IPTables, rule ...string) error {
	if exists, err := it.Exists(table, chain, rule...); err != nil {
		return err
	} else if exists {
		if err2 := it.Delete(table, chain, rule...); err2 != nil {
			return err2
		}
	}

	return it.Insert(table, chain, position, rule...)
}
