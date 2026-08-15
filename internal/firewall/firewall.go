package firewall

import (
	"context"
	"fmt"
	"os/exec"
)

type Rule struct {
	SourceIP string
	Port     uint16
	Protocol string
}

type Backend interface {
	Allow(context.Context, Rule) error
	Deny(context.Context, Rule) error
	List(context.Context) ([]Rule, error)
}

type NFTables struct {
	Table string
	Chain string
}

func (n NFTables) Allow(ctx context.Context, rule Rule) error {
	return n.run(ctx, "add", "rule", n.Table, n.Chain, "ip", "saddr", rule.SourceIP, rule.Protocol, "dport", fmt.Sprint(rule.Port), "accept")
}

func (n NFTables) Deny(ctx context.Context, rule Rule) error {
	return n.run(ctx, "add", "rule", n.Table, n.Chain, "ip", "saddr", rule.SourceIP, rule.Protocol, "dport", fmt.Sprint(rule.Port), "drop")
}

func (n NFTables) List(ctx context.Context) ([]Rule, error) {
	// Listing/parsing nft JSON will be implemented once the target ruleset
	// contract is defined. Do not infer access state from knockd.conf.
	return nil, nil
}

func (n NFTables) run(ctx context.Context, args ...string) error {
	if n.Table == "" || n.Chain == "" {
		return fmt.Errorf("nftables table and chain are required")
	}
	cmd := exec.CommandContext(ctx, "nft", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft %v: %w: %s", args, err, output)
	}
	return nil
}
