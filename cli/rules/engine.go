package rules

import (
	"detector/alert"
	"detector/config"
	"detector/features"
)

type Rule interface {
	Name() string
	Evaluate(feat *features.WindowFeatures) []alert.Alert
}

type Engine struct {
	rules []Rule
}

func NewEngine(cfg *config.Config) *Engine {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	var activeRules []Rule

	if cfg.Rules.PortScan.Enabled {
		activeRules = append(activeRules, NewPortScanRule(cfg.Rules.PortScan))
	}
	if cfg.Rules.HostScan.Enabled {
		activeRules = append(activeRules, NewHostScanRule(cfg.Rules.HostScan))
	}
	if cfg.Rules.SynFlood.Enabled {
		activeRules = append(activeRules, NewSynFloodRule(cfg.Rules.SynFlood))
	}
	if cfg.Rules.AckFlood.Enabled {
		activeRules = append(activeRules, NewAckFloodRule(cfg.Rules.AckFlood))
	}
	if cfg.Rules.RstFlood.Enabled {
		activeRules = append(activeRules, NewRstFloodRule(cfg.Rules.RstFlood))
	}
	if cfg.Rules.UdpFlood.Enabled {
		activeRules = append(activeRules, NewUdpFloodRule(cfg.Rules.UdpFlood))
	}
	if cfg.Rules.IcmpFlood.Enabled {
		activeRules = append(activeRules, NewIcmpFloodRule(cfg.Rules.IcmpFlood))
	}
	if cfg.Rules.DnsFlood.Enabled {
		activeRules = append(activeRules, NewDnsAmplificationRule(cfg.Rules.DnsFlood))
	}
	if cfg.Rules.StealthScan.Enabled {
		activeRules = append(activeRules, NewStealthScanRule(cfg.Rules.StealthScan))
	}
	if cfg.Rules.ConnectionBurst.Enabled {
		activeRules = append(activeRules, NewConnectionBurstRule(cfg.Rules.ConnectionBurst))
	}
	if cfg.Rules.SuspiciousFlags.Enabled {
		activeRules = append(activeRules, NewSuspiciousFlagsRule(cfg.Rules.SuspiciousFlags))
	}

	return &Engine{rules: activeRules}
}

func (e *Engine) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil {
		return nil
	}

	var alerts []alert.Alert
	for _, rule := range e.rules {
		res := rule.Evaluate(feat)
		if len(res) > 0 {
			alerts = append(alerts, res...)
		}
	}
	return alerts
}

