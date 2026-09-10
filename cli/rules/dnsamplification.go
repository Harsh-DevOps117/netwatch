package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type DnsAmplificationRule struct {
	cfg config.DnsFloodConfig
}

func NewDnsAmplificationRule(cfg config.DnsFloodConfig) *DnsAmplificationRule {
	return &DnsAmplificationRule{cfg: cfg}
}

func (r *DnsAmplificationRule) Name() string {
	return alert.TypeDnsAmplificationIndicator
}

func (r *DnsAmplificationRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled {
		return nil
	}

	rateBreached := feat.DNSPacketsPerSecond >= r.cfg.DnsPacketsPerSecond && r.cfg.DnsPacketsPerSecond > 0
	byteBreached := feat.DNSBytesPerSecond >= r.cfg.DnsBytesPerSecond && r.cfg.DnsBytesPerSecond > 0

	if rateBreached || byteBreached {
		return []alert.Alert{
			{
				Timestamp:   time.Now(),
				WindowStart: feat.WindowStart,
				WindowEnd:   feat.WindowEnd,
				Type:        alert.TypeDnsAmplificationIndicator,
				Severity:    alert.SeverityHigh,
				Protocol:    "UDP/DNS",
				Reason: fmt.Sprintf(
					"Unusually high DNS traffic detected (%.1f pkts/sec, %.1f KB/sec). Potential DNS Amplification or Flood attack.",
					feat.DNSPacketsPerSecond, feat.DNSBytesPerSecond/1024.0,
				),
				Features: map[string]interface{}{
					"dns_rate":          feat.DNSPacketsPerSecond,
					"dns_bytes_per_sec": feat.DNSBytesPerSecond,
					"dns_count":         feat.DNSPackets,
					"duration_seconds":  feat.DurationSeconds,
				},
			},
		}
	}

	return nil
}
