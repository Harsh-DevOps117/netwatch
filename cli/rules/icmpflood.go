package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type IcmpFloodRule struct {
	cfg config.IcmpFloodConfig
}

func NewIcmpFloodRule(cfg config.IcmpFloodConfig) *IcmpFloodRule {
	return &IcmpFloodRule{cfg: cfg}
}

func (r *IcmpFloodRule) Name() string {
	return alert.TypeIcmpFloodIndicator
}

func (r *IcmpFloodRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled {
		return nil
	}

	var alerts []alert.Alert

	// 1. Volumetric ICMP Flood Evaluation
	if feat.ICMPPacketsPerSecond >= r.cfg.IcmpPerSecond && r.cfg.IcmpPerSecond > 0 {
		alerts = append(alerts, alert.Alert{
			Timestamp:          time.Now(),
			WindowIndex:        feat.WindowIndex,
			WindowStart:        feat.WindowStart,
			WindowEnd:          feat.WindowEnd,
			Type:               alert.TypeIcmpFloodIndicator,
			Severity:           alert.SeverityHigh,
			MitreAttackID:      "T1498.001",
			MitreTactic:        "Impact",
			MitreTechniqueName: "Direct Network Flood (ICMP Flood)",
			Protocol:           "ICMP",
			Reason: fmt.Sprintf(
				"Excessive ICMP packet rate detected (%.1f pkts/sec exceeds threshold %.1f pkts/sec). Possible ICMP/Ping Flood attack.",
				feat.ICMPPacketsPerSecond, r.cfg.IcmpPerSecond,
			),
			Features: map[string]interface{}{
				"icmp_rate":        feat.ICMPPacketsPerSecond,
				"icmp_count":       feat.ICMPPackets,
				"icmp_bytes":       feat.ICMPBytes,
				"threshold":        r.cfg.IcmpPerSecond,
				"duration_seconds": feat.DurationSeconds,
			},
		})
	}

	// 2. Ping Sweep / Reconnaissance Evaluation
	if r.cfg.PingSweepEnabled {
		for srcIP, targetHosts := range feat.SrcIPToICMPEcho {
			uniqueTargetsCount := len(targetHosts)
			if uniqueTargetsCount >= r.cfg.UniqueTargets && r.cfg.UniqueTargets > 0 {
				alerts = append(alerts, alert.Alert{
					Timestamp:          time.Now(),
					WindowIndex:        feat.WindowIndex,
					WindowStart:        feat.WindowStart,
					WindowEnd:          feat.WindowEnd,
					Type:               alert.TypePingSweepIndicator,
					Severity:           alert.SeverityHigh,
					MitreAttackID:      "T1595.001",
					MitreTactic:        "Reconnaissance",
					MitreTechniqueName: "Active Scanning: IP Network Scanning",
					SourceIP:           srcIP,
					Protocol:           "ICMP",
					Reason: fmt.Sprintf(
						"Reconnaissance ping sweep observed: host probed %d unique destination IPs via ICMP Echo within %.0fs window.",
						uniqueTargetsCount, feat.DurationSeconds,
					),
					Features: map[string]interface{}{
						"unique_targets":   uniqueTargetsCount,
						"threshold":        r.cfg.UniqueTargets,
						"duration_seconds": feat.DurationSeconds,
					},
				})
			}
		}
	}

	return alerts
}
