package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type UdpFloodRule struct {
	cfg config.UdpFloodConfig
}

func NewUdpFloodRule(cfg config.UdpFloodConfig) *UdpFloodRule {
	return &UdpFloodRule{cfg: cfg}
}

func (r *UdpFloodRule) Name() string {
	return alert.TypeUdpFloodIndicator
}

func (r *UdpFloodRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled {
		return nil
	}

	if feat.UDPPacketsPerSecond >= r.cfg.UdpPacketsPerSecond && r.cfg.UdpPacketsPerSecond > 0 {
		return []alert.Alert{
			{
				Timestamp:          time.Now(),
				WindowIndex:        feat.WindowIndex,
				WindowStart:        feat.WindowStart,
				WindowEnd:          feat.WindowEnd,
				Type:               alert.TypeUdpFloodIndicator,
				Severity:           alert.SeverityHigh,
				MitreAttackID:      "T1498.001",
				MitreTactic:        "Impact",
				MitreTechniqueName: "Direct Network Flood (UDP Flood)",
				Protocol:           "UDP",
				Reason: fmt.Sprintf(
					"Unusually high UDP packet rate (%.1f/sec exceeds threshold %.1f/sec).",
					feat.UDPPacketsPerSecond, r.cfg.UdpPacketsPerSecond,
				),
				Features: map[string]interface{}{
					"udp_rate":         feat.UDPPacketsPerSecond,
					"udp_count":        feat.UDPPackets,
					"udp_bytes":        feat.UDPBytes,
					"threshold":        r.cfg.UdpPacketsPerSecond,
					"duration_seconds": feat.DurationSeconds,
				},
			},
		}
	}

	return nil
}
