package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type AckFloodRule struct {
	cfg config.AckFloodConfig
}

func NewAckFloodRule(cfg config.AckFloodConfig) *AckFloodRule {
	return &AckFloodRule{cfg: cfg}
}

func (r *AckFloodRule) Name() string {
	return alert.TypeAckFloodIndicator
}

func (r *AckFloodRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled {
		return nil
	}

	if feat.ACKPerSecond >= r.cfg.AckPerSecond && r.cfg.AckPerSecond > 0 {
		return []alert.Alert{
			{
				Timestamp:          time.Now(),
				WindowIndex:        feat.WindowIndex,
				WindowStart:        feat.WindowStart,
				WindowEnd:          feat.WindowEnd,
				Type:               alert.TypeAckFloodIndicator,
				Severity:           alert.SeverityHigh,
				MitreAttackID:      "T1498.001",
				MitreTactic:        "Impact",
				MitreTechniqueName: "Direct Network Flood (ACK Flood)",
				Protocol:           "TCP",
				Reason: fmt.Sprintf(
					"Abnormal TCP ACK traffic rate (%.1f/sec exceeds threshold %.1f/sec).",
					feat.ACKPerSecond, r.cfg.AckPerSecond,
				),
				Features: map[string]interface{}{
					"ack_rate":         feat.ACKPerSecond,
					"ack_count":        feat.ACKCount,
					"threshold":        r.cfg.AckPerSecond,
					"duration_seconds": feat.DurationSeconds,
				},
			},
		}
	}

	return nil
}
