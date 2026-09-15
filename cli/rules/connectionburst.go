package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type ConnectionBurstRule struct {
	cfg config.ConnectionBurstConfig
}

func NewConnectionBurstRule(cfg config.ConnectionBurstConfig) *ConnectionBurstRule {
	return &ConnectionBurstRule{cfg: cfg}
}

func (r *ConnectionBurstRule) Name() string {
	return alert.TypeConnectionBurstIndicator
}

func (r *ConnectionBurstRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled {
		return nil
	}

	if feat.SYNPerSecond >= r.cfg.SynPerSecond && r.cfg.SynPerSecond > 0 {
		return []alert.Alert{
			{
				Timestamp:          time.Now(),
				WindowIndex:        feat.WindowIndex,
				WindowStart:        feat.WindowStart,
				WindowEnd:          feat.WindowEnd,
				Type:               alert.TypeConnectionBurstIndicator,
				Severity:           alert.SeverityMedium,
				MitreAttackID:      "T1071",
				MitreTactic:        "Command and Control",
				MitreTechniqueName: "Application Layer Protocol: Connection Spike",
				Protocol:           "TCP",
				Reason: fmt.Sprintf(
					"Unusually high number of new TCP connection attempts (%.1f SYN/sec in window).",
					feat.SYNPerSecond,
				),
				Features: map[string]interface{}{
					"syn_rate":         feat.SYNPerSecond,
					"syn_count":        feat.SYNCount,
					"threshold":        r.cfg.SynPerSecond,
					"duration_seconds": feat.DurationSeconds,
				},
			},
		}
	}

	return nil
}
