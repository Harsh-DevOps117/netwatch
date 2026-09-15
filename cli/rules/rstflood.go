package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type RstFloodRule struct {
	cfg config.RstFloodConfig
}

func NewRstFloodRule(cfg config.RstFloodConfig) *RstFloodRule {
	return &RstFloodRule{cfg: cfg}
}

func (r *RstFloodRule) Name() string {
	return alert.TypeRstFloodIndicator
}

func (r *RstFloodRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled {
		return nil
	}

	if feat.RSTPerSecond >= r.cfg.RstPerSecond && r.cfg.RstPerSecond > 0 {
		return []alert.Alert{
			{
				Timestamp:          time.Now(),
				WindowIndex:        feat.WindowIndex,
				WindowStart:        feat.WindowStart,
				WindowEnd:          feat.WindowEnd,
				Type:               alert.TypeRstFloodIndicator,
				Severity:           alert.SeverityHigh,
				MitreAttackID:      "T1499",
				MitreTactic:        "Impact",
				MitreTechniqueName: "Endpoint Denial of Service: Connection Teardown",
				Protocol:           "TCP",
				Reason: fmt.Sprintf(
					"Abnormal TCP RST packet rate detected (%.1f/sec exceeds threshold %.1f/sec). Possible connection teardown attack.",
					feat.RSTPerSecond, r.cfg.RstPerSecond,
				),
				Features: map[string]interface{}{
					"rst_rate":         feat.RSTPerSecond,
					"rst_count":        feat.RSTCount,
					"threshold":        r.cfg.RstPerSecond,
					"duration_seconds": feat.DurationSeconds,
				},
			},
		}
	}

	return nil
}
