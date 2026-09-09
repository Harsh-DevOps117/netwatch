package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type SuspiciousFlagsRule struct {
	cfg config.SuspiciousFlagsConfig
}

func NewSuspiciousFlagsRule(cfg config.SuspiciousFlagsConfig) *SuspiciousFlagsRule {
	return &SuspiciousFlagsRule{cfg: cfg}
}

func (r *SuspiciousFlagsRule) Name() string {
	return alert.TypeSuspiciousTCPFlags
}

func (r *SuspiciousFlagsRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled || len(feat.SuspiciousFlagPackets) == 0 {
		return nil
	}

	var alerts []alert.Alert
	flagCounts := make(map[string]int)
	for _, rec := range feat.SuspiciousFlagPackets {
		flagCounts[rec.Flags]++
	}

	for flagCombo, count := range flagCounts {
		alerts = append(alerts, alert.Alert{
			Timestamp:   time.Now(),
			WindowStart: feat.WindowStart,
			WindowEnd:   feat.WindowEnd,
			Type:        alert.TypeSuspiciousTCPFlags,
			Severity:    alert.SeverityMedium,
			Protocol:    "TCP",
			Reason: fmt.Sprintf(
				"Unusual TCP flag combination observed (%s detected in %d packet(s)).",
				flagCombo, count,
			),
			Features: map[string]interface{}{
				"flag_combination": flagCombo,
				"packet_count":     count,
				"duration_seconds": feat.DurationSeconds,
			},
		})
	}

	return alerts
}
