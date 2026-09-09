package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type SynFloodRule struct {
	cfg config.SynFloodConfig
}

func NewSynFloodRule(cfg config.SynFloodConfig) *SynFloodRule {
	return &SynFloodRule{cfg: cfg}
}

func (r *SynFloodRule) Name() string {
	return alert.TypeSynFloodIndicator
}

func (r *SynFloodRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled {
		return nil
	}

	highRate := feat.SYNPerSecond >= r.cfg.SynPerSecond && r.cfg.SynPerSecond > 0
	highRatio := feat.SYNCount >= r.cfg.MinSynCount && feat.SYNAckRatio >= r.cfg.SynAckRatio && r.cfg.SynAckRatio > 0

	if highRate || highRatio {
		var reason string
		if highRate && highRatio {
			reason = fmt.Sprintf(
				"High SYN rate (%.1f/sec) combined with abnormal SYN/SYN-ACK ratio (%.1f).",
				feat.SYNPerSecond, feat.SYNAckRatio,
			)
		} else if highRate {
			reason = fmt.Sprintf(
				"Excessive TCP SYN packet rate (%.1f/sec exceeds threshold %.1f/sec).",
				feat.SYNPerSecond, r.cfg.SynPerSecond,
			)
		} else {
			reason = fmt.Sprintf(
				"Abnormal SYN/SYN-ACK ratio (%.1f with %d SYNs and %d SYN-ACKs).",
				feat.SYNAckRatio, feat.SYNCount, feat.SYNACKCount,
			)
		}

		return []alert.Alert{
			{
				Timestamp:   time.Now(),
				WindowStart: feat.WindowStart,
				WindowEnd:   feat.WindowEnd,
				Type:        alert.TypeSynFloodIndicator,
				Severity:    alert.SeverityHigh,
				Protocol:    "TCP",
				Reason:      reason,
				Features: map[string]interface{}{
					"syn_rate":          feat.SYNPerSecond,
					"syn_count":         feat.SYNCount,
					"syn_ack_count":     feat.SYNACKCount,
					"syn_ack_ratio":     feat.SYNAckRatio,
					"incomplete_conns":  feat.ApproxIncompleteConnections,
					"duration_seconds":  feat.DurationSeconds,
				},
			},
		}
	}

	return nil
}
