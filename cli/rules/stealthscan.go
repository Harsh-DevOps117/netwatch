package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type StealthScanRule struct {
	cfg config.StealthScanConfig
}

func NewStealthScanRule(cfg config.StealthScanConfig) *StealthScanRule {
	return &StealthScanRule{cfg: cfg}
}

func (r *StealthScanRule) Name() string {
	return "STEALTH_SCAN_INDICATOR"
}

func (r *StealthScanRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled {
		return nil
	}

	var alerts []alert.Alert
	minPackets := r.cfg.MinPackets
	if minPackets <= 0 {
		minPackets = 1
	}

	// 1. NULL Scan Evaluation (No TCP flags set)
	if len(feat.NullScanPackets) >= minPackets {
		alerts = append(alerts, alert.Alert{
			Timestamp:          time.Now(),
			WindowIndex:        feat.WindowIndex,
			WindowStart:        feat.WindowStart,
			WindowEnd:          feat.WindowEnd,
			Type:               alert.TypeNullScanIndicator,
			Severity:           alert.SeverityHigh,
			MitreAttackID:      "T1046",
			MitreTactic:        "Discovery",
			MitreTechniqueName: "Network Service Discovery (Stealth NULL Scan)",
			Protocol:           "TCP",
			Reason: fmt.Sprintf(
				"Stealth TCP NULL scan detected (%d packet(s) with 0 TCP control flags set). Commonly used to evade simple packet filters.",
				len(feat.NullScanPackets),
			),
			Features: map[string]interface{}{
				"packet_count":     len(feat.NullScanPackets),
				"duration_seconds": feat.DurationSeconds,
			},
		})
	}

	// 2. XMAS Scan Evaluation (FIN+PSH+URG set)
	if len(feat.XmasScanPackets) >= minPackets {
		alerts = append(alerts, alert.Alert{
			Timestamp:          time.Now(),
			WindowIndex:        feat.WindowIndex,
			WindowStart:        feat.WindowStart,
			WindowEnd:          feat.WindowEnd,
			Type:               alert.TypeXmasScanIndicator,
			Severity:           alert.SeverityHigh,
			MitreAttackID:      "T1046",
			MitreTactic:        "Discovery",
			MitreTechniqueName: "Network Service Discovery (Stealth XMAS Scan)",
			Protocol:           "TCP",
			Reason: fmt.Sprintf(
				"Stealth TCP XMAS scan detected (%d packet(s) with FIN+PSH+URG flags set). Used for firewall probing and OS fingerprinting.",
				len(feat.XmasScanPackets),
			),
			Features: map[string]interface{}{
				"packet_count":     len(feat.XmasScanPackets),
				"duration_seconds": feat.DurationSeconds,
			},
		})
	}

	// 3. FIN Scan Evaluation (FIN flag only without established connection)
	if len(feat.FinScanPackets) >= minPackets {
		alerts = append(alerts, alert.Alert{
			Timestamp:          time.Now(),
			WindowIndex:        feat.WindowIndex,
			WindowStart:        feat.WindowStart,
			WindowEnd:          feat.WindowEnd,
			Type:               alert.TypeFinScanIndicator,
			Severity:           alert.SeverityMedium,
			MitreAttackID:      "T1046",
			MitreTactic:        "Discovery",
			MitreTechniqueName: "Network Service Discovery (Stealth FIN Scan)",
			Protocol:           "TCP",
			Reason: fmt.Sprintf(
				"Stealth TCP FIN scan pattern detected (%d isolated FIN packet(s) without ACK). Used to bypass SYN packet filters.",
				len(feat.FinScanPackets),
			),
			Features: map[string]interface{}{
				"packet_count":     len(feat.FinScanPackets),
				"duration_seconds": feat.DurationSeconds,
			},
		})
	}

	return alerts
}
