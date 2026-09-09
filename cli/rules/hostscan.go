package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type HostScanRule struct {
	cfg config.HostScanConfig
}

func NewHostScanRule(cfg config.HostScanConfig) *HostScanRule {
	return &HostScanRule{cfg: cfg}
}

func (r *HostScanRule) Name() string {
	return alert.TypeHostScanIndicator
}

func (r *HostScanRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled {
		return nil
	}

	var alerts []alert.Alert
	for srcIP, dstIPs := range feat.SrcIPToDstIPs {
		uniqueHostsCount := len(dstIPs)
		if uniqueHostsCount >= r.cfg.UniqueHosts {
			alerts = append(alerts, alert.Alert{
				Timestamp:   time.Now(),
				WindowStart: feat.WindowStart,
				WindowEnd:   feat.WindowEnd,
				Type:        alert.TypeHostScanIndicator,
				Severity:    alert.SeverityHigh,
				SourceIP:    srcIP,
				Protocol:    "IP",
				Reason: fmt.Sprintf(
					"One source contacted an unusually large number of destination hosts (%d unique hosts in %.0fs window).",
					uniqueHostsCount, feat.DurationSeconds,
				),
				Features: map[string]interface{}{
					"unique_destination_hosts": uniqueHostsCount,
					"threshold":                r.cfg.UniqueHosts,
					"duration_seconds":         feat.DurationSeconds,
				},
			})
		}
	}

	return alerts
}
