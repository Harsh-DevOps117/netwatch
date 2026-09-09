package rules

import (
	"fmt"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

type PortScanRule struct {
	cfg config.PortScanConfig
}

func NewPortScanRule(cfg config.PortScanConfig) *PortScanRule {
	return &PortScanRule{cfg: cfg}
}

func (r *PortScanRule) Name() string {
	return alert.TypePortScanIndicator
}

func (r *PortScanRule) Evaluate(feat *features.WindowFeatures) []alert.Alert {
	if feat == nil || !r.cfg.Enabled {
		return nil
	}

	var alerts []alert.Alert
	for srcIP, dstPorts := range feat.SrcIPToDstPorts {
		uniquePortsCount := len(dstPorts)
		if uniquePortsCount >= r.cfg.UniquePorts {
			alerts = append(alerts, alert.Alert{
				Timestamp:   time.Now(),
				WindowStart: feat.WindowStart,
				WindowEnd:   feat.WindowEnd,
				Type:        alert.TypePortScanIndicator,
				Severity:    alert.SeverityHigh,
				SourceIP:    srcIP,
				Protocol:    "TCP/UDP",
				Reason: fmt.Sprintf(
					"One source contacted an unusually large number of destination ports (%d unique ports in %.0fs window).",
					uniquePortsCount, feat.DurationSeconds,
				),
				Features: map[string]interface{}{
					"unique_destination_ports": uniquePortsCount,
					"threshold":                r.cfg.UniquePorts,
					"duration_seconds":         feat.DurationSeconds,
				},
			})
		}
	}

	return alerts
}
