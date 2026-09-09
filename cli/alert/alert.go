package alert

import "time"

const (
	SeverityLow    = "LOW"
	SeverityMedium = "MEDIUM"
	SeverityHigh   = "HIGH"
)

const (
	TypePortScanIndicator        = "PORT_SCAN_INDICATOR"
	TypeHostScanIndicator        = "HOST_SCAN_INDICATOR"
	TypeSynFloodIndicator        = "SYN_FLOOD_INDICATOR"
	TypeAckFloodIndicator        = "ACK_FLOOD_INDICATOR"
	TypeUdpFloodIndicator        = "UDP_FLOOD_INDICATOR"
	TypeConnectionBurstIndicator = "CONNECTION_BURST_INDICATOR"
	TypeSuspiciousTCPFlags       = "SUSPICIOUS_TCP_FLAGS"
)

type Alert struct {
	Timestamp     time.Time              `json:"timestamp"`
	WindowStart   time.Time              `json:"window_start"`
	WindowEnd     time.Time              `json:"window_end"`
	Type          string                 `json:"type"`
	Severity      string                 `json:"severity"`
	SourceIP      string                 `json:"source_ip,omitempty"`
	DestinationIP string                 `json:"destination_ip,omitempty"`
	Protocol      string                 `json:"protocol,omitempty"`
	Reason        string                 `json:"reason"`
	Features      map[string]interface{} `json:"features,omitempty"`
}
