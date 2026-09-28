package alert

import "time"

const (
	SeverityLow    = "LOW"
	SeverityMedium = "MEDIUM"
	SeverityHigh   = "HIGH"
)

const (
	TypePortScanIndicator         = "PORT_SCAN_INDICATOR"
	TypeHostScanIndicator         = "HOST_SCAN_INDICATOR"
	TypeSynFloodIndicator         = "SYN_FLOOD_INDICATOR"
	TypeAckFloodIndicator         = "ACK_FLOOD_INDICATOR"
	TypeUdpFloodIndicator         = "UDP_FLOOD_INDICATOR"
	TypeRstFloodIndicator         = "RST_FLOOD_INDICATOR"
	TypeIcmpFloodIndicator        = "ICMP_FLOOD_INDICATOR"
	TypePingSweepIndicator        = "PING_SWEEP_INDICATOR"
	TypeDnsAmplificationIndicator = "DNS_AMPLIFICATION_INDICATOR"
	TypeNullScanIndicator         = "NULL_SCAN_INDICATOR"
	TypeXmasScanIndicator         = "XMAS_SCAN_INDICATOR"
	TypeFinScanIndicator          = "FIN_SCAN_INDICATOR"
	TypeConnectionBurstIndicator  = "CONNECTION_BURST_INDICATOR"
	TypeSuspiciousTCPFlags        = "SUSPICIOUS_TCP_FLAGS"
)

type Alert struct {
	Timestamp          time.Time              `json:"timestamp"`
	WindowIndex        int                    `json:"window_index"`
	WindowStart        time.Time              `json:"window_start"`
	WindowEnd          time.Time              `json:"window_end"`
	Type               string                 `json:"type"`
	Severity           string                 `json:"severity"`
	MitreAttackID      string                 `json:"mitre_attack_id,omitempty"`
	MitreTactic        string                 `json:"mitre_tactic,omitempty"`
	MitreTechniqueName string                 `json:"mitre_technique_name,omitempty"`
	SourceIP           string                 `json:"source_ip,omitempty"`
	DestinationIP      string                 `json:"destination_ip,omitempty"`
	Protocol           string                 `json:"protocol,omitempty"`
	Reason             string                 `json:"reason"`
	Features           map[string]interface{} `json:"features,omitempty"`
}
