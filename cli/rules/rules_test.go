package rules

import (
	"testing"
	"time"

	"detector/alert"
	"detector/config"
	"detector/features"
)

func newTestWindowFeatures() *features.WindowFeatures {
	now := time.Now()
	return &features.WindowFeatures{
		WindowStart:            now,
		WindowEnd:              now.Add(10 * time.Second),
		DurationSeconds:        10.0,
		TotalPackets:           100,
		TotalBytes:             15000,
		PacketsPerSecond:       10.0,
		BytesPerSecond:         1500.0,
		UniqueSourceIPs:        2,
		UniqueDestinationIPs:   3,
		UniqueSourcePorts:      10,
		UniqueDestinationPorts: 5,
		TCPPackets:             80,
		SYNCount:               10,
		SYNACKCount:            10,
		ACKCount:               60,
		RSTCount:               0,
		FINCount:               2,
		PSHCount:               5,
		SYNPerSecond:           1.0,
		ACKPerSecond:           6.0,
		SYNAckRatio:            1.0,
		UDPPackets:             20,
		UDPBytes:               3000,
		UDPPacketsPerSecond:    2.0,
		UDPBytesPerSecond:      300.0,
		SrcIPToDstPorts: map[string]map[uint16]int{
			"192.168.1.50": {80: 20, 443: 30},
		},
		SrcIPToDstIPs: map[string]map[string]int{
			"192.168.1.50": {"1.1.1.1": 25, "8.8.8.8": 25},
		},
		SuspiciousFlagPackets: []features.SuspiciousFlagRecord{},
	}
}

func TestPortScanTriggersAboveThreshold(t *testing.T) {
	rule := NewPortScanRule(config.PortScanConfig{Enabled: true, UniquePorts: 20})
	feat := newTestWindowFeatures()

	portsMap := make(map[uint16]int)
	for p := uint16(1); p <= 25; p++ {
		portsMap[p] = 1
	}
	feat.SrcIPToDstPorts["192.168.1.100"] = portsMap

	alerts := rule.Evaluate(feat)
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Type != alert.TypePortScanIndicator {
		t.Errorf("Expected type %s, got %s", alert.TypePortScanIndicator, alerts[0].Type)
	}
	if alerts[0].SourceIP != "192.168.1.100" {
		t.Errorf("Expected source IP 192.168.1.100, got %s", alerts[0].SourceIP)
	}
}

func TestPortScanDoesNotTriggerBelowThreshold(t *testing.T) {
	rule := NewPortScanRule(config.PortScanConfig{Enabled: true, UniquePorts: 20})
	feat := newTestWindowFeatures()

	portsMap := make(map[uint16]int)
	for p := uint16(1); p <= 5; p++ {
		portsMap[p] = 1
	}
	feat.SrcIPToDstPorts["192.168.1.100"] = portsMap

	alerts := rule.Evaluate(feat)
	if len(alerts) != 0 {
		t.Errorf("Expected 0 alerts for below threshold, got %d", len(alerts))
	}
}

func TestSynFloodTriggersOnHighRate(t *testing.T) {
	rule := NewSynFloodRule(config.SynFloodConfig{
		Enabled:      true,
		SynPerSecond: 500,
		SynAckRatio:  5.0,
		MinSynCount:  50,
	})
	feat := newTestWindowFeatures()
	feat.SYNCount = 6000
	feat.SYNPerSecond = 600.0
	feat.SYNACKCount = 1000
	feat.SYNAckRatio = 6.0

	alerts := rule.Evaluate(feat)
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 SYN flood alert, got %d", len(alerts))
	}
	if alerts[0].Type != alert.TypeSynFloodIndicator {
		t.Errorf("Expected type %s, got %s", alert.TypeSynFloodIndicator, alerts[0].Type)
	}
}

func TestSynFloodTriggersOnAbnormalRatio(t *testing.T) {
	rule := NewSynFloodRule(config.SynFloodConfig{
		Enabled:      true,
		SynPerSecond: 500,
		SynAckRatio:  5.0,
		MinSynCount:  50,
	})
	feat := newTestWindowFeatures()
	feat.SYNCount = 200
	feat.SYNACKCount = 2
	feat.SYNPerSecond = 20.0
	feat.SYNAckRatio = 100.0

	alerts := rule.Evaluate(feat)
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 SYN flood alert on high ratio, got %d", len(alerts))
	}
	if alerts[0].Type != alert.TypeSynFloodIndicator {
		t.Errorf("Expected alert type %s, got %s", alert.TypeSynFloodIndicator, alerts[0].Type)
	}
}

func TestAckFloodTriggersAboveThreshold(t *testing.T) {
	rule := NewAckFloodRule(config.AckFloodConfig{Enabled: true, AckPerSecond: 1000})
	feat := newTestWindowFeatures()
	feat.ACKCount = 15000
	feat.ACKPerSecond = 1500.0

	alerts := rule.Evaluate(feat)
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 ACK flood alert, got %d", len(alerts))
	}
	if alerts[0].Type != alert.TypeAckFloodIndicator {
		t.Errorf("Expected type %s, got %s", alert.TypeAckFloodIndicator, alerts[0].Type)
	}
}

func TestUdpFloodTriggersAboveThreshold(t *testing.T) {
	rule := NewUdpFloodRule(config.UdpFloodConfig{Enabled: true, UdpPacketsPerSecond: 1000})
	feat := newTestWindowFeatures()
	feat.UDPPackets = 12000
	feat.UDPPacketsPerSecond = 1200.0

	alerts := rule.Evaluate(feat)
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 UDP flood alert, got %d", len(alerts))
	}
	if alerts[0].Type != alert.TypeUdpFloodIndicator {
		t.Errorf("Expected type %s, got %s", alert.TypeUdpFloodIndicator, alerts[0].Type)
	}
}

func TestHostScanTriggersAboveThreshold(t *testing.T) {
	rule := NewHostScanRule(config.HostScanConfig{Enabled: true, UniqueHosts: 20})
	feat := newTestWindowFeatures()

	hostsMap := make(map[string]int)
	for i := 1; i <= 30; i++ {
		hostsMap[time.Now().String()+string(rune(i))] = 1
	}
	feat.SrcIPToDstIPs["10.0.0.5"] = hostsMap

	alerts := rule.Evaluate(feat)
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 host scan alert, got %d", len(alerts))
	}
	if alerts[0].Type != alert.TypeHostScanIndicator {
		t.Errorf("Expected type %s, got %s", alert.TypeHostScanIndicator, alerts[0].Type)
	}
	if alerts[0].SourceIP != "10.0.0.5" {
		t.Errorf("Expected source IP 10.0.0.5, got %s", alerts[0].SourceIP)
	}
}

func TestSuspiciousTCPFlagsTrigger(t *testing.T) {
	rule := NewSuspiciousFlagsRule(config.SuspiciousFlagsConfig{Enabled: true})
	feat := newTestWindowFeatures()
	feat.SuspiciousFlagPackets = []features.SuspiciousFlagRecord{
		{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.15",
			DstIP:     "192.168.1.1",
			SrcPort:   50000,
			DstPort:   80,
			Flags:     "SYN+FIN",
		},
	}

	alerts := rule.Evaluate(feat)
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 suspicious flag alert, got %d", len(alerts))
	}
	if alerts[0].Type != alert.TypeSuspiciousTCPFlags {
		t.Errorf("Expected type %s, got %s", alert.TypeSuspiciousTCPFlags, alerts[0].Type)
	}
}

func TestNormalTrafficProducesZeroAlerts(t *testing.T) {
	cfg := config.DefaultConfig()
	engine := NewEngine(cfg)
	normalFeat := newTestWindowFeatures()

	alerts := engine.Evaluate(normalFeat)
	if len(alerts) != 0 {
		t.Errorf("Expected 0 alerts on normal baseline traffic, got %d: %+v", len(alerts), alerts)
	}
}
