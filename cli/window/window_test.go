package window

import (
	"net"
	"testing"
	"time"

	"detector/features"
	"detector/parser"
)

func TestWindowManager10SecondWindows(t *testing.T) {
	var closedWindows []*features.WindowFeatures
	mgr := NewManager(10*time.Second, func(feat *features.WindowFeatures) {
		closedWindows = append(closedWindows, feat)
	})

	baseTime := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		mgr.ProcessPacket(&parser.ParsedPacket{
			Timestamp: baseTime.Add(time.Duration(i*2) * time.Second),
			Length:    100,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("8.8.8.8"),
			Protocol:  "TCP",
		})
	}

	mgr.ProcessPacket(&parser.ParsedPacket{
		Timestamp: baseTime.Add(12 * time.Second),
		Length:    200,
		SrcIP:     net.ParseIP("192.168.1.10"),
		DstIP:     net.ParseIP("8.8.8.8"),
		Protocol:  "TCP",
	})

	if len(closedWindows) != 1 {
		t.Fatalf("Expected 1 window closed, got %d", len(closedWindows))
	}
	if closedWindows[0].TotalPackets != 5 {
		t.Errorf("Expected 5 packets in window 1, got %d", closedWindows[0].TotalPackets)
	}

	mgr.Flush()

	if len(closedWindows) != 2 {
		t.Fatalf("Expected 2 windows closed after flush, got %d", len(closedWindows))
	}
	if closedWindows[1].TotalPackets != 1 {
		t.Errorf("Expected 1 packet in window 2, got %d", closedWindows[1].TotalPackets)
	}
}
