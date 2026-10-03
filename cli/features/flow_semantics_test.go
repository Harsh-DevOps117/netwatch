package features

import (
	"net"
	"testing"
	"time"

	"detector/parser"
	"detector/semantics"
)

func TestReverseFlowNeedsConnectionEvidence(t *testing.T) {
	tracker := NewFlowTracker(time.Minute, 10)
	client := net.ParseIP("10.4.4.120")
	server := net.ParseIP("8.8.8.8")
	first := &parser.ParsedPacket{Timestamp: time.Unix(1, 0), HasIP: true, SrcIP: client, DstIP: server, SrcPort: 64912, DstPort: 443, Protocol: "TCP", TCPFlags: parser.TCPFlags{SYN: true}}
	first.Tags = semantics.Classify(semantics.Observation{Transport: "TCP", SrcIP: client.String(), DstIP: server.String(), SrcPort: 64912, DstPort: 443})
	tracker.ProcessPacket(first)
	if first.ConnectionRole != "OUTBOUND_CLIENT" {
		t.Fatalf("request role: %+v", first.Tags)
	}
	uncorroborated := &parser.ParsedPacket{Timestamp: time.Unix(2, 0), HasIP: true, SrcIP: server, DstIP: client, SrcPort: 443, DstPort: 64912, Protocol: "TCP", TCPFlags: parser.TCPFlags{ACK: true}}
	tracker.ProcessPacket(uncorroborated)
	if uncorroborated.TrafficClass == "RESPONSE_TRAFFIC" {
		t.Fatalf("unestablished reverse traffic: %+v", uncorroborated.Tags)
	}
	handshake := &parser.ParsedPacket{Timestamp: time.Unix(3, 0), HasIP: true, SrcIP: server, DstIP: client, SrcPort: 443, DstPort: 64912, Protocol: "TCP", TCPFlags: parser.TCPFlags{SYN: true, ACK: true}}
	tracker.ProcessPacket(handshake)
	response := &parser.ParsedPacket{Timestamp: time.Unix(4, 0), HasIP: true, SrcIP: server, DstIP: client, SrcPort: 443, DstPort: 64912, Protocol: "TCP", TCPFlags: parser.TCPFlags{ACK: true}}
	tracker.ProcessPacket(response)
	if response.ProtocolTag != "HTTPS" || response.TrafficClass != "RESPONSE_TRAFFIC" || response.ConnectionRole != "SERVER_RESPONSE" {
		t.Fatalf("established reverse traffic: %+v", response.Tags)
	}
}
