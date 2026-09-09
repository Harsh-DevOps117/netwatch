package parser

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseIPv4TCPPacket(t *testing.T) {
	ipLayer := &layers.IPv4{
		Version:  4,
		SrcIP:    net.ParseIP("192.168.1.10"),
		DstIP:    net.ParseIP("10.0.0.1"),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(54321),
		DstPort: layers.TCPPort(80),
		SYN:     true,
		ACK:     false,
	}
	_ = tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	parsed := ParsePacket(pkt)

	if parsed == nil {
		t.Fatal("Expected non-nil ParsedPacket")
	}
	if parsed.Protocol != "TCP" {
		t.Errorf("Expected protocol TCP, got %s", parsed.Protocol)
	}
	if !parsed.SrcIP.Equal(net.ParseIP("192.168.1.10")) {
		t.Errorf("Expected SrcIP 192.168.1.10, got %v", parsed.SrcIP)
	}
	if !parsed.DstIP.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("Expected DstIP 10.0.0.1, got %v", parsed.DstIP)
	}
	if parsed.SrcPort != 54321 || parsed.DstPort != 80 {
		t.Errorf("Expected ports 54321->80, got %d->%d", parsed.SrcPort, parsed.DstPort)
	}
	if !parsed.TCPFlags.SYN || parsed.TCPFlags.ACK {
		t.Errorf("Expected SYN=true, ACK=false, got %+v", parsed.TCPFlags)
	}
}

func TestParseIPv6UDPPacket(t *testing.T) {
	ipLayer := &layers.IPv6{
		Version:    6,
		SrcIP:      net.ParseIP("fe80::1"),
		DstIP:      net.ParseIP("fe80::2"),
		NextHeader: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(5353),
		DstPort: layers.UDPPort(5353),
	}
	_ = udpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, ipLayer, udpLayer)
	if err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
	parsed := ParsePacket(pkt)

	if parsed == nil {
		t.Fatal("Expected non-nil ParsedPacket")
	}
	if parsed.Protocol != "UDP" {
		t.Errorf("Expected protocol UDP, got %s", parsed.Protocol)
	}
	if !parsed.SrcIP.Equal(net.ParseIP("fe80::1")) {
		t.Errorf("Expected SrcIP fe80::1, got %v", parsed.SrcIP)
	}
	if parsed.SrcPort != 5353 || parsed.DstPort != 5353 {
		t.Errorf("Expected ports 5353->5353, got %d->%d", parsed.SrcPort, parsed.DstPort)
	}
}

func TestParseICMPPacket(t *testing.T) {
	ipLayer := &layers.IPv4{
		Version:  4,
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("8.8.8.8"),
		Protocol: layers.IPProtocolICMPv4,
	}
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       1,
		Seq:      1,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, ipLayer, icmpLayer)
	if err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	parsed := ParsePacket(pkt)

	if parsed.Protocol != "ICMP" {
		t.Errorf("Expected protocol ICMP, got %s", parsed.Protocol)
	}
	if parsed.SrcPort != 0 || parsed.DstPort != 0 {
		t.Errorf("ICMP should have 0 for transport ports, got %d->%d", parsed.SrcPort, parsed.DstPort)
	}
}

func TestParseNilAndEmptyPackets(t *testing.T) {
	if ParsePacket(nil) != nil {
		t.Error("Expected nil result for nil packet")
	}

	raw := []byte{0x00, 0x01, 0x02, 0x03}
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	parsed := ParsePacket(pkt)
	if parsed == nil {
		t.Fatal("Expected non-nil ParsedPacket for raw bytes")
	}
	if parsed.Timestamp.IsZero() {
		t.Errorf("Timestamp should be populated")
	}
}
