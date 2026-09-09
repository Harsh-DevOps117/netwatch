package capture

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func createTestPCAP(t *testing.T, count int) string {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("Failed to create test pcap file: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("Failed to write pcap header: %v", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		SrcIP:    net.ParseIP("192.168.1.100"),
		DstIP:    net.ParseIP("192.168.1.1"),
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(40000),
		DstPort: layers.TCPPort(80),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("Failed to serialize layers: %v", err)
	}

	data := buf.Bytes()
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(1700000000, 0),
		CaptureLength: len(data),
		Length:        len(data),
	}

	for i := 0; i < count; i++ {
		ci.Timestamp = ci.Timestamp.Add(time.Second)
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatalf("Failed to write packet: %v", err)
		}
	}

	return pcapPath
}

func TestOpenPCAPAndReadPackets(t *testing.T) {
	const packetCount = 5
	pcapPath := createTestPCAP(t, packetCount)

	handle, err := OpenPCAP(pcapPath)
	if err != nil {
		t.Fatalf("OpenPCAP failed: %v", err)
	}
	defer handle.Close()

	readCount := 0
	for pkt := range handle.Packets() {
		if pkt == nil {
			t.Error("Received nil packet")
		}
		readCount++
	}

	if readCount != packetCount {
		t.Errorf("Expected %d packets, got %d", packetCount, readCount)
	}
}

func TestOpenNonExistentFile(t *testing.T) {
	_, err := OpenPCAP("non_existent_file.pcap")
	if err == nil {
		t.Error("Expected error opening non-existent file, got nil")
	}
}
