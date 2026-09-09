package main

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	fileName := "attack_sample.pcap"
	f, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("Failed to create pcap: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("Failed to write header: %v", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	baseTime := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)

	for port := uint16(1); port <= 35; port++ {
		ip := &layers.IPv4{
			Version:  4,
			SrcIP:    net.ParseIP("192.168.1.50"),
			DstIP:    net.ParseIP("10.0.0.1"),
			Protocol: layers.IPProtocolTCP,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(50000 + port),
			DstPort: layers.TCPPort(port),
			SYN:     true,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)

		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(port*100) * time.Millisecond),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		_ = w.WritePacket(ci, buf.Bytes())
	}

	for i := 0; i < 600; i++ {
		ip := &layers.IPv4{
			Version:  4,
			SrcIP:    net.ParseIP("192.168.1.99"),
			DstIP:    net.ParseIP("10.0.0.1"),
			Protocol: layers.IPProtocolTCP,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(40000 + (i % 10000)),
			DstPort: layers.TCPPort(80),
			SYN:     true,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)

		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(10*time.Second + time.Duration(i*15)*time.Millisecond),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		_ = w.WritePacket(ci, buf.Bytes())
	}

	for i := 0; i < 5; i++ {
		ip := &layers.IPv4{
			Version:  4,
			SrcIP:    net.ParseIP("192.168.1.77"),
			DstIP:    net.ParseIP("10.0.0.1"),
			Protocol: layers.IPProtocolTCP,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(55000 + uint16(i)),
			DstPort: layers.TCPPort(443),
			SYN:     true,
			FIN:     true,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)

		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(20*time.Second + time.Duration(i*500)*time.Millisecond),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		_ = w.WritePacket(ci, buf.Bytes())
	}

	log.Printf("Generated %s containing Port Scan, SYN Flood, and Suspicious Flags scenarios.\n", fileName)
}
