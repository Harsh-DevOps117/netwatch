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
	fileName := "sample.pcap"
	f, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("Failed to create sample pcap: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("Failed to write header: %v", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c},
		DstMAC:       net.HardwareAddr{0x00, 0x50, 0x56, 0xfa, 0xeb, 0xdc},
		EthernetType: layers.EthernetTypeIPv4,
	}

	baseTime := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 50; i++ {
		ip := &layers.IPv4{
			Version:  4,
			SrcIP:    net.ParseIP("192.168.1.50"),
			DstIP:    net.ParseIP("142.250.190.46"),
			Protocol: layers.IPProtocolTCP,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(49152 + i),
			DstPort: layers.TCPPort(443),
			SYN:     i%5 == 0,
			ACK:     true,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("HTTP_DATA_PAYLOAD"))); err != nil {
			log.Fatalf("Serialize error: %v", err)
		}

		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(i*200) * time.Millisecond),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		_ = w.WritePacket(ci, buf.Bytes())
	}

	for i := 0; i < 20; i++ {
		ip := &layers.IPv4{
			Version:  4,
			SrcIP:    net.ParseIP("192.168.1.50"),
			DstIP:    net.ParseIP("8.8.8.8"),
			Protocol: layers.IPProtocolUDP,
		}
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(53535 + i),
			DstPort: layers.UDPPort(53),
		}
		_ = udp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		_ = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte("DNS_QUERY_DATA")))

		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(10+i*200) * time.Millisecond),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		_ = w.WritePacket(ci, buf.Bytes())
	}

	log.Printf("Successfully generated %s with 70 sample packets\n", fileName)
}
