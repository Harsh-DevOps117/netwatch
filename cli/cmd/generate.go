package cmd

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate [sample|attack]",
	Short: "Generate synthetic PCAP captures for testing and demonstrations",
	Long: `Generate synthetic network packet capture (PCAP) files to test deterministic rules:
  - 'sample': Generates clean baseline traffic.
  - 'attack': Generates scenarios containing Port Scan, SYN Flood, and Flag anomalies.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "sample":
			generateNormalSample("sample.pcap")
		case "attack":
			generateAttackSample("attack_sample.pcap")
		default:
			fmt.Fprintf(os.Stderr, "Unknown scenario %q. Use 'sample' or 'attack'.\n", args[0])
			os.Exit(1)
		}
	},
}

func generateNormalSample(fileName string) {
	f, err := os.Create(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create %s: %v\n", fileName, err)
		return
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write header: %v\n", err)
		return
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
		_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("HTTP_BASELINE_TRAFFIC")))

		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(i*200) * time.Millisecond),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		_ = w.WritePacket(ci, buf.Bytes())
	}

	fmt.Printf("[✓] Successfully generated %s (Clean Baseline Traffic)\n", fileName)
}

func generateAttackSample(fileName string) {
	f, err := os.Create(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create %s: %v\n", fileName, err)
		return
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write header: %v\n", err)
		return
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

	fmt.Printf("[✓] Successfully generated %s (Attack Scenarios: Port Scan, SYN Flood, Flag Anomalies)\n", fileName)
}

func init() {
	rootCmd.AddCommand(generateCmd)
}
