package pipeline

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"netflow/config"
	"netflow/models"
)

// InterfaceInfo stores details about a network adapter.
type InterfaceInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"` // "WiFi", "Ethernet", "Loopback", "Other"
	IPs         []string `json:"ips"`
}

// ClassifyInterface returns whether an interface is WiFi, Ethernet, Loopback, or Other.
func ClassifyInterface(name, description string) string {
	combined := strings.ToLower(name + " " + description)

	if strings.Contains(combined, "loopback") || strings.Contains(combined, "127.0.0.1") {
		return "Loopback"
	}
	if strings.Contains(combined, "wi-fi") || strings.Contains(combined, "wifi") ||
		strings.Contains(combined, "wireless") || strings.Contains(combined, "wlan") ||
		strings.Contains(combined, "802.11") {
		return "WiFi"
	}
	if strings.Contains(combined, "ethernet") || strings.Contains(combined, "eth") ||
		strings.Contains(combined, "lan") || strings.Contains(combined, "local area connection") ||
		strings.Contains(combined, "realtek") || strings.Contains(combined, "gigabit") ||
		strings.Contains(combined, "intel") {
		return "Ethernet"
	}
	return "Other"
}

// ListInterfaces enumerates all Npcap network devices present on the Windows host.
func ListInterfaces() ([]InterfaceInfo, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate Npcap devices: %w", err)
	}

	var results []InterfaceInfo
	for _, dev := range devices {
		var ips []string
		for _, addr := range dev.Addresses {
			ips = append(ips, addr.IP.String())
		}
		ifType := ClassifyInterface(dev.Name, dev.Description)

		results = append(results, InterfaceInfo{
			Name:        dev.Name,
			Description: dev.Description,
			Type:        ifType,
			IPs:         ips,
		})
	}
	return results, nil
}

// StartCapture initiates multi-interface packet capture or synthetic simulation.
func StartCapture(ctx context.Context, cfg *config.Config, outChan chan<- *models.PacketEvent, rawPktChan chan<- gopacket.Packet) error {
	if cfg.SimulateMode {
		log.Println("[Capturer] Running in SIMULATION MODE (Synthetic packet generation)...")
		go runSimulatedCapture(ctx, outChan, rawPktChan)
		return nil
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("failed to list pcap devices: %w", err)
	}

	var targetDevices []pcap.Interface
	for _, dev := range devices {
		ifType := ClassifyInterface(dev.Name, dev.Description)

		if len(cfg.TargetIfaces) > 0 {
			matched := false
			for _, target := range cfg.TargetIfaces {
				t := strings.ToLower(target)
				if strings.Contains(strings.ToLower(dev.Name), t) || strings.Contains(strings.ToLower(dev.Description), t) {
					matched = true
					break
				}
			}
			if matched {
				targetDevices = append(targetDevices, dev)
			}
		} else {
			if ifType == "WiFi" || ifType == "Ethernet" {
				targetDevices = append(targetDevices, dev)
			}
		}
	}

	if len(targetDevices) == 0 {
		log.Println("[Capturer] Warning: No specific WiFi/Ethernet label matches. Capturing from all available non-loopback devices.")
		for _, dev := range devices {
			if ClassifyInterface(dev.Name, dev.Description) != "Loopback" {
				targetDevices = append(targetDevices, dev)
			}
		}
	}

	if len(targetDevices) == 0 {
		return fmt.Errorf("no suitable network capture interfaces found on system")
	}

	log.Printf("[Capturer] Starting packet capture on %d interface(s)...", len(targetDevices))
	var wg sync.WaitGroup

	for _, dev := range targetDevices {
		ifType := ClassifyInterface(dev.Name, dev.Description)
		log.Printf("[Capturer] Opening interface [%s] - %s (Type: %s)", dev.Name, dev.Description, ifType)

		wg.Add(1)
		go func(d pcap.Interface, itype string) {
			defer wg.Done()
			captureSingleDevice(ctx, d, itype, cfg, outChan, rawPktChan)
		}(dev, ifType)
	}

	go func() {
		<-ctx.Done()
		wg.Wait()
	}()

	return nil
}

// captureSingleDevice handles live packet reading for a single pcap device.
func captureSingleDevice(ctx context.Context, dev pcap.Interface, ifType string, cfg *config.Config, outChan chan<- *models.PacketEvent, rawPktChan chan<- gopacket.Packet) {
	handle, err := pcap.OpenLive(dev.Name, cfg.SnapLen, cfg.Promiscuous, 500*time.Millisecond)
	if err != nil {
		log.Printf("[Capturer Error] Could not open interface %s (%s): %v", dev.Name, dev.Description, err)
		return
	}
	defer handle.Close()

	if cfg.BPFFilter != "" {
		if err := handle.SetBPFFilter(cfg.BPFFilter); err != nil {
			log.Printf("[Capturer Error] Failed to apply BPF filter '%s' to %s: %v", cfg.BPFFilter, dev.Name, err)
		} else {
			log.Printf("[Capturer] BPF filter '%s' applied to interface %s", cfg.BPFFilter, dev.Name)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[Capturer] Stopped capture on %s", dev.Name)
			return
		case pkt, ok := <-packets:
			if !ok {
				log.Printf("[Capturer] Packet channel closed for %s", dev.Name)
				return
			}
			if pkt == nil {
				continue
			}

			// Send to 2-minute PCAP aggregator
			select {
			case rawPktChan <- pkt:
			default:
			}

			// Decode and send to Kafka event channel
			evt := DecodePacket(pkt, dev.Description, ifType)
			if evt != nil {
				select {
				case outChan <- evt:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// runSimulatedCapture generates valid synthetic raw packets and metadata for testing without live Npcap.
func runSimulatedCapture(ctx context.Context, outChan chan<- *models.PacketEvent, rawPktChan chan<- gopacket.Packet) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	ifaces := []struct {
		Name string
		Type string
	}{
		{"Wi-Fi Adapter (Intel Wi-Fi 6 AX201)", "WiFi"},
		{"Ethernet Adapter (Realtek PCIe GbE)", "Ethernet"},
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[Simulated Capturer] Stopped synthetic generator.")
			return
		case t := <-ticker.C:
			iface := ifaces[r.Intn(len(ifaces))]
			srcIP := net.IPv4(192, 168, 1, byte(10+r.Intn(100)))
			dstIP := net.IPv4(142, 250, 190, byte(1+r.Intn(254)))
			srcPort := layers.TCPPort(1024 + r.Intn(64000))
			dstPort := layers.TCPPort(443)

			// Construct raw packet layers
			ethLayer := &layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(r.Intn(256))},
				DstMAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, byte(r.Intn(256))},
				EthernetType: layers.EthernetTypeIPv4,
			}
			ipLayer := &layers.IPv4{
				Version:  4,
				IHL:      5,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    srcIP,
				DstIP:    dstIP,
			}
			tcpLayer := &layers.TCP{
				SrcPort: srcPort,
				DstPort: dstPort,
				Seq:     r.Uint32(),
				Ack:     r.Uint32(),
				SYN:     r.Intn(10) == 0,
				ACK:     true,
				PSH:     r.Intn(5) == 0,
				Window:  64240,
			}
			tcpLayer.SetNetworkLayerForChecksum(ipLayer)

			payload := []byte("GET /stream HTTP/1.1\r\nHost: example.com\r\n\r\nSynthetic NetFlow Payload Data")

			buffer := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
			if err := gopacket.SerializeLayers(buffer, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
				continue
			}

			rawBytes := buffer.Bytes()
			pkt := gopacket.NewPacket(rawBytes, layers.LayerTypeEthernet, gopacket.Default)
			pkt.Metadata().Timestamp = t
			pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
				Timestamp:      t,
				CaptureLength:  len(rawBytes),
				Length:         len(rawBytes),
				InterfaceIndex: 0,
			}

			// Send raw packet to PCAP aggregator
			select {
			case rawPktChan <- pkt:
			default:
			}

			// Decode and send event to Kafka
			evt := DecodePacket(pkt, iface.Name, iface.Type)
			if evt != nil {
				select {
				case outChan <- evt:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}
