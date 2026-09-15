package pipeline

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"netflow/models"
)

// DecodePacket transforms a raw gopacket.Packet into a structured models.PacketEvent.
func DecodePacket(packet gopacket.Packet, interfaceName, interfaceType string) *models.PacketEvent {
	if packet == nil {
		return nil
	}

	meta := packet.Metadata()
	ts := meta.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	evt := &models.PacketEvent{
		ID:            fmt.Sprintf("%d-%d", ts.UnixNano(), meta.CaptureInfo.Length),
		Timestamp:     ts,
		InterfaceName: interfaceName,
		InterfaceType: interfaceType,
		Length:        meta.CaptureInfo.Length,
		Protocol:      "UNKNOWN",
	}

	// 1. Ethernet / Link Layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			evt.SrcMAC = eth.SrcMAC.String()
			evt.DstMAC = eth.DstMAC.String()
			evt.EtherType = eth.EthernetType.String()
		}
	}

	// 2. Network Layer (IPv4 / IPv6)
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		if ip4, ok := ip4Layer.(*layers.IPv4); ok {
			evt.SrcIP = ip4.SrcIP.String()
			evt.DstIP = ip4.DstIP.String()
			evt.Protocol = ip4.Protocol.String()
		}
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		if ip6, ok := ip6Layer.(*layers.IPv6); ok {
			evt.SrcIP = ip6.SrcIP.String()
			evt.DstIP = ip6.DstIP.String()
			evt.Protocol = ip6.NextHeader.String()
		}
	}

	// 3. Transport Layer (TCP / UDP / ICMP)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			evt.SrcPort = int(tcp.SrcPort)
			evt.DstPort = int(tcp.DstPort)
			evt.Protocol = "TCP"
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			evt.SrcPort = int(udp.SrcPort)
			evt.DstPort = int(udp.DstPort)
			evt.Protocol = "UDP"
		}
	} else if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		evt.Protocol = "ICMPv4"
	} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		evt.Protocol = "ICMPv6"
	}

	// 4. Payload Layer
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		evt.PayloadLen = len(payload)
		if len(payload) > 0 {
			maxPreview := 64
			if len(payload) < maxPreview {
				maxPreview = len(payload)
			}
			evt.PayloadHex = hex.EncodeToString(payload[:maxPreview])
		}
	}

	return evt
}
