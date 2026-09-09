package parser

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPFlags struct {
	SYN bool `json:"syn"`
	ACK bool `json:"ack"`
	RST bool `json:"rst"`
	FIN bool `json:"fin"`
	PSH bool `json:"psh"`
}

type ParsedPacket struct {
	Timestamp time.Time `json:"timestamp"`
	Length    int       `json:"length"`
	SrcIP     net.IP    `json:"src_ip,omitempty"`
	DstIP     net.IP    `json:"dst_ip,omitempty"`
	SrcPort   uint16    `json:"src_port,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	Protocol  string    `json:"protocol"`
	TCPFlags  TCPFlags  `json:"tcp_flags,omitempty"`
}

func ParsePacket(pkt gopacket.Packet) *ParsedPacket {
	if pkt == nil {
		return nil
	}

	parsed := &ParsedPacket{
		Protocol: "UNKNOWN",
	}

	if meta := pkt.Metadata(); meta != nil {
		parsed.Timestamp = meta.Timestamp
		parsed.Length = meta.Length
	}
	if parsed.Timestamp.IsZero() {
		parsed.Timestamp = time.Now()
	}
	if parsed.Length == 0 {
		parsed.Length = len(pkt.Data())
	}

	if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		if ip4, ok := ip4Layer.(*layers.IPv4); ok {
			parsed.SrcIP = ip4.SrcIP
			parsed.DstIP = ip4.DstIP
			parsed.Protocol = "IPv4"
		}
	} else if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		if ip6, ok := ip6Layer.(*layers.IPv6); ok {
			parsed.SrcIP = ip6.SrcIP
			parsed.DstIP = ip6.DstIP
			parsed.Protocol = "IPv6"
		}
	}

	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			parsed.Protocol = "TCP"
			parsed.SrcPort = uint16(tcp.SrcPort)
			parsed.DstPort = uint16(tcp.DstPort)
			parsed.TCPFlags = TCPFlags{
				SYN: tcp.SYN,
				ACK: tcp.ACK,
				RST: tcp.RST,
				FIN: tcp.FIN,
				PSH: tcp.PSH,
			}
		}
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			parsed.Protocol = "UDP"
			parsed.SrcPort = uint16(udp.SrcPort)
			parsed.DstPort = uint16(udp.DstPort)
		}
	} else if pkt.Layer(layers.LayerTypeICMPv4) != nil {
		parsed.Protocol = "ICMP"
	} else if pkt.Layer(layers.LayerTypeICMPv6) != nil {
		parsed.Protocol = "ICMPv6"
	} else if pkt.Layer(layers.LayerTypeARP) != nil {
		parsed.Protocol = "ARP"
	}

	return parsed
}
