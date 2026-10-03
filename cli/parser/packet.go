package parser

import (
	"net"
	"time"

	"detector/semantics"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPFlags struct {
	SYN bool `json:"syn"`
	ACK bool `json:"ack"`
	RST bool `json:"rst"`
	FIN bool `json:"fin"`
	PSH bool `json:"psh"`
	URG bool `json:"urg"`
	ECE bool `json:"ece"`
	CWR bool `json:"cwr"`
	NS  bool `json:"ns"`
}

func (f TCPFlags) IsZero() bool {
	return !f.SYN && !f.ACK && !f.RST && !f.FIN && !f.PSH && !f.URG && !f.ECE && !f.CWR && !f.NS
}

func (f TCPFlags) IsXmas() bool {
	return f.FIN && f.PSH && f.URG && !f.SYN && !f.ACK && !f.RST
}

func (f TCPFlags) IsFinOnly() bool {
	return f.FIN && !f.SYN && !f.ACK && !f.RST && !f.PSH && !f.URG
}

type ParsedPacket struct {
	semantics.Tags
	Timestamp         time.Time `json:"timestamp"`
	Length            int       `json:"length"`
	PayloadLength     int       `json:"payload_length"`
	SrcIP             net.IP    `json:"src_ip,omitempty"`
	DstIP             net.IP    `json:"dst_ip,omitempty"`
	SrcPort           uint16    `json:"src_port,omitempty"`
	DstPort           uint16    `json:"dst_port,omitempty"`
	Protocol          string    `json:"protocol"`
	HasIP             bool      `json:"has_ip"`
	TTL               uint8     `json:"ttl,omitempty"`
	IsFragmented      bool      `json:"is_fragmented"`
	FragOffset        uint16    `json:"frag_offset,omitempty"`
	TCPFlags          TCPFlags  `json:"tcp_flags,omitempty"`
	TCPWindowSize     uint16    `json:"tcp_window_size,omitempty"`
	TCPSeq            uint32    `json:"tcp_seq,omitempty"`
	TCPAck            uint32    `json:"tcp_ack,omitempty"`
	IsICMPEchoRequest bool      `json:"is_icmp_echo_request,omitempty"`
	IsDNS             bool      `json:"is_dns,omitempty"`
	// DNSHostnames holds IP-to-domain mappings observed in DNS answer packets.
	// It is internal telemetry for graph labelling, not a packet export field.
	DNSHostnames map[string]string `json:"-"`
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

	// 1. IP Layer Parsing (IPv4 / IPv6)
	if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		if ip4, ok := ip4Layer.(*layers.IPv4); ok {
			parsed.SrcIP = ip4.SrcIP
			parsed.DstIP = ip4.DstIP
			parsed.Protocol = "IPv4"
			parsed.HasIP = true
			parsed.TTL = ip4.TTL
			parsed.FragOffset = ip4.FragOffset
			if (ip4.Flags&layers.IPv4MoreFragments != 0) || ip4.FragOffset > 0 {
				parsed.IsFragmented = true
			}
		}
	} else if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		if ip6, ok := ip6Layer.(*layers.IPv6); ok {
			parsed.SrcIP = ip6.SrcIP
			parsed.DstIP = ip6.DstIP
			parsed.Protocol = "IPv6"
			parsed.HasIP = true
			parsed.TTL = uint8(ip6.HopLimit)
		}
	}

	if pkt.Layer(layers.LayerTypeIPv6Fragment) != nil {
		parsed.IsFragmented = true
	}

	// 2. Transport & Upper Layer Parsing
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			parsed.Protocol = "TCP"
			parsed.SrcPort = uint16(tcp.SrcPort)
			parsed.DstPort = uint16(tcp.DstPort)
			parsed.TCPWindowSize = tcp.Window
			parsed.TCPSeq = tcp.Seq
			parsed.TCPAck = tcp.Ack
			parsed.PayloadLength = len(tcp.Payload)
			parsed.TCPFlags = TCPFlags{
				SYN: tcp.SYN,
				ACK: tcp.ACK,
				RST: tcp.RST,
				FIN: tcp.FIN,
				PSH: tcp.PSH,
				URG: tcp.URG,
				ECE: tcp.ECE,
				CWR: tcp.CWR,
				NS:  tcp.NS,
			}
			if parsed.SrcPort == 53 || parsed.DstPort == 53 {
				parsed.IsDNS = true
			}
		}
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			parsed.Protocol = "UDP"
			parsed.SrcPort = uint16(udp.SrcPort)
			parsed.DstPort = uint16(udp.DstPort)
			parsed.PayloadLength = len(udp.Payload)
			if parsed.SrcPort == 53 || parsed.DstPort == 53 {
				parsed.IsDNS = true
			}
		}
	} else if icmp4Layer := pkt.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		parsed.Protocol = "ICMP"
		if icmp4, ok := icmp4Layer.(*layers.ICMPv4); ok {
			parsed.PayloadLength = len(icmp4.Payload)
			if icmp4.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
				parsed.IsICMPEchoRequest = true
			}
		}
	} else if icmp6Layer := pkt.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		parsed.Protocol = "ICMPv6"
		if icmp6, ok := icmp6Layer.(*layers.ICMPv6); ok {
			parsed.PayloadLength = len(icmp6.Payload)
			if icmp6.TypeCode.Type() == layers.ICMPv6TypeEchoRequest {
				parsed.IsICMPEchoRequest = true
			}
		}
	} else if pkt.Layer(layers.LayerTypeARP) != nil {
		parsed.Protocol = "ARP"
	}

	// Capture only names actually present in an observed DNS response. This avoids
	// reverse-DNS lookups or fabricated website labels in downstream consumers.
	if dnsLayer := pkt.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		if dns, ok := dnsLayer.(*layers.DNS); ok {
			parsed.IsDNS = true
			for _, answer := range dns.Answers {
				if answer.IP == nil || len(answer.Name) == 0 {
					continue
				}
				if parsed.DNSHostnames == nil {
					parsed.DNSHostnames = make(map[string]string)
				}
				parsed.DNSHostnames[answer.IP.String()] = string(answer.Name)
			}
		}
	}

	// Fallback for payload length from application layer if available
	if parsed.PayloadLength == 0 {
		if appLayer := pkt.ApplicationLayer(); appLayer != nil {
			parsed.PayloadLength = len(appLayer.Payload())
		}
	}
	parsed.Tags = semantics.Classify(semantics.Observation{
		Transport: parsed.Protocol, SrcIP: parsed.SrcIP.String(), DstIP: parsed.DstIP.String(),
		SrcPort: parsed.SrcPort, DstPort: parsed.DstPort,
	})

	return parsed
}
