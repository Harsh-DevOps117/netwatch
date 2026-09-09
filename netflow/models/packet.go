package models

import "time"

// PacketEvent represents structured metadata and payload of a captured network packet.
type PacketEvent struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	InterfaceName string    `json:"interface_name"`
	InterfaceType string    `json:"interface_type"` // e.g. "WiFi", "Ethernet", "Loopback", "Synthetic"
	SrcMAC        string    `json:"src_mac,omitempty"`
	DstMAC        string    `json:"dst_mac,omitempty"`
	EtherType     string    `json:"ether_type,omitempty"`
	SrcIP         string    `json:"src_ip,omitempty"`
	DstIP         string    `json:"dst_ip,omitempty"`
	SrcPort       int       `json:"src_port,omitempty"`
	DstPort       int       `json:"dst_port,omitempty"`
	Protocol      string    `json:"protocol"` // e.g. TCP, UDP, ICMP, IPv4, IPv6
	Length        int       `json:"length"`
	PayloadLen    int       `json:"payload_len"`
	PayloadHex    string    `json:"payload_hex,omitempty"`
}
