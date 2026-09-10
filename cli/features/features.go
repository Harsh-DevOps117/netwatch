package features

import (
	"math"
	"time"

	"detector/parser"
)

type SuspiciousFlagRecord struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Flags     string    `json:"flags"`
}

type WindowFeatures struct {
	WindowStart     time.Time `json:"window_start"`
	WindowEnd       time.Time `json:"window_end"`
	DurationSeconds float64   `json:"duration_seconds"`

	TotalPackets     int     `json:"total_packets"`
	TotalBytes       int64   `json:"total_bytes"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	BytesPerSecond   float64 `json:"bytes_per_second"`

	UniqueSourceIPs      int `json:"unique_source_ips"`
	UniqueDestinationIPs int `json:"unique_destination_ips"`

	UniqueSourcePorts      int `json:"unique_source_ports"`
	UniqueDestinationPorts int `json:"unique_destination_ports"`

	TCPPackets   int     `json:"tcp_packets"`
	SYNCount     int     `json:"syn_count"`
	SYNACKCount  int     `json:"syn_ack_count"`
	ACKCount     int     `json:"ack_count"`
	RSTCount     int     `json:"rst_count"`
	FINCount     int     `json:"fin_count"`
	PSHCount     int     `json:"psh_count"`
	URGCount     int     `json:"urg_count"`
	SYNPerSecond float64 `json:"syn_per_second"`
	ACKPerSecond float64 `json:"ack_per_second"`
	RSTPerSecond float64 `json:"rst_per_second"`
	SYNAckRatio  float64 `json:"syn_ack_ratio"`

	UDPPackets          int     `json:"udp_packets"`
	UDPBytes            int64   `json:"udp_bytes"`
	UDPPacketsPerSecond float64 `json:"udp_packets_per_second"`
	UDPBytesPerSecond   float64 `json:"udp_bytes_per_second"`

	DNSPackets          int     `json:"dns_packets"`
	DNSBytes            int64   `json:"dns_bytes"`
	DNSPacketsPerSecond float64 `json:"dns_packets_per_second"`
	DNSBytesPerSecond   float64 `json:"dns_bytes_per_second"`

	ICMPPackets          int     `json:"icmp_packets"`
	ICMPBytes            int64   `json:"icmp_bytes"`
	ICMPPacketsPerSecond float64 `json:"icmp_packets_per_second"`
	ICMPEchoRequests     int     `json:"icmp_echo_requests"`

	ApproxIncompleteConnections int `json:"approx_incomplete_connections"`

	SrcIPToDstPorts       map[string]map[uint16]int    `json:"-"`
	SrcIPToDstIPs         map[string]map[string]int    `json:"-"`
	SrcIPToPackets        map[string]int               `json:"-"`
	SrcIPToSYNs           map[string]int               `json:"-"`
	SrcIPToICMPEcho       map[string]map[string]int    `json:"-"`
	SuspiciousFlagPackets []SuspiciousFlagRecord       `json:"-"`
	NullScanPackets       []SuspiciousFlagRecord       `json:"-"`
	XmasScanPackets       []SuspiciousFlagRecord       `json:"-"`
	FinScanPackets        []SuspiciousFlagRecord       `json:"-"`
}

type FeatureAggregator struct {
	windowStart           time.Time
	windowEnd             time.Time
	totalPackets          int
	totalBytes            int64
	srcIPs                map[string]int
	dstIPs                map[string]int
	srcPorts              map[uint16]int
	dstPorts              map[uint16]int
	tcpPackets            int
	synCount              int
	synAckCount           int
	ackCount              int
	rstCount              int
	finCount              int
	pshCount              int
	urgCount              int
	udpPackets            int
	udpBytes              int64
	dnsPackets            int
	dnsBytes              int64
	icmpPackets           int
	icmpBytes             int64
	icmpEchoRequests      int
	srcIPToDstPorts       map[string]map[uint16]int
	srcIPToDstIPs         map[string]map[string]int
	srcIPToPackets        map[string]int
	srcIPToSYNs           map[string]int
	srcIPToICMPEcho       map[string]map[string]int
	suspiciousFlagPackets []SuspiciousFlagRecord
	nullScanPackets       []SuspiciousFlagRecord
	xmasScanPackets       []SuspiciousFlagRecord
	finScanPackets        []SuspiciousFlagRecord
}

func NewAggregator(start, end time.Time) *FeatureAggregator {
	return &FeatureAggregator{
		windowStart:           start,
		windowEnd:             end,
		srcIPs:                make(map[string]int),
		dstIPs:                make(map[string]int),
		srcPorts:              make(map[uint16]int),
		dstPorts:              make(map[uint16]int),
		srcIPToDstPorts:       make(map[string]map[uint16]int),
		srcIPToDstIPs:         make(map[string]map[string]int),
		srcIPToPackets:        make(map[string]int),
		srcIPToSYNs:           make(map[string]int),
		srcIPToICMPEcho:       make(map[string]map[string]int),
		suspiciousFlagPackets: make([]SuspiciousFlagRecord, 0),
		nullScanPackets:       make([]SuspiciousFlagRecord, 0),
		xmasScanPackets:       make([]SuspiciousFlagRecord, 0),
		finScanPackets:        make([]SuspiciousFlagRecord, 0),
	}
}

func (a *FeatureAggregator) AddPacket(p *parser.ParsedPacket) {
	if p == nil {
		return
	}

	a.totalPackets++
	a.totalBytes += int64(p.Length)

	var srcIPStr, dstIPStr string
	if p.SrcIP != nil {
		srcIPStr = p.SrcIP.String()
		a.srcIPs[srcIPStr]++
		a.srcIPToPackets[srcIPStr]++
	}
	if p.DstIP != nil {
		dstIPStr = p.DstIP.String()
		a.dstIPs[dstIPStr]++
	}

	if p.SrcPort > 0 {
		a.srcPorts[p.SrcPort]++
	}
	if p.DstPort > 0 {
		a.dstPorts[p.DstPort]++
	}

	if srcIPStr != "" && dstIPStr != "" {
		if a.srcIPToDstIPs[srcIPStr] == nil {
			a.srcIPToDstIPs[srcIPStr] = make(map[string]int)
		}
		a.srcIPToDstIPs[srcIPStr][dstIPStr]++
	}

	if srcIPStr != "" && p.DstPort > 0 {
		if a.srcIPToDstPorts[srcIPStr] == nil {
			a.srcIPToDstPorts[srcIPStr] = make(map[uint16]int)
		}
		a.srcIPToDstPorts[srcIPStr][p.DstPort]++
	}

	if p.IsDNS {
		a.dnsPackets++
		a.dnsBytes += int64(p.Length)
	}

	if p.IsICMPEchoRequest && srcIPStr != "" && dstIPStr != "" {
		a.icmpEchoRequests++
		if a.srcIPToICMPEcho[srcIPStr] == nil {
			a.srcIPToICMPEcho[srcIPStr] = make(map[string]int)
		}
		a.srcIPToICMPEcho[srcIPStr][dstIPStr]++
	}

	switch p.Protocol {
	case "TCP":
		a.tcpPackets++
		f := p.TCPFlags

		if f.SYN && f.ACK {
			a.synAckCount++
		} else if f.SYN {
			a.synCount++
			if srcIPStr != "" {
				a.srcIPToSYNs[srcIPStr]++
			}
		}

		if f.ACK {
			a.ackCount++
		}
		if f.RST {
			a.rstCount++
		}
		if f.FIN {
			a.finCount++
		}
		if f.PSH {
			a.pshCount++
		}
		if f.URG {
			a.urgCount++
		}

		// Stealth Scan Detections (NULL, XMAS, FIN)
		if f.IsZero() {
			a.nullScanPackets = append(a.nullScanPackets, SuspiciousFlagRecord{
				Timestamp: p.Timestamp,
				SrcIP:     srcIPStr,
				DstIP:     dstIPStr,
				SrcPort:   p.SrcPort,
				DstPort:   p.DstPort,
				Flags:     "NULL (No flags)",
			})
		}
		if f.IsXmas() {
			a.xmasScanPackets = append(a.xmasScanPackets, SuspiciousFlagRecord{
				Timestamp: p.Timestamp,
				SrcIP:     srcIPStr,
				DstIP:     dstIPStr,
				SrcPort:   p.SrcPort,
				DstPort:   p.DstPort,
				Flags:     "XMAS (FIN+PSH+URG)",
			})
		}
		if f.IsFinOnly() {
			a.finScanPackets = append(a.finScanPackets, SuspiciousFlagRecord{
				Timestamp: p.Timestamp,
				SrcIP:     srcIPStr,
				DstIP:     dstIPStr,
				SrcPort:   p.SrcPort,
				DstPort:   p.DstPort,
				Flags:     "FIN (FIN scan)",
			})
		}

		// Illegal Flag Combinations
		if (f.SYN && f.FIN) || (f.SYN && f.RST) || (f.FIN && f.RST) {
			flagDesc := ""
			if f.SYN && f.FIN {
				flagDesc = "SYN+FIN"
			} else if f.SYN && f.RST {
				flagDesc = "SYN+RST"
			} else if f.FIN && f.RST {
				flagDesc = "FIN+RST"
			}
			a.suspiciousFlagPackets = append(a.suspiciousFlagPackets, SuspiciousFlagRecord{
				Timestamp: p.Timestamp,
				SrcIP:     srcIPStr,
				DstIP:     dstIPStr,
				SrcPort:   p.SrcPort,
				DstPort:   p.DstPort,
				Flags:     flagDesc,
			})
		}

	case "UDP":
		a.udpPackets++
		a.udpBytes += int64(p.Length)

	case "ICMP", "ICMPv6":
		a.icmpPackets++
		a.icmpBytes += int64(p.Length)
	}
}

func (a *FeatureAggregator) ComputeFinalFeatures() *WindowFeatures {
	duration := a.windowEnd.Sub(a.windowStart).Seconds()
	if duration <= 0 {
		duration = 1.0
	}

	pps := float64(a.totalPackets) / duration
	bps := float64(a.totalBytes) / duration
	synPerSec := float64(a.synCount) / duration
	ackPerSec := float64(a.ackCount) / duration
	rstPerSec := float64(a.rstCount) / duration
	udpPps := float64(a.udpPackets) / duration
	udpBps := float64(a.udpBytes) / duration
	dnsPps := float64(a.dnsPackets) / duration
	dnsBps := float64(a.dnsBytes) / duration
	icmpPps := float64(a.icmpPackets) / duration

	var synAckRatio float64
	if a.synAckCount > 0 {
		synAckRatio = float64(a.synCount) / float64(a.synAckCount)
	} else if a.synCount > 0 {
		synAckRatio = float64(a.synCount)
	}

	incompleteConns := a.synCount - a.synAckCount
	if incompleteConns < 0 {
		incompleteConns = 0
	}

	return &WindowFeatures{
		WindowStart:                 a.windowStart,
		WindowEnd:                   a.windowEnd,
		DurationSeconds:             duration,
		TotalPackets:                a.totalPackets,
		TotalBytes:                  a.totalBytes,
		PacketsPerSecond:            math.Round(pps*100) / 100,
		BytesPerSecond:              math.Round(bps*100) / 100,
		UniqueSourceIPs:             len(a.srcIPs),
		UniqueDestinationIPs:        len(a.dstIPs),
		UniqueSourcePorts:           len(a.srcPorts),
		UniqueDestinationPorts:      len(a.dstPorts),
		TCPPackets:                  a.tcpPackets,
		SYNCount:                    a.synCount,
		SYNACKCount:                 a.synAckCount,
		ACKCount:                    a.ackCount,
		RSTCount:                    a.rstCount,
		FINCount:                    a.finCount,
		PSHCount:                    a.pshCount,
		URGCount:                    a.urgCount,
		SYNPerSecond:                math.Round(synPerSec*100) / 100,
		ACKPerSecond:                math.Round(ackPerSec*100) / 100,
		RSTPerSecond:                math.Round(rstPerSec*100) / 100,
		SYNAckRatio:                 math.Round(synAckRatio*100) / 100,
		UDPPackets:                  a.udpPackets,
		UDPBytes:                    a.udpBytes,
		UDPPacketsPerSecond:         math.Round(udpPps*100) / 100,
		UDPBytesPerSecond:           math.Round(udpBps*100) / 100,
		DNSPackets:                  a.dnsPackets,
		DNSBytes:                    a.dnsBytes,
		DNSPacketsPerSecond:         math.Round(dnsPps*100) / 100,
		DNSBytesPerSecond:           math.Round(dnsBps*100) / 100,
		ICMPPackets:                 a.icmpPackets,
		ICMPBytes:                   a.icmpBytes,
		ICMPPacketsPerSecond:        math.Round(icmpPps*100) / 100,
		ICMPEchoRequests:            a.icmpEchoRequests,
		ApproxIncompleteConnections: incompleteConns,
		SrcIPToDstPorts:             a.srcIPToDstPorts,
		SrcIPToDstIPs:               a.srcIPToDstIPs,
		SrcIPToPackets:              a.srcIPToPackets,
		SrcIPToSYNs:                 a.srcIPToSYNs,
		SrcIPToICMPEcho:             a.srcIPToICMPEcho,
		SuspiciousFlagPackets:       a.suspiciousFlagPackets,
		NullScanPackets:             a.nullScanPackets,
		XmasScanPackets:             a.xmasScanPackets,
		FinScanPackets:              a.finScanPackets,
	}
}
