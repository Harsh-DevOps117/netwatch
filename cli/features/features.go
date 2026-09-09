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
	SYNPerSecond float64 `json:"syn_per_second"`
	ACKPerSecond float64 `json:"ack_per_second"`
	SYNAckRatio  float64 `json:"syn_ack_ratio"`

	UDPPackets          int     `json:"udp_packets"`
	UDPBytes            int64   `json:"udp_bytes"`
	UDPPacketsPerSecond float64 `json:"udp_packets_per_second"`
	UDPBytesPerSecond   float64 `json:"udp_bytes_per_second"`

	ApproxIncompleteConnections int `json:"approx_incomplete_connections"`

	SrcIPToDstPorts       map[string]map[uint16]int `json:"-"`
	SrcIPToDstIPs         map[string]map[string]int `json:"-"`
	SrcIPToPackets        map[string]int            `json:"-"`
	SrcIPToSYNs           map[string]int            `json:"-"`
	SuspiciousFlagPackets []SuspiciousFlagRecord    `json:"-"`
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
	udpPackets            int
	udpBytes              int64
	srcIPToDstPorts       map[string]map[uint16]int
	srcIPToDstIPs         map[string]map[string]int
	srcIPToPackets        map[string]int
	srcIPToSYNs           map[string]int
	suspiciousFlagPackets []SuspiciousFlagRecord
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
		suspiciousFlagPackets: make([]SuspiciousFlagRecord, 0),
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
	udpPps := float64(a.udpPackets) / duration
	udpBps := float64(a.udpBytes) / duration

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
		SYNPerSecond:                math.Round(synPerSec*100) / 100,
		ACKPerSecond:                math.Round(ackPerSec*100) / 100,
		SYNAckRatio:                 math.Round(synAckRatio*100) / 100,
		UDPPackets:                  a.udpPackets,
		UDPBytes:                    a.udpBytes,
		UDPPacketsPerSecond:         math.Round(udpPps*100) / 100,
		UDPBytesPerSecond:           math.Round(udpBps*100) / 100,
		ApproxIncompleteConnections: incompleteConns,
		SrcIPToDstPorts:             a.srcIPToDstPorts,
		SrcIPToDstIPs:               a.srcIPToDstIPs,
		SrcIPToPackets:              a.srcIPToPackets,
		SrcIPToSYNs:                 a.srcIPToSYNs,
		SuspiciousFlagPackets:       a.suspiciousFlagPackets,
	}
}
