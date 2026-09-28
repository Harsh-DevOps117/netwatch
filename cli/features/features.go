package features

import (
	"fmt"
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
	SchemaVersion   string    `json:"schema_version"`
	WindowIndex     int       `json:"window_index"`
	WindowStart     time.Time `json:"window_start"`
	WindowEnd       time.Time `json:"window_end"`
	DurationSeconds float64   `json:"duration_seconds"`

	// Traffic Volume & Bandwidth
	TotalPackets     int     `json:"total_packets"`
	TotalBytes       int64   `json:"total_bytes"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	BytesPerSecond   float64 `json:"bytes_per_second"`

	// Packet-Level Features
	TTLMean                 float64        `json:"ttl_mean"`
	TTLMin                  uint8          `json:"ttl_min"`
	TTLMax                  uint8          `json:"ttl_max"`
	TTLStdDev               float64        `json:"ttl_stddev"`
	TCPWindowMean           float64        `json:"tcp_window_mean"`
	TCPWindowMin            uint16         `json:"tcp_window_min"`
	TCPWindowMax            uint16         `json:"tcp_window_max"`
	TCPWindowStdDev         float64        `json:"tcp_window_stddev"`
	FragmentedPacketsCount  int            `json:"fragmented_packets_count"`
	FragmentedPacketsRatio  float64        `json:"fragmented_packets_ratio"`
	PayloadMean             float64        `json:"payload_mean"`
	PayloadMin              int            `json:"payload_min"`
	PayloadMax              int            `json:"payload_max"`
	PayloadStdDev           float64        `json:"payload_stddev"`
	PayloadDistribution     map[string]int `json:"payload_distribution"`
	IATMeanMicroseconds     float64        `json:"iat_mean_us"`
	IATStdDevMicroseconds   float64        `json:"iat_stddev_us"`
	IATMinMicroseconds      float64        `json:"iat_min_us"`
	IATMaxMicroseconds      float64        `json:"iat_max_us"`
	TCPRetransmissionsCount int            `json:"tcp_retransmissions_count"`
	TCPRetransmissionRatio  float64        `json:"tcp_retransmission_ratio"`

	// Host & Port Cardinalities
	UniqueSourceIPs        int `json:"unique_source_ips"`
	UniqueDestinationIPs   int `json:"unique_destination_ips"`
	UniqueSourcePorts      int `json:"unique_source_ports"`
	UniqueDestinationPorts int `json:"unique_destination_ports"`

	// Protocol Dynamics
	TCPPackets                  int     `json:"tcp_packets"`
	SYNCount                    int     `json:"syn_count"`
	SYNACKCount                 int     `json:"syn_ack_count"`
	ACKCount                    int     `json:"ack_count"`
	RSTCount                    int     `json:"rst_count"`
	FINCount                    int     `json:"fin_count"`
	PSHCount                    int     `json:"psh_count"`
	URGCount                    int     `json:"urg_count"`
	SYNPerSecond                float64 `json:"syn_per_second"`
	ACKPerSecond                float64 `json:"ack_per_second"`
	RSTPerSecond                float64 `json:"rst_per_second"`
	SYNAckRatio                 float64 `json:"syn_ack_ratio"`
	ApproxIncompleteConnections int     `json:"approx_incomplete_connections"`

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

	// Graph & Flow State
	Graph       NetworkGraph `json:"graph"`
	ActiveFlows []FlowRecord `json:"active_flows,omitempty"`

	// Internal relational structures for deterministic rules
	SrcIPToDstPorts       map[string]map[uint16]int `json:"-"`
	SrcIPToDstIPs         map[string]map[string]int `json:"-"`
	SrcIPToPackets        map[string]int            `json:"-"`
	SrcIPToSYNs           map[string]int            `json:"-"`
	SrcIPToICMPEcho       map[string]map[string]int `json:"-"`
	SuspiciousFlagPackets []SuspiciousFlagRecord    `json:"-"`
	NullScanPackets       []SuspiciousFlagRecord    `json:"-"`
	XmasScanPackets       []SuspiciousFlagRecord    `json:"-"`
	FinScanPackets        []SuspiciousFlagRecord    `json:"-"`
}

type FeatureAggregator struct {
	windowIndex  int
	windowStart  time.Time
	windowEnd    time.Time
	totalPackets int
	totalBytes   int64

	// Packet stats accumulators
	ttlSum         float64
	ttlSumSq       float64
	ttlCount       int
	ttlMin         uint8
	ttlMax         uint8
	tcpWinSum      float64
	tcpWinSumSq    float64
	tcpWinCount    int
	tcpWinMin      uint16
	tcpWinMax      uint16
	fragCount      int
	payloadSum     float64
	payloadSumSq   float64
	payloadCount   int
	payloadMin     int
	payloadMax     int
	payloadBuckets map[string]int

	// IAT accumulators
	lastPacketTime time.Time
	iatSumUs       float64
	iatSumSqUs     float64
	iatCount       int
	iatMinUs       float64
	iatMaxUs       float64

	// Retransmissions
	seenTCPSeqs  map[string]time.Time
	retransCount int

	// Host & Protocol Tracking
	srcIPs           map[string]int
	dstIPs           map[string]int
	srcPorts         map[uint16]int
	dstPorts         map[uint16]int
	tcpPackets       int
	synCount         int
	synAckCount      int
	ackCount         int
	rstCount         int
	finCount         int
	pshCount         int
	urgCount         int
	udpPackets       int
	udpBytes         int64
	dnsPackets       int
	dnsBytes         int64
	icmpPackets      int
	icmpBytes        int64
	icmpEchoRequests int

	srcIPToDstPorts       map[string]map[uint16]int
	srcIPToDstIPs         map[string]map[string]int
	srcIPToPackets        map[string]int
	srcIPToSYNs           map[string]int
	srcIPToICMPEcho       map[string]map[string]int
	suspiciousFlagPackets []SuspiciousFlagRecord
	nullScanPackets       []SuspiciousFlagRecord
	xmasScanPackets       []SuspiciousFlagRecord
	finScanPackets        []SuspiciousFlagRecord

	graphBuilder *GraphBuilder
	flowTracker  *FlowTracker
}

func NewAggregator(windowIndex int, start, end time.Time, flowTracker *FlowTracker) *FeatureAggregator {
	return &FeatureAggregator{
		windowIndex: windowIndex,
		windowStart: start,
		windowEnd:   end,
		ttlMin:      255,
		tcpWinMin:   65535,
		payloadMin:  math.MaxInt32,
		iatMinUs:    math.MaxFloat64,
		payloadBuckets: map[string]int{
			"0_64":      0,
			"65_512":    0,
			"513_1024":  0,
			"1025_1500": 0,
			"1501_plus": 0,
		},
		seenTCPSeqs:           make(map[string]time.Time),
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
		graphBuilder:          NewGraphBuilder(5000, 20000),
		flowTracker:           flowTracker,
	}
}

func (a *FeatureAggregator) AddPacket(p *parser.ParsedPacket) {
	if p == nil {
		return
	}

	a.totalPackets++
	a.totalBytes += int64(p.Length)

	// 1. Inter-Arrival Time (IAT)
	if !a.lastPacketTime.IsZero() {
		iatUs := float64(p.Timestamp.Sub(a.lastPacketTime).Microseconds())
		if iatUs >= 0 {
			a.iatSumUs += iatUs
			a.iatSumSqUs += iatUs * iatUs
			a.iatCount++
			if iatUs < a.iatMinUs {
				a.iatMinUs = iatUs
			}
			if iatUs > a.iatMaxUs {
				a.iatMaxUs = iatUs
			}
		}
	}
	a.lastPacketTime = p.Timestamp

	// 2. TTL Statistics
	if p.HasIP {
		ttlVal := float64(p.TTL)
		a.ttlSum += ttlVal
		a.ttlSumSq += ttlVal * ttlVal
		a.ttlCount++
		if p.TTL < a.ttlMin {
			a.ttlMin = p.TTL
		}
		if p.TTL > a.ttlMax {
			a.ttlMax = p.TTL
		}
	}

	// 3. IP Fragmentation
	if p.IsFragmented {
		a.fragCount++
	}

	// 4. Payload Size Distribution
	payloadLen := p.PayloadLength
	a.payloadSum += float64(payloadLen)
	a.payloadSumSq += float64(payloadLen * payloadLen)
	a.payloadCount++
	if payloadLen < a.payloadMin {
		a.payloadMin = payloadLen
	}
	if payloadLen > a.payloadMax {
		a.payloadMax = payloadLen
	}

	if payloadLen <= 64 {
		a.payloadBuckets["0_64"]++
	} else if payloadLen <= 512 {
		a.payloadBuckets["65_512"]++
	} else if payloadLen <= 1024 {
		a.payloadBuckets["513_1024"]++
	} else if payloadLen <= 1500 {
		a.payloadBuckets["1025_1500"]++
	} else {
		a.payloadBuckets["1501_plus"]++
	}

	// 5. Host & Port Mappings
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

	// 6. Protocol Specifics
	switch p.Protocol {
	case "TCP":
		a.tcpPackets++
		f := p.TCPFlags

		// Window size stats
		winVal := float64(p.TCPWindowSize)
		a.tcpWinSum += winVal
		a.tcpWinSumSq += winVal * winVal
		a.tcpWinCount++
		if p.TCPWindowSize < a.tcpWinMin {
			a.tcpWinMin = p.TCPWindowSize
		}
		if p.TCPWindowSize > a.tcpWinMax {
			a.tcpWinMax = p.TCPWindowSize
		}

		// Retransmission check
		if srcIPStr != "" && dstIPStr != "" && (p.PayloadLength > 0 || f.SYN || f.FIN) {
			seqKey := fmt.Sprintf("%s:%d->%s:%d#%d#%d", srcIPStr, p.SrcPort, dstIPStr, p.DstPort, p.TCPSeq, p.PayloadLength)
			if lastTime, seen := a.seenTCPSeqs[seqKey]; seen {
				if p.Timestamp.Sub(lastTime) > 2*time.Millisecond {
					a.retransCount++
				}
			} else {
				a.seenTCPSeqs[seqKey] = p.Timestamp
			}
		}

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

		// Stealth Scan Detections
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

	// 7. Graph Representation Accumulator
	if a.graphBuilder != nil {
		isSYN := (p.Protocol == "TCP" && p.TCPFlags.SYN)
		isACK := (p.Protocol == "TCP" && p.TCPFlags.ACK)
		isRST := (p.Protocol == "TCP" && p.TCPFlags.RST)
		a.graphBuilder.AddPacket(srcIPStr, dstIPStr, p.SrcPort, p.DstPort, p.Length, p.Protocol, isSYN, isACK, isRST)
		a.graphBuilder.AddDNSHostnames(p.DNSHostnames)
	}

	// 8. Bidirectional Flow Tracking
	if a.flowTracker != nil {
		a.flowTracker.ProcessPacket(p)
	}
}

func calcMeanAndStdDev(sum, sumSq float64, count int) (mean, stdDev float64) {
	if count <= 0 {
		return 0, 0
	}
	mean = sum / float64(count)
	variance := (sumSq / float64(count)) - (mean * mean)
	if variance > 0 {
		stdDev = math.Sqrt(variance)
	}
	return math.Round(mean*100) / 100, math.Round(stdDev*100) / 100
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

	// Statistical calculations
	ttlMean, ttlStdDev := calcMeanAndStdDev(a.ttlSum, a.ttlSumSq, a.ttlCount)
	tcpWinMean, tcpWinStdDev := calcMeanAndStdDev(a.tcpWinSum, a.tcpWinSumSq, a.tcpWinCount)
	payloadMean, payloadStdDev := calcMeanAndStdDev(a.payloadSum, a.payloadSumSq, a.payloadCount)
	iatMean, iatStdDev := calcMeanAndStdDev(a.iatSumUs, a.iatSumSqUs, a.iatCount)

	minTTL := a.ttlMin
	if a.ttlCount == 0 {
		minTTL = 0
	}
	minTCPWin := a.tcpWinMin
	if a.tcpWinCount == 0 {
		minTCPWin = 0
	}
	minPayload := a.payloadMin
	if a.payloadCount == 0 {
		minPayload = 0
	}
	minIAT := a.iatMinUs
	if a.iatCount == 0 {
		minIAT = 0
	}

	var fragRatio float64
	if a.totalPackets > 0 {
		fragRatio = math.Round((float64(a.fragCount)/float64(a.totalPackets))*10000) / 10000
	}

	var retransRatio float64
	if a.tcpPackets > 0 {
		retransRatio = math.Round((float64(a.retransCount)/float64(a.tcpPackets))*10000) / 10000
	}

	// Graph calculation
	var netGraph NetworkGraph
	if a.graphBuilder != nil {
		netGraph = a.graphBuilder.BuildGraph()
	}

	// Active flows snapshot
	var activeFlows []FlowRecord
	if a.flowTracker != nil {
		activeFlows = a.flowTracker.SnapshotActiveFlows(a.windowStart, a.windowEnd, 500)
		a.flowTracker.Prune(a.windowEnd)
	}

	return &WindowFeatures{
		SchemaVersion:               "2.0",
		WindowIndex:                 a.windowIndex,
		WindowStart:                 a.windowStart,
		WindowEnd:                   a.windowEnd,
		DurationSeconds:             duration,
		TotalPackets:                a.totalPackets,
		TotalBytes:                  a.totalBytes,
		PacketsPerSecond:            math.Round(pps*100) / 100,
		BytesPerSecond:              math.Round(bps*100) / 100,
		TTLMean:                     ttlMean,
		TTLMin:                      minTTL,
		TTLMax:                      a.ttlMax,
		TTLStdDev:                   ttlStdDev,
		TCPWindowMean:               tcpWinMean,
		TCPWindowMin:                minTCPWin,
		TCPWindowMax:                a.tcpWinMax,
		TCPWindowStdDev:             tcpWinStdDev,
		FragmentedPacketsCount:      a.fragCount,
		FragmentedPacketsRatio:      fragRatio,
		PayloadMean:                 payloadMean,
		PayloadMin:                  minPayload,
		PayloadMax:                  a.payloadMax,
		PayloadStdDev:               payloadStdDev,
		PayloadDistribution:         a.payloadBuckets,
		IATMeanMicroseconds:         iatMean,
		IATStdDevMicroseconds:       iatStdDev,
		IATMinMicroseconds:          math.Round(minIAT*10) / 10,
		IATMaxMicroseconds:          math.Round(a.iatMaxUs*10) / 10,
		TCPRetransmissionsCount:     a.retransCount,
		TCPRetransmissionRatio:      retransRatio,
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
		Graph:                       netGraph,
		ActiveFlows:                 activeFlows,
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
