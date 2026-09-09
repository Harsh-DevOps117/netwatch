package pipeline

import (
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"netflow/models"
)

// packetMeta holds essential fields of a single packet for flow feature calculation.
type packetMeta struct {
	Timestamp  time.Time
	Length     int
	HeaderLen  int
	TCPFlags   uint8 // Bitfield: FIN(1), SYN(2), RST(4), PSH(8), ACK(16), URG(32), ECE(64), CWR(128)
	WinSize    int
	IsForward  bool
	HasPayload bool
}

// internalFlow aggregates packets sharing a bidirectional 5-tuple.
type internalFlow struct {
	ID         string
	SrcIP      string
	DstIP      string
	SrcPort    int
	DstPort    int
	Protocol   int
	StartTime  time.Time
	LastTime   time.Time
	FwdPackets []packetMeta
	BwdPackets []packetMeta
	AllPackets []packetMeta
}

// ProcessPcapFile parses a PCAP file and extracts CICFlowMeter flow features.
func ProcessPcapFile(pcapPath string) ([]*models.FlowFeature, error) {
	file, err := os.Open(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file '%s': %w", pcapPath, err)
	}
	defer file.Close()

	pcapReader, err := pcapgo.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize pcap reader: %w", err)
	}

	flows := make(map[string]*internalFlow)

	for {
		data, ci, err := pcapReader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if packet == nil {
			continue
		}

		processPacketIntoFlows(packet, ci.Timestamp, ci.Length, flows)
	}

	var features []*models.FlowFeature
	for _, flow := range flows {
		feat := calculateFeaturesForFlow(flow)
		if feat != nil {
			features = append(features, feat)
		}
	}

	return features, nil
}

// processPacketIntoFlows extracts 5-tuple from a packet and appends to the corresponding internalFlow.
func processPacketIntoFlows(packet gopacket.Packet, ts time.Time, capLen int, flows map[string]*internalFlow) {
	var srcIP, dstIP string
	var srcPort, dstPort, proto int

	// IP Layer
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		srcIP = ip4.SrcIP.String()
		dstIP = ip4.DstIP.String()
		proto = int(ip4.Protocol)
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		srcIP = ip6.SrcIP.String()
		dstIP = ip6.DstIP.String()
		proto = int(ip6.NextHeader)
	} else {
		return // Ignore non-IP packets
	}

	var tcpFlags uint8
	var winSize int
	var headerLen int

	// Transport Layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
		winSize = int(tcp.Window)
		headerLen = len(tcp.Contents)

		if tcp.FIN {
			tcpFlags |= 1
		}
		if tcp.SYN {
			tcpFlags |= 2
		}
		if tcp.RST {
			tcpFlags |= 4
		}
		if tcp.PSH {
			tcpFlags |= 8
		}
		if tcp.ACK {
			tcpFlags |= 16
		}
		if tcp.URG {
			tcpFlags |= 32
		}
		if tcp.ECE {
			tcpFlags |= 64
		}
		if tcp.CWR {
			tcpFlags |= 128
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = int(udp.SrcPort)
		dstPort = int(udp.DstPort)
		headerLen = 8
	} else {
		srcPort = 0
		dstPort = 0
	}

	hasPayload := false
	if appLayer := packet.ApplicationLayer(); appLayer != nil && len(appLayer.Payload()) > 0 {
		hasPayload = true
	}

	// Determine Bidirectional Key
	fwdKey := fmt.Sprintf("%s:%d-%s:%d-%d", srcIP, srcPort, dstIP, dstPort, proto)
	bwdKey := fmt.Sprintf("%s:%d-%s:%d-%d", dstIP, dstPort, srcIP, srcPort, proto)

	var flow *internalFlow
	isForward := true

	if f, exists := flows[fwdKey]; exists {
		flow = f
		isForward = true
	} else if f, exists := flows[bwdKey]; exists {
		flow = f
		isForward = false
	} else {
		// New Flow
		flow = &internalFlow{
			ID:        fwdKey,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  proto,
			StartTime: ts,
			LastTime:  ts,
		}
		flows[fwdKey] = flow
		isForward = true
	}

	if ts.After(flow.LastTime) {
		flow.LastTime = ts
	}

	pm := packetMeta{
		Timestamp:  ts,
		Length:     capLen,
		HeaderLen:  headerLen,
		TCPFlags:   tcpFlags,
		WinSize:    winSize,
		IsForward:  isForward,
		HasPayload: hasPayload,
	}

	flow.AllPackets = append(flow.AllPackets, pm)
	if isForward {
		flow.FwdPackets = append(flow.FwdPackets, pm)
	} else {
		flow.BwdPackets = append(flow.BwdPackets, pm)
	}
}

// calculateFeaturesForFlow computes all 80+ CICFlowMeter statistical features for a flow.
func calculateFeaturesForFlow(flow *internalFlow) *models.FlowFeature {
	if flow == nil || len(flow.AllPackets) == 0 {
		return nil
	}

	durationMicro := flow.LastTime.Sub(flow.StartTime).Microseconds()
	if durationMicro < 0 {
		durationMicro = 0
	}
	durationSec := float64(durationMicro) / 1000000.0

	var totalFwdBytes, totalBwdBytes int64
	var fwdLengths, bwdLengths, allLengths []float64
	var fwdHeaderLen, bwdHeaderLen int64
	var fwdPSH, bwdPSH, fwdURG, bwdURG int
	var finCount, synCount, rstCount, pshCount, ackCount, urgCount, cweCount, eceCount int
	var initWinFwd, initWinBwd int
	var actDataPktFwd int64
	var minSegSizeFwd int64 = -1

	initWinFwdSet, initWinBwdSet := false, false

	for _, p := range flow.AllPackets {
		allLengths = append(allLengths, float64(p.Length))

		// Flag Counts
		if p.TCPFlags&1 != 0 {
			finCount++
		}
		if p.TCPFlags&2 != 0 {
			synCount++
		}
		if p.TCPFlags&4 != 0 {
			rstCount++
		}
		if p.TCPFlags&8 != 0 {
			pshCount++
		}
		if p.TCPFlags&16 != 0 {
			ackCount++
		}
		if p.TCPFlags&32 != 0 {
			urgCount++
		}
		if p.TCPFlags&64 != 0 {
			eceCount++
		}
		if p.TCPFlags&128 != 0 {
			cweCount++
		}

		if p.IsForward {
			totalFwdBytes += int64(p.Length)
			fwdLengths = append(fwdLengths, float64(p.Length))
			fwdHeaderLen += int64(p.HeaderLen)

			if p.TCPFlags&8 != 0 {
				fwdPSH++
			}
			if p.TCPFlags&32 != 0 {
				fwdURG++
			}
			if !initWinFwdSet && p.WinSize > 0 {
				initWinFwd = p.WinSize
				initWinFwdSet = true
			}
			if p.HasPayload {
				actDataPktFwd++
			}
			if minSegSizeFwd == -1 || int64(p.HeaderLen) < minSegSizeFwd {
				minSegSizeFwd = int64(p.HeaderLen)
			}
		} else {
			totalBwdBytes += int64(p.Length)
			bwdLengths = append(bwdLengths, float64(p.Length))
			bwdHeaderLen += int64(p.HeaderLen)

			if p.TCPFlags&8 != 0 {
				bwdPSH++
			}
			if p.TCPFlags&32 != 0 {
				bwdURG++
			}
			if !initWinBwdSet && p.WinSize > 0 {
				initWinBwd = p.WinSize
				initWinBwdSet = true
			}
		}
	}

	if minSegSizeFwd == -1 {
		minSegSizeFwd = 0
	}

	// Length Statistics
	fwdMin, fwdMax, fwdMean, fwdStd := calcStats(fwdLengths)
	bwdMin, bwdMax, bwdMean, bwdStd := calcStats(bwdLengths)
	allMin, allMax, allMean, allStd := calcStats(allLengths)
	allVar := allStd * allStd

	// IAT (Inter-Arrival Time) Statistics (in Microseconds)
	flowIATs := calcIATs(flow.AllPackets)
	fwdIATs := calcIATs(flow.FwdPackets)
	bwdIATs := calcIATs(flow.BwdPackets)

	_, _, flowIATMean, flowIATStd := calcStats(flowIATs)
	flowIATMin, flowIATMax := minMax(flowIATs)

	fwdIATSum, _, fwdIATMean, fwdIATStd := calcStats(fwdIATs)
	fwdIATMin, fwdIATMax := minMax(fwdIATs)

	bwdIATSum, _, bwdIATMean, bwdIATStd := calcStats(bwdIATs)
	bwdIATMin, bwdIATMax := minMax(bwdIATs)

	// Rates
	var flowBytesPerSec, flowPktsPerSec, fwdPktsPerSec, bwdPktsPerSec float64
	if durationSec > 0 {
		flowBytesPerSec = float64(totalFwdBytes+totalBwdBytes) / durationSec
		flowPktsPerSec = float64(len(flow.AllPackets)) / durationSec
		fwdPktsPerSec = float64(len(flow.FwdPackets)) / durationSec
		bwdPktsPerSec = float64(len(flow.BwdPackets)) / durationSec
	}

	// Down/Up Ratio
	var downUpRatio float64
	if len(flow.FwdPackets) > 0 {
		downUpRatio = float64(len(flow.BwdPackets)) / float64(len(flow.FwdPackets))
	}

	// Active and Idle Calculation (Threshold: 5 seconds = 5,000,000 microseconds)
	activeList, idleList := calcActiveIdle(flow.AllPackets, 5000000.0)
	_, _, activeMean, activeStd := calcStats(activeList)
	activeMin, activeMax := minMax(activeList)
	_, _, idleMean, idleStd := calcStats(idleList)
	idleMin, idleMax := minMax(idleList)

	return &models.FlowFeature{
		FlowID:                flow.ID,
		SourceIP:              flow.SrcIP,
		SourcePort:            flow.SrcPort,
		DestinationIP:         flow.DstIP,
		DestinationPort:       flow.DstPort,
		Protocol:              flow.Protocol,
		Timestamp:             flow.StartTime.Format("2006-01-02 15:04:05"),
		FlowDuration:          durationMicro,
		TotalFwdPackets:       int64(len(flow.FwdPackets)),
		TotalBackwardPackets:  int64(len(flow.BwdPackets)),
		TotalLengthFwdPackets: totalFwdBytes,
		TotalLengthBwdPackets: totalBwdBytes,
		FwdPacketLengthMax:    fwdMax,
		FwdPacketLengthMin:    fwdMin,
		FwdPacketLengthMean:   fwdMean,
		FwdPacketLengthStd:    fwdStd,
		BwdPacketLengthMax:    bwdMax,
		BwdPacketLengthMin:    bwdMin,
		BwdPacketLengthMean:   bwdMean,
		BwdPacketLengthStd:    bwdStd,
		FlowBytesPerSec:       flowBytesPerSec,
		FlowPacketsPerSec:     flowPktsPerSec,
		FlowIATMean:           flowIATMean,
		FlowIATStd:            flowIATStd,
		FlowIATMax:            flowIATMax,
		FlowIATMin:            flowIATMin,
		FwdIATTotal:           fwdIATSum,
		FwdIATMean:            fwdIATMean,
		FwdIATStd:             fwdIATStd,
		FwdIATMax:             fwdIATMax,
		FwdIATMin:             fwdIATMin,
		BwdIATTotal:           bwdIATSum,
		BwdIATMean:            bwdIATMean,
		BwdIATStd:             bwdIATStd,
		BwdIATMax:             bwdIATMax,
		BwdIATMin:             bwdIATMin,
		FwdPSHFlags:           fwdPSH,
		BwdPSHFlags:           bwdPSH,
		FwdURGFlags:           fwdURG,
		BwdURGFlags:           bwdURG,
		FwdHeaderLength:       fwdHeaderLen,
		BwdHeaderLength:       bwdHeaderLen,
		FwdPacketsPerSec:      fwdPktsPerSec,
		BwdPacketsPerSec:      bwdPktsPerSec,
		MinPacketLength:       allMin,
		MaxPacketLength:       allMax,
		PacketLengthMean:      allMean,
		PacketLengthStd:       allStd,
		PacketLengthVariance:  allVar,
		FINFlagCount:          finCount,
		SYNFlagCount:          synCount,
		RSTFlagCount:          rstCount,
		PSHFlagCount:          pshCount,
		ACKFlagCount:          ackCount,
		URGFlagCount:          urgCount,
		CWEFlagCount:          cweCount,
		ECEFlagCount:          eceCount,
		DownUpRatio:           downUpRatio,
		AveragePacketSize:     allMean,
		AvgFwdSegmentSize:     fwdMean,
		AvgBwdSegmentSize:     bwdMean,
		SubflowFwdPackets:     int64(len(flow.FwdPackets)),
		SubflowFwdBytes:       totalFwdBytes,
		SubflowBwdPackets:     int64(len(flow.BwdPackets)),
		SubflowBwdBytes:       totalBwdBytes,
		InitWinBytesForward:   initWinFwd,
		InitWinBytesBackward:  initWinBwd,
		ActDataPktFwd:         actDataPktFwd,
		MinSegSizeForward:     minSegSizeFwd,
		ActiveMean:            activeMean,
		ActiveStd:             activeStd,
		ActiveMax:             activeMax,
		ActiveMin:             activeMin,
		IdleMean:              idleMean,
		IdleStd:               idleStd,
		IdleMax:               idleMax,
		IdleMin:               idleMin,
	}
}

// calcIATs returns inter-arrival times in microseconds between consecutive packets.
func calcIATs(packets []packetMeta) []float64 {
	if len(packets) < 2 {
		return nil
	}
	var iats []float64
	for i := 1; i < len(packets); i++ {
		diff := float64(packets[i].Timestamp.Sub(packets[i-1].Timestamp).Microseconds())
		if diff < 0 {
			diff = 0
		}
		iats = append(iats, diff)
	}
	return iats
}

// calcStats returns sum, min, max, mean, stddev for a float64 slice.
func calcStats(vals []float64) (min float64, max float64, mean float64, std float64) {
	if len(vals) == 0 {
		return 0, 0, 0, 0
	}
	var sum float64
	min = vals[0]
	max = vals[0]

	for _, v := range vals {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	n := float64(len(vals))
	mean = sum / n

	if len(vals) < 2 {
		return min, max, mean, 0
	}

	var varianceSum float64
	for _, v := range vals {
		varianceSum += (v - mean) * (v - mean)
	}
	std = math.Sqrt(varianceSum / (n - 1))
	return min, max, mean, std
}

// minMax returns min and max values for a slice.
func minMax(vals []float64) (min float64, max float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	min, max = vals[0], vals[0]
	for _, v := range vals {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max
}

// calcActiveIdle calculates active and idle duration statistics based on an idle threshold in microseconds.
func calcActiveIdle(packets []packetMeta, idleThresholdMicro float64) (actives []float64, idles []float64) {
	if len(packets) < 2 {
		return nil, nil
	}

	lastTime := packets[0].Timestamp
	activeStart := packets[0].Timestamp

	for i := 1; i < len(packets); i++ {
		gap := float64(packets[i].Timestamp.Sub(lastTime).Microseconds())
		if gap >= idleThresholdMicro {
			activeDuration := float64(lastTime.Sub(activeStart).Microseconds())
			if activeDuration > 0 {
				actives = append(actives, activeDuration)
			}
			idles = append(idles, gap)
			activeStart = packets[i].Timestamp
		}
		lastTime = packets[i].Timestamp
	}

	finalActive := float64(lastTime.Sub(activeStart).Microseconds())
	if finalActive > 0 {
		actives = append(actives, finalActive)
	}

	return actives, idles
}
