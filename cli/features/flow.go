package features

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"detector/parser"
	"detector/semantics"
)

type FlowRecord struct {
	semantics.Tags
	FlowID                 string    `json:"flow_id"`
	Protocol               string    `json:"protocol"`
	InitiatorIP            string    `json:"initiator_ip"`
	InitiatorPort          uint16    `json:"initiator_port"`
	ResponderIP            string    `json:"responder_ip"`
	ResponderPort          uint16    `json:"responder_port"`
	StartTime              time.Time `json:"start_time"`
	LastSeen               time.Time `json:"last_seen"`
	DurationSeconds        float64   `json:"duration_seconds"`
	State                  string    `json:"state"`
	ForwardPackets         int       `json:"fwd_packets"`
	BackwardPackets        int       `json:"bwd_packets"`
	TotalPackets           int       `json:"total_packets"`
	ForwardBytes           int64     `json:"fwd_bytes"`
	BackwardBytes          int64     `json:"bwd_bytes"`
	TotalBytes             int64     `json:"total_bytes"`
	ForwardPayloadBytes    int64     `json:"fwd_payload_bytes"`
	BackwardPayloadBytes   int64     `json:"bwd_payload_bytes"`
	FwdIATMeanMicroseconds float64   `json:"fwd_iat_mean_us"`
	BwdIATMeanMicroseconds float64   `json:"bwd_iat_mean_us"`
	FwdIATMaxMicroseconds  float64   `json:"fwd_iat_max_us"`
	BwdIATMaxMicroseconds  float64   `json:"bwd_iat_max_us"`
	FwdPacketLenMean       float64   `json:"fwd_pkt_len_mean"`
	BwdPacketLenMean       float64   `json:"bwd_pkt_len_mean"`
	SYNCount               int       `json:"syn_count"`
	SYNACKCount            int       `json:"syn_ack_count"`
	RSTCount               int       `json:"rst_count"`
	FINCount               int       `json:"fin_count"`

	// Internal state tracking
	lastFwdTime  time.Time
	lastBwdTime  time.Time
	fwdIATSumUs  float64
	bwdIATSumUs  float64
	fwdIATCount  int
	bwdIATCount  int
	fwdPktLenSum int64
	bwdPktLenSum int64
}

type FlowTracker struct {
	mu           sync.RWMutex
	flows        map[string]*FlowRecord
	idleTimeout  time.Duration
	maxFlowCount int
}

func NewFlowTracker(idleTimeout time.Duration, maxFlows int) *FlowTracker {
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	if maxFlows <= 0 {
		maxFlows = 10000
	}
	return &FlowTracker{
		flows:        make(map[string]*FlowRecord),
		idleTimeout:  idleTimeout,
		maxFlowCount: maxFlows,
	}
}

func canonicalKey(ip1, ip2 string, port1, port2 uint16, proto string) string {
	if ip1 < ip2 || (ip1 == ip2 && port1 <= port2) {
		return fmt.Sprintf("%s:%d<->%s:%d(%s)", ip1, port1, ip2, port2, proto)
	}
	return fmt.Sprintf("%s:%d<->%s:%d(%s)", ip2, port2, ip1, port1, proto)
}

func (ft *FlowTracker) ProcessPacket(p *parser.ParsedPacket) {
	if p == nil || !p.HasIP || p.SrcIP == nil || p.DstIP == nil {
		return
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	srcIPStr := p.SrcIP.String()
	dstIPStr := p.DstIP.String()
	key := canonicalKey(srcIPStr, dstIPStr, p.SrcPort, p.DstPort, p.Protocol)

	flow, exists := ft.flows[key]
	if !exists {
		// Enforce bounded memory size before inserting
		if len(ft.flows) >= ft.maxFlowCount {
			ft.pruneLocked(p.Timestamp, true)
		}

		initialState := "INIT"
		if p.Protocol == "UDP" {
			initialState = "UDP_ACTIVE"
		} else if p.Protocol == "ICMP" || p.Protocol == "ICMPv6" {
			initialState = "ICMP_ACTIVE"
		} else if p.Protocol == "TCP" {
			if p.TCPFlags.SYN && !p.TCPFlags.ACK {
				initialState = "SYN_SENT"
			}
		}

		flow = &FlowRecord{
			Tags:          p.Tags,
			FlowID:        key,
			Protocol:      p.Protocol,
			InitiatorIP:   srcIPStr,
			InitiatorPort: p.SrcPort,
			ResponderIP:   dstIPStr,
			ResponderPort: p.DstPort,
			StartTime:     p.Timestamp,
			LastSeen:      p.Timestamp,
			State:         initialState,
		}
		ft.flows[key] = flow
	}

	flow.LastSeen = p.Timestamp
	flow.TotalPackets++
	flow.TotalBytes += int64(p.Length)
	flow.DurationSeconds = math.Round(flow.LastSeen.Sub(flow.StartTime).Seconds()*1000) / 1000

	isFwd := (srcIPStr == flow.InitiatorIP && p.SrcPort == flow.InitiatorPort)
	if !isFwd {
		// Only label a reverse packet as a response when this flow has a
		// preceding request. TCP additionally needs established state.
		corroborated := flow.ForwardPackets > 0 && (p.Protocol == "UDP" || (flow.SYNACKCount > 0 && (flow.State == "ESTABLISHED" || flow.State == "FIN_WAIT")))
		p.Tags = semantics.Classify(semantics.Observation{Transport: p.Protocol, SrcIP: srcIPStr, DstIP: dstIPStr, SrcPort: p.SrcPort, DstPort: p.DstPort, Established: corroborated})
	}

	if isFwd {
		flow.ForwardPackets++
		flow.ForwardBytes += int64(p.Length)
		flow.ForwardPayloadBytes += int64(p.PayloadLength)
		flow.fwdPktLenSum += int64(p.Length)
		flow.FwdPacketLenMean = math.Round(float64(flow.fwdPktLenSum)/float64(flow.ForwardPackets)*10) / 10

		if !flow.lastFwdTime.IsZero() {
			iatUs := float64(p.Timestamp.Sub(flow.lastFwdTime).Microseconds())
			if iatUs >= 0 {
				flow.fwdIATSumUs += iatUs
				flow.fwdIATCount++
				flow.FwdIATMeanMicroseconds = math.Round(flow.fwdIATSumUs/float64(flow.fwdIATCount)*10) / 10
				if iatUs > flow.FwdIATMaxMicroseconds {
					flow.FwdIATMaxMicroseconds = iatUs
				}
			}
		}
		flow.lastFwdTime = p.Timestamp
	} else {
		flow.BackwardPackets++
		flow.BackwardBytes += int64(p.Length)
		flow.BackwardPayloadBytes += int64(p.PayloadLength)
		flow.bwdPktLenSum += int64(p.Length)
		flow.BwdPacketLenMean = math.Round(float64(flow.bwdPktLenSum)/float64(flow.BackwardPackets)*10) / 10

		if !flow.lastBwdTime.IsZero() {
			iatUs := float64(p.Timestamp.Sub(flow.lastBwdTime).Microseconds())
			if iatUs >= 0 {
				flow.bwdIATSumUs += iatUs
				flow.bwdIATCount++
				flow.BwdIATMeanMicroseconds = math.Round(flow.bwdIATSumUs/float64(flow.bwdIATCount)*10) / 10
				if iatUs > flow.BwdIATMaxMicroseconds {
					flow.BwdIATMaxMicroseconds = iatUs
				}
			}
		}
		flow.lastBwdTime = p.Timestamp
	}

	// TCP State Machine Updating
	if p.Protocol == "TCP" {
		f := p.TCPFlags
		if f.SYN && f.ACK {
			flow.SYNACKCount++
			if flow.State == "SYN_SENT" || flow.State == "INIT" {
				flow.State = "ESTABLISHED"
			}
		} else if f.SYN {
			flow.SYNCount++
			if flow.State == "INIT" {
				flow.State = "SYN_SENT"
			}
		}

		if f.ACK && !f.SYN && !f.FIN && !f.RST {
			if flow.State == "SYN_SENT" {
				flow.State = "ESTABLISHED"
			}
		}

		if f.FIN {
			flow.FINCount++
			if flow.State == "ESTABLISHED" {
				flow.State = "FIN_WAIT"
			} else if flow.State == "FIN_WAIT" {
				flow.State = "CLOSED"
			}
		}

		if f.RST {
			flow.RSTCount++
			flow.State = "RESET"
		}
	}
}

func (ft *FlowTracker) Prune(now time.Time) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.pruneLocked(now, false)
}

func (ft *FlowTracker) pruneLocked(now time.Time, forceTrim bool) {
	// 1. Remove expired flows based on idle timeout
	for key, flow := range ft.flows {
		if now.Sub(flow.LastSeen) > ft.idleTimeout || flow.State == "CLOSED" || flow.State == "RESET" {
			delete(ft.flows, key)
		}
	}

	// 2. If table is still over limit, trim oldest flows
	if forceTrim && len(ft.flows) >= ft.maxFlowCount {
		type flowAge struct {
			key      string
			lastSeen time.Time
		}
		ages := make([]flowAge, 0, len(ft.flows))
		for k, f := range ft.flows {
			ages = append(ages, flowAge{key: k, lastSeen: f.LastSeen})
		}
		sort.Slice(ages, func(i, j int) bool {
			return ages[i].lastSeen.Before(ages[j].lastSeen)
		})

		// Evict oldest 20%
		evictCount := len(ages) / 5
		if evictCount < 1 {
			evictCount = 1
		}
		for i := 0; i < evictCount && i < len(ages); i++ {
			delete(ft.flows, ages[i].key)
		}
	}
}

func (ft *FlowTracker) SnapshotActiveFlows(windowStart, windowEnd time.Time, maxSnapshot int) []FlowRecord {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	if maxSnapshot <= 0 {
		maxSnapshot = 1000
	}

	active := make([]FlowRecord, 0, min(len(ft.flows), maxSnapshot))
	for _, flow := range ft.flows {
		// Include if flow had activity in this window
		if !flow.LastSeen.Before(windowStart) && !flow.StartTime.After(windowEnd) {
			active = append(active, *flow)
			if len(active) >= maxSnapshot {
				break
			}
		}
	}
	return active
}

func (ft *FlowTracker) TotalActiveFlowsCount() int {
	ft.mu.RLock()
	defer ft.mu.RUnlock()
	return len(ft.flows)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
