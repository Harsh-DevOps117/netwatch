package features

import (
	"math"
	"sort"
)

type HostNode struct {
	IP                       string   `json:"ip"`
	Hostnames                []string `json:"hostnames,omitempty"`
	OutDegree                int      `json:"out_degree"`
	InDegree                 int      `json:"in_degree"`
	PacketsSent              int      `json:"packets_sent"`
	PacketsReceived          int      `json:"packets_received"`
	BytesSent                int64    `json:"bytes_sent"`
	BytesReceived            int64    `json:"bytes_received"`
	DistinctPortsContacted   int      `json:"distinct_ports_contacted"`
	IncompleteConnsInitiated int      `json:"incomplete_conns_initiated"`
}

type HostEdge struct {
	SrcIP            string   `json:"src_ip"`
	DstIP            string   `json:"dst_ip"`
	PacketCount      int      `json:"packet_count"`
	ByteCount        int64    `json:"byte_count"`
	Protocols        []string `json:"protocols"`
	DistinctDstPorts int      `json:"distinct_dst_ports"`
	SYNCount         int      `json:"syn_count"`
	ACKCount         int      `json:"ack_count"`
	RSTCount         int      `json:"rst_count"`
}

type NetworkGraph struct {
	TotalNodes int        `json:"total_nodes"`
	TotalEdges int        `json:"total_edges"`
	Density    float64    `json:"density"`
	Nodes      []HostNode `json:"nodes"`
	Edges      []HostEdge `json:"edges"`
}

type edgeAccumulator struct {
	srcIP       string
	dstIP       string
	packetCount int
	byteCount   int64
	protocols   map[string]bool
	dstPorts    map[uint16]bool
	synCount    int
	ackCount    int
	rstCount    int
}

type GraphBuilder struct {
	nodes     map[string]*HostNode
	edges     map[string]*edgeAccumulator
	srcPorts  map[string]map[uint16]bool
	hostnames map[string]map[string]bool
	maxNodes  int
	maxEdges  int
}

func NewGraphBuilder(maxNodes, maxEdges int) *GraphBuilder {
	if maxNodes <= 0 {
		maxNodes = 5000
	}
	if maxEdges <= 0 {
		maxEdges = 20000
	}
	return &GraphBuilder{
		nodes:     make(map[string]*HostNode),
		edges:     make(map[string]*edgeAccumulator),
		srcPorts:  make(map[string]map[uint16]bool),
		hostnames: make(map[string]map[string]bool),
		maxNodes:  maxNodes,
		maxEdges:  maxEdges,
	}
}

// AddDNSHostnames records only domains carried in captured DNS answer packets.
// It never performs external resolution and therefore cannot invent host labels.
func (gb *GraphBuilder) AddDNSHostnames(names map[string]string) {
	for ip, hostname := range names {
		if ip == "" || hostname == "" {
			continue
		}
		if gb.hostnames[ip] == nil {
			gb.hostnames[ip] = make(map[string]bool)
		}
		gb.hostnames[ip][hostname] = true
	}
}

func (gb *GraphBuilder) AddPacket(srcIP, dstIP string, srcPort, dstPort uint16, length int, proto string, isSYN, isACK, isRST bool) {
	if srcIP == "" || dstIP == "" {
		return
	}

	// Update Source Node
	srcNode, exists := gb.nodes[srcIP]
	if !exists && len(gb.nodes) < gb.maxNodes {
		srcNode = &HostNode{IP: srcIP}
		gb.nodes[srcIP] = srcNode
	}
	if srcNode != nil {
		srcNode.PacketsSent++
		srcNode.BytesSent += int64(length)
		if isSYN && !isACK {
			srcNode.IncompleteConnsInitiated++
		}
	}

	// Update Destination Node
	dstNode, exists := gb.nodes[dstIP]
	if !exists && len(gb.nodes) < gb.maxNodes {
		dstNode = &HostNode{IP: dstIP}
		gb.nodes[dstIP] = dstNode
	}
	if dstNode != nil {
		dstNode.PacketsReceived++
		dstNode.BytesReceived += int64(length)
	}

	// Track Distinct Ports Contacted
	if dstPort > 0 {
		if gb.srcPorts[srcIP] == nil {
			gb.srcPorts[srcIP] = make(map[uint16]bool)
		}
		gb.srcPorts[srcIP][dstPort] = true
	}

	// Update Directed Edge
	edgeKey := srcIP + "->" + dstIP
	edge, exists := gb.edges[edgeKey]
	if !exists && len(gb.edges) < gb.maxEdges {
		edge = &edgeAccumulator{
			srcIP:     srcIP,
			dstIP:     dstIP,
			protocols: make(map[string]bool),
			dstPorts:  make(map[uint16]bool),
		}
		gb.edges[edgeKey] = edge
	}

	if edge != nil {
		edge.packetCount++
		edge.byteCount += int64(length)
		if proto != "" {
			edge.protocols[proto] = true
		}
		if dstPort > 0 {
			edge.dstPorts[dstPort] = true
		}
		if isSYN {
			edge.synCount++
		}
		if isACK {
			edge.ackCount++
		}
		if isRST {
			edge.rstCount++
		}
	}
}

func (gb *GraphBuilder) BuildGraph() NetworkGraph {
	// Calculate in-degree, out-degree, distinct ports
	for _, edge := range gb.edges {
		if srcNode, ok := gb.nodes[edge.srcIP]; ok {
			srcNode.OutDegree++
		}
		if dstNode, ok := gb.nodes[edge.dstIP]; ok {
			dstNode.InDegree++
		}
	}

	for ip, ports := range gb.srcPorts {
		if node, ok := gb.nodes[ip]; ok {
			node.DistinctPortsContacted = len(ports)
		}
	}
	for ip, names := range gb.hostnames {
		if node, ok := gb.nodes[ip]; ok {
			node.Hostnames = node.Hostnames[:0]
			for hostname := range names {
				node.Hostnames = append(node.Hostnames, hostname)
			}
			sort.Strings(node.Hostnames)
		}
	}

	nodeList := make([]HostNode, 0, len(gb.nodes))
	for _, n := range gb.nodes {
		nodeList = append(nodeList, *n)
	}
	sort.Slice(nodeList, func(i, j int) bool {
		return nodeList[i].PacketsSent+nodeList[i].PacketsReceived > nodeList[j].PacketsSent+nodeList[j].PacketsReceived
	})

	edgeList := make([]HostEdge, 0, len(gb.edges))
	for _, e := range gb.edges {
		protos := make([]string, 0, len(e.protocols))
		for p := range e.protocols {
			protos = append(protos, p)
		}
		sort.Strings(protos)

		edgeList = append(edgeList, HostEdge{
			SrcIP:            e.srcIP,
			DstIP:            e.dstIP,
			PacketCount:      e.packetCount,
			ByteCount:        e.byteCount,
			Protocols:        protos,
			DistinctDstPorts: len(e.dstPorts),
			SYNCount:         e.synCount,
			ACKCount:         e.ackCount,
			RSTCount:         e.rstCount,
		})
	}
	sort.Slice(edgeList, func(i, j int) bool {
		return edgeList[i].PacketCount > edgeList[j].PacketCount
	})

	totalNodes := len(nodeList)
	totalEdges := len(edgeList)
	var density float64
	if totalNodes > 1 {
		maxPossibleEdges := float64(totalNodes * (totalNodes - 1))
		density = math.Round((float64(totalEdges)/maxPossibleEdges)*10000) / 10000
	}

	return NetworkGraph{
		TotalNodes: totalNodes,
		TotalEdges: totalEdges,
		Density:    density,
		Nodes:      nodeList,
		Edges:      edgeList,
	}
}
