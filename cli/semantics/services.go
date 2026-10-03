// Package semantics adds deterministic service context to packets and model
// events. It does not change model inputs, scores, or checkpoint calibration.
package semantics

import (
	"fmt"
	"net/netip"
	"strings"
)

type Service struct {
	Tag      string
	Name     string
	Internal bool // backend service expected on private/loopback networks
}

type serviceKey struct {
	transport string
	port      uint16
}

// Registry is the one place to add or revise protocol/port associations.
// A registry match is context, never proof that a flow is harmless.
var Registry = map[serviceKey]Service{
	{"UDP", 53}: {"DNS", "DNS", false}, {"TCP", 53}: {"DNS", "DNS", false},
	{"TCP", 80}: {"HTTP", "HTTP", false}, {"TCP", 443}: {"HTTPS", "HTTPS", false},
	{"TCP", 22}: {"SSH", "SSH", false}, {"TCP", 21}: {"FTP", "FTP", false},
	{"TCP", 25}: {"SMTP", "SMTP", false}, {"TCP", 465}: {"SMTPS", "SMTPS", false},
	{"TCP", 587}:  {"SMTP_SUBMISSION", "SMTP submission", false},
	{"TCP", 853}:  {"DNS_OVER_TLS", "DNS over TLS", false},
	{"UDP", 123}:  {"NTP", "NTP", false},
	{"UDP", 3956}: {"GVCP", "GigE Vision discovery/control", false},
	{"UDP", 67}:   {"DHCP_SERVER", "DHCP server", false}, {"UDP", 68}: {"DHCP_CLIENT", "DHCP client", false},
	{"UDP", 161}: {"SNMP", "SNMP", false}, {"UDP", 162}: {"SNMP_TRAP", "SNMP trap", false},
	{"TCP", 389}: {"LDAP", "LDAP", false}, {"TCP", 636}: {"LDAPS", "LDAPS", false},
	{"TCP", 88}: {"KERBEROS", "Kerberos", false}, {"UDP", 88}: {"KERBEROS", "Kerberos", false},
	{"TCP", 3389}: {"RDP", "RDP", false}, {"TCP", 445}: {"SMB", "SMB", false},
	{"UDP", 137}:   {"NETBIOS_NS", "NetBIOS name service", false},
	{"UDP", 138}:   {"NETBIOS_DGM", "NetBIOS datagram", false},
	{"TCP", 139}:   {"NETBIOS_SESSION", "NetBIOS session", false},
	{"TCP", 23}:    {"TELNET", "Telnet", false},
	{"TCP", 6379}:  {"REDIS", "Redis", true},
	{"TCP", 27017}: {"MONGODB", "MongoDB", true},
	{"TCP", 5432}:  {"POSTGRESQL", "PostgreSQL", true},
	{"TCP", 3306}:  {"MYSQL", "MySQL", true},
	{"TCP", 9092}:  {"KAFKA", "Kafka", true},
	{"TCP", 5672}:  {"RABBITMQ", "RabbitMQ", true},
	{"TCP", 15672}: {"RABBITMQ_MANAGEMENT", "RabbitMQ management", true},
	{"TCP", 6443}:  {"KUBERNETES_API", "Kubernetes API", true},
}

type Observation struct {
	Transport           string
	SrcIP               string
	DstIP               string
	SrcPort             uint16
	DstPort             uint16
	Established         bool // reverse traffic needs actual connection/flow evidence
	NormalGVCPDiscovery bool // parsed eight-byte discovery command, never a port-only match
}

type Tags struct {
	ProtocolTag        string `json:"protocol_tag"`
	Service            string `json:"service"`
	TrafficClass       string `json:"traffic_class"`
	ConnectionRole     string `json:"connection_role"`
	IsWellKnownService bool   `json:"is_well_known_service"`
	IsInternalService  bool   `json:"is_internal_service"`
	IsEphemeralPort    bool   `json:"is_ephemeral_port"`
	RuleClassification string `json:"rule_classification"`
	RuleReason         string `json:"rule_reason"`
}

func Classify(o Observation) Tags {
	transport := strings.ToUpper(o.Transport)
	unknown := Tags{ProtocolTag: "UNKNOWN", Service: "UNKNOWN", TrafficClass: "UNKNOWN", ConnectionRole: "UNKNOWN", RuleClassification: "UNKNOWN", RuleReason: "No registered service pattern"}
	dst, dstOK := Registry[serviceKey{transport, o.DstPort}]
	src, srcOK := Registry[serviceKey{transport, o.SrcPort}]
	if dstOK {
		class, role := "NORMAL_SERVICE", "OUTBOUND_CLIENT"
		if dst.Tag == "DNS" {
			role = "CLIENT_TO_DNS"
		}
		internal := privatePair(o.SrcIP, o.DstIP)
		source, parseError := netip.ParseAddr(o.SrcIP)
		if dst.Tag == "GVCP" && o.NormalGVCPDiscovery && parseError == nil && source.IsPrivate() && o.DstIP == "255.255.255.255" {
			return Tags{ProtocolTag: dst.Tag, Service: dst.Name, TrafficClass: "INTERNAL_SERVICE", ConnectionRole: "SERVICE_DISCOVERY",
				IsWellKnownService: true, IsInternalService: true, IsEphemeralPort: o.SrcPort >= 49152,
				RuleClassification: "INTERNAL_SERVICE", RuleReason: "Validated GVCP discovery command to LAN broadcast"}
		}
		if internal && dst.Internal {
			class, role = "INTERNAL_SERVICE", "INTERNAL_CLIENT"
		}
		return Tags{ProtocolTag: dst.Tag, Service: dst.Name, TrafficClass: class, ConnectionRole: role, IsWellKnownService: true, IsInternalService: internal, IsEphemeralPort: o.SrcPort >= 49152, RuleClassification: class, RuleReason: fmt.Sprintf("%s destination port %d matches %s; port match is baseline context only", transport, o.DstPort, dst.Tag)}
	}
	if srcOK {
		// A source service port alone can be spoofed. Only a corroborated
		// connection/flow may be called a server response.
		if !o.Established {
			unknown.ProtocolTag, unknown.Service = src.Tag, src.Name
			unknown.IsWellKnownService = true
			unknown.IsInternalService = privatePair(o.SrcIP, o.DstIP)
			unknown.IsEphemeralPort = o.DstPort >= 49152
			unknown.RuleReason = "Service source port observed without established reverse-flow evidence"
			return unknown
		}
		internal := privatePair(o.SrcIP, o.DstIP)
		return Tags{ProtocolTag: src.Tag, Service: src.Name, TrafficClass: "RESPONSE_TRAFFIC", ConnectionRole: "SERVER_RESPONSE", IsWellKnownService: true, IsInternalService: internal, IsEphemeralPort: o.DstPort >= 49152, RuleClassification: "RESPONSE_TRAFFIC", RuleReason: fmt.Sprintf("Established reverse flow from %s port %d", src.Tag, o.SrcPort)}
	}
	if o.SrcPort >= 49152 {
		unknown.ProtocolTag, unknown.Service = "EPHEMERAL_CLIENT_PORT", "Ephemeral client port"
		unknown.TrafficClass, unknown.ConnectionRole = "EPHEMERAL_CLIENT", "OUTBOUND_CLIENT"
		unknown.IsEphemeralPort = true
		unknown.RuleClassification = "EPHEMERAL_CLIENT"
		unknown.RuleReason = "Dynamic source port is not independently suspicious"
	}
	return unknown
}

func privatePair(a, b string) bool {
	x, ex := netip.ParseAddr(a)
	y, ey := netip.ParseAddr(b)
	return ex == nil && ey == nil && (x.IsPrivate() || x.IsLoopback()) && (y.IsPrivate() || y.IsLoopback())
}
