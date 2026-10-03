package semantics

import "testing"

func TestServiceRegistry(t *testing.T) {
	cases := []struct {
		proto string
		port  uint16
		tag   string
	}{
		{"UDP", 53, "DNS"}, {"TCP", 53, "DNS"}, {"TCP", 80, "HTTP"},
		{"TCP", 443, "HTTPS"}, {"TCP", 22, "SSH"}, {"TCP", 21, "FTP"},
		{"TCP", 25, "SMTP"}, {"TCP", 465, "SMTPS"}, {"TCP", 587, "SMTP_SUBMISSION"},
		{"TCP", 853, "DNS_OVER_TLS"}, {"UDP", 123, "NTP"},
		{"UDP", 67, "DHCP_SERVER"}, {"UDP", 68, "DHCP_CLIENT"},
		{"UDP", 161, "SNMP"}, {"UDP", 162, "SNMP_TRAP"},
		{"TCP", 389, "LDAP"}, {"TCP", 636, "LDAPS"},
		{"TCP", 88, "KERBEROS"}, {"UDP", 88, "KERBEROS"},
		{"TCP", 3389, "RDP"}, {"TCP", 445, "SMB"},
		{"UDP", 137, "NETBIOS_NS"}, {"UDP", 138, "NETBIOS_DGM"},
		{"TCP", 139, "NETBIOS_SESSION"}, {"TCP", 23, "TELNET"},
		{"TCP", 6379, "REDIS"}, {"TCP", 27017, "MONGODB"},
		{"TCP", 5432, "POSTGRESQL"}, {"TCP", 3306, "MYSQL"},
		{"TCP", 9092, "KAFKA"}, {"TCP", 5672, "RABBITMQ"},
		{"TCP", 15672, "RABBITMQ_MANAGEMENT"}, {"TCP", 6443, "KUBERNETES_API"},
	}
	for _, tc := range cases {
		tags := Classify(Observation{Transport: tc.proto, SrcIP: "10.4.4.120", DstIP: "10.200.0.200", SrcPort: 63746, DstPort: tc.port})
		if tags.ProtocolTag != tc.tag || !tags.IsWellKnownService || tags.TrafficClass == "SUSPICIOUS" {
			t.Errorf("%s/%d: %+v", tc.proto, tc.port, tags)
		}
	}
}

func TestRolesAndEphemeralPorts(t *testing.T) {
	dns := Classify(Observation{Transport: "UDP", SrcIP: "10.4.4.120", DstIP: "10.200.0.200", SrcPort: 63746, DstPort: 53})
	if dns.ProtocolTag != "DNS" || dns.TrafficClass != "NORMAL_SERVICE" || dns.ConnectionRole != "CLIENT_TO_DNS" || !dns.IsEphemeralPort || !dns.IsInternalService {
		t.Fatalf("DNS query: %+v", dns)
	}
	https := Classify(Observation{Transport: "TCP", SrcIP: "10.4.4.120", DstIP: "8.8.8.8", SrcPort: 64912, DstPort: 443})
	if https.ProtocolTag != "HTTPS" || https.TrafficClass != "NORMAL_SERVICE" || https.ConnectionRole != "OUTBOUND_CLIENT" {
		t.Fatalf("HTTPS request: %+v", https)
	}
	response := Observation{Transport: "TCP", SrcIP: "8.8.8.8", DstIP: "10.4.4.120", SrcPort: 443, DstPort: 64912}
	if got := Classify(response); got.TrafficClass == "RESPONSE_TRAFFIC" {
		t.Fatalf("uncorroborated source port treated as response: %+v", got)
	}
	response.Established = true
	if got := Classify(response); got.ProtocolTag != "HTTPS" || got.TrafficClass != "RESPONSE_TRAFFIC" || got.ConnectionRole != "SERVER_RESPONSE" {
		t.Fatalf("established HTTPS response: %+v", got)
	}
	redis := Classify(Observation{Transport: "TCP", SrcIP: "127.0.0.1", DstIP: "127.0.0.1", SrcPort: 64912, DstPort: 6379})
	if redis.TrafficClass != "INTERNAL_SERVICE" || !redis.IsInternalService {
		t.Fatalf("local Redis: %+v", redis)
	}
	unknown := Classify(Observation{Transport: "TCP", SrcIP: "10.4.4.120", DstIP: "1.2.3.4", SrcPort: 63746, DstPort: 11111})
	if unknown.TrafficClass != "EPHEMERAL_CLIENT" || unknown.RuleClassification == "SUSPICIOUS" {
		t.Fatalf("high source port: %+v", unknown)
	}
}
