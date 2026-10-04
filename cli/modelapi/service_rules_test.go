package modelapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceIncidentDecision(t *testing.T) {
	incident := Incident{Family: "Infiltration", Incident: 1, Score: .99, ModelClassification: "Infiltration", ModelScore: .99, FinalDecision: "RETAINED"}
	events := []DetectionIncidentEvent{
		{Family: "Infiltration", Score: .99, Src: "10.4.4.120", Dst: "10.200.0.200", SrcPort: 63746, DstPort: 53, Protocol: 17, TObs: 10},
		{Family: "Infiltration", Score: .98, Src: "10.4.4.120", Dst: "10.200.0.200", SrcPort: 63746, DstPort: 53, Protocol: 17, TObs: 20},
		{Family: "Infiltration", Score: .97, Src: "10.4.4.120", Dst: "10.200.0.200", SrcPort: 63746, DstPort: 53, Protocol: 17, TObs: 30},
	}
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "SUPPRESSED" || got.ModelScore != incident.Score || got.ProtocolTag != "DNS" {
		t.Fatalf("ordinary DNS: %+v", got)
	}
	events[1].DstPort = 2222
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "RETAINED" {
		t.Fatalf("mixed service should remain visible: %+v", got)
	}
	events[1].DstPort = 53
	for i := range events {
		events[i].TObs = 10 + float64(i)/10
	}
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "SUPPRESSED" {
		t.Fatalf("parallel DNS flow observations are not a measured packet-rate attack: %+v", got)
	}
	if got := decideServiceIncident(incident, nil); got.FinalDecision != "RETAINED" {
		t.Fatalf("missing evidence must fail open: %+v", got)
	}
	if got := decideLinkedIncident(incident, &IncidentEventsResponse{Events: events, Total: 3}); got.FinalDecision != "SUPPRESSED" {
		t.Fatalf("complete evidence keeps its decision: %+v", got)
	}
	partial := decideLinkedIncident(incident, &IncidentEventsResponse{Events: events, Total: 40000, Truncated: true})
	if partial.FinalDecision != "RETAINED" || !strings.Contains(partial.RuleReason, "first 3 of 40000") || partial.ProtocolTag != "" {
		t.Fatalf("a truncated answer must not suppress: %+v", partial)
	}
	for i := range events {
		events[i].Dst = "8.8.8.8"
		events[i].DstPort = 443
		events[i].Protocol = 6
		events[i].TObs = 10 + float64(i)*10
	}
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "RETAINED" {
		t.Fatalf("external HTTPS port is not a whitelist: %+v", got)
	}
	scan := make([]DetectionIncidentEvent, 8)
	for i := range scan {
		scan[i] = DetectionIncidentEvent{Family: "Infiltration", Src: "10.4.4.120", Dst: "10.200.0." + string(rune('1'+i)), SrcPort: 63746, DstPort: 22, Protocol: 6, TObs: 10 + float64(i)*10}
	}
	annotateIncidentEvents(scan)
	if got := decideServiceIncident(incident, scan); got.FinalDecision != "RETAINED" || got.RuleClassification != "SUSPICIOUS" {
		t.Fatalf("SSH host fanout is not benign: %+v", got)
	}
}

func TestInternalDNSCrossingsAreNotSuspiciousByCountAlone(t *testing.T) {
	incident := Incident{Family: "Infiltration", Incident: 1, Score: .88415, ModelClassification: "Infiltration", ModelScore: .88415, FinalDecision: "RETAINED"}
	events := make([]DetectionIncidentEvent, 16)
	for i := range events {
		events[i] = DetectionIncidentEvent{Family: "Infiltration", Score: .88, Src: "10.4.0.165", Dst: "10.200.0.200", SrcPort: 51000 + i, DstPort: 53, Protocol: 17, TObs: 1000 + float64(i)*3}
	}
	annotateIncidentEvents(events)
	got := decideServiceIncident(incident, events)
	if got.FinalDecision != "SUPPRESSED" || got.ProtocolTag != "DNS" || got.TrafficClass != "NORMAL_SERVICE" || got.ModelScore != incident.Score {
		t.Fatalf("ordinary internal DNS with 16 crossings: %+v", got)
	}
}

func TestDetectionsWithRulesPreservesRawModelIncident(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/detections":
			_, _ = w.Write([]byte(`{"status":"RUNNING","incidents":[{"family":"Infiltration","incident":1,"t":123,"score":0.991},{"family":"Bot","incident":2,"t":124,"score":0.999}],"recent_incidents":[{"family":"Infiltration","incident":1,"t":123,"score":0.991}],"incidents_by_family":{"Infiltration":1,"Bot":1},"recent_detections":[{"family":"Infiltration","probability":0.991,"src":"10.4.4.120","dst":"10.200.0.200","src_port":63746,"dst_port":53,"protocol":17}]}`))
		case "/incident-events":
			_, _ = w.Write([]byte(`{"events":[{"family":"Infiltration","score":0.991,"src":"10.4.4.120","dst":"10.200.0.200","src_port":63746,"dst_port":53,"protocol":17,"t_obs":10},{"family":"Infiltration","score":0.992,"src":"10.4.4.120","dst":"10.200.0.200","src_port":63746,"dst_port":53,"protocol":17,"t_obs":20},{"family":"Infiltration","score":0.993,"src":"10.4.4.120","dst":"10.200.0.200","src_port":63746,"dst_port":53,"protocol":17,"t_obs":30}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewClient("", server.URL+"/detections")
	d, err := client.DetectionsWithRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Incidents) != 1 || d.Incidents[0].Family != "Bot" || d.IncidentsByFamily["Infiltration"] != 0 {
		t.Fatalf("final incidents: %+v, counts: %+v", d.Incidents, d.IncidentsByFamily)
	}
	if len(d.RawIncidents) != 2 || len(d.SuppressedIncidents) != 1 || d.SuppressedIncidents[0].ModelScore != .991 {
		t.Fatalf("raw incident history lost: raw=%+v suppressed=%+v", d.RawIncidents, d.SuppressedIncidents)
	}
	if got := d.RecentDetections[0]; got.ModelClassification != "Infiltration" || got.ModelScore != .991 || got.ProtocolTag != "DNS" {
		t.Fatalf("raw detection not preserved/tagged: %+v", got)
	}
	linked, err := client.IncidentEvents(context.Background(), "Infiltration", 1, 123)
	if err != nil || !strings.Contains(linked.Events[0].RuleReason, "DNS") {
		t.Fatalf("linked event not enriched: %+v, %v", linked, err)
	}
}

func TestWebSuppressionRequiresCorroborationAndRetainsAttackIndicators(t *testing.T) {
	incident := Incident{Family: "DoS-Hulk", Score: .99, ModelScore: .99, FinalDecision: "RETAINED"}
	events := make([]DetectionIncidentEvent, 12)
	for i := range events {
		events[i] = DetectionIncidentEvent{Src: "198.51.100.5", Dst: "192.168.0.2", SrcPort: 443,
			DstPort: 51000 + i, Protocol: 6, TObs: 100 + float64(i), EstablishedConnection: true,
			ServiceEvidenceVersion: 1, SourcePacketsPerSecond: 25}
	}
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "SUPPRESSED" || got.ModelScore != .99 {
		t.Fatalf("verified HTTPS replies, ephemeral client ports are not service fanout: %+v", got)
	}
	for _, family := range []string{"Bot", "Infiltration"} {
		candidate := incident
		candidate.Family = family
		if got := decideServiceIncident(candidate, events); got.FinalDecision != "RETAINED" {
			t.Fatalf("legitimate HTTPS does not exclude %s: %+v", family, got)
		}
	}
	events[0].EstablishedConnection = false
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "RETAINED" {
		t.Fatalf("spoofed service source port: %+v", got)
	}
	events[0].EstablishedConnection = true
	events[0].SourcePacketsPerSecond = 300
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "RETAINED" || got.RuleClassification != "SUSPICIOUS" {
		t.Fatalf("high-rate response flood: %+v", got)
	}
}

func TestRoutineInternalServicesCoverWebFamiliesWithoutWhitelistingRequests(t *testing.T) {
	incident := Incident{Family: "Brute Force -Web", FinalDecision: "RETAINED"}
	events := make([]DetectionIncidentEvent, 3)
	for i := range events {
		events[i] = DetectionIncidentEvent{Src: "192.168.0.2", Dst: "192.168.0.1", SrcPort: 51000 + i,
			DstPort: 53, Protocol: 17, TObs: 100 + float64(i), NormalDNSQuery: true, ServiceEvidenceVersion: 1}
	}
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "SUPPRESSED" {
		t.Fatalf("routine internal DNS is not a web request attack: %+v", got)
	}
	events[0].NormalDNSQuery = false
	if got := decideServiceIncident(incident, events); got.FinalDecision != "RETAINED" {
		t.Fatalf("arbitrary UDP port 53 payload: %+v", got)
	}
	for i := range events {
		events[i].Protocol = 6
		events[i].DstPort = 5432
		events[i].EstablishedConnection = true
	}
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "SUPPRESSED" {
		t.Fatalf("routine internal database socket is not a web request attack: %+v", got)
	}
	for i := range events {
		events[i].DstPort = 443
	}
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "RETAINED" {
		t.Fatalf("established internal HTTPS requests can still carry web attacks: %+v", got)
	}
}

func TestLowRateValidatedCameraDiscoveryAndNotArbitraryPort3956(t *testing.T) {
	incident := Incident{Family: "Infiltration", FinalDecision: "RETAINED"}
	events := make([]DetectionIncidentEvent, 3)
	for i := range events {
		events[i] = DetectionIncidentEvent{Src: "192.168.0.152", Dst: "255.255.255.255", SrcPort: 51000 + i,
			DstPort: 3956, Protocol: 17, TObs: 100 + float64(i), NormalGVCPDiscovery: true,
			ServiceEvidenceVersion: 1, SourcePacketsPerSecond: 1}
	}
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "SUPPRESSED" || got.ProtocolTag != "GVCP" {
		t.Fatalf("routine camera discovery: %+v", got)
	}
	events[0].NormalGVCPDiscovery = false
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "RETAINED" {
		t.Fatalf("port-only match: %+v", got)
	}
	events[0].NormalGVCPDiscovery = true
	events[0].SourcePacketsPerSecond = 11
	annotateIncidentEvents(events)
	if got := decideServiceIncident(incident, events); got.FinalDecision != "RETAINED" {
		t.Fatalf("discovery flood: %+v", got)
	}
}

func TestWorldFlagsFollowTheServiceRules(t *testing.T) {
	event := func(id int, at float64, receiver string, port int) ObservedAlert {
		return ObservedAlert{EventID: id, T: at, SenderIP: "10.4.4.120", ReceiverIP: receiver, Value: .999, Severity: "MEDIUM",
			Src: "10.4.4.120", Dst: receiver, SrcPort: 50000 + id, DstPort: port, Protocol: 17,
			NormalDNSQuery: true, SourcePacketsPerSecond: 2, ServiceEvidenceVersion: 1}
	}
	resolver, other := "10.200.0.200", "10.200.0.9"
	dns := ObservedIncident{ID: "dns", Opened: 10, SenderIP: "10.4.4.120", ReceiverIP: resolver, Events: 3,
		RelatedEvents: []ObservedAlert{event(1, 10, resolver, 53), event(2, 20, resolver, 53), event(3, 30, resolver, 53)}}
	bare := ObservedIncident{ID: "bare", Opened: 10, SenderIP: "10.4.4.120", ReceiverIP: "203.0.113.9", Events: 3,
		RelatedEvents: []ObservedAlert{{EventID: 7, T: 10, SenderIP: "10.4.4.120", ReceiverIP: "203.0.113.9"},
			{EventID: 8, T: 20, SenderIP: "10.4.4.120", ReceiverIP: "203.0.113.9"}, {EventID: 9, T: 30, SenderIP: "10.4.4.120", ReceiverIP: "203.0.113.9"}}}
	f := &ForecastResponse{
		Observed: Observed{Incidents: []ObservedIncident{dns, bare},
			// one resolver crossing, and one crossing on an unregistered port of another internal host
			Alerts: []ObservedAlert{event(3, 30, resolver, 53), event(4, 40, other, 4444)}},
		Alerts: []ForecastAlert{{SenderIP: resolver, ReceiverIP: "10.4.4.120"}, {SenderIP: "10.4.4.120", ReceiverIP: "203.0.113.9"}},
	}
	applyWorldRules(f)
	o := f.Observed
	if len(o.Incidents) != 1 || o.Incidents[0].ID != "bare" || o.Incidents[0].FinalDecision != "RETAINED" {
		t.Fatalf("flags without port evidence must fail open: %+v", o.Incidents)
	}
	if len(o.SuppressedIncidents) != 1 || o.SuppressedIncidents[0].ProtocolTag != "DNS" || len(o.RawIncidents) != 2 {
		t.Fatalf("routine internal DNS: suppressed %+v raw %d", o.SuppressedIncidents, len(o.RawIncidents))
	}
	if len(o.SuppressedLinks) != 1 || o.SuppressedLinks[0].Key != "10.200.0.200|10.4.4.120" || o.SuppressedLinks[0].Events != 3 || o.SuppressedLinks[0].Incidents != 1 {
		t.Fatalf("suppressed links: %+v", o.SuppressedLinks)
	}
	if len(o.Alerts) != 1 || o.Alerts[0].EventID != 4 || len(o.SuppressedAlerts) != 1 {
		t.Fatalf("only the routine link's flags leave the alert list: %+v", o.Alerts)
	}
	if len(f.Alerts) != 1 || f.Alerts[0].ReceiverIP != "203.0.113.9" || len(f.SuppressedAlerts) != 1 {
		t.Fatalf("forecast alerts on a routine link are set aside: %+v", f.Alerts)
	}

	// One flagged resolver lookup is complete evidence; a second port on the same link is not routine.
	single := &ForecastResponse{Observed: Observed{Alerts: []ObservedAlert{event(1, 10, resolver, 53)}}}
	applyWorldRules(single)
	if len(single.Observed.SuppressedLinks) != 1 || len(single.Observed.Alerts) != 0 {
		t.Fatalf("a single routine crossing: %+v", single.Observed)
	}
	mixed := &ForecastResponse{Observed: Observed{Alerts: []ObservedAlert{event(1, 10, resolver, 53), event(2, 20, resolver, 4444)}}}
	applyWorldRules(mixed)
	if len(mixed.Observed.SuppressedLinks) != 0 || len(mixed.Observed.Alerts) != 2 {
		t.Fatalf("a link carrying another port stays visible: %+v", mixed.Observed)
	}
}
