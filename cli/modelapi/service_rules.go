package modelapi

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"detector/semantics"
)

type cachedRuleIncident struct {
	incident Incident
	expires  time.Time
}

func transportName(number int) string {
	switch number {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

func observation(src, dst string, srcPort, dstPort, protocol int) semantics.Observation {
	o := semantics.Observation{Transport: transportName(protocol), SrcIP: src, DstIP: dst}
	if srcPort >= 0 && srcPort <= 65535 {
		o.SrcPort = uint16(srcPort)
	}
	if dstPort >= 0 && dstPort <= 65535 {
		o.DstPort = uint16(dstPort)
	}
	return o
}

func annotateIncidentEvents(events []DetectionIncidentEvent) {
	for i := range events {
		x := &events[i]
		x.ModelClassification, x.ModelScore = x.Family, x.Score
		o := observation(x.Src, x.Dst, x.SrcPort, x.DstPort, x.Protocol)
		o.Established = x.EstablishedConnection
		o.NormalGVCPDiscovery = x.NormalGVCPDiscovery && x.ServiceEvidenceVersion > 0
		x.Tags = semantics.Classify(o)
	}
}

func annotateDetections(events []Detection) {
	for i := range events {
		x := &events[i]
		x.ModelClassification, x.ModelScore = x.Family, x.Probability
		x.Tags = semantics.Classify(observation(x.Src, x.Dst, x.SrcPort, x.DstPort, x.Protocol))
	}
}

func incidentKey(x Incident) string {
	return fmt.Sprintf("%s:%d:%.9f", x.Family, x.Incident, x.T)
}

func webRequestFamily(family string) bool {
	switch strings.ToLower(strings.ReplaceAll(family, " ", "")) {
	case "dos-hulk", "dos-goldeneye", "dos-slowloris", "dos-slowhttptest", "bruteforce-web", "bruteforce-xss", "sqlinjection":
		return true
	}
	return false
}

func serviceRuleFamily(family string) bool {
	return strings.EqualFold(family, "Infiltration") || webRequestFamily(family)
}

// DetectionsWithRules preserves the model's raw result and creates an
// operator-facing decision separately. It never changes scores or calibration.
// On missing linked evidence or an enrichment error, incidents fail open.
func (c *Client) DetectionsWithRules(ctx context.Context) (*DetectionsResponse, error) {
	d, err := c.Detections(ctx)
	if err != nil {
		return nil, err
	}
	annotateDetections(d.RecentDetections)
	d.RawIncidents = append([]Incident{}, d.Incidents...)
	d.RawRecentIncidents = append([]Incident{}, d.RecentIncidents...)
	for i := range d.RawIncidents {
		d.RawIncidents[i].ModelClassification, d.RawIncidents[i].ModelScore = d.RawIncidents[i].Family, d.RawIncidents[i].Score
	}
	for i := range d.RawRecentIncidents {
		d.RawRecentIncidents[i].ModelClassification, d.RawRecentIncidents[i].ModelScore = d.RawRecentIncidents[i].Family, d.RawRecentIncidents[i].Score
	}
	decision := make(map[string]Incident)
	ruleCtx, stopRules := context.WithTimeout(ctx, 2*time.Second)
	defer stopRules()
	active := make(map[string]bool, len(d.Incidents))
	for _, x := range d.Incidents {
		active[incidentKey(x)] = true
	}
	for _, x := range append(append([]Incident{}, d.Incidents...), d.RecentIncidents...) {
		key := incidentKey(x)
		if _, seen := decision[key]; seen {
			continue
		}
		x.ModelClassification, x.ModelScore = x.Family, x.Score
		x.FinalDecision = "RETAINED"
		x.RuleClassification = "UNKNOWN"
		x.RuleReason = "Model incident retained; no deterministic service suppression rule applies"
		if serviceRuleFamily(x.Family) {
			x = c.evaluateServiceIncident(ruleCtx, x, active[key])
		}
		decision[key] = x
	}
	filter := func(input []Incident) []Incident {
		out := make([]Incident, 0, len(input))
		for _, x := range input {
			classified := decision[incidentKey(x)]
			if classified.FinalDecision == "SUPPRESSED" {
				continue
			}
			out = append(out, classified)
		}
		return out
	}
	d.Incidents, d.RecentIncidents = filter(d.Incidents), filter(d.RecentIncidents)
	d.IncidentsByFamily = make(map[string]int)
	for _, x := range d.Incidents {
		d.IncidentsByFamily[x.Family]++
	}
	for _, x := range decision {
		if x.FinalDecision == "SUPPRESSED" {
			d.SuppressedIncidents = append(d.SuppressedIncidents, x)
		}
	}
	return d, nil
}

func (c *Client) evaluateServiceIncident(ctx context.Context, x Incident, active bool) Incident {
	key := incidentKey(x)
	c.ruleMu.Lock()
	cached, ok := c.ruleCache[key]
	c.ruleMu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return cached.incident
	}
	linked, err := c.IncidentEvents(ctx, x.Family, x.Incident, x.T)
	if err != nil {
		x.RuleReason = "Linked events unavailable; model incident retained: " + err.Error()
		c.ruleMu.Lock()
		if c.ruleCache == nil {
			c.ruleCache = make(map[string]cachedRuleIncident)
		}
		c.ruleCache[key] = cachedRuleIncident{incident: x, expires: time.Now().Add(10 * time.Second)}
		c.ruleMu.Unlock()
		return x
	}
	x = decideLinkedIncident(x, linked)
	c.ruleMu.Lock()
	if c.ruleCache == nil {
		c.ruleCache = make(map[string]cachedRuleIncident)
	}
	if len(c.ruleCache) > 1000 {
		c.ruleCache = make(map[string]cachedRuleIncident)
	}
	ttl := 3 * time.Hour // closed incident ledger is immutable
	if active && !linked.Truncated {
		// Growing evidence can invalidate an earlier benign decision. A truncated
		// incident only grows, so it stays retained and is not asked for again.
		ttl = 2 * time.Second
	}
	c.ruleCache[key] = cachedRuleIncident{incident: x, expires: time.Now().Add(ttl)}
	c.ruleMu.Unlock()
	return x
}

// decideLinkedIncident applies the service rules to a detector answer.
// Suppression needs every linked event, so a truncated answer can only add a
// suspicious classification; it never suppresses.
func decideLinkedIncident(x Incident, linked *IncidentEventsResponse) Incident {
	decided := decideServiceIncident(x, linked.Events)
	if linked.Truncated && decided.FinalDecision == "SUPPRESSED" {
		x.RuleReason = fmt.Sprintf("Only the first %d of %d linked events were evaluated; model incident retained", len(linked.Events), linked.Total)
		return x
	}
	return decided
}

func decideServiceIncident(x Incident, events []DetectionIncidentEvent) Incident {
	return decideServiceEvents(x, events, 3)
}

// decideServiceEvents is the rule itself. minimum is the fewest linked events
// that count as complete evidence: three for a detector incident, which is
// three crossings by construction, so fewer means evidence went missing.
func decideServiceEvents(x Incident, events []DetectionIncidentEvent, minimum int) Incident {
	if !serviceRuleFamily(x.Family) {
		return x
	}
	if len(events) < minimum {
		x.RuleReason = "Fewer than three linked events; insufficient evidence for service suppression"
		return x
	}
	first := events[0]
	peers := map[string]bool{}
	ports := map[int]bool{}
	normalRole, internalPattern, homogeneous := true, true, true
	serviceEndpoint := func(event DetectionIncidentEvent) (string, string, int) {
		if event.TrafficClass == "RESPONSE_TRAFFIC" {
			return event.Src, event.Dst, event.SrcPort
		}
		return event.Dst, event.Src, event.DstPort
	}
	firstServer, firstClient, firstPort := serviceEndpoint(first)
	firstTime, lastTime := first.TObs, first.TObs
	for _, event := range events {
		_, srcErr := netip.ParseAddr(event.Src)
		_, dstErr := netip.ParseAddr(event.Dst)
		if srcErr != nil || dstErr != nil || event.SrcPort < 0 || event.SrcPort > 65535 || event.DstPort < 0 || event.DstPort > 65535 || event.TObs <= 0 {
			x.RuleReason = "Linked event has incomplete network evidence; model incident retained"
			return x
		}
		server, client, port := serviceEndpoint(event)
		peers[server] = true
		ports[port] = true
		if event.TObs < firstTime {
			firstTime = event.TObs
		}
		if event.TObs > lastTime {
			lastTime = event.TObs
		}
		if event.SourcePacketsPerSecond > 250 || event.SourcePacketsPerSecond < 0 {
			x.RuleClassification = "SUSPICIOUS"
			x.RuleReason = "Measured source packet burst; routine-service suppression disabled"
			return x
		}
		if event.ProtocolTag == "GVCP" && (event.SourcePacketsPerSecond > 10 || !event.NormalGVCPDiscovery || event.ServiceEvidenceVersion == 0) {
			x.RuleReason = "Unverified or excessive camera discovery traffic; model incident retained"
			return x
		}
		if event.TrafficClass != "NORMAL_SERVICE" && event.TrafficClass != "INTERNAL_SERVICE" && event.TrafficClass != "RESPONSE_TRAFFIC" {
			normalRole = false
		}
		// Web-request attack families may be discounted for verified HTTPS
		// responses, but Bot/exfiltration can operate over legitimate sockets.
		response := event.TrafficClass == "RESPONSE_TRAFFIC" && event.ProtocolTag == "HTTPS" &&
			webRequestFamily(x.Family) && event.DstPort >= 49152 && event.ServiceEvidenceVersion > 0
		if !event.IsInternalService && !response {
			internalPattern = false
		}
		if event.ProtocolTag != first.ProtocolTag || server != firstServer || client != firstClient || port != firstPort || event.Protocol != first.Protocol {
			homogeneous = false
		}
		if !response {
			if !strings.EqualFold(x.Family, "Infiltration") && (event.ServiceEvidenceVersion == 0 ||
				(event.ProtocolTag == "DNS" && !event.NormalDNSQuery) || event.ProtocolTag == "HTTP" || event.ProtocolTag == "HTTPS") {
				normalRole = false
			}
			if event.Protocol == 6 && !event.EstablishedConnection {
				normalRole = false
			}
			if event.Protocol == 17 && event.ProtocolTag != "DNS" && event.ProtocolTag != "GVCP" {
				normalRole = false
			}
			if event.ServiceEvidenceVersion > 0 && event.ProtocolTag == "DNS" && !event.NormalDNSQuery {
				normalRole = false
			}
		}
	}
	// Model crossings are flow observations, not packet-rate samples: several
	// ordinary DNS lookups can share nearly the same t_obs. Packet-rate evidence
	// is measured separately rather than inferred from model score counts.
	if len(peers) >= 8 || len(ports) >= 8 {
		x.TrafficClass, x.RuleClassification = "SUSPICIOUS", "SUSPICIOUS"
		x.RuleReason = "Linked events show destination or port fanout; service port is not a whitelist"
		return x
	}
	if len(events) > 20 && lastTime-firstTime < 1 {
		x.RuleClassification = "SUSPICIOUS"
		x.RuleReason = "Concentrated flow crossings; routine-service suppression disabled"
		return x
	}
	if !normalRole {
		x.RuleReason = "At least one linked event lacks a corroborated normal service role"
		return x
	}
	if !internalPattern {
		x.RuleReason = "External service port alone cannot establish benign behavior; model incident retained"
		return x
	}
	if !homogeneous {
		x.RuleReason = "Linked events span different services or peers; model incident retained"
		return x
	}
	x.Tags = first.Tags
	x.RuleClassification = first.TrafficClass
	x.RuleReason = "Linked crossings match one routine internal service or established HTTPS response peer, without measured bursts or service fanout; raw model verdict retained separately"
	x.FinalDecision = "SUPPRESSED"
	return x
}

// worldRuleFamily is the detector family whose service rule judges the world
// model's flags: the internal-service rule, which has no exception for
// responses from external hosts.
const worldRuleFamily = "Infiltration"

func linkKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

// ForecastWithRules applies the detector's deterministic service rules to the
// world model's flags. It never changes scores or calibration, and what it
// sets aside stays in the response. A flag without port evidence fails open.
func (c *Client) ForecastWithRules(ctx context.Context) (*ForecastResponse, error) {
	f, err := c.Forecast(ctx)
	if err != nil {
		return nil, err
	}
	applyWorldRules(f)
	return f, nil
}

// applyWorldRules judges each observed link by all of its flagged events in
// the window: single crossings and incident crossings alike. The world model
// flags single events, each with its own port evidence, so one event is
// complete evidence here. A link whose flags are all one routine internal
// service loses its incidents, its flagged events and its forecast alerts,
// and is listed so the dashboard does not draw it.
func applyWorldRules(f *ForecastResponse) {
	o := &f.Observed
	flagged, seen := map[string][]ObservedAlert{}, map[int]bool{}
	add := func(e ObservedAlert) {
		if !seen[e.EventID] {
			seen[e.EventID] = true
			key := linkKey(e.SenderIP, e.ReceiverIP)
			flagged[key] = append(flagged[key], e)
		}
	}
	for i := range o.Incidents {
		o.Incidents[i].RelatedEvents = tagWorldEvents(o.Incidents[i].RelatedEvents)
		for _, e := range o.Incidents[i].RelatedEvents {
			add(e)
		}
	}
	for _, e := range o.Alerts {
		add(e)
	}
	routine := map[string]*SuppressedLink{}
	for key, events := range flagged {
		sort.SliceStable(events, func(i, j int) bool { return events[i].T < events[j].T })
		decided := decideServiceEvents(Incident{Family: worldRuleFamily}, worldLinkedEvents(events), 1)
		if decided.FinalDecision == "SUPPRESSED" {
			routine[key] = &SuppressedLink{Key: key, ProtocolTag: decided.ProtocolTag, RuleClassification: decided.RuleClassification,
				RuleReason: decided.RuleReason, Events: len(events)}
		}
	}
	if len(o.Incidents) > 0 {
		o.RawIncidents = append([]ObservedIncident{}, o.Incidents...)
	}
	retained := make([]ObservedIncident, 0, len(o.Incidents))
	for _, x := range o.Incidents {
		x.FinalDecision, x.RuleClassification = "RETAINED", "UNKNOWN"
		x.RuleReason = "Model incident retained; no deterministic service suppression rule applies"
		link := routine[linkKey(x.SenderIP, x.ReceiverIP)]
		if link == nil {
			retained = append(retained, x)
			continue
		}
		link.Incidents++
		x.FinalDecision, x.RuleClassification, x.RuleReason, x.ProtocolTag = "SUPPRESSED", link.RuleClassification, link.RuleReason, link.ProtocolTag
		o.SuppressedIncidents = append(o.SuppressedIncidents, x)
	}
	o.Incidents = retained
	alerts := make([]ObservedAlert, 0, len(o.Alerts))
	for _, x := range o.Alerts {
		if routine[linkKey(x.SenderIP, x.ReceiverIP)] != nil {
			o.SuppressedAlerts = append(o.SuppressedAlerts, x)
		} else {
			alerts = append(alerts, x)
		}
	}
	o.Alerts = alerts
	// A forecast alert has no ports to judge. On a routine-service link it is
	// that service again, so it is set aside with the link rather than raised.
	predicted := make([]ForecastAlert, 0, len(f.Alerts))
	for _, x := range f.Alerts {
		if routine[linkKey(x.SenderIP, x.ReceiverIP)] != nil {
			f.SuppressedAlerts = append(f.SuppressedAlerts, x)
		} else {
			predicted = append(predicted, x)
		}
	}
	f.Alerts = predicted
	for _, link := range routine {
		o.SuppressedLinks = append(o.SuppressedLinks, *link)
	}
	sort.Slice(o.SuppressedLinks, func(i, j int) bool { return o.SuppressedLinks[i].Key < o.SuppressedLinks[j].Key })
}

func worldLinkedEvents(events []ObservedAlert) []DetectionIncidentEvent {
	linked := make([]DetectionIncidentEvent, len(events))
	for i, e := range events {
		linked[i] = DetectionIncidentEvent{Family: "World model", EventID: e.EventID, TObs: e.T, Score: e.Value,
			Src: e.Src, Dst: e.Dst, SrcPort: e.SrcPort, DstPort: e.DstPort, Protocol: e.Protocol,
			EstablishedConnection: e.EstablishedConnection, NormalDNSQuery: e.NormalDNSQuery,
			NormalGVCPDiscovery: e.NormalGVCPDiscovery, SourcePacketsPerSecond: e.SourcePacketsPerSecond,
			ServiceEvidenceVersion: e.ServiceEvidenceVersion}
	}
	annotateIncidentEvents(linked)
	return linked
}

// tagWorldEvents returns the events with their service tags, for display.
func tagWorldEvents(events []ObservedAlert) []ObservedAlert {
	linked := worldLinkedEvents(events)
	tagged := append([]ObservedAlert{}, events...)
	for i := range tagged {
		if tagged[i].Src != "" {
			tagged[i].ProtocolTag, tagged[i].TrafficClass, tagged[i].ConnectionRole = linked[i].ProtocolTag, linked[i].TrafficClass, linked[i].ConnectionRole
		}
	}
	return tagged
}
