package modelapi

import (
	"context"
	"fmt"
	"net/netip"
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
	if !serviceRuleFamily(x.Family) {
		return x
	}
	if len(events) < 3 {
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
