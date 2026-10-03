package modelapi

// OfflineIncident is the completed-PCAP incident shape. Related events are
// already present, so no detector service call or checkpoint change is needed.
type OfflineIncident struct {
	Incident
	RelatedEvents []DetectionIncidentEvent `json:"related_events"`
}

// ApplyOfflineRules returns the operator-facing and suppressed views while
// leaving the caller's original model incidents available as raw history.
func ApplyOfflineRules(input []OfflineIncident) (visible, suppressed []OfflineIncident) {
	visible = make([]OfflineIncident, 0, len(input))
	for _, row := range input {
		row.ModelClassification, row.ModelScore = row.Family, row.Score
		row.FinalDecision = "RETAINED"
		row.RuleClassification = "UNKNOWN"
		row.RuleReason = "Model incident retained; no deterministic service suppression rule applies"
		annotateIncidentEvents(row.RelatedEvents)
		if serviceRuleFamily(row.Family) {
			row.Incident = decideServiceIncident(row.Incident, row.RelatedEvents)
		}
		if row.FinalDecision == "SUPPRESSED" {
			suppressed = append(suppressed, row)
		} else {
			visible = append(visible, row)
		}
	}
	return visible, suppressed
}
