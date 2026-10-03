package cmd

import (
	"strings"
	"testing"

	"detector/modelapi"
)

func TestModelAlarmsPrimeAndSeparateObservedModes(t *testing.T) {
	tracker := newModelAlarmTracker("both", "incident")
	forecast := &modelapi.ForecastResponse{Observed: modelapi.Observed{
		Incidents: []modelapi.ObservedIncident{{ID: "old", SenderIP: "a", ReceiverIP: "b"}},
		Alerts:    []modelapi.ObservedAlert{{T: 1, SenderIP: "a", ReceiverIP: "b"}},
	}}
	detections := &modelapi.DetectionsResponse{
		Incidents:        []modelapi.Incident{{Incident: 1, Family: "Bot"}},
		RecentDetections: []modelapi.Detection{{Family: "Bot", TObs: 1}},
	}
	if got := tracker.report(forecast, detections); len(got) != 0 {
		t.Fatalf("historical first snapshot alarmed: %v", got)
	}
	if got := tracker.report(forecast, detections); len(got) != 0 {
		t.Fatalf("unchanged snapshot alarmed: %v", got)
	}
	forecast.Observed.Alerts = append(forecast.Observed.Alerts, modelapi.ObservedAlert{T: 2, SenderIP: "c", ReceiverIP: "d"})
	detections.Incidents = append(detections.Incidents, modelapi.Incident{Incident: 2, Family: "Bot"})
	detections.RecentDetections = append(detections.RecentDetections, modelapi.Detection{Family: "Bot", TObs: 2})
	got := tracker.report(forecast, detections)
	if len(got) != 2 || !strings.Contains(got[0], "world event") || !strings.Contains(got[1], "detector incident") {
		t.Fatalf("wanted only new selected observations, got %v", got)
	}
}

func TestModelAlarmsSeeRecentlyClosedIncident(t *testing.T) {
	tracker := newModelAlarmTracker("off", "incident")
	forecast := &modelapi.ForecastResponse{}
	detections := &modelapi.DetectionsResponse{
		RecentIncidents: []modelapi.Incident{{Incident: 1, Family: "Bot", T: 100}},
	}
	if got := tracker.report(forecast, detections); len(got) != 0 {
		t.Fatalf("initial history alarmed: %v", got)
	}
	detections.RecentIncidents = append(detections.RecentIncidents,
		modelapi.Incident{Incident: 2, Family: "Bot", T: 200})
	if got := tracker.report(forecast, detections); len(got) != 1 || !strings.Contains(got[0], "detector incident") {
		t.Fatalf("new closed incident was not alarmed: %v", got)
	}
}
