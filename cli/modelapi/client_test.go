package modelapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestURLsForService(t *testing.T) {
	tests := []struct {
		service string
		want    string
	}{
		{"lag", "http://127.0.0.1:8901/forecast"},
		{"live", "http://127.0.0.1:8902/forecast"},
		{"replay", "http://127.0.0.1:8900/forecast"},
	}
	for _, tc := range tests {
		got, _, err := URLsForService(tc.service)
		if err != nil || got != tc.want {
			t.Fatalf("URLsForService(%q) = %q, %v; want %q", tc.service, got, err, tc.want)
		}
	}
}

func TestForecast(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"CONNECTED","score":"target_probability","source":{"mode":"live","tag":"lag"},"future_states":["S[t+1]"]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	response, err := client.Forecast(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != "CONNECTED" || response.Source == nil || response.Source.Tag != "lag" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestForecastIncludesUpstreamError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "live model not promoted", http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	_, err := client.Forecast(context.Background())
	if err == nil || !strings.Contains(err.Error(), "live model not promoted") {
		t.Fatalf("expected upstream detail, got %v", err)
	}
}

func TestDetectionsRuntimeContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"RUNNING","packets":120,"events_scored":12,"thresholds":{"Bot":{"threshold":0.5402,"baseline_threshold":0.4402,"false_alarm_budget":0.0001,"effective_false_alarm_budget":0.004,"adaptive":true,"adaptive_ready":true,"adaptive_samples":1024,"adaptive_warmup":1024},"Uncalibrated":{"threshold":null,"false_alarm_budget":null}},"incidents_by_family":{"Bot":1},"recent_detections":[{"family":"Bot","protocol":6,"sender":"192.0.2.1"}],"incidents":[{"key":3,"incident":1}],"attention":[{"event_id":9,"sender_ip":"192.0.2.1","receiver_ip":"198.51.100.2","attended":[{"edge":"192.0.2.1 -> 198.51.100.3","attention":0.75}]}]}`))
	}))
	defer server.Close()
	response, err := NewClient("", server.URL).Detections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	threshold := response.Thresholds["Bot"]
	if response.Status != "RUNNING" || response.Packets != 120 || response.EventsScored != 12 ||
		threshold.Threshold == nil || *threshold.Threshold != 0.5402 ||
		threshold.BaselineThreshold == nil || *threshold.BaselineThreshold != 0.4402 ||
		threshold.FalseAlarmBudget == nil || *threshold.FalseAlarmBudget != 0.0001 ||
		threshold.EffectiveFalseAlarmBudget == nil || *threshold.EffectiveFalseAlarmBudget != 0.004 ||
		!threshold.Adaptive || !threshold.AdaptiveReady || threshold.AdaptiveSamples != 1024 || threshold.AdaptiveWarmup != 1024 ||
		response.Thresholds["Uncalibrated"].Threshold != nil ||
		response.IncidentsByFamily["Bot"] != 1 ||
		response.RecentDetections[0].Protocol != 6 || response.Incidents[0].Key != 3 ||
		len(response.Attention) != 1 || response.Attention[0].Attended[0].Attention != 0.75 {
		t.Fatalf("unexpected detection payload: %#v", response)
	}
}
