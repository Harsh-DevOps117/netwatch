package cmd

import (
	"encoding/json"
	"testing"
)

func TestEnrichOfflineResultKeepsRawIncidents(t *testing.T) {
	input := []byte(`{"mode":"offline","world":{"status":"CONNECTED"},"detection":{"status":"RUNNING","incidents":[{"family":"Infiltration","incident":1,"t":123,"score":0.99,"related_events":[{"family":"Infiltration","src":"10.4.4.120","dst":"10.200.0.200","src_port":63746,"dst_port":53,"protocol":17,"t_obs":10,"score":0.99},{"family":"Infiltration","src":"10.4.4.120","dst":"10.200.0.200","src_port":63746,"dst_port":53,"protocol":17,"t_obs":20,"score":0.99},{"family":"Infiltration","src":"10.4.4.120","dst":"10.200.0.200","src_port":63746,"dst_port":53,"protocol":17,"t_obs":30,"score":0.99}]}]}}`)
	output, err := enrichOfflineResult(input)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		World     json.RawMessage `json:"world"`
		Detection struct {
			Incidents           []json.RawMessage `json:"incidents"`
			RawIncidents        []json.RawMessage `json:"raw_incidents"`
			SuppressedIncidents []json.RawMessage `json:"suppressed_incidents"`
		} `json:"detection"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Detection.Incidents) != 0 || len(result.Detection.RawIncidents) != 1 || len(result.Detection.SuppressedIncidents) != 1 || len(result.World) == 0 {
		t.Fatalf("incorrect offline rule views: %s", output)
	}
}
