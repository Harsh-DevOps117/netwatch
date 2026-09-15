package output

import (
	"encoding/json"
	"fmt"
	"os"

	"detector/alert"
	"detector/features"
)

type WindowRecord struct {
	SchemaVersion       string                   `json:"schema_version"`
	WindowIndex         int                      `json:"window_index"`
	WindowStart         string                   `json:"window_start"`
	WindowEnd           string                   `json:"window_end"`
	DurationSeconds     float64                  `json:"duration_seconds"`
	Features            *features.WindowFeatures `json:"features"`
	ActiveFlows         []features.FlowRecord    `json:"active_flows,omitempty"`
	Graph               features.NetworkGraph    `json:"graph"`
	DeterministicAlerts []alert.Alert            `json:"deterministic_alerts"`
	GroundTruthLabel    string                   `json:"ground_truth_label,omitempty"`
}

func ExportJSON(path string, records []WindowRecord) error {
	if path == "" {
		return nil
	}

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize JSON output: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON output to %q: %w", path, err)
	}

	return nil
}
