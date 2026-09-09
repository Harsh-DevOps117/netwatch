package output

import (
	"encoding/json"
	"fmt"
	"os"

	"detector/alert"
	"detector/features"
)

type WindowRecord struct {
	WindowStart     string                   `json:"window_start"`
	WindowEnd       string                   `json:"window_end"`
	DurationSeconds float64                  `json:"duration_seconds"`
	Features        *features.WindowFeatures `json:"features"`
	Alerts          []alert.Alert            `json:"alerts"`
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
