package pipeline

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"netflow/models"
)

// CSVWriter manages thread-safe writing of CICFlowMeter flow features to a CSV file.
type CSVWriter struct {
	mu       sync.Mutex
	filePath string
}

// NewCSVWriter creates a new CSVWriter instance and ensures output directory exists.
func NewCSVWriter(filePath string) (*CSVWriter, error) {
	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory for CSV output '%s': %w", dir, err)
		}
	}

	return &CSVWriter{
		filePath: filePath,
	}, nil
}

// WriteFlowFeatures appends a slice of FlowFeature objects to the target CSV file.
func (cw *CSVWriter) WriteFlowFeatures(features []*models.FlowFeature) error {
	if len(features) == 0 {
		return nil
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	fileExists := false
	if info, err := os.Stat(cw.filePath); err == nil && info.Size() > 0 {
		fileExists = true
	}

	file, err := os.OpenFile(cw.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open CSV file '%s': %w", cw.filePath, err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header if creating a new file
	if !fileExists {
		if err := writer.Write(models.CSVHeaders()); err != nil {
			return fmt.Errorf("failed to write CSV headers: %w", err)
		}
	}

	for _, feat := range features {
		if err := writer.Write(feat.ToCSVRow()); err != nil {
			return fmt.Errorf("failed to write flow feature row: %w", err)
		}
	}

	log.Printf("[CSV Writer] Successfully appended %d flow feature rows to '%s'", len(features), cw.filePath)
	return nil
}
