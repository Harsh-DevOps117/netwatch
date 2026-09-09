package pipeline

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"netflow/config"
)

// PCAPAggregator manages 2-minute rolling PCAP aggregate dumping and triggers CICFlowMeter parsing.
type PCAPAggregator struct {
	cfg        *config.Config
	csvWriter  *CSVWriter
	mu         sync.Mutex
	currentFile *os.File
	pcapWriter *pcapgo.Writer
	filePath   string
	startTime  time.Time
	pktCount   int64
}

// NewPCAPAggregator creates a new PCAPAggregator instance.
func NewPCAPAggregator(cfg *config.Config, csvWriter *CSVWriter) (*PCAPAggregator, error) {
	if err := os.MkdirAll(cfg.TempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp dir '%s': %w", cfg.TempDir, err)
	}

	agg := &PCAPAggregator{
		cfg:       cfg,
		csvWriter: csvWriter,
	}

	return agg, nil
}

// Start begins the rolling window manager loop.
func (pa *PCAPAggregator) Start(ctx context.Context, packetChan <-chan gopacket.Packet) {
	if err := pa.rotateWindow(); err != nil {
		log.Printf("[Aggregator Error] Failed to initialize first PCAP window: %v", err)
	}

	ticker := time.NewTicker(pa.cfg.WindowDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[Aggregator] Shutting down rolling PCAP aggregator...")
			pa.closeAndProcessCurrentWindow()
			return

		case <-ticker.C:
			log.Printf("[Aggregator] Rolling window interval (%v) reached. Rotating PCAP aggregate file...", pa.cfg.WindowDuration)
			pa.closeAndProcessCurrentWindow()
			if err := pa.rotateWindow(); err != nil {
				log.Printf("[Aggregator Error] Failed to rotate PCAP window: %v", err)
			}

		case pkt, ok := <-packetChan:
			if !ok {
				pa.closeAndProcessCurrentWindow()
				return
			}
			pa.writePacket(pkt)
		}
	}
}

// writePacket appends a single packet to the current open PCAP file.
func (pa *PCAPAggregator) writePacket(pkt gopacket.Packet) {
	if pkt == nil {
		return
	}

	pa.mu.Lock()
	defer pa.mu.Unlock()

	if pa.pcapWriter == nil {
		return
	}

	meta := pkt.Metadata()
	ci := gopacket.CaptureInfo{
		Timestamp:      meta.Timestamp,
		CaptureLength:  meta.CaptureInfo.CaptureLength,
		Length:         meta.CaptureInfo.Length,
		InterfaceIndex: 0,
	}

	if ci.Timestamp.IsZero() {
		ci.Timestamp = time.Now()
	}
	if ci.CaptureLength == 0 {
		ci.CaptureLength = len(pkt.Data())
		ci.Length = len(pkt.Data())
	}

	if err := pa.pcapWriter.WritePacket(ci, pkt.Data()); err != nil {
		log.Printf("[Aggregator Warning] Error writing packet to PCAP: %v", err)
	} else {
		pa.pktCount++
	}
}

// rotateWindow opens a new timestamped PCAP dump file.
func (pa *PCAPAggregator) rotateWindow() error {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	now := time.Now()
	fileName := fmt.Sprintf("aggregate_%s.pcap", now.Format("20060102_150405"))
	pa.filePath = filepath.Join(pa.cfg.TempDir, fileName)
	pa.startTime = now
	pa.pktCount = 0

	f, err := os.Create(pa.filePath)
	if err != nil {
		return fmt.Errorf("failed to create PCAP dump file '%s': %w", pa.filePath, err)
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return fmt.Errorf("failed to write PCAP header: %w", err)
	}

	pa.currentFile = f
	pa.pcapWriter = w

	log.Printf("[Aggregator] Opened new rolling PCAP window: '%s'", pa.filePath)
	return nil
}

// closeAndProcessCurrentWindow closes the current PCAP file and triggers CICFlowMeter processing.
func (pa *PCAPAggregator) closeAndProcessCurrentWindow() {
	pa.mu.Lock()
	fileToProcess := pa.filePath
	f := pa.currentFile
	count := pa.pktCount

	pa.currentFile = nil
	pa.pcapWriter = nil
	pa.mu.Unlock()

	if f != nil {
		f.Sync()
		f.Close()
		log.Printf("[Aggregator] Closed PCAP aggregate '%s' (%d packets collected).", fileToProcess, count)
	}

	if fileToProcess == "" || count == 0 {
		if fileToProcess != "" && !pa.cfg.KeepTempPCAP {
			os.Remove(fileToProcess)
		}
		return
	}

	// Asynchronously process PCAP with CICFlowMeter
	go func(pcapPath string) {
		log.Printf("[CICFlowMeter Engine] Processing 2-minute PCAP aggregate '%s'...", pcapPath)
		features, err := ProcessPcapFile(pcapPath)
		if err != nil {
			log.Printf("[CICFlowMeter Engine Error] Failed to extract features from '%s': %v", pcapPath, err)
			return
		}

		log.Printf("[CICFlowMeter Engine] Extracted %d bidirectional flows from '%s'. Exporting to CSV...", len(features), pcapPath)

		if err := pa.csvWriter.WriteFlowFeatures(features); err != nil {
			log.Printf("[CICFlowMeter Engine Error] Failed to write features to CSV: %v", err)
		}

		if !pa.cfg.KeepTempPCAP {
			if err := os.Remove(pcapPath); err != nil {
				log.Printf("[Aggregator Warning] Could not remove temp file '%s': %v", pcapPath, err)
			}
		}
	}(fileToProcess)
}
