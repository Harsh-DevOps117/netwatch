package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds runtime configuration options for packet capture, Kafka, and CICFlowMeter feature extraction.
type Config struct {
	KafkaBrokers  []string
	KafkaTopic    string
	SnapLen       int32
	Promiscuous   bool
	BPFFilter     string
	BatchSize     int
	BatchTimeout  time.Duration
	TargetIfaces  []string      // Specific interface names or keywords to filter (e.g. WiFi, Ethernet)
	ListIfaces    bool          // Flag to list all interfaces and exit
	SimulateMode  bool          // Flag to generate synthetic network packets for testing
	WindowDuration time.Duration // Aggregation window duration for PCAP dumping (e.g., 2m)
	CSVOutputPath string        // Output path for CSV containing CICFlowMeter features
	TempDir       string        // Directory to store temporary PCAP dumps
	KeepTempPCAP  bool          // Keep PCAP aggregate files after processing
}

// LoadConfig parses command-line flags into a Config struct.
func LoadConfig() *Config {
	brokersStr := flag.String("kafka", "localhost:9092", "Comma-separated list of Kafka broker addresses")
	topic := flag.String("topic", "network-packets", "Kafka topic name for network packets")
	snapLen := flag.Int("snaplen", 65535, "Snapshot length for packet capture (bytes)")
	promisc := flag.Bool("promisc", true, "Enable promiscuous mode for network interfaces")
	bpf := flag.String("bpf", "", "BPF filter string (e.g., 'tcp or udp' or 'port 80')")
	batchSize := flag.Int("batch-size", 100, "Kafka producer message batch size")
	batchTimeout := flag.Duration("batch-timeout", 200*time.Millisecond, "Kafka producer batch flush timeout")
	ifacesStr := flag.String("iface", "", "Comma-separated specific interface names/keywords to capture from (default: WiFi and Ethernet)")
	listIfaces := flag.Bool("list-ifaces", false, "List all available network capture interfaces and exit")
	simulate := flag.Bool("simulate", false, "Run in simulation mode with synthetic packet generation (no Npcap required)")

	// CICFlowMeter & Aggregation Window options
	window := flag.Duration("window", 2*time.Minute, "Rolling PCAP aggregation window duration for CICFlowMeter parsing (e.g., 2m, 30s)")
	csvOutput := flag.String("csv-output", "output/cicflow_features.csv", "CSV output file path for extracted CICFlowMeter features")
	tempDir := flag.String("temp-dir", "temp", "Directory to store temporary 2-minute PCAP aggregate dumps")
	keepTemp := flag.Bool("keep-temp-pcap", false, "Retain temporary PCAP dump files after feature extraction")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of NetFlow Packet Ingestion & CICFlowMeter Pipeline:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	var targetIfaces []string
	if *ifacesStr != "" {
		parts := strings.Split(*ifacesStr, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				targetIfaces = append(targetIfaces, trimmed)
			}
		}
	}

	brokers := strings.Split(*brokersStr, ",")
	for i := range brokers {
		brokers[i] = strings.TrimSpace(brokers[i])
	}

	return &Config{
		KafkaBrokers:   brokers,
		KafkaTopic:     *topic,
		SnapLen:        int32(*snapLen),
		Promiscuous:    *promisc,
		BPFFilter:      *bpf,
		BatchSize:      *batchSize,
		BatchTimeout:   *batchTimeout,
		TargetIfaces:   targetIfaces,
		ListIfaces:     *listIfaces,
		SimulateMode:   *simulate,
		WindowDuration: *window,
		CSVOutputPath:  *csvOutput,
		TempDir:        *tempDir,
		KeepTempPCAP:   *keepTemp,
	}
}
