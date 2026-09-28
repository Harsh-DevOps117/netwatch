package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"detector/alert"
	"detector/capture"
	"detector/config"
	"detector/features"
	"detector/output"
	"detector/parser"
	"detector/rules"
	"detector/window"

	"github.com/spf13/cobra"
)

var (
	configPath string
	windowSec  int
	outputPath string
	pcapFlag   string
	liveFlag   bool
	ifaceFlag  string
	stdinFlag  bool
	bpfFlag    string
)

var rootCmd = &cobra.Command{
	Use:   "detector",
	Short: "Deterministic Network Threat Detection Engine",
	Long: `Deterministic network threat detection engine for real-time traffic monitoring
and PCAP analysis using deterministic telemetry and sliding time windows.`,
	Run: func(cmd *cobra.Command, args []string) {
		targetPCAP := pcapFlag
		if len(args) > 0 && targetPCAP == "" {
			targetPCAP = args[0]
		}

		if targetPCAP != "" {
			runAnalysis(targetPCAP)
			return
		}

		if liveFlag || ifaceFlag != "" {
			runLive(ifaceFlag, bpfFlag)
			return
		}

		if stdinFlag {
			runStdin()
			return
		}

		runInteractive()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "Path to YAML configuration file")
	rootCmd.PersistentFlags().IntVarP(&windowSec, "window", "w", 0, "Time window duration in seconds (default 10)")
	rootCmd.PersistentFlags().StringVarP(&outputPath, "output", "o", "", "Path to export per-window JSON telemetry and alerts")

	rootCmd.Flags().StringVarP(&pcapFlag, "pcap", "p", "", "Path to PCAP file to analyze")
	rootCmd.Flags().BoolVarP(&liveFlag, "live", "l", false, "Start real-time live network monitoring on default interface")
	rootCmd.Flags().StringVarP(&ifaceFlag, "interface", "i", "", "Network interface for real-time capture (e.g. wlo1, any)")
	rootCmd.Flags().BoolVar(&stdinFlag, "stdin", false, "Stream PCAP from standard input pipe")
	rootCmd.Flags().StringVar(&bpfFlag, "bpf", "", "BPF packet capture filter")
}

func runPipeline(reader capture.PacketReader, sourceDesc string, isLive bool) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		return
	}
	if windowSec > 0 {
		cfg.WindowSeconds = windowSec
	}

	output.PrintBanner(sourceDesc, cfg.WindowSeconds, isLive)

	engine := rules.NewEngine(cfg)
	var recordsMu sync.Mutex
	var records []output.WindowRecord
	var windowIndex int
	var totalAlerts int
	var totalPackets int

	windowDuration := time.Duration(cfg.WindowSeconds) * time.Second
	flowIdleTimeout := time.Duration(cfg.FlowTracking.IdleTimeoutSeconds) * time.Second

	windowMgr := window.NewManager(
		windowDuration,
		flowIdleTimeout,
		cfg.FlowTracking.MaxActiveFlows,
		func(feat *features.WindowFeatures) {
			recordsMu.Lock()
			defer recordsMu.Unlock()

			alerts := engine.Evaluate(feat)
			if alerts == nil {
				alerts = []alert.Alert{}
			}
			totalAlerts += len(alerts)

			output.PrintWindowReport(windowIndex, feat, alerts)
			windowIndex++

			records = append(records, output.WindowRecord{
				SchemaVersion:       feat.SchemaVersion,
				WindowIndex:         feat.WindowIndex,
				WindowStart:         feat.WindowStart.Format(time.RFC3339Nano),
				WindowEnd:           feat.WindowEnd.Format(time.RFC3339Nano),
				DurationSeconds:     feat.DurationSeconds,
				Features:            feat,
				ActiveFlows:         feat.ActiveFlows,
				Graph:               feat.Graph,
				DeterministicAlerts: alerts,
				GroundTruthLabel:    "",
			})
		},
	)

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	tickerDone := make(chan struct{})
	if isLive {
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case now := <-ticker.C:
					windowMgr.Tick(now)
				case <-tickerDone:
					return
				}
			}
		}()
	}

	packetsChan := reader.Packets()
	running := true

	for running {
		select {
		case <-stopChan:
			fmt.Printf("\n%s\n", "[!] Received termination signal. Finalizing telemetry...")
			running = false

		case pkt, ok := <-packetsChan:
			if !ok {
				running = false
				break
			}

			parsed := parser.ParsePacket(pkt)
			if parsed == nil {
				continue
			}
			totalPackets++
			windowMgr.ProcessPacket(parsed)
		}
	}

	if isLive {
		close(tickerDone)
	}

	windowMgr.Flush()

	output.PrintSummary(totalPackets, windowIndex, totalAlerts)

	if outputPath != "" {
		recordsMu.Lock()
		exportErr := output.ExportJSON(outputPath, records)
		recordsMu.Unlock()

		if exportErr != nil {
			fmt.Fprintf(os.Stderr, "Error exporting JSON: %v\n", exportErr)
		} else {
			fmt.Printf("Exported %d window records to %s\n", len(records), outputPath)
		}
	}
}
