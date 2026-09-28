package cmd

import (
	"fmt"
	"os"

	"detector/capture"

	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [pcap-file]",
	Short: "Analyze network traffic from an offline PCAP / PCAP-NG file",
	Long: `Analyze offline network packet captures (PCAP / PCAP-NG) by streaming packets
through 10-second relative time windows, computing statistical telemetry, and
evaluating deterministic attack indicator rules.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetFile := pcapFlag
		if len(args) > 0 {
			targetFile = args[0]
		}
		if targetFile == "" {
			fmt.Fprintln(os.Stderr, "Error: Please specify a PCAP file path (e.g. 'detector analyze sample.pcap' or '--pcap sample.pcap')")
			return
		}
		runAnalysis(targetFile)
	},
}

func runAnalysis(filePath string) {
	h, err := capture.OpenPCAP(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening PCAP file %q: %v\n", filePath, err)
		return
	}
	defer h.Close()

	runPipeline(h, fmt.Sprintf("PCAP File: %s", filePath), false)
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
}
