package cmd

import (
	"fmt"
	"os"

	"detector/capture"

	"github.com/spf13/cobra"
)

var (
	liveIface string
	liveBPF   string
)

var liveCmd = &cobra.Command{
	Use:   "live",
	Short: "Start real-time live network traffic monitoring on a local interface",
	Long: `Stream raw packets in real-time from a local network interface (e.g. wlo1, eth0),
accumulating live packets into 10-second tumbling windows, extracting behavioral
telemetry, and triggering deterministic alerts instantly.`,
	Run: func(cmd *cobra.Command, args []string) {
		runLive(liveIface, liveBPF)
	},
}

func runLive(iface string, bpf string) {
	targetIface := iface
	if targetIface == "" {
		targetIface = capture.GetDefaultInterface()
	}

	liveH, err := capture.OpenLive(targetIface, bpf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting live capture on interface %q: %v\n", targetIface, err)
		os.Exit(1)
	}
	defer liveH.Close()

	sourceDesc := fmt.Sprintf("Live Interface: %s", targetIface)
	if bpf != "" {
		sourceDesc += fmt.Sprintf(" (BPF: %s)", bpf)
	}

	runPipeline(liveH, sourceDesc, true)
}

func runStdin() {
	stdinH, err := capture.OpenStdin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing PCAP reader from stdin: %v\n", err)
		os.Exit(1)
	}
	defer stdinH.Close()

	runPipeline(stdinH, "Standard Input (PCAP Stream)", false)
}

func init() {
	liveCmd.Flags().StringVarP(&liveIface, "interface", "i", "", "Network interface (e.g. wlo1, eth0, any)")
	liveCmd.Flags().StringVarP(&liveBPF, "bpf", "b", "", "BPF capture filter expression (e.g. 'tcp or udp')")
	rootCmd.AddCommand(liveCmd)
}
