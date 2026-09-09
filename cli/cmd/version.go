package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	Version   = "1.0.0"
	BuildDate = "2026-09-05"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print engine version and build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Deterministic Network Threat Detection Engine\n")
		fmt.Printf("  Version     : %s\n", Version)
		fmt.Printf("  Build Date  : %s\n", BuildDate)
		fmt.Printf("  Go Version  : %s\n", runtime.Version())
		fmt.Printf("  OS/Arch     : %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("  NTRO Target : AI Based Network Attack Forecasting (Phase 1: Deterministic Engine)\n")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
