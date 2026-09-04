package cmd

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(lipgloss.NewStyle().Foreground(primary).Bold(true).Render("Netwatch CLI v1.0.0"))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
