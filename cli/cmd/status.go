package cmd

import (
	"fmt"
	"netwatch/api"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Netwatch system status",
	Run: func(cmd *cobra.Command, args []string) {
		client := api.NewClient("http://localhost:8080")
		status, err := client.GetStatus()
		
		fmt.Println(lipgloss.NewStyle().Foreground(textLight).Background(primary).Bold(true).Padding(0, 1).Render("Netwatch System Status"))
		fmt.Println()

		if err != nil {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Render(fmt.Sprintf("Error connecting to backend: %v", err)))
			return
		}

		keyStyle := lipgloss.NewStyle().Foreground(primary).Width(10).Bold(true)
		valStyle := lipgloss.NewStyle().Foreground(accent)

		fmt.Printf("%s %s\n", keyStyle.Render("Status:"), valStyle.Render(status.Status))
		fmt.Printf("%s %s\n", keyStyle.Render("Uptime:"), valStyle.Render(status.Uptime))
		fmt.Printf("%s %s\n", keyStyle.Render("Version:"), valStyle.Render(status.Version))
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
