package cmd

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a static network security report",
	Run: func(cmd *cobra.Command, args []string) {
		boxStyle := lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(primary).
			Padding(1, 4).
			MarginTop(1).
			MarginBottom(1)

		titleStyle := lipgloss.NewStyle().Foreground(textLight).Background(primary).Bold(true).Padding(0, 1)
		keyStyle := lipgloss.NewStyle().Foreground(primary).Width(25)
		valStyle := lipgloss.NewStyle().Foreground(accent)
		alertStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)

		content := fmt.Sprintf("%s\n\n", titleStyle.Render("SECURITY AUDIT REPORT"))
		content += fmt.Sprintf("%s %s\n", keyStyle.Render("Total Packets Analyzed:"), valStyle.Render("2,450,112"))
		content += fmt.Sprintf("%s %s\n", keyStyle.Render("Analysis Duration:"), valStyle.Render("24h 00m 12s"))
		content += fmt.Sprintf("%s %s\n", keyStyle.Render("Threat Level:"), alertStyle.Render("ELEVATED"))
		content += fmt.Sprintf("%s %s\n", keyStyle.Render("Detected Anomalies:"), alertStyle.Render("143"))
		content += fmt.Sprintf("%s %s\n", keyStyle.Render("Primary Vector:"), valStyle.Render("Lateral Movement (SSH Brute Force)"))
		content += fmt.Sprintf("%s %s\n", keyStyle.Render("Confidence Score:"), valStyle.Render("92%"))
		content += "\n"
		content += fmt.Sprintf("%s %s\n", keyStyle.Render("Mitigation Suggested:"), valStyle.Render("Isolate Subnet 10.0.5.0/24"))

		fmt.Println(boxStyle.Render(content))
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
}
