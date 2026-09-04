package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var (
	primary   = lipgloss.Color("#0033ff") // Blue
	accent    = lipgloss.Color("#befd66") // Chartreuse
	textLight = lipgloss.Color("#e3e3e3")
	textDark  = lipgloss.Color("#111111")

	bannerStyle  = lipgloss.NewStyle().Foreground(primary).Bold(true)
	titleStyle   = lipgloss.NewStyle().Foreground(textLight).Background(primary).Bold(true).Padding(1, 1).Margin(1, 0, 1, 0)
	tagStyle     = lipgloss.NewStyle().Foreground(accent).Padding(0, 0, 1, 8)
	quoteStyle   = lipgloss.NewStyle().Foreground(primary).Padding(0, 0, 2, 8)
	cmdHdrStyle  = lipgloss.NewStyle().Foreground(primary).Bold(true).Padding(0, 0, 1, 2)
	cmdNameStyle = lipgloss.NewStyle().Foreground(accent).Width(12).Padding(0, 0, 0, 2)
	cmdDescStyle = lipgloss.NewStyle().Foreground(primary)
)

const asciiBanner = `
███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝`

var rootCmd = &cobra.Command{
	Use:   "netwatch",
	Short: "AI based Network Attack Forecasting",
	Long:  "Netwatch is a CLI tool for AI based Network Attack Forecasting.\nIt learns, predicts, and defends your network.",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Println(bannerStyle.Render(asciiBanner))
		fmt.Println(titleStyle.Render("AI based Network Attack Forecasting"))
		fmt.Println(tagStyle.Render("Learn · Predict · Defend"))
		fmt.Println(quoteStyle.Render("A safer tomorrow, one packet ahead."))

		fmt.Println(cmdHdrStyle.Render("Commands"))

		for _, c := range cmd.Commands() {
			if c.IsAvailableCommand() || c.Name() == "help" {
				name := cmdNameStyle.Render(fmt.Sprintf("%-12s", c.Name()))
				desc := cmdDescStyle.Render(c.Short)
				fmt.Printf("%s %s\n", name, desc)
			}
		}
		fmt.Println()
	})
}
