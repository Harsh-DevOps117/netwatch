package cmd

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Launch network security dashboard",
	Run: func(cmd *cobra.Command, args []string) {
		p := tea.NewProgram(initialModel())
		if _, err := p.Run(); err != nil {
			fmt.Printf("Error running program: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(dashboardCmd)
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*500, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type packetLog struct {
	Timestamp string
	Source    string
	Dest      string
	Proto     string
	Size      int
	Flags     string
}

type model struct {
	totalPackets int
	tcpCount     int
	udpCount     int
	icmpCount    int
	anomalous    int
	logs         []packetLog
}

func initialModel() model {
	return model{
		totalPackets: 14235,
		tcpCount:     9500,
		udpCount:     4000,
		icmpCount:    735,
		anomalous:    12,
		logs:         make([]packetLog, 0),
	}
}

func (m model) Init() tea.Cmd {
	return tickCmd()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	case tickMsg:
		m.totalPackets += rand.Intn(10) + 1
		
		proto := "TCP"
		r := rand.Intn(100)
		if r > 80 {
			proto = "UDP"
			m.udpCount++
		} else if r > 95 {
			proto = "ICMP"
			m.icmpCount++
		} else {
			m.tcpCount++
		}

		if rand.Intn(100) > 95 {
			m.anomalous++
		}

		flags := []string{"SYN", "ACK", "PSH", "FIN"}
		flag := flags[rand.Intn(len(flags))]
		if proto != "TCP" {
			flag = "-"
		}

		newLog := packetLog{
			Timestamp: time.Now().Format("15:04:05.000"),
			Source:    fmt.Sprintf("192.168.1.%d:%d", rand.Intn(255), rand.Intn(60000)+1024),
			Dest:      fmt.Sprintf("10.0.0.%d:%d", rand.Intn(255), rand.Intn(1024)+1),
			Proto:     proto,
			Size:      rand.Intn(1400) + 40,
			Flags:     flag,
		}

		m.logs = append(m.logs, newLog)
		if len(m.logs) > 10 {
			m.logs = m.logs[1:]
		}

		return m, tickCmd()
	}
	return m, nil
}

func (m model) View() string {
	headerStyle := lipgloss.NewStyle().
		Foreground(textLight).
		Background(primary).
		Bold(true).
		Padding(0, 1).
		MarginBottom(1)

	panelStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(primary).
		Padding(1, 2).
		Width(35)

	logPanelStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(accent).
		Padding(1, 2).
		Width(74)

	title := headerStyle.Render("Netwatch Security Dashboard - LIVE MONITORING")
	
	trafficContent := fmt.Sprintf(
		"Traffic Analytics\n\nTotal Flows: %d\nTCP: %d | UDP: %d | ICMP: %d\nAnomalous: %d\nAvg Latency: %dms",
		m.totalPackets, m.tcpCount, m.udpCount, m.icmpCount, m.anomalous, rand.Intn(20)+10,
	)
	trafficPanel := panelStyle.Render(trafficContent)
	
	predictionContent := fmt.Sprintf(
		"AI Predictions\n\nInfiltration Prob: %d%%\nAttack Stage: Lateral Movement\nTop Feature: Port Scan (SYN)",
		80 + rand.Intn(15),
	)
	predictionPanel := panelStyle.Render(predictionContent)

	statsUi := lipgloss.JoinHorizontal(lipgloss.Top, trafficPanel, "  ", predictionPanel)
	
	var logLines []string
	logLines = append(logLines, "LIVE PACKET CAPTURE (MOCK)")
	logLines = append(logLines, fmt.Sprintf("%-12s | %-21s -> %-21s | %-4s | %-5s | %-4s", "TIME", "SOURCE", "DESTINATION", "TYPE", "SIZE", "FLAG"))
	logLines = append(logLines, strings.Repeat("-", 70))
	for _, l := range m.logs {
		logLines = append(logLines, fmt.Sprintf("%-12s | %-21s -> %-21s | %-4s | %-5db | %-4s", l.Timestamp, l.Source, l.Dest, l.Proto, l.Size, l.Flags))
	}
	
	for i := len(m.logs); i < 10; i++ {
		logLines = append(logLines, "")
	}

	logUi := logPanelStyle.Render(strings.Join(logLines, "\n"))

	footer := lipgloss.NewStyle().Foreground(lipgloss.Color("#666666")).MarginTop(1).Render("Press 'q' to quit")

	return fmt.Sprintf("\n%s\n%s\n%s\n%s\n", title, statsUi, logUi, footer)
}
