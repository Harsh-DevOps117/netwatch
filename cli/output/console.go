package output

import (
	"fmt"
	"strings"

	"detector/alert"
	"detector/features"
)

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"

	colorBgRed   = "\033[41m"
	colorBgGreen = "\033[42m"
	colorBgCyan  = "\033[46m"
)

func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func PrintBanner(sourceDesc string, windowSeconds int, isLive bool) {
	fmt.Println()
	fmt.Printf("%s%s╔════════════════════════════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║                   DETERMINISTIC NETWORK THREAT DETECTION ENGINE                    ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║                     NTRO Cyber Security & Threat Telemetry                         ║%s\n", colorCyan, colorDim, colorReset)
	fmt.Printf("%s%s╚════════════════════════════════════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorCyan, colorReset)

	modeStr := "Offline PCAP Forensics"
	if isLive {
		modeStr = "Real-Time Live Network Monitoring (Streaming)"
	}

	fmt.Printf("  %s%sTraffic Source :%s %s%s%s\n", colorBold, colorWhite, colorReset, colorCyan, sourceDesc, colorReset)
	fmt.Printf("  %s%sOperating Mode :%s %s%s%s\n", colorBold, colorWhite, colorReset, colorGreen, modeStr, colorReset)
	fmt.Printf("  %s%sTime Window    :%s %s%d seconds per aggregation slice%s\n", colorBold, colorWhite, colorReset, colorYellow, windowSeconds, colorReset)
	if isLive {
		fmt.Printf("  %s%sStatus         :%s %s[LIVE MONITORING ACTIVE - Press Ctrl+C to stop]%s\n", colorBold, colorWhite, colorReset, colorYellow, colorReset)
	}
	fmt.Println()
}

func PrintWindowReport(index int, feat *features.WindowFeatures, alerts []alert.Alert) {
	timeSpan := fmt.Sprintf("[%s → %s]",
		feat.WindowStart.Format("15:04:05.000"),
		feat.WindowEnd.Format("15:04:05.000"),
	)

	hasAlerts := len(alerts) > 0
	cardColor := colorCyan
	if hasAlerts {
		cardColor = colorYellow
		for _, a := range alerts {
			if a.Severity == alert.SeverityHigh {
				cardColor = colorRed
				break
			}
		}
	}

	headerText := fmt.Sprintf("── WINDOW #%d (%.0fs duration) ", index+1, feat.DurationSeconds)
	paddingLength := 86 - len(headerText) - len(timeSpan) - 4
	if paddingLength < 2 {
		paddingLength = 2
	}
	padding := strings.Repeat("─", paddingLength)

	fmt.Printf("%s%s┌%s%s %s%s%s%s┐%s\n",
		colorBold, cardColor, headerText, padding, colorWhite, timeSpan, colorBold, cardColor, colorReset,
	)

	fmt.Printf("%s│%s  %s%sTRAFFIC VOLUME%s\n", cardColor, colorReset, colorBold, colorWhite, colorReset)
	fmt.Printf("%s│%s    Packets : %s%-8d%s | Volume  : %s%-11s%s | Rate : %s%.1f pkts/s (%.1f KB/s)%s\n",
		cardColor, colorReset,
		colorBold, feat.TotalPackets, colorReset,
		colorCyan, FormatBytes(feat.TotalBytes), colorReset,
		colorYellow, feat.PacketsPerSecond, feat.BytesPerSecond/1024.0, colorReset,
	)
	fmt.Printf("%s│%s\n", cardColor, colorReset)

	fmt.Printf("%s│%s  %s%sPROTOCOL & TRAFFIC DYNAMICS%s\n", cardColor, colorReset, colorBold, colorWhite, colorReset)
	fmt.Printf("%s│%s    TCP  : %s%-6d%s (SYN: %s%d%s | SYN-ACK: %s%d%s | ACK: %d | RST: %s%d%s | FIN: %d | PSH: %d | URG: %d)\n",
		cardColor, colorReset,
		colorBold, feat.TCPPackets, colorReset,
		colorYellow, feat.SYNCount, colorReset,
		colorCyan, feat.SYNACKCount, colorReset,
		feat.ACKCount,
		colorRed, feat.RSTCount, colorReset,
		feat.FINCount, feat.PSHCount, feat.URGCount,
	)
	fmt.Printf("%s│%s    UDP  : %s%-6d%s (%s) | DNS: %s%-4d%s (%s) | ICMP: %s%-4d%s (Echo: %d)\n",
		cardColor, colorReset,
		colorBold, feat.UDPPackets, colorReset,
		FormatBytes(feat.UDPBytes),
		colorCyan, feat.DNSPackets, colorReset,
		FormatBytes(feat.DNSBytes),
		colorYellow, feat.ICMPPackets, colorReset,
		feat.ICMPEchoRequests,
	)
	fmt.Printf("%s│%s    Rate : SYN %.1f/s | ACK %.1f/s | RST %.1f/s | Ratio SYN/SYN-ACK: %.1f | Incomplete: %d\n",
		cardColor, colorReset,
		feat.SYNPerSecond, feat.ACKPerSecond, feat.RSTPerSecond, feat.SYNAckRatio, feat.ApproxIncompleteConnections,
	)
	fmt.Printf("%s│%s\n", cardColor, colorReset)

	fmt.Printf("%s│%s  %s%sHOST & PORT CARDINALITY%s\n", cardColor, colorReset, colorBold, colorWhite, colorReset)
	fmt.Printf("%s│%s    Unique Source IPs : %s%-4d%s | Unique Dest IPs : %s%-4d%s | Unique Dest Ports : %s%-4d%s\n",
		cardColor, colorReset,
		colorBold, feat.UniqueSourceIPs, colorReset,
		colorBold, feat.UniqueDestinationIPs, colorReset,
		colorBold, feat.UniqueDestinationPorts, colorReset,
	)
	fmt.Printf("%s│%s\n", cardColor, colorReset)

	fmt.Printf("%s│%s  %s%sDETERMINISTIC THREAT INDICATORS%s\n", cardColor, colorReset, colorBold, colorWhite, colorReset)
	if !hasAlerts {
		fmt.Printf("%s│%s    %s%s[✓] CLEAN:%s %sNo abnormal threshold violations or threat indicators detected.%s\n",
			cardColor, colorReset, colorBold, colorGreen, colorReset, colorDim, colorReset,
		)
	} else {
		for _, a := range alerts {
			var badge string
			switch a.Severity {
			case alert.SeverityHigh:
				badge = fmt.Sprintf("%s%s[▲ HIGH ALARM]%s", colorBold, colorRed, colorReset)
			case alert.SeverityMedium:
				badge = fmt.Sprintf("%s%s[● MEDIUM]%s", colorBold, colorYellow, colorReset)
			default:
				badge = fmt.Sprintf("%s%s[○ LOW]%s", colorBold, colorBlue, colorReset)
			}

			fmt.Printf("%s│%s    %s %s%s%s\n", cardColor, colorReset, badge, colorBold, a.Type, colorReset)
			if a.SourceIP != "" {
				fmt.Printf("%s│%s        %sAttacker / Source IP:%s %s%s%s\n",
					cardColor, colorReset, colorDim, colorReset, colorBold, a.SourceIP, colorReset)
			}
			if a.DestinationIP != "" {
				fmt.Printf("%s│%s        %sTarget / Dest IP    :%s %s%s%s\n",
					cardColor, colorReset, colorDim, colorReset, colorBold, a.DestinationIP, colorReset)
			}
			fmt.Printf("%s│%s        %sDiagnostic Evidence :%s %s\n",
				cardColor, colorReset, colorDim, colorReset, a.Reason)
		}
	}

	fmt.Printf("%s%s└%s┘%s\n\n", colorBold, cardColor, strings.Repeat("─", 86), colorReset)
}

func PrintSummary(totalPackets, totalWindows, totalAlerts int) {
	fmt.Printf("%s%s╔════════════════════════════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║                             EXECUTIVE AUDIT SUMMARY                                    ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s╚════════════════════════════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)

	fmt.Printf("  %s• Total Packets Ingested :%s %s%d%s\n", colorBold, colorReset, colorCyan, totalPackets, colorReset)
	fmt.Printf("  %s• Total Windows Evaluated:%s %s%d%s\n", colorBold, colorReset, colorCyan, totalWindows, colorReset)
	fmt.Printf("  %s• Threat Indicators Raised:%s ", colorBold, colorReset)

	if totalAlerts == 0 {
		fmt.Printf("%s%s0 (Clean Traffic)%s\n", colorBold, colorGreen, colorReset)
		fmt.Println()
		fmt.Printf("  %s%s[PASS] AUDIT CONCLUSION:%s Normal network traffic baseline. No deterministic attack\n", colorBold, colorGreen, colorReset)
		fmt.Printf("  indicators triggered within configured confidence thresholds.\n")
	} else {
		fmt.Printf("%s%s%d Indicator(s) Triggered%s\n", colorBold, colorRed, totalAlerts, colorReset)
		fmt.Println()
		fmt.Printf("  %s%s[ACTION REQUIRED] AUDIT CONCLUSION:%s %d behavioral threat indicator(s) identified.\n", colorBold, colorRed, colorReset, totalAlerts)
		fmt.Printf("  Telemetry is packaged and ready for downstream temporal state forecasting.\n")
	}
	fmt.Println()
}
