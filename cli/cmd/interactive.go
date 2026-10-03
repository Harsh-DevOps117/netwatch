package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"detector/modelapi"
)

const (
	terminalReset = "\033[0m"
	terminalBlue  = "\033[38;5;39m"
	terminalCyan  = "\033[38;5;51m"
	terminalGreen = "\033[38;5;82m"
	terminalBold  = "\033[1m"
)

func runInteractive() {
	printTerminalHeader()
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("netwatch> ")
		if !scanner.Scan() {
			fmt.Println()
			return
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "exit", "quit":
			return
		case "help":
			printInteractiveHelp()
		case "version":
			versionCmd.Run(versionCmd, nil)
		case "analyze":
			file, ok := configureInteractiveOptions(fields[1:])
			if !ok || file == "" {
				fmt.Println("Usage: analyze <file.pcap> [-w seconds] [-o report.json] [-c config.yaml]")
				continue
			}
			runAnalysis(file)
			resetInteractiveOptions()
		case "live":
			iface, ok := configureInteractiveOptions(fields[1:])
			if !ok {
				fmt.Println("Usage: live [interface] [-w seconds] [-o report.json] [-c config.yaml] [--bpf expression]")
				continue
			}
			runLive(iface, bpfFlag)
			resetInteractiveOptions()
		case "dashboard":
			if len(fields) != 1 {
				fmt.Println("Usage: dashboard (use 'detector dashboard --port 8787' for options)")
				continue
			}
			runDashboard()
		case "model":
			if len(fields) != 1 {
				fmt.Println("Usage: model (use 'detector model --help' for service and watch options)")
				continue
			}
			forecastURL, detectionsURL, err := resolveModelEndpoints("lag", "", "")
			if err != nil {
				fmt.Printf("Model configuration error: %v\n", err)
				continue
			}
			if err := renderModelSnapshot(context.Background(), modelapi.NewClient(forecastURL, detectionsURL), false, false, nil); err != nil {
				fmt.Printf("Model service unavailable: %v\n", err)
			}
		case "protect":
			if len(fields) != 1 {
				fmt.Println("Usage: protect")
				continue
			}
			if err := runProtection(context.Background(), "lag", ""); err != nil {
				fmt.Printf("Protection unavailable: %v\n", err)
			}
		default:
			fmt.Printf("Unknown command %q. Type 'help'.\n", fields[0])
		}
	}
}

func printTerminalHeader() {
	logo := []string{
		"███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗",
		"████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║",
		"██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║",
		"██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║",
		"██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║",
		"╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝",
		"NETWORK THREAT DETECTION TERMINAL", "Type help for commands · exit to quit",
	}
	fmt.Println()
	for _, line := range logo {
		fmt.Printf("%s%s%s\n", terminalBold+terminalCyan, line, terminalReset)
	}
	fmt.Println()
}

func configureInteractiveOptions(args []string) (string, bool) {
	var positional string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-w", "--window":
			if i+1 >= len(args) {
				return "", false
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				return "", false
			}
			windowSec, i = n, i+1
		case "-o", "--output":
			if i+1 >= len(args) {
				return "", false
			}
			outputPath, i = args[i+1], i+1
		case "-c", "--config":
			if i+1 >= len(args) {
				return "", false
			}
			configPath, i = args[i+1], i+1
		case "-b", "--bpf":
			if i+1 >= len(args) {
				return "", false
			}
			bpfFlag, i = args[i+1], i+1
		default:
			if strings.HasPrefix(args[i], "-") || positional != "" {
				return "", false
			}
			positional = args[i]
		}
	}
	return positional, true
}

func resetInteractiveOptions() { configPath, outputPath, bpfFlag, windowSec = "", "", "", 0 }

func printInteractiveHelp() {
	fmt.Println("  protect                       Groq incident advice and optional host block")
	fmt.Printf("  %s➜%s analyze <file.pcap> [-w seconds] [-o report.json] [-c config.yaml]\n", terminalGreen, terminalReset)
	fmt.Printf("  %s➜%s live [interface] [-w seconds] [-o report.json] [-c config.yaml] [--bpf expression]\n", terminalGreen, terminalReset)
	fmt.Printf("  %s➜%s dashboard [--port 8787] [--interface iface] [--bpf expression]\n", terminalGreen, terminalReset)
	fmt.Printf("  %s➜%s model [--service lag|live|replay] [--detections] [--watch 5s]\n", terminalGreen, terminalReset)
	fmt.Printf("  %s➜%s version                         Show detector version\n", terminalGreen, terminalReset)
	fmt.Printf("  %s➜%s help                            Show this help\n", terminalGreen, terminalReset)
	fmt.Printf("  %s➜%s exit                            Close the terminal\n", terminalGreen, terminalReset)
}
