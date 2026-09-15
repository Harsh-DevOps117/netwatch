package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"detector/alert"
	"detector/capture"
	"detector/config"
	"detector/features"
	"detector/output"
	"detector/parser"
	"detector/rules"
	"detector/window"

	"github.com/spf13/cobra"
)

var dashboardPort int

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Run the local Netwatch observability dashboard",
	Long:  "Captures real local traffic, evaluates deterministic rules, and serves a local-only dashboard at http://127.0.0.1:<port>.",
	Run:   func(cmd *cobra.Command, args []string) { runDashboard() },
}

func init() {
	dashboardCmd.Flags().IntVarP(&dashboardPort, "port", "p", 8787, "Local dashboard port")
	dashboardCmd.Flags().StringVarP(&liveIface, "interface", "i", "", "Network interface (default: active interface)")
	dashboardCmd.Flags().StringVarP(&liveBPF, "bpf", "b", "", "BPF packet capture filter")
	rootCmd.AddCommand(dashboardCmd)
}

type dashboardStore struct {
	mu          sync.RWMutex
	iface       string
	started     time.Time
	current     *features.WindowFeatures
	history     []*features.WindowFeatures
	alerts      []alert.Alert
	inBytes     int64
	outBytes    int64
	inPackets   int
	outPackets  int
	subscribers map[chan struct{}]struct{}
}

func newDashboardStore(iface string) *dashboardStore {
	return &dashboardStore{iface: iface, started: time.Now(), subscribers: make(map[chan struct{}]struct{})}
}

func (s *dashboardStore) ingest(f *features.WindowFeatures, alerts []alert.Alert) {
	s.mu.Lock()
	s.current = f
	s.history = append(s.history, f)
	if len(s.history) > 120 {
		s.history = s.history[len(s.history)-120:]
	}
	s.alerts = append(s.alerts, alerts...)
	if len(s.alerts) > 300 {
		s.alerts = s.alerts[len(s.alerts)-300:]
	}
	s.inBytes, s.outBytes, s.inPackets, s.outPackets = 0, 0, 0, 0
	for _, node := range f.Graph.Nodes {
		if isLocalIP(node.IP) {
			s.inBytes += node.BytesReceived
			s.outBytes += node.BytesSent
			s.inPackets += node.PacketsReceived
			s.outPackets += node.PacketsSent
		}
	}
	for subscriber := range s.subscribers {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
	s.mu.Unlock()
}

func (s *dashboardStore) subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.subscribers, ch)
		s.mu.Unlock()
	}
}

func isLocalIP(ip string) bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var candidate net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				candidate = v.IP
			case *net.IPAddr:
				candidate = v.IP
			}
			if candidate != nil && candidate.String() == ip {
				return true
			}
		}
	}
	return false
}

func (s *dashboardStore) snapshot() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	current := s.current
	flows := []features.FlowRecord{}
	graph := features.NetworkGraph{}
	if current != nil {
		flows, graph = current.ActiveFlows, current.Graph
	}
	sort.Slice(flows, func(i, j int) bool { return flows[i].LastSeen.After(flows[j].LastSeen) })
	return map[string]interface{}{
		"status":  map[string]interface{}{"interface": s.iface, "started_at": s.started, "capture_duration_seconds": int(time.Since(s.started).Seconds()), "connected": true, "deterministic": true},
		"current": current, "history": s.history, "flows": flows, "graph": graph, "alerts": s.alerts,
		"direction": map[string]interface{}{"inbound_bytes": s.inBytes, "outbound_bytes": s.outBytes, "inbound_packets": s.inPackets, "outbound_packets": s.outPackets},
		"system":    localSystemInfo(s.iface),
	}
}

func localSystemInfo(captureInterface string) map[string]interface{} {
	hostname, _ := os.Hostname()
	info := map[string]interface{}{"hostname": hostname, "operating_system": runtime.GOOS, "network_interface": captureInterface, "interface_ips": []string{}, "mac_address": "", "gateway_ip": defaultGateway(captureInterface)}
	if iface, err := net.InterfaceByName(captureInterface); err == nil {
		info["mac_address"] = iface.HardwareAddr.String()
		addrs, _ := iface.Addrs()
		ips := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if ip, _, err := net.ParseCIDR(addr.String()); err == nil {
				ips = append(ips, ip.String())
			}
		}
		info["interface_ips"] = ips
	}
	return info
}

// defaultGateway reads Linux's route table only to label an actual gateway that
// already appears in observed traffic. If it cannot be determined, the UI omits it.
func defaultGateway(ifaceName string) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != ifaceName || fields[1] != "00000000" {
			continue
		}
		value, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}
		return net.IPv4(byte(value), byte(value>>8), byte(value>>16), byte(value>>24)).String()
	}
	return ""
}

func runDashboard() {
	if dashboardPort < 1 || dashboardPort > 65535 {
		fmt.Fprintln(os.Stderr, "dashboard port must be between 1 and 65535")
		return
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		return
	}
	if windowSec > 0 {
		cfg.WindowSeconds = windowSec
	}
	liveH, err := capture.OpenLive(liveIface, liveBPF)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting live capture: %v\n", err)
		return
	}
	defer liveH.Close()

	store := newDashboardStore(liveH.Interface())
	server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", dashboardPort), Handler: dashboardHandler(store)}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Dashboard server error: %v\n", err)
		}
	}()
	url := fmt.Sprintf("http://127.0.0.1:%d", dashboardPort)
	fmt.Printf("\n  NETWATCH\n  Deterministic Network Threat Detection\n\n  Starting local dashboard...\n  Interface: %s\n  Server: %s\n\n  Press Ctrl+C to stop.\n\n", liveH.Interface(), url)
	openBrowser(url)

	engine := rules.NewEngine(cfg)
	mgr := window.NewManager(time.Duration(cfg.WindowSeconds)*time.Second, time.Duration(cfg.FlowTracking.IdleTimeoutSeconds)*time.Second, cfg.FlowTracking.MaxActiveFlows, func(f *features.WindowFeatures) {
		alerts := engine.Evaluate(f)
		if alerts == nil {
			alerts = []alert.Alert{}
		}
		store.ingest(f, alerts)
		output.PrintWindowReport(f.WindowIndex, f, alerts)
	})
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	tickDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				mgr.Tick(now)
			case <-tickDone:
				return
			}
		}
	}()
	for {
		select {
		case <-stop:
			close(tickDone)
			mgr.Flush()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = server.Shutdown(ctx)
			cancel()
			return
		case pkt, ok := <-liveH.Packets():
			if !ok {
				close(tickDone)
				mgr.Flush()
				_ = server.Close()
				return
			}
			if parsed := parser.ParsePacket(pkt); parsed != nil {
				mgr.ProcessPacket(parsed)
			}
		}
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if cmd != nil {
		_ = cmd.Start()
	}
}

func dashboardHandler(store *dashboardStore) http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, value interface{}) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["status"]) })
	mux.HandleFunc("/api/telemetry/current", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["current"]) })
	mux.HandleFunc("/api/telemetry/history", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["history"]) })
	mux.HandleFunc("/api/flows", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["flows"]) })
	mux.HandleFunc("/api/graph", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["graph"]) })
	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["alerts"]) })
	mux.HandleFunc("/api/windows", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["history"]) })
	mux.HandleFunc("/api/system", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["system"]) })
	mux.HandleFunc("/api/forecast", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]interface{}{"status": "NOT_CONNECTED", "current_state": "S[t]", "future_states": []interface{}{}, "infiltration_probability": []interface{}{}, "predicted_stage": "", "driving_features": []interface{}{}})
	})
	mux.HandleFunc("/api/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		updates, unsubscribe := store.subscribe()
		defer unsubscribe()
		send := func() {
			data, _ := json.Marshal(store.snapshot())
			fmt.Fprintf(w, "event: telemetry\ndata: %s\n\n", data)
			flusher.Flush()
		}
		send()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-updates:
				send()
			case <-time.After(25 * time.Second):
				fmt.Fprint(w, ": keepalive\n\n")
				flusher.Flush()
			}
		}
	})
	return mux
}
