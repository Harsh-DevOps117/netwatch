package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	"detector/modelapi"
	"detector/output"
	"detector/parser"
	"detector/rules"
	"detector/window"

	"github.com/spf13/cobra"
)

var (
	dashboardPort          int
	dashboardModelService  string
	dashboardForecastURL   string
	dashboardDetectionsURL string
	dashboardNoBrowser     bool
	dashboardCapture       bool
)

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Run the local Netwatch observability dashboard",
	Long:  "Serves a local-only dashboard with deterministic capture telemetry and model forecasts. If capture is unavailable, the model dashboard still starts.",
	Run:   func(cmd *cobra.Command, args []string) { runDashboard() },
}

func init() {
	dashboardCmd.Flags().IntVarP(&dashboardPort, "port", "p", 8787, "Local dashboard port")
	dashboardCmd.Flags().StringVarP(&liveIface, "interface", "i", "", "Network interface (default: active interface)")
	dashboardCmd.Flags().StringVarP(&liveBPF, "bpf", "b", "", "BPF packet capture filter")
	dashboardCmd.Flags().StringVar(&dashboardModelService, "model-service", "lag", "Forecast service: lag, live, or replay")
	dashboardCmd.Flags().StringVar(&dashboardForecastURL, "forecast-url", "", "Override the forecast endpoint")
	dashboardCmd.Flags().StringVar(&dashboardDetectionsURL, "detections-url", "", "Override the detections endpoint")
	dashboardCmd.Flags().BoolVar(&dashboardNoBrowser, "no-browser", false, "Do not open the dashboard in a browser")
	dashboardCmd.Flags().BoolVar(&dashboardCapture, "capture", true, "Capture local packets (disable with --capture=false for model-only mode)")
	rootCmd.AddCommand(dashboardCmd)
}

type dashboardStore struct {
	mu               sync.RWMutex
	iface            string
	started          time.Time
	current          *features.WindowFeatures
	history          []*features.WindowFeatures
	alerts           []alert.Alert
	inBytes          int64
	outBytes         int64
	inPackets        int
	outPackets       int
	captureConnected bool
	captureError     string
	subscribers      map[chan struct{}]struct{}
}

func newDashboardStore(iface string) *dashboardStore {
	return &dashboardStore{iface: iface, started: time.Now(), subscribers: make(map[chan struct{}]struct{})}
}

func (s *dashboardStore) setCaptureState(iface string, connected bool, captureError string) {
	s.mu.Lock()
	s.iface = iface
	s.captureConnected = connected
	s.captureError = captureError
	s.notifyLocked()
	s.mu.Unlock()
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
	s.notifyLocked()
	s.mu.Unlock()
}

// notifyLocked wakes live dashboards for both capture state and traffic changes.
// The caller holds s.mu; a slow browser must never block capture.
func (s *dashboardStore) notifyLocked() {
	for subscriber := range s.subscribers {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
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
		flows = append(flows, current.ActiveFlows...)
		graph = current.Graph
	}
	sort.Slice(flows, func(i, j int) bool { return flows[i].LastSeen.After(flows[j].LastSeen) })
	system := localSystemInfo(s.iface)
	activeRoute, _ := system["active_route_interface"].(string)
	routeMismatch := s.captureConnected && captureRouteMismatch(s.iface, activeRoute)
	return map[string]interface{}{
		"status":  map[string]interface{}{"interface": s.iface, "active_route_interface": activeRoute, "route_mismatch": routeMismatch, "started_at": s.started, "capture_duration_seconds": int(time.Since(s.started).Seconds()), "connected": s.captureConnected, "capture_error": s.captureError, "deterministic": true},
		"current": current, "history": s.history, "flows": flows, "graph": graph, "alerts": s.alerts,
		"direction": map[string]interface{}{"inbound_bytes": s.inBytes, "outbound_bytes": s.outBytes, "inbound_packets": s.inPackets, "outbound_packets": s.outPackets},
		"system":    system,
	}
}

func captureRouteMismatch(selected, active string) bool {
	return selected != "" && selected != "any" && active != "" && active != "any" && selected != active
}

func localSystemInfo(captureInterface string) map[string]interface{} {
	hostname, _ := os.Hostname()
	info := map[string]interface{}{"hostname": hostname, "operating_system": runtime.GOOS, "network_interface": captureInterface, "active_route_interface": capture.GetDefaultInterface(), "interface_ips": []string{}, "mac_address": "", "gateway_ip": defaultGateway(captureInterface)}
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
	forecastURL, detectionsURL, err := resolveModelEndpoints(dashboardModelService, dashboardForecastURL, dashboardDetectionsURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Model configuration error: %v\n", err)
		return
	}
	modelClient := modelapi.NewClient(forecastURL, detectionsURL)

	requestedInterface := liveIface
	if requestedInterface == "" {
		requestedInterface = capture.GetDefaultInterface()
	}
	store := newDashboardStore(requestedInterface)
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", dashboardPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting dashboard server: %v\n", err)
		return
	}
	server := &http.Server{Handler: dashboardHandler(store, modelClient), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Dashboard server error: %v\n", err)
		}
	}()
	url := fmt.Sprintf("http://127.0.0.1:%d", dashboardPort)
	fmt.Printf("\n  NETWATCH\n  Network telemetry + model intelligence\n\n  Dashboard: %s\n  Forecast:  %s\n", url, forecastURL)
	if detectionsURL != "" {
		fmt.Printf("  Detections: %s\n", detectionsURL)
	}
	if !dashboardNoBrowser {
		openBrowser(url)
	}
	if !dashboardCapture {
		store.setCaptureState(requestedInterface, false, "Packet capture disabled by --capture=false")
		fmt.Println("  Capture:    disabled (model-only mode)\n\n  Press Ctrl+C to stop.")
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		signal.Stop(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = server.Shutdown(ctx)
		cancel()
		return
	}

	liveH, err := capture.OpenLive(liveIface, liveBPF)
	if err != nil {
		store.setCaptureState(requestedInterface, false, err.Error())
		fmt.Fprintf(os.Stderr, "\n  Capture unavailable; continuing with model dashboard.\n  %v\n\n  Press Ctrl+C to stop.\n", err)
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		signal.Stop(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = server.Shutdown(ctx)
		cancel()
		return
	}
	defer liveH.Close()
	store.setCaptureState(liveH.Interface(), true, "")
	fmt.Printf("  Capture:    %s\n\n  Press Ctrl+C to stop.\n\n", liveH.Interface())

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

func dashboardHandler(store *dashboardStore, modelClient *modelapi.Client) http.Handler {
	mux := http.NewServeMux()
	(&offlineManager{repo: offlineRepo(), errors: make(map[string]string)}).register(mux)
	registerProtectionRoutes(mux, modelClient)
	font, fontErr := loadDashboardFont()
	write := func(w http.ResponseWriter, value interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/offline" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(dashboardHTML))
	})
	mux.HandleFunc("/assets/NeueMachina-Regular.woff2", func(w http.ResponseWriter, r *http.Request) {
		if fontErr != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "font/woff2")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(font)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["status"]) })
	mux.HandleFunc("/api/telemetry", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()) })
	mux.HandleFunc("/api/telemetry/current", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["current"]) })
	mux.HandleFunc("/api/telemetry/history", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["history"]) })
	mux.HandleFunc("/api/flows", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["flows"]) })
	mux.HandleFunc("/api/graph", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["graph"]) })
	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["alerts"]) })
	mux.HandleFunc("/api/windows", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["history"]) })
	mux.HandleFunc("/api/system", func(w http.ResponseWriter, r *http.Request) { write(w, store.snapshot()["system"]) })
	mux.HandleFunc("/api/forecast", func(w http.ResponseWriter, r *http.Request) {
		forecast, err := modelClient.Forecast(r.Context())
		if err != nil {
			write(w, map[string]interface{}{"status": "NOT_CONNECTED", "reason": err.Error(), "current_state": "S[t]", "future_states": []interface{}{}, "predicted_stage": ""})
			return
		}
		write(w, forecast)
	})
	mux.HandleFunc("/api/detections", func(w http.ResponseWriter, r *http.Request) {
		detections, err := modelClient.DetectionsWithRules(r.Context())
		if err != nil {
			write(w, map[string]interface{}{"status": "NOT_CONNECTED", "reason": err.Error()})
			return
		}
		write(w, detections)
	})
	mux.HandleFunc("/api/detection-incident-events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		family := r.URL.Query().Get("family")
		incident, incidentErr := strconv.Atoi(r.URL.Query().Get("incident"))
		opened, openedErr := strconv.ParseFloat(r.URL.Query().Get("opened_at"), 64)
		if family == "" || incidentErr != nil || incident < 1 || openedErr != nil || opened <= 0 {
			http.Error(w, "invalid incident identity", http.StatusBadRequest)
			return
		}
		events, err := modelClient.IncidentEvents(r.Context(), family, incident, opened)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		write(w, events)
	})
	changeThresholdMode := func(kind string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST required", http.StatusMethodNotAllowed)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				parsed, err := url.Parse(origin)
				if err != nil || !strings.EqualFold(parsed.Host, r.Host) {
					http.Error(w, "cross-origin setting change refused", http.StatusForbidden)
					return
				}
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
				return
			}
			var request struct {
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128)).Decode(&request); err != nil {
				http.Error(w, "invalid mode request", http.StatusBadRequest)
				return
			}
			if request.Mode != "checkpoint" && request.Mode != "live" {
				http.Error(w, "mode must be checkpoint or live", http.StatusBadRequest)
				return
			}
			status, body, err := modelClient.SetThresholdMode(r.Context(), kind, request.Mode)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}
	}
	mux.HandleFunc("/api/detection-threshold-mode", changeThresholdMode("detection"))
	mux.HandleFunc("/api/world-threshold-mode", changeThresholdMode("world"))
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

func loadDashboardFont() ([]byte, error) {
	candidates := []string{
		filepath.Join("cli", "NeueMachina-Regular.woff2"),
		filepath.Join("..", "NeueMachina-Regular.woff2"),
		"NeueMachina-Regular.woff2",
	}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "..", "..", "cli",
			"NeueMachina-Regular.woff2"))
	}
	var last error
	for _, path := range candidates {
		font, err := os.ReadFile(path)
		if err == nil {
			return font, nil
		}
		last = err
	}
	return nil, fmt.Errorf("NeueMachina-Regular.woff2 was not found: %w", last)
}
