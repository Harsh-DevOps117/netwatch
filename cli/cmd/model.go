package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"detector/modelapi"

	"github.com/spf13/cobra"
)

var (
	modelService        string
	modelForecastURL    string
	modelDetectionsURL  string
	modelShowDetections bool
	modelJSON           bool
	modelWatch          time.Duration
	modelWorldAlarm     string
	modelDetectionAlarm string
)

var modelCmd = &cobra.Command{
	Use:   "model",
	Short: "Show forecasts and model incidents",
	Long: `Reads the Netwatch model services without changing their state.

Forecast scores are shown as scores, never as calibrated probabilities. A
future step is one imagined event, not a unit of clock time.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, selected := range []struct{ name, mode string }{{"world", modelWorldAlarm}, {"detection", modelDetectionAlarm}} {
			if selected.mode != "off" && selected.mode != "incident" && selected.mode != "event" && selected.mode != "both" {
				return fmt.Errorf("--%s-alarm must be off, incident, event, or both", selected.name)
			}
			if selected.mode != "off" && (modelWatch <= 0 || modelJSON) {
				return fmt.Errorf("--%s-alarm requires --watch and cannot be combined with --json", selected.name)
			}
		}
		forecastURL, detectionsURL, err := resolveModelEndpoints(modelService, modelForecastURL, modelDetectionsURL)
		if err != nil {
			return err
		}
		client := modelapi.NewClient(forecastURL, detectionsURL)
		includeDetections := modelShowDetections || modelDetectionAlarm != "off"
		if modelWatch <= 0 {
			return renderModelSnapshot(cmd.Context(), client, includeDetections, modelJSON, nil)
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ticker := time.NewTicker(modelWatch)
		defer ticker.Stop()
		alarms := newModelAlarmTracker(modelWorldAlarm, modelDetectionAlarm)
		for {
			if !modelJSON {
				fmt.Print("\033[2J\033[H")
			}
			if err := renderModelSnapshot(ctx, client, includeDetections, modelJSON, alarms); err != nil {
				fmt.Fprintf(os.Stderr, "Model service unavailable: %v\n", err)
			}
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	},
}

func init() {
	modelCmd.Flags().StringVar(&modelService, "service", "lag", "Forecast service: lag, live, or replay")
	modelCmd.Flags().StringVar(&modelForecastURL, "forecast-url", "", "Override the forecast endpoint")
	modelCmd.Flags().StringVar(&modelDetectionsURL, "detections-url", "", "Override the detections endpoint")
	modelCmd.Flags().BoolVar(&modelShowDetections, "detections", false, "Also show live detector incidents")
	modelCmd.Flags().BoolVar(&modelJSON, "json", false, "Print the service payload as JSON")
	modelCmd.Flags().DurationVar(&modelWatch, "watch", 0, "Refresh interval, for example 5s (zero prints once)")
	modelCmd.Flags().StringVar(&modelWorldAlarm, "world-alarm", "off", "Terminal bell on new observed world incidents, events, both, or off (requires --watch)")
	modelCmd.Flags().StringVar(&modelDetectionAlarm, "detection-alarm", "off", "Terminal bell on new detector incidents, events, both, or off (requires --watch)")
	rootCmd.AddCommand(modelCmd)
}

func resolveModelEndpoints(service, forecastOverride, detectionsOverride string) (string, string, error) {
	forecastURL, detectionsURL, err := modelapi.URLsForService(service)
	if err != nil {
		return "", "", err
	}
	if forecastOverride != "" {
		forecastURL = forecastOverride
	}
	if detectionsOverride != "" {
		detectionsURL = detectionsOverride
	}
	if err := modelapi.ValidateEndpoint(forecastURL); err != nil {
		return "", "", err
	}
	if detectionsURL != "" {
		if err := modelapi.ValidateEndpoint(detectionsURL); err != nil {
			return "", "", err
		}
	}
	return forecastURL, detectionsURL, nil
}

func renderModelSnapshot(ctx context.Context, client *modelapi.Client, includeDetections, asJSON bool, alarms *modelAlarmTracker) error {
	forecast, err := client.ForecastWithRules(ctx)
	if err != nil {
		return err
	}
	var detections *modelapi.DetectionsResponse
	var detectionsErr error
	if includeDetections {
		detections, detectionsErr = client.DetectionsWithRules(ctx)
	}
	if asJSON {
		payload := map[string]interface{}{"forecast": forecast}
		if includeDetections {
			payload["detections"] = incidentReport(detections)
			if detectionsErr != nil {
				payload["detections_error"] = detectionsErr.Error()
			}
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(payload)
	}

	printForecast(forecast)
	if includeDetections {
		if detectionsErr != nil {
			fmt.Printf("\nINCIDENTS\n  Unavailable: %v\n", detectionsErr)
		} else {
			printDetections(detections)
		}
	}
	if alarms != nil {
		for _, entry := range alarms.report(forecast, detections) {
			fmt.Printf("\aALARM: %s\n", entry)
		}
	}
	return nil
}

type modelAlarmTracker struct {
	worldMode, detectionMode string
	seen                     map[string]bool
	order                    []string
	primed                   bool
}

func newModelAlarmTracker(worldMode, detectionMode string) *modelAlarmTracker {
	return &modelAlarmTracker{worldMode: worldMode, detectionMode: detectionMode, seen: make(map[string]bool)}
}

func (a *modelAlarmTracker) report(f *modelapi.ForecastResponse, d *modelapi.DetectionsResponse) []string {
	entries := make([]string, 0)
	collect := func(mode, kind, key, label string) {
		if mode == "off" || (mode != "both" && mode != kind) {
			return
		}
		if a.seen[key] {
			return
		}
		a.seen[key] = true
		a.order = append(a.order, key)
		entries = append(entries, label)
	}
	for _, x := range f.Observed.Incidents {
		collect(a.worldMode, "incident", "wi:"+x.ID, fmt.Sprintf("world incident %s -> %s (observed, score %.5f)", x.SenderIP, x.ReceiverIP, x.OpeningScore))
	}
	for _, x := range f.Observed.Alerts {
		collect(a.worldMode, "event", fmt.Sprintf("we:%f:%s:%s", x.T, x.SenderIP, x.ReceiverIP),
			fmt.Sprintf("world event %s -> %s (observed, score %.5f)", x.SenderIP, x.ReceiverIP, x.Value))
	}
	if d != nil {
		incidents := d.RecentIncidents
		if incidents == nil {
			incidents = d.Incidents
		}
		for _, x := range incidents {
			collect(a.detectionMode, "incident", fmt.Sprintf("di:%s:%d:%f", x.Family, x.Incident, x.T),
				fmt.Sprintf("detector incident %s on sender node %d (score %.5f)", x.Family, x.Key, x.Score))
		}
		for _, x := range d.RecentDetections {
			collect(a.detectionMode, "event", fmt.Sprintf("de:%s:%f:%s:%s:%d:%d", x.Family, x.TObs, x.Src, x.Dst, x.SrcPort, x.DstPort),
				fmt.Sprintf("detector event %s %s -> %s (score %.5f)", x.Family, x.Src, x.Dst, x.Probability))
		}
	}
	if len(a.order) > 4096 {
		for _, old := range a.order[:len(a.order)-2048] {
			delete(a.seen, old)
		}
		a.order = a.order[len(a.order)-2048:]
	}
	if a.primed {
		return entries
	} else {
		a.primed = true // initial snapshot is history, not a newly arriving alarm
		return nil
	}
}

func printForecast(f *modelapi.ForecastResponse) {
	fmt.Printf("%s%sNETWATCH MODEL%s  %s\n", terminalBold, terminalCyan, terminalReset, time.Now().Format(time.RFC3339))
	fmt.Printf("Status       : %s\n", f.Status)
	if f.Device != "" {
		fmt.Printf("World model  : Running in %s\n", strings.ToUpper(f.Device))
	}
	if f.Status != "CONNECTED" {
		fmt.Printf("Reason       : %s\n", f.Reason)
		return
	}

	if source := f.Source; source != nil {
		fmt.Printf("Source       : %s", source.Mode)
		if source.Mode == "replay" {
			fmt.Printf(" · recorded dataset day %s", source.Day)
		} else {
			fmt.Printf(" · %s · tag %s", source.Day, source.Tag)
		}
		fmt.Println()
		if source.StateAsOf > 0 {
			fmt.Printf("Network as of: %s (about %.0f s ago; complete flows only)\n", time.Unix(int64(source.StateAsOf), 0).Format(time.RFC3339), source.LagSeconds)
		}
	}
	fmt.Printf("State        : %s · %d observed events · %d events scored\n", f.CurrentState, f.Observed.Events, f.EventsScored)
	fmt.Printf("Score        : %s (model score, not a calibrated probability)\n", f.Score)
	if f.Threshold == nil {
		fmt.Println("Operating pt : uncalibrated — alerts are disabled")
	} else {
		t := f.Threshold
		fmt.Printf("Operating pt : %s · budget %.4g · epoch %d\n", t.Rule, t.Budget, t.Epoch)
		fmt.Printf("Calibration  : %s\n", t.CalibratedOn)
		fmt.Printf("Test result  : recall %.3f%% · FPR %.4f%% · %d false alarms over %.2f h\n", 100*t.Recall, 100*t.FPR, t.FalseAlarms, t.TestHours)
		if live := t.LiveCalibration; live != nil {
			fmt.Printf("Live scores  : %.2f/%.2f h, %d distinct flows, ready %t\n", live.ElapsedS/3600, live.WindowS/3600, live.Samples, live.Ready)
			fmt.Printf("Live target  : %.4f%% score exceedance, not measured FPR\n", 100*live.TargetExceedanceBudget)
			fmt.Println("Test result above describes the checkpoint, not this live threshold.")
		}
		if t.Recall == 0 {
			fmt.Println("WARNING      : measured test recall is zero; this is not a working detector yet")
		}
	}

	fmt.Printf("\nFORECAST — each step is one imagined event\n")
	if len(f.PredictedEdges) == 0 {
		fmt.Println("  No predicted links returned.")
	} else {
		edges := append([]modelapi.PredictedEdge(nil), f.PredictedEdges...)
		sort.SliceStable(edges, func(i, j int) bool {
			if edges[i].Step == edges[j].Step {
				return edges[i].Value > edges[j].Value
			}
			return edges[i].Step < edges[j].Step
		})
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  RANK\tSTATE\tPREDICTED LINK\tSCORE\tSEVERITY\tMANIFOLD")
		limit := len(edges)
		if limit > 18 {
			limit = 18
		}
		for i, edge := range edges[:limit] {
			severity := edge.Severity
			if severity == "" {
				severity = "—"
			}
			fmt.Fprintf(w, "  %s\tS[t+%d]\t%s → %s\t%.5f\t%s\t%t\n", ordinal(i+1), edge.Step, edge.SenderIP, edge.ReceiverIP, edge.Value, severity, edge.OnManifold)
		}
		_ = w.Flush()
	}

	if n := len(f.Observed.SuppressedLinks); n > 0 {
		fmt.Printf("\n  %d link(s) judged routine internal services by deterministic rules: %d flagged event(s), %d incident(s) and %d forecast alert(s) set aside; raw model history remains in JSON.\n",
			n, len(f.Observed.SuppressedAlerts), len(f.Observed.SuppressedIncidents), len(f.SuppressedAlerts))
	}

	if len(f.Explanation) > 0 {
		fmt.Println("\nMODEL ATTENTION")
		for _, explanation := range f.Explanation {
			peers := make([]string, 0, len(explanation.Attended))
			for _, peer := range explanation.Attended {
				peers = append(peers, fmt.Sprintf("%s %.1f%%", peer.IP, 100*peer.Attention))
			}
			if len(peers) == 0 {
				fmt.Printf("  %s: no neighbourhood was available\n", explanation.SenderIP)
				continue
			}
			fmt.Printf("  %s: the model attended to %s\n", explanation.SenderIP, strings.Join(peers, ", "))
		}
	}
	if len(f.Caveats) > 0 {
		fmt.Println("\nCAVEATS")
		for _, caveat := range f.Caveats {
			fmt.Printf("  • %s\n", caveat)
		}
	}
}

func printDetections(d *modelapi.DetectionsResponse) {
	if d.Device != "" {
		fmt.Printf("Detection    : Running in %s\n", strings.ToUpper(d.Device))
	}
	total := 0
	for _, count := range d.IncidentsByFamily {
		total += count
	}
	latency := d.LatencyFromFirstPacketS
	if latency.Median == 0 && latency.P99 == 0 {
		latency.Median = max(0, d.BudgetS+d.LatencyAfterTObsS.Median)
		latency.P99 = max(0, d.BudgetS+d.LatencyAfterTObsS.P99)
	}
	fmt.Printf("\nINCIDENTS\n  %d active after persistence and quiet-gap aggregation · %d events scored internally · capture-to-verdict median %.1f ms / p99 %.1f ms\n", total, d.EventsScored, 1000*latency.Median, 1000*latency.P99)
	if len(d.SuppressedIncidents) > 0 {
		fmt.Printf("  %d model INFILTRATION incident(s) suppressed by deterministic internal-service rules; raw model history remains in JSON.\n", len(d.SuppressedIncidents))
	}
	if d.TotalIPPackets > 0 && d.IPv6PacketsExcluded > 0 {
		fmt.Printf("  IPv6 outside checkpoint: %d / %d parsed IP packets (%.1f%%); only IPv4 TCP/UDP flows are scored\n", d.IPv6PacketsExcluded, d.TotalIPPackets, 100*float64(d.IPv6PacketsExcluded)/float64(d.TotalIPPackets))
	}
	if d.FutureTimestampEvents > 0 {
		fmt.Printf("  Packet timestamps ahead of serving clock: %d events; negative durations are floored at zero\n", d.FutureTimestampEvents)
	}
	if d.PacketQueueDepth > 0 {
		fmt.Printf("  Capture-to-detector backlog: %d queued packets\n", d.PacketQueueDepth)
	}
	adaptive, ready, adjusted, samples, warmup := 0, 0, 0, 0, 0
	for _, threshold := range d.Thresholds {
		if !threshold.Adaptive {
			continue
		}
		adaptive++
		if threshold.AdaptiveReady {
			ready++
		}
		if threshold.Threshold != nil && threshold.BaselineThreshold != nil && *threshold.Threshold > *threshold.BaselineThreshold {
			adjusted++
		}
		if threshold.AdaptiveSamples > samples {
			samples = threshold.AdaptiveSamples
		}
		if threshold.AdaptiveWarmup > warmup {
			warmup = threshold.AdaptiveWarmup
		}
	}
	if adaptive > 0 {
		fmt.Printf("  Adaptive thresholds: %d/%d ready · %d/%d samples · %d currently above checkpoint floor\n", ready, adaptive, samples, warmup, adjusted)
	}
	for _, threshold := range d.Thresholds {
		if live := threshold.LiveCalibration; live != nil {
			fmt.Printf("  Live threshold window: %.2f/%.2f h, %d flows per family, ready %t (checkpoint scores unchanged; unlabeled tail, not FPR)\n", live.ElapsedS/3600, live.WindowS/3600, live.Samples, live.Ready)
			break
		}
	}
	incidents := d.RecentIncidents
	if incidents == nil {
		incidents = d.Incidents
	}
	if len(incidents) == 0 {
		fmt.Println("  No incidents opened in the last three hours.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  RECENT INCIDENT (3H)\tFAMILY\tSENDER NODE\tOPENING SCORE\tOPENED\tSTATUS")
	start := len(incidents) - 12
	if start < 0 {
		start = 0
	}
	for i := len(incidents) - 1; i >= start; i-- {
		x := incidents[i]
		status := "closed"
		for _, active := range d.Incidents {
			if active.Family == x.Family && active.Incident == x.Incident && active.T == x.T {
				status = "active"
				break
			}
		}
		fmt.Fprintf(w, "  #%d\t%s\t%d\t%.5f\t%s\t%s\n", x.Incident, x.Family, x.Key, x.Score, time.Unix(int64(x.T), 0).Format(time.RFC3339), status)
	}
	_ = w.Flush()
	fmt.Println("  Each row passed its family threshold, three-event persistence, and the 120-second incident rule.")
}

func incidentReport(d *modelapi.DetectionsResponse) interface{} {
	if d == nil {
		return nil
	}
	return map[string]interface{}{
		"status": d.Status, "reason": d.Reason, "clock": d.Clock, "packets": d.Packets,
		"open_flows": d.OpenFlows, "uptime_s": d.UptimeS, "budget_s": d.BudgetS,
		"events_scored": d.EventsScored, "packet_queue_depth": d.PacketQueueDepth,
		"latency_after_t_obs_s": d.LatencyAfterTObsS,
		"thresholds":            d.Thresholds, "incidents_by_family": d.IncidentsByFamily,
		"incidents_opened_by_family": d.IncidentsOpenedByFamily, "incidents": d.Incidents,
		"recent_incidents": d.RecentIncidents, "incident_history_window_s": d.IncidentHistoryWindowS,
		"raw_incidents": d.RawIncidents, "raw_recent_incidents": d.RawRecentIncidents,
		"suppressed_incidents":   d.SuppressedIncidents,
		"recent_detections":      d.RecentDetections,
		"incident_history_limit": d.IncidentHistoryLimit,
	}
}

func ordinal(n int) string {
	if n%100 >= 11 && n%100 <= 13 {
		return fmt.Sprintf("%dth", n)
	}
	suffix := "th"
	switch n % 10 {
	case 1:
		suffix = "st"
	case 2:
		suffix = "nd"
	case 3:
		suffix = "rd"
	}
	return fmt.Sprintf("%d%s", n, suffix)
}
