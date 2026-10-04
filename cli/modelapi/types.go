package modelapi

import "detector/semantics"

// ForecastResponse is the stable v3.2 forecast contract exposed by the model
// services. Fields that are not yet produced by the model are deliberately not
// invented here; the CLI and dashboard render only data present in the payload.
type ForecastResponse struct {
	Status         string          `json:"status"`
	Device         string          `json:"device,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	Score          string          `json:"score,omitempty"`
	Threshold      *Threshold      `json:"threshold,omitempty"`
	Source         *Source         `json:"source,omitempty"`
	Observed       Observed        `json:"observed"`
	PredictedEdges []PredictedEdge `json:"predicted_edges"`
	Alerts         []ForecastAlert `json:"alerts"`
	// Forecast alerts on a link the service rules judged a routine internal service.
	SuppressedAlerts []ForecastAlert `json:"suppressed_alerts,omitempty"`
	RolloutSteps     int             `json:"rollout_steps"`
	CurrentState     string          `json:"current_state"`
	FutureStates     []string        `json:"future_states"`
	StepValue        []float64       `json:"step_value"`
	AlertShare       []float64       `json:"alert_share"`
	PredictedStage   string          `json:"predicted_stage"`
	Caveats          []string        `json:"caveats"`
	EventsScored     int             `json:"events_scored"`
	Explanation      []Explanation   `json:"explanation"`
}

type Threshold struct {
	Rule                      string             `json:"rule"`
	Direction                 int                `json:"direction"`
	Budget                    float64            `json:"budget"`
	Threshold                 float64            `json:"threshold"`
	CalibratedOn              string             `json:"calibrated_on"`
	CheckpointCalibratedOn    string             `json:"checkpoint_calibrated_on,omitempty"`
	ThresholdSource           string             `json:"threshold_source,omitempty"`
	FPR                       float64            `json:"fpr"`
	OvershootVsBudget         float64            `json:"overshoot_vs_budget"`
	Recall                    float64            `json:"recall"`
	FalseAlarms               int                `json:"false_alarms"`
	TestAttack                int                `json:"test_attack"`
	TestBenign                int                `json:"test_benign"`
	TestHours                 float64            `json:"test_hours"`
	PersistRecall             float64            `json:"persist_recall"`
	PersistFalseAlarms        int                `json:"persist_false_alarms"`
	FalseAlarmsPerHour        float64            `json:"false_alarms_per_hour"`
	PersistFalseAlarmsPerHour float64            `json:"persist_false_alarms_per_hour"`
	FalseIncidentsPerHour     float64            `json:"false_incidents_per_hour"`
	CalibBenign               int                `json:"calib_benign"`
	Days                      []string           `json:"days"`
	Thresholds                map[string]float64 `json:"thresholds"`
	Epoch                     int                `json:"epoch"`
	Score                     string             `json:"score"`
	BaselineThreshold         *float64           `json:"baseline_threshold,omitempty"`
	LiveCalibration           *LiveCalibration   `json:"live_calibration,omitempty"`
	ThresholdMode             *ThresholdMode     `json:"threshold_mode,omitempty"`
}

type ThresholdMode struct {
	Requested string `json:"requested"`
	Effective string `json:"effective"`
	LiveReady bool   `json:"live_ready"`
}

// LiveCalibration describes an unlabeled score-tail estimate, not measured FPR.
type LiveCalibration struct {
	Ready                     bool     `json:"ready"`
	WindowS                   float64  `json:"window_s"`
	ElapsedS                  float64  `json:"elapsed_s"`
	RemainingS                float64  `json:"remaining_s"`
	Samples                   int      `json:"samples"`
	MinimumSamples            int      `json:"minimum_samples"`
	FirstObserved             *float64 `json:"first_observed"`
	LastObserved              *float64 `json:"last_observed"`
	BaselineThreshold         float64  `json:"baseline_threshold"`
	LiveThreshold             *float64 `json:"live_threshold"`
	TargetExceedanceBudget    float64  `json:"target_exceedance_budget"`
	EffectiveExceedanceBudget *float64 `json:"effective_exceedance_budget"`
	LabelsAvailable           bool     `json:"labels_available"`
	CalibrationType           string   `json:"calibration_type,omitempty"`
	ProbabilityCalibration    string   `json:"probability_calibration,omitempty"`
}

type Source struct {
	Mode              string   `json:"mode"`
	Day               string   `json:"day"`
	Position          int      `json:"position"`
	EventsScoredTotal int      `json:"events_scored_total,omitempty"`
	EventsPerSecond   *float64 `json:"events_per_second,omitempty"`
	EventRateWindowS  *float64 `json:"event_rate_window_s,omitempty"`
	Total             int      `json:"total"`
	T                 float64  `json:"t"`
	Captures          []string `json:"captures"`
	Cycle             int      `json:"cycle"`
	BuildSeconds      float64  `json:"build_seconds"`
	LagSeconds        float64  `json:"lag_seconds"`
	LocalIPs          []string `json:"local_ips"`
	StateAsOf         float64  `json:"state_as_of"`
	NewestPacket      float64  `json:"newest_packet"`
	HoldSeconds       float64  `json:"hold_seconds"`
	Tag               string   `json:"tag"`
}

type Observed struct {
	Edges     []ObservedEdge     `json:"edges"`
	Alerts    []ObservedAlert    `json:"alerts"`
	Incidents []ObservedIncident `json:"incidents"`
	Events    int                `json:"events"`
	// Set by ForecastWithRules. Incidents and Alerts hold the operator-facing
	// view; what the service rules set aside stays in the fields below.
	RawIncidents        []ObservedIncident `json:"raw_incidents,omitempty"`
	SuppressedIncidents []ObservedIncident `json:"suppressed_incidents,omitempty"`
	SuppressedAlerts    []ObservedAlert    `json:"suppressed_alerts,omitempty"`
	SuppressedLinks     []SuppressedLink   `json:"suppressed_links,omitempty"`
}

// SuppressedLink is a host pair whose every flagged event in the window is one
// routine internal service. Key is "a|b" with the two hosts sorted.
type SuppressedLink struct {
	Key                string `json:"key"`
	ProtocolTag        string `json:"protocol_tag"`
	RuleClassification string `json:"rule_classification"`
	RuleReason         string `json:"rule_reason"`
	Events             int    `json:"events"`
	Incidents          int    `json:"incidents"`
}

type ObservedIncident struct {
	ID            string          `json:"id"`
	Opened        float64         `json:"opened"`
	LastSeen      float64         `json:"last_seen"`
	SenderIP      string          `json:"sender_ip"`
	ReceiverIP    string          `json:"receiver_ip"`
	OpeningScore  float64         `json:"opening_score"`
	Events        int             `json:"events"`
	RelatedEvents []ObservedAlert `json:"related_events,omitempty"`
	Severity      string          `json:"severity"`
	// Deterministic service-rule decision; the model's score is not changed.
	FinalDecision      string `json:"final_decision,omitempty"`
	RuleClassification string `json:"rule_classification,omitempty"`
	RuleReason         string `json:"rule_reason,omitempty"`
	ProtocolTag        string `json:"protocol_tag,omitempty"`
}

type ObservedEdge struct {
	SenderIP   string  `json:"sender_ip"`
	ReceiverIP string  `json:"receiver_ip"`
	Events     int     `json:"events"`
	Value      float64 `json:"value"`
	Severity   string  `json:"severity"`
}

type ObservedAlert struct {
	EventID    int     `json:"event_id"`
	T          float64 `json:"t"`
	SenderIP   string  `json:"sender_ip"`
	ReceiverIP string  `json:"receiver_ip"`
	Value      float64 `json:"value"`
	Severity   string  `json:"severity"`
	// Flow endpoints and service evidence, when the service supplies them
	// (the lag service does); the tags are added by the CLI.
	Src                    string `json:"src,omitempty"`
	Dst                    string `json:"dst,omitempty"`
	SrcPort                int    `json:"src_port,omitempty"`
	DstPort                int    `json:"dst_port,omitempty"`
	Protocol               int    `json:"protocol,omitempty"`
	EstablishedConnection  bool   `json:"established_connection,omitempty"`
	NormalDNSQuery         bool   `json:"normal_dns_query,omitempty"`
	NormalGVCPDiscovery    bool   `json:"normal_gvcp_discovery,omitempty"`
	SourcePacketsPerSecond int    `json:"source_packets_per_second,omitempty"`
	ServiceEvidenceVersion int    `json:"service_evidence_version,omitempty"`
	ProtocolTag            string `json:"protocol_tag,omitempty"`
	TrafficClass           string `json:"traffic_class,omitempty"`
	ConnectionRole         string `json:"connection_role,omitempty"`
}

type Candidate struct {
	IP          string  `json:"ip"`
	Node        int     `json:"node"`
	Probability float64 `json:"probability"`
	Surprise    float64 `json:"surprise"`
	Value       float64 `json:"value"`
	Severity    string  `json:"severity"`
}

type PredictedEdge struct {
	Step           int         `json:"step"`
	SeedEvent      int         `json:"seed_event"`
	Sender         int         `json:"sender"`
	Receiver       int         `json:"receiver"`
	SenderIP       string      `json:"sender_ip"`
	ReceiverIP     string      `json:"receiver_ip"`
	Surprise       float64     `json:"surprise"`
	Value          float64     `json:"value"`
	Severity       string      `json:"severity"`
	Probability    float64     `json:"probability"`
	Candidates     []Candidate `json:"candidates"`
	CumulativeRisk float64     `json:"cumulative_risk"`
	OnManifold     bool        `json:"on_manifold"`
}

type ForecastAlert struct {
	SenderIP      string  `json:"sender_ip"`
	ReceiverIP    string  `json:"receiver_ip"`
	Sender        int     `json:"sender"`
	Receiver      int     `json:"receiver"`
	CrossesAtStep int     `json:"crosses_at_step"`
	Value         float64 `json:"value"`
	Severity      string  `json:"severity"`
	Extrapolated  bool    `json:"extrapolated"`
}

type Explanation struct {
	SeedEvent           int            `json:"seed_event"`
	T                   float64        `json:"t"`
	Sender              int            `json:"sender"`
	Receiver            int            `json:"receiver"`
	SenderIP            string         `json:"sender_ip"`
	ReceiverIP          string         `json:"receiver_ip"`
	Surprise            float64        `json:"surprise"`
	NeighboursAvailable int            `json:"neighbours_available"`
	Attended            []AttendedPeer `json:"attended"`
}

type AttendedPeer struct {
	Node      int     `json:"node"`
	IP        string  `json:"ip"`
	Attention float64 `json:"attention"`
}

type DetectionsResponse struct {
	Status                   string                        `json:"status"`
	Device                   string                        `json:"device,omitempty"`
	Reason                   string                        `json:"reason,omitempty"`
	Clock                    float64                       `json:"clock"`
	Packets                  int                           `json:"packets"`
	TotalIPPackets           int                           `json:"total_ip_packets"`
	IPv6PacketsExcluded      int                           `json:"ipv6_packets_excluded"`
	OtherProtocolExcluded    int                           `json:"other_ipv4_protocol_packets_excluded"`
	PacketTimestampReversals int                           `json:"packet_timestamp_reversals"`
	OpenFlows                int                           `json:"open_flows"`
	UptimeS                  float64                       `json:"uptime_s"`
	BudgetS                  float64                       `json:"budget_s"`
	EventsScored             int                           `json:"events_scored"`
	EventsPerSecond          float64                       `json:"events_per_second"`
	PacketQueueDepth         int                           `json:"packet_queue_depth"`
	ScoredWithOnePacket      int                           `json:"scored_with_one_packet"`
	LatencyAfterTObsS        Latency                       `json:"latency_after_t_obs_s"`
	LatencyFromFirstPacketS  Latency                       `json:"latency_from_first_packet_s"`
	LatencyStagesS           map[string]Latency            `json:"latency_stages_s,omitempty"`
	Capture                  map[string]interface{}        `json:"capture,omitempty"`
	FutureTimestampEvents    int                           `json:"future_timestamp_events"`
	Thresholds               map[string]DetectionThreshold `json:"thresholds"`
	DetectionsByFamily       map[string]int                `json:"detections_by_family"`
	IncidentsByFamily        map[string]int                `json:"incidents_by_family"`
	IncidentsOpenedByFamily  map[string]int                `json:"incidents_opened_by_family"`
	RecentDetections         []Detection                   `json:"recent_detections"`
	Incidents                []Incident                    `json:"incidents"`
	RecentIncidents          []Incident                    `json:"recent_incidents"`
	RawIncidents             []Incident                    `json:"raw_incidents,omitempty"`
	RawRecentIncidents       []Incident                    `json:"raw_recent_incidents,omitempty"`
	SuppressedIncidents      []Incident                    `json:"suppressed_incidents,omitempty"`
	IncidentHistoryWindowS   float64                       `json:"incident_history_window_s"`
	IncidentHistoryLimit     int                           `json:"incident_history_limit"`
	ThresholdMode            *ThresholdMode                `json:"threshold_mode,omitempty"`
	Attention                []DetectionAttention          `json:"attention"`
}

type DetectionAttention struct {
	EventID    int                      `json:"event_id"`
	TObs       float64                  `json:"t_obs"`
	Sender     int                      `json:"sender"`
	Receiver   int                      `json:"receiver"`
	SenderIP   string                   `json:"sender_ip"`
	ReceiverIP string                   `json:"receiver_ip"`
	Attended   []DetectionAttentionEdge `json:"attended"`
}

type DetectionAttentionEdge struct {
	Sender    int     `json:"sender"`
	Receiver  int     `json:"receiver"`
	Edge      string  `json:"edge"`
	Attention float64 `json:"attention"`
}

type DetectionThreshold struct {
	Threshold                 *float64         `json:"threshold"`
	BaselineThreshold         *float64         `json:"baseline_threshold"`
	FalseAlarmBudget          *float64         `json:"false_alarm_budget"`
	EffectiveFalseAlarmBudget *float64         `json:"effective_false_alarm_budget"`
	Adaptive                  bool             `json:"adaptive"`
	AdaptiveReady             bool             `json:"adaptive_ready"`
	AdaptiveSamples           int              `json:"adaptive_samples"`
	AdaptiveWarmup            int              `json:"adaptive_warmup"`
	ThresholdSource           string           `json:"threshold_source,omitempty"`
	ProbabilityCalibration    string           `json:"probability_calibration,omitempty"`
	LiveCalibration           *LiveCalibration `json:"live_calibration,omitempty"`
}

type Latency struct {
	Median float64 `json:"median"`
	P50    float64 `json:"p50,omitempty"`
	P90    float64 `json:"p90,omitempty"`
	P99    float64 `json:"p99"`
}

type Detection struct {
	semantics.Tags
	ModelClassification string  `json:"model_classification"`
	ModelScore          float64 `json:"model_score"`
	Family              string  `json:"family"`
	Probability         float64 `json:"probability"`
	Threshold           float64 `json:"threshold"`
	TObs                float64 `json:"t_obs"`
	Src                 string  `json:"src"`
	Dst                 string  `json:"dst"`
	SrcPort             int     `json:"src_port"`
	DstPort             int     `json:"dst_port"`
	Protocol            int     `json:"protocol"`
	Sender              string  `json:"sender"`
}

type Incident struct {
	semantics.Tags
	ModelClassification string  `json:"model_classification"`
	ModelScore          float64 `json:"model_score"`
	FinalDecision       string  `json:"final_decision"`
	Key                 int     `json:"key"`
	T                   float64 `json:"t"`
	Score               float64 `json:"score"`
	Incident            int     `json:"incident"`
	Family              string  `json:"family"`
}

// IncidentEventsResponse carries an incident's linked events. For a very large
// incident the detector returns only the first events and sets Truncated.
type IncidentEventsResponse struct {
	Events    []DetectionIncidentEvent `json:"events"`
	Total     int                      `json:"total"`
	Truncated bool                     `json:"truncated"`
}

type DetectionIncidentEvent struct {
	semantics.Tags
	ModelClassification    string  `json:"model_classification"`
	ModelScore             float64 `json:"model_score"`
	Family                 string  `json:"family"`
	Incident               int     `json:"incident"`
	OpenedAt               float64 `json:"opened_at"`
	EventID                int     `json:"event_id"`
	TObs                   float64 `json:"t_obs"`
	Src                    string  `json:"src"`
	Dst                    string  `json:"dst"`
	SrcPort                int     `json:"src_port"`
	DstPort                int     `json:"dst_port"`
	Protocol               int     `json:"protocol"`
	SenderIP               string  `json:"sender_ip"`
	Score                  float64 `json:"score"`
	Threshold              float64 `json:"threshold"`
	EstablishedConnection  bool    `json:"established_connection,omitempty"`
	NormalDNSQuery         bool    `json:"normal_dns_query,omitempty"`
	NormalGVCPDiscovery    bool    `json:"normal_gvcp_discovery,omitempty"`
	SourcePacketsPerSecond int     `json:"source_packets_per_second,omitempty"`
	ServiceEvidenceVersion int     `json:"service_evidence_version,omitempty"`
}
