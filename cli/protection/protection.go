package protection

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"detector/modelapi"
)

const (
	groqEndpoint = "https://api.groq.com/openai/v1/chat/completions"
	groqModel    = "openai/gpt-oss-20b"
	planLifetime = 5 * time.Minute
)

type Identity struct {
	Family   string  `json:"family"`
	Incident int     `json:"incident"`
	OpenedAt float64 `json:"opened_at"`
}

type Plan struct {
	Token        string `json:"token,omitempty"`
	Family       string `json:"family"`
	Incident     int    `json:"incident"`
	SourceIP     string `json:"source_ip,omitempty"`
	SourceScope  string `json:"source_scope"`
	Active       bool   `json:"active"`
	LinkedEvents int    `json:"linked_events"`
	Advice       string `json:"advice"`
	CanExecute   bool   `json:"can_execute"`
	Reason       string `json:"reason,omitempty"`
	Action       string `json:"action,omitempty"`
	Confirmation string `json:"confirmation,omitempty"`
}

type Result struct {
	SourceIP    string `json:"source_ip"`
	Rule        string `json:"rule"`
	UndoToken   string `json:"undo_token"`
	UndoCommand string `json:"undo_command"`
}

// BlockEntry is an active host-firewall rule created under Netwatch's rule name.
type BlockEntry struct {
	SourceIP string `json:"source_ip"`
	Rule     string `json:"rule"`
}

var managedRuleName = regexp.MustCompile(`^Netwatch-[0-9a-f]{32}$`)

type firewall interface {
	Block(context.Context, string, string) (string, error)
	Unblock(context.Context, string, string) error
	List(context.Context) ([]BlockEntry, error)
	Supported() bool
}

type pendingPlan struct {
	identity     Identity
	ip           string
	confirmation string
	expires      time.Time
}

type pendingUndo struct {
	ip      string
	rule    string
	expires time.Time
}

type Service struct {
	Models   *modelapi.Client
	HTTP     *http.Client
	Endpoint string
	Model    string
	Firewall firewall
	mu       sync.Mutex
	plans    map[string]pendingPlan
	undos    map[string]pendingUndo
}

func New(models *modelapi.Client) *Service {
	return &Service{
		Models: models, Endpoint: groqEndpoint, Model: groqModel, Firewall: localFirewall{},
		HTTP: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Groq redirect refused")
		}},
		plans: make(map[string]pendingPlan), undos: make(map[string]pendingUndo),
	}
}

type incidentContext struct {
	incident         modelapi.Incident
	active           bool
	ip               string
	events           int
	reason           string
	localDestination bool
}

func (s *Service) resolve(ctx context.Context, id Identity) (incidentContext, error) {
	if s.Models == nil || !loopbackEndpoint(s.Models.DetectionsURL) {
		return incidentContext{}, errors.New("protection requires a local detector service")
	}
	if id.Family == "" || len(id.Family) > 100 || id.Incident < 1 || id.OpenedAt <= 0 {
		return incidentContext{}, errors.New("invalid incident identity")
	}
	d, err := s.Models.DetectionsWithRules(ctx)
	if err != nil {
		return incidentContext{}, err
	}
	match := func(x modelapi.Incident) bool {
		return x.Family == id.Family && x.Incident == id.Incident && x.T == id.OpenedAt
	}
	var result incidentContext
	for _, x := range d.Incidents {
		if match(x) {
			result.incident, result.active = x, true
			break
		}
	}
	if !result.active {
		for _, x := range d.RecentIncidents {
			if match(x) {
				result.incident = x
				break
			}
		}
	}
	if result.incident.Incident == 0 {
		return incidentContext{}, errors.New("incident is no longer in the detector's recent history")
	}
	linked, err := s.Models.IncidentEvents(ctx, id.Family, id.Incident, id.OpenedAt)
	if err != nil {
		return incidentContext{}, err
	}
	result.events = len(linked.Events)
	if result.events == 0 {
		result.reason = "No linked source-IP evidence was retained for this incident."
		return result, nil
	}
	for _, event := range linked.Events {
		if event.SenderIP == "" || (result.ip != "" && event.SenderIP != result.ip) {
			result.ip = ""
			result.reason = "Linked events do not agree on one source IP."
			return result, nil
		}
		result.ip = event.SenderIP
		if event.Src != "" && event.Src != event.SenderIP {
			result.reason = "Linked traffic does not consistently originate from the sender IP."
			return result, nil
		}
		if localAddress(event.Dst) {
			result.localDestination = true
		}
	}
	if linked.Truncated {
		// One source must account for every linked event, not only those returned.
		result.reason = fmt.Sprintf("Only the first %d of %d linked events could be checked for a single source; automatic blocking is disabled.", result.events, linked.Total)
	} else if result.events < 3 {
		result.reason = "At least three linked threshold-crossing events are required for a host block."
	} else if !result.localDestination {
		result.reason = "No linked event targets this host; an inbound host block would not contain the observed traffic."
	} else if !blockableIPv4(result.ip) {
		result.reason = "Source is not a validated public or private IPv4 address; automatic blocking is disabled."
	} else if localAddress(result.ip) {
		result.reason = "Source IP belongs to this host; automatic blocking is disabled."
	}
	return result, nil
}

func loopbackEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" {
		return false
	}
	host := u.Hostname()
	return strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func publicIPv4(raw string) bool {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, network := range []string{"0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		if netip.MustParsePrefix(network).Contains(ip) {
			return false
		}
	}
	return true
}

func blockableIPv4(raw string) bool {
	ip, err := netip.ParseAddr(raw)
	return err == nil && ip.Is4() && ip.IsGlobalUnicast() && (ip.IsPrivate() || publicIPv4(raw))
}

func sourceScope(raw string) string {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.Is4() {
		return "unverified"
	}
	if ip.IsPrivate() {
		return "private LAN"
	}
	if publicIPv4(raw) {
		return "public IPv4"
	}
	return "reserved or non-public"
}

func localAddress(raw string) bool {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return true // fail closed if the host's addresses cannot be inspected
	}
	target := net.ParseIP(raw)
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network.IP.Equal(target) {
			return true
		}
	}
	return false
}

func token() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func (s *Service) Advise(ctx context.Context, id Identity, apiKey string) (Plan, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" || len(apiKey) > 512 || strings.ContainsAny(apiKey, "\r\n") {
		return Plan{}, errors.New("enter a valid Groq API key")
	}
	incident, err := s.resolve(ctx, id)
	if err != nil {
		return Plan{}, err
	}
	advice, err := s.askGroq(ctx, apiKey, incident)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Family: id.Family, Incident: id.Incident, SourceIP: incident.ip, SourceScope: sourceScope(incident.ip), Active: incident.active, LinkedEvents: incident.events, Advice: advice,
		Action: "Block this source IP in the local host firewall (inbound traffic only)."}
	if ip, err := netip.ParseAddr(incident.ip); err == nil && ip.IsPrivate() {
		plan.Action += " This is a LAN source; blocking it may disrupt a legitimate local device or service."
		plan.Confirmation = "BLOCK LAN " + incident.ip
	} else {
		plan.Confirmation = "BLOCK " + incident.ip
	}
	switch {
	case !incident.active:
		plan.Reason = "Incident is closed; automatic blocking is limited to active detector incidents."
	case incident.reason != "":
		plan.Reason = incident.reason
	case !s.Firewall.Supported():
		plan.Reason = "Automatic blocking requires netsh on Windows or iptables on Linux."
	default:
		plan.CanExecute = true
		plan.Token, err = token()
		if err != nil {
			return Plan{}, err
		}
		s.mu.Lock()
		for key, pending := range s.plans {
			if time.Now().After(pending.expires) {
				delete(s.plans, key)
			}
		}
		s.plans[plan.Token] = pendingPlan{identity: id, ip: incident.ip, confirmation: plan.Confirmation, expires: time.Now().Add(planLifetime)}
		s.mu.Unlock()
	}
	return plan, nil
}

func (s *Service) askGroq(ctx context.Context, apiKey string, incident incidentContext) (string, error) {
	requestBody := map[string]interface{}{
		"model": s.Model, "max_completion_tokens": 800, "temperature": 0.2,
		"reasoning_effort": "low", "tool_choice": "none",
		"messages": []map[string]string{
			{"role": "system", "content": "You are a defensive network-incident advisor. The attack family and score are unverified model flags, not packet-payload evidence or calibrated probabilities. Never claim observed HTTP methods, payloads, compromise, malicious intent, botnets, or endpoint exposure. No raw addresses or packet contents are provided. Never call a private LAN source public. For closed incidents give retrospective checks, not an immediate block. Suggest reversible validation before disruptive containment. Do not output shell commands or imply a single host block stops a distributed attack. Respond in 3-5 short plain-text bullets without Markdown emphasis."},
			{"role": "user", "content": fmt.Sprintf("Detector model flag: family=%s, opening score=%.5f, active=%t, linked threshold-crossing flows=%d, source scope=%s. Addresses and packet payloads are deliberately withheld. Suggest validation, proportionate containment, and recovery based only on these facts. Automatic action, if eligible, is limited to one separately confirmed local host-firewall inbound block.", incident.incident.Family, incident.incident.Score, incident.active, incident.events, sourceScope(incident.ip))},
		},
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	response, err := s.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("Groq request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Groq request failed (HTTP %d); check the API key and model access", response.StatusCode)
	}
	var payload struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&payload); err != nil {
		return "", fmt.Errorf("invalid Groq response: %w", err)
	}
	if len(payload.Choices) == 0 || strings.TrimSpace(payload.Choices[0].Message.Content) == "" {
		return "", errors.New("Groq returned no guidance")
	}
	clean := strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, payload.Choices[0].Message.Content)
	return strings.TrimSpace(clean), nil
}

func (s *Service) Execute(ctx context.Context, planToken, confirmation string) (Result, error) {
	s.mu.Lock()
	pending, ok := s.plans[planToken]
	delete(s.plans, planToken)
	s.mu.Unlock()
	if !ok || time.Now().After(pending.expires) {
		return Result{}, errors.New("protection plan expired; request fresh guidance")
	}
	if confirmation != pending.confirmation {
		return Result{}, fmt.Errorf("confirmation must be exactly %s", pending.confirmation)
	}
	current, err := s.resolve(ctx, pending.identity)
	if err != nil {
		return Result{}, err
	}
	if !current.active || current.ip != pending.ip || current.reason != "" || !blockableIPv4(current.ip) {
		return Result{}, errors.New("incident or source IP changed; no firewall rule was added")
	}
	ruleToken, err := token()
	if err != nil {
		return Result{}, err
	}
	undoToken, err := token()
	if err != nil {
		return Result{}, err
	}
	rule := "Netwatch-" + ruleToken
	undoCommand, err := s.Firewall.Block(ctx, current.ip, rule)
	if err != nil {
		return Result{}, err
	}
	s.mu.Lock()
	s.undos[undoToken] = pendingUndo{ip: current.ip, rule: rule, expires: time.Now().Add(24 * time.Hour)}
	s.mu.Unlock()
	return Result{SourceIP: current.ip, Rule: rule, UndoToken: undoToken, UndoCommand: undoCommand}, nil
}

func (s *Service) Undo(ctx context.Context, undoToken string) error {
	s.mu.Lock()
	pending, ok := s.undos[undoToken]
	s.mu.Unlock()
	if !ok || time.Now().After(pending.expires) {
		return errors.New("undo token expired; remove the named firewall rule manually")
	}
	if err := s.Firewall.Unblock(ctx, pending.ip, pending.rule); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.undos, undoToken)
	s.mu.Unlock()
	return nil
}

func (s *Service) ListBlocks(ctx context.Context) ([]BlockEntry, error) {
	blocks, err := s.Firewall.List(ctx)
	if err != nil {
		return nil, err
	}
	managed := make([]BlockEntry, 0, len(blocks))
	for _, block := range blocks {
		if managedRuleName.MatchString(block.Rule) && blockableIPv4(block.SourceIP) {
			managed = append(managed, block)
		}
	}
	return managed, nil
}

// UnblockRule removes only an active Netwatch-named firewall rule. It does not
// depend on an incident, a browser-held token, or the dashboard process age.
func (s *Service) UnblockRule(ctx context.Context, ip, rule string) error {
	if !blockableIPv4(ip) || !managedRuleName.MatchString(rule) {
		return errors.New("invalid Netwatch firewall rule")
	}
	blocks, err := s.ListBlocks(ctx)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		if block.SourceIP == ip && block.Rule == rule {
			if err := s.Firewall.Unblock(ctx, ip, rule); err != nil {
				return err
			}
			s.mu.Lock()
			for key, pending := range s.undos {
				if pending.ip == ip && pending.rule == rule {
					delete(s.undos, key)
				}
			}
			s.mu.Unlock()
			return nil
		}
	}
	return errors.New("Netwatch firewall rule is no longer present")
}

type localFirewall struct{}

func (localFirewall) Supported() bool {
	command := ""
	switch runtime.GOOS {
	case "windows":
		command = "netsh"
	case "linux":
		command = "iptables"
	}
	if command == "" {
		return false
	}
	_, err := exec.LookPath(command)
	return err == nil
}

func (localFirewall) Block(ctx context.Context, ip, rule string) (string, error) {
	var name string
	var args []string
	var undo string
	switch runtime.GOOS {
	case "windows":
		name = "netsh"
		args = []string{"advfirewall", "firewall", "add", "rule", "name=" + rule, "dir=in", "action=block", "remoteip=" + ip}
		undo = "netsh advfirewall firewall delete rule name=" + rule
	case "linux":
		name = "iptables"
		args = []string{"-I", "INPUT", "-s", ip, "-m", "comment", "--comment", rule, "-j", "DROP"}
		undo = "iptables -D INPUT -s " + ip + " -m comment --comment " + rule + " -j DROP"
	default:
		return "", errors.New("automatic blocking is not supported on this OS")
	}
	output, err := runFirewallCommand(ctx, name, args)
	if err != nil {
		return "", fmt.Errorf("firewall rule was not added (%s): %w", strings.TrimSpace(string(output)), err)
	}
	return undo, nil
}

func (localFirewall) Unblock(ctx context.Context, ip, rule string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "windows":
		name, args = "netsh", []string{"advfirewall", "firewall", "delete", "rule", "name=" + rule, "dir=in", "remoteip=" + ip}
	case "linux":
		name, args = "iptables", []string{"-D", "INPUT", "-s", ip, "-m", "comment", "--comment", rule, "-j", "DROP"}
	default:
		return errors.New("automatic unblock is not supported on this OS")
	}
	output, err := runFirewallCommand(ctx, name, args)
	if err != nil {
		return fmt.Errorf("firewall rule was not removed (%s): %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}
