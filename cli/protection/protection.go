package protection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"detector/modelapi"
)

const planLifetime = 5 * time.Minute

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
	Firewall firewall
	mu       sync.Mutex
	plans    map[string]pendingPlan
	undos    map[string]pendingUndo
}

func New(models *modelapi.Client) *Service {
	return &Service{
		Models: models, Firewall: localFirewall{},
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
	// servedPort is set when the linked flows are this host's replies from one
	// served port: ip is then the client those replies go to.
	servedPort int
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
	// What the linked flows are between: taken from the events, or, when the
	// detector sent only a preview of a flood, from its summary of all of them.
	type group struct {
		sender, src, dst string
		events           int
	}
	var groups []group
	peers, localPorts, peerPorts := map[string]int{}, map[int]int{}, 0
	counted := !linked.Truncated
	if linked.Truncated && linked.Summary != nil {
		for _, g := range linked.Summary.Groups {
			groups = append(groups, group{g.SenderIP, g.Src, g.Dst, g.Events})
			result.events += g.Events
			if g.DstPorts > peerPorts {
				peerPorts = g.DstPorts
			}
		}
		localPorts[linked.Summary.TopSrcPort.Port] = linked.Summary.TopSrcPort.Events
		// The summary lists the largest groups: it settles the matter only when they are all of them.
		counted = result.events == linked.Total
	} else {
		ports := map[int]bool{}
		for _, event := range linked.Events {
			groups = append(groups, group{event.SenderIP, event.Src, event.Dst, 1})
			localPorts[event.SrcPort]++
			ports[event.DstPort] = true
		}
		result.events, peerPorts = len(linked.Events), len(ports)
	}
	if result.events == 0 {
		result.reason = "No linked source-IP evidence was retained for this incident."
		return result, nil
	}
	known := map[string]bool{}
	local := func(ip string) bool {
		if _, seen := known[ip]; !seen {
			known[ip] = localAddress(ip)
		}
		return known[ip]
	}
	for _, g := range groups {
		peers[g.dst] += g.events
		if g.sender == "" || (result.ip != "" && g.sender != result.ip) {
			result.ip = ""
			result.reason = "Linked events do not agree on one source IP."
			return result, nil
		}
		result.ip = g.sender
		// Under a flood some flows between the same two hosts are recorded from
		// this host's side (its reply is the first packet seen). They are the
		// sender's traffic with this host all the same.
		reply := g.dst == g.sender && local(g.src)
		if g.src != "" && g.src != g.sender && !reply {
			result.reason = "Linked traffic does not consistently originate from the sender IP."
			return result, nil
		}
		if reply || local(g.dst) {
			result.localDestination = true
		}
	}
	// A flood on a service this host runs is often seen from the reply side: the
	// linked flows leave this host from the served port towards one client's
	// changing ports. The traffic to contain is then that client's, so the block
	// is offered for it. An incident is keyed by its sender, so a few unrelated
	// flows of this host can be linked too: the port and the client must each
	// account for nine in ten of the linked flows. Traffic this host starts
	// itself has the opposite shape (changing local ports, one remote port) and
	// stays ineligible.
	if local(result.ip) && peerPorts >= 3 {
		most := func(counts map[string]int) (string, bool) {
			for key, count := range counts {
				if count*10 >= result.events*9 {
					return key, true
				}
			}
			return "", false
		}
		ports := map[string]int{}
		for port, count := range localPorts {
			ports[strconv.Itoa(port)] = count
		}
		port, served := most(ports)
		if peer, one := most(peers); served && one && port != "0" && peer != "" {
			result.ip, result.localDestination = peer, true
			result.servedPort, _ = strconv.Atoi(port)
		}
	}
	if !counted {
		// One source must account for every linked event, not only those returned.
		result.reason = fmt.Sprintf("Only %d of %d linked events could be checked for a single source; automatic blocking is disabled.", result.events, linked.Total)
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

// Advise returns the response guide for one incident and, when the incident is
// eligible, a pending host-block plan that Execute applies after confirmation.
func (s *Service) Advise(ctx context.Context, id Identity) (Plan, error) {
	incident, err := s.resolve(ctx, id)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Family: id.Family, Incident: id.Incident, SourceIP: incident.ip, SourceScope: sourceScope(incident.ip), Active: incident.active, LinkedEvents: incident.events,
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
	plan.Advice = guide(incident, plan.Reason)
	return plan, nil
}

// guide is the response guide for one incident: what the flag establishes, what
// to check for its family, what containment this host offers, and how to recover.
// It is built from the incident's verified facts alone, so one incident always
// reads the same, and it claims nothing about packet contents, intent or
// compromise, none of which the detector observes. blocked is why no host block
// is offered, empty when one is.
func guide(incident incidentContext, blocked string) string {
	evidence := fmt.Sprintf("%d linked flows scored", incident.events)
	switch incident.events {
	case 0:
		evidence = "no linked flow was kept, but the incident opened"
	case 1:
		evidence = "1 linked flow scored"
	}
	lines := []string{
		fmt.Sprintf("This is a model flag, not proof of an attack: %s above the %s threshold (opening score %.3f, source: %s). A score is not a probability, and the flag shows neither packet contents nor intent.",
			evidence, incident.incident.Family, incident.incident.Score, sourceScope(incident.ip)),
		familyCheck(incident.incident.Family),
	}
	switch {
	case !incident.active:
		lines = append(lines, "The incident is closed, so review it in retrospect: confirm the traffic stopped and keep its period for the check above. No block is offered for a closed incident.")
	case blocked != "":
		lines = append(lines, "No host block is offered. "+blocked+" If the check confirms unwanted traffic, limit it at the service or upstream instead.")
	default:
		containment := "If the check confirms unwanted traffic, a block of this one source in the host firewall is available: inbound traffic only, kept until you remove it. It does not stop traffic that comes from many addresses."
		if incident.servedPort != 0 {
			containment = fmt.Sprintf("The linked flows are this host's replies from its port %d to %s, so that address is the client sending the requests, and the block applies to it. ", incident.servedPort, incident.ip) + containment
		}
		if ip, err := netip.ParseAddr(incident.ip); err == nil && ip.IsPrivate() {
			containment += " The source is on your own LAN: identify the device first, because blocking it may cut off a legitimate device or service."
		}
		lines = append(lines, containment, "To recover, remove the firewall rule once the traffic has stopped, then confirm that the service's usual clients still connect.")
	}
	return "- " + strings.Join(lines, "\n- ")
}

// familyCheck names what to look at first for a flagged family. The family is the
// model's label for the flows, so each line says where confirmation would show,
// never that it is there.
func familyCheck(family string) string {
	name := strings.ToLower(strings.ReplaceAll(family, " ", ""))
	switch {
	case strings.HasPrefix(name, "dos-"):
		return "Check the service these flows reach: its open connections, request rate and response times over the same period. A flood shows there; ordinary busy traffic can raise this flag too."
	case name == "bruteforce-web":
		return "Check the web server's access log over the same period for repeated failed logins from this source."
	case name == "bruteforce-xss", name == "sqlinjection":
		return "Check the web server's access and error logs over the same period for request parameters that carry script or SQL text from this source."
	case name == "bot":
		return "Check the source host for a process that makes regular outbound connections to a destination nobody recognises."
	case name == "infiltration":
		return "Check the source host's recent logins, new processes, and connections to hosts it does not normally reach."
	}
	return "Compare the linked flows with this source's normal traffic before acting."
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
