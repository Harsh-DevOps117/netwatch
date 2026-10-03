package protection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"detector/modelapi"
)

type fakeFirewall struct {
	blocks   int
	unblocks int
	active   map[string]string
}

func (*fakeFirewall) Supported() bool { return true }
func (f *fakeFirewall) Block(_ context.Context, ip, rule string) (string, error) {
	f.blocks++
	if f.active == nil {
		f.active = make(map[string]string)
	}
	f.active[rule] = ip
	return "remove " + rule + " " + ip, nil
}
func (f *fakeFirewall) Unblock(_ context.Context, _, rule string) error {
	f.unblocks++
	delete(f.active, rule)
	return nil
}
func (f *fakeFirewall) List(context.Context) ([]BlockEntry, error) {
	var blocks []BlockEntry
	for rule, ip := range f.active {
		blocks = append(blocks, BlockEntry{SourceIP: ip, Rule: rule})
	}
	return blocks, nil
}

func TestListAndUnblockOnlyManagedRule(t *testing.T) {
	firewall := &fakeFirewall{active: map[string]string{
		"Netwatch-0123456789abcdef0123456789abcdef": "8.8.4.4",
		"Unrelated": "1.1.1.1",
	}}
	service := New(nil)
	service.Firewall = firewall
	blocks, err := service.ListBlocks(context.Background())
	if err != nil || len(blocks) != 1 || blocks[0].SourceIP != "8.8.4.4" {
		t.Fatalf("blocks = %+v, %v", blocks, err)
	}
	for _, candidate := range []BlockEntry{
		{SourceIP: "1.1.1.1", Rule: "Unrelated"},
		{SourceIP: "8.8.4.4", Rule: "Netwatch-bad"},
		{SourceIP: "1.1.1.1", Rule: "Netwatch-0123456789abcdef0123456789abcdef"},
	} {
		if err := service.UnblockRule(context.Background(), candidate.SourceIP, candidate.Rule); err == nil {
			t.Fatalf("unblock accepted %+v", candidate)
		}
	}
	if firewall.unblocks != 0 {
		t.Fatal("invalid unblock reached firewall")
	}
	if err := service.UnblockRule(context.Background(), "8.8.4.4", "Netwatch-0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if firewall.unblocks != 1 {
		t.Fatal("managed block was not removed")
	}
}

func TestProtectionRequiresActivePublicSourceAndConfirmation(t *testing.T) {
	const opened = 1720000000.25
	sourceIP, active := "8.8.4.4", true
	detector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		incident := map[string]any{"key": 11, "t": opened, "score": 0.9, "incident": 7, "family": "DoS-Hulk"}
		switch r.URL.Path {
		case "/detections":
			payload := map[string]any{"status": "RUNNING", "recent_incidents": []any{incident}}
			if active {
				payload["incidents"] = []any{incident}
			}
			_ = json.NewEncoder(w).Encode(payload)
		case "/incident-events":
			_ = json.NewEncoder(w).Encode(map[string]any{"events": []any{
				map[string]any{"sender_ip": sourceIP, "src": sourceIP, "dst": "127.0.0.1"},
				map[string]any{"sender_ip": sourceIP, "src": sourceIP, "dst": "127.0.0.1"},
				map[string]any{"sender_ip": sourceIP, "src": sourceIP, "dst": "127.0.0.1"},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer detector.Close()
	groq := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q", got)
		}
		var request struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		} else if len(request.Messages) < 2 || strings.Contains(request.Messages[1].Content, sourceIP) || !strings.Contains(request.Messages[1].Content, sourceScope(sourceIP)) {
			t.Errorf("Groq request leaked an address or omitted the source scope: %+v", request.Messages)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Check traffic, then contain it."}}]}`))
	}))
	defer groq.Close()
	service := New(modelapi.NewClient("", detector.URL+"/detections"))
	service.Endpoint = groq.URL
	service.Firewall = &fakeFirewall{}
	id := Identity{Family: "DoS-Hulk", Incident: 7, OpenedAt: opened}
	plan, err := service.Advise(context.Background(), id, "test-key")
	if err != nil || !plan.CanExecute || plan.SourceIP != sourceIP || plan.SourceScope != "public IPv4" || !plan.Active || plan.LinkedEvents != 3 {
		t.Fatalf("public active plan = %+v, %v", plan, err)
	}
	if _, err := service.Execute(context.Background(), plan.Token, "BLOCK 1.1.1.1"); err == nil {
		t.Fatal("wrong confirmation accepted")
	}
	plan, err = service.Advise(context.Background(), id, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(context.Background(), plan.Token, "BLOCK "+sourceIP)
	if err != nil || result.SourceIP != sourceIP {
		t.Fatalf("execute = %+v, %v", result, err)
	}
	if err := service.Undo(context.Background(), result.UndoToken); err != nil {
		t.Fatal(err)
	}
	if f := service.Firewall.(*fakeFirewall); f.blocks != 1 || f.unblocks != 1 {
		t.Fatalf("firewall calls = %+v", f)
	}
	active = false
	plan, err = service.Advise(context.Background(), id, "test-key")
	if err != nil || plan.CanExecute || !strings.Contains(plan.Reason, "closed") {
		t.Fatalf("closed plan = %+v, %v", plan, err)
	}
	active, sourceIP = true, "192.168.1.10"
	plan, err = service.Advise(context.Background(), id, "test-key")
	if err != nil || !plan.CanExecute || plan.Confirmation != "BLOCK LAN 192.168.1.10" || plan.SourceScope != "private LAN" {
		t.Fatalf("private source plan = %+v, %v", plan, err)
	}
	if _, err := service.Execute(context.Background(), plan.Token, "BLOCK 192.168.1.10"); err == nil {
		t.Fatal("LAN block accepted the public-IP confirmation phrase")
	}
}

func TestProtectionRejectsRemoteDetector(t *testing.T) {
	service := New(modelapi.NewClient("", "http://example.com/detections"))
	_, err := service.Advise(context.Background(), Identity{Family: "Bot", Incident: 1, OpenedAt: 1}, "test-key")
	if err == nil || !strings.Contains(err.Error(), "local detector") {
		t.Fatalf("remote detector error = %v", err)
	}
}

func TestPublicIPv4Allowlist(t *testing.T) {
	for _, candidate := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.5", "169.254.1.1", "100.64.1.2", "203.0.113.5", "ff00::1", "1.2.3.4;echo unsafe"} {
		if publicIPv4(candidate) {
			t.Errorf("unsafe source %q accepted", candidate)
		}
	}
	if !publicIPv4("8.8.4.4") {
		t.Fatal("public IPv4 source rejected")
	}
}

func TestBlockableIPv4IncludesPrivateButNotReserved(t *testing.T) {
	if !blockableIPv4("10.4.2.245") || !blockableIPv4("8.8.4.4") {
		t.Fatal("valid IPv4 source rejected")
	}
	for _, address := range []string{"127.0.0.1", "169.254.2.3", "100.64.1.2", "203.0.113.5", "ff00::1"} {
		if blockableIPv4(address) {
			t.Errorf("reserved source %q accepted", address)
		}
	}
}

func TestSavedAPIKeyRoundTrip(t *testing.T) {
	config := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", config)
	} else {
		t.Setenv("XDG_CONFIG_HOME", config)
	}
	if _, err := LoadAPIKey(); !os.IsNotExist(err) {
		t.Fatalf("missing key error = %v", err)
	}
	if err := SaveAPIKey("test-secret-key"); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAPIKey()
	if err != nil || got != "test-secret-key" {
		t.Fatalf("loaded key = %q, err = %v", got, err)
	}
	data, err := os.ReadFile(filepath.Join(config, "netwatch", "groq-api-key"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" && strings.Contains(string(data), "test-secret-key") {
		t.Fatal("Windows key file contains plaintext")
	}
	if err := SaveAPIKey("replacement-secret"); err != nil {
		t.Fatalf("replace key: %v", err)
	}
	if got, err := LoadAPIKey(); err != nil || got != "replacement-secret" {
		t.Fatalf("replacement key = %q, err = %v", got, err)
	}
	if err := ClearAPIKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAPIKey(); !os.IsNotExist(err) {
		t.Fatalf("cleared key error = %v", err)
	}
}
