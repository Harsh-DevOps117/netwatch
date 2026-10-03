package cmd

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"detector/modelapi"
)

func TestDashboardForecastProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/forecast" {
			t.Fatalf("unexpected upstream path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"status":"CONNECTED","score":"target_probability","source":{"mode":"live","tag":"lag"}}`))
	}))
	defer upstream.Close()

	handler := dashboardHandler(newDashboardStore("test0"), modelapi.NewClient(upstream.URL+"/forecast", ""))
	request := httptest.NewRequest(http.MethodGet, "/api/forecast", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	var payload modelapi.ForecastResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Status != "CONNECTED" || payload.Source == nil || payload.Source.Tag != "lag" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestCaptureRouteMismatch(t *testing.T) {
	for _, tc := range []struct {
		selected string
		active   string
		want     bool
	}{
		{"Wi-Fi", "Ethernet", true},
		{"Ethernet", "Ethernet", false},
		{"any", "Ethernet", false},
		{"Ethernet", "", false},
	} {
		if got := captureRouteMismatch(tc.selected, tc.active); got != tc.want {
			t.Errorf("captureRouteMismatch(%q, %q) = %t, want %t", tc.selected, tc.active, got, tc.want)
		}
	}
}

func TestCaptureStateChangesNotifyDashboardWithoutTraffic(t *testing.T) {
	store := newDashboardStore("Wi-Fi")
	updates, unsubscribe := store.subscribe()
	defer unsubscribe()
	for _, connected := range []bool{true, false} {
		store.setCaptureState("Wi-Fi", connected, "")
		select {
		case <-updates:
		default:
			t.Fatal("capture state changed without notifying the live page")
		}
		if got := store.snapshot()["status"].(map[string]interface{})["connected"]; got != connected {
			t.Fatalf("connected = %v, want %v", got, connected)
		}
	}
}

func TestTelemetryFallbackReportsCaptureState(t *testing.T) {
	store := newDashboardStore("Wi-Fi")
	store.setCaptureState("Wi-Fi", true, "")
	handler := dashboardHandler(store, modelapi.NewClient("", ""))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/telemetry", nil))
	var payload struct {
		Status struct {
			Connected bool   `json:"connected"`
			Interface string `json:"interface"`
		} `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || !payload.Status.Connected || payload.Status.Interface != "Wi-Fi" {
		t.Fatalf("unexpected telemetry fallback: %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("capture state must not be cached")
	}
}

func TestDashboardForecastUnavailable(t *testing.T) {
	client := modelapi.NewClient("http://127.0.0.1:1/forecast", "")
	handler := dashboardHandler(newDashboardStore("test0"), client)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/forecast", nil))

	if !strings.Contains(response.Body.String(), `"status":"NOT_CONNECTED"`) || !strings.Contains(response.Body.String(), `"reason"`) {
		t.Fatalf("unexpected fallback: %s", response.Body.String())
	}
}

func TestProtectionRouteRejectsCrossOriginAndMissingActionHeader(t *testing.T) {
	handler := dashboardHandler(newDashboardStore("test0"), modelapi.NewClient("", "http://127.0.0.1:8902/detections"))
	for _, test := range []struct {
		name   string
		origin string
		header string
	}{
		{"no action header", "", ""},
		{"cross origin", "http://malicious.example", "protection"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/protection/execute", strings.NewReader(`{"token":"x","confirmation":"BLOCK 8.8.8.8"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Netwatch-Action", test.header)
			request.Header.Set("Origin", test.origin)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}
}

func TestDashboardProtectionGuideNeedsNoKey(t *testing.T) {
	handler := dashboardHandler(newDashboardStore("test0"), modelapi.NewClient("", "http://127.0.0.1:8902/detections"))
	for _, path := range []string{"/api/protection/key", "/api/protection/key/save", "/api/protection/key/clear"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s = %d, want no such route", path, response.Code)
		}
	}
	if strings.Contains(dashboardHTML, "Groq") || strings.Contains(strings.ToLower(dashboardHTML), "api key") {
		t.Fatal("the response guide is built on this machine; the dashboard must not ask for a key")
	}
}

func TestDashboardThresholdModeProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/threshold-mode" || r.Method != http.MethodPost {
			t.Errorf("unexpected upstream request %s %s", r.Method, r.URL.Path)
		}
		var request struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Mode != "checkpoint" {
			t.Errorf("upstream mode = %q, error = %v", request.Mode, err)
		}
		_, _ = w.Write([]byte(`{"requested":"checkpoint","effective":"checkpoint","live_ready":false}`))
	}))
	defer upstream.Close()
	handler := dashboardHandler(newDashboardStore("test0"), modelapi.NewClient(upstream.URL+"/forecast", upstream.URL+"/detections"))
	request := httptest.NewRequest(http.MethodPost, "/api/detection-threshold-mode", strings.NewReader(`{"mode":"checkpoint"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"effective":"checkpoint"`) {
		t.Fatalf("unexpected threshold proxy response %d: %s", response.Code, response.Body.String())
	}
}

func TestDashboardIncidentEventsProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/incident-events" || r.URL.Query().Get("family") != "Bot" ||
			r.URL.Query().Get("incident") != "7" {
			t.Errorf("unexpected incident request: %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"events":[{"family":"Bot","incident":7,"event_id":9,"src":"192.0.2.1","dst":"198.51.100.2"}]}`))
	}))
	defer upstream.Close()
	handler := dashboardHandler(newDashboardStore("test0"), modelapi.NewClient("", upstream.URL+"/detections"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/api/detection-incident-events?family=Bot&incident=7&opened_at=123.5", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"src":"192.0.2.1"`) {
		t.Fatalf("unexpected incident events response %d: %s", response.Code, response.Body.String())
	}
}

func TestDashboardHTMLIsSelfContained(t *testing.T) {
	if strings.Contains(dashboardHTML, "cdn.jsdelivr") || strings.Contains(dashboardHTML, "fonts.googleapis") {
		t.Fatal("dashboard must not depend on remote CSS or font services")
	}
	for _, required := range []string{"/api/forecast", "/api/detections", "Measured test recall", "not calibrated probability"} {
		if !strings.Contains(dashboardHTML, required) {
			t.Fatalf("dashboard is missing %q", required)
		}
	}
}

func TestProtectionHasSidebarDestinationAndIncidentPicker(t *testing.T) {
	protection := strings.Index(dashboardHTML, `data-view="protection"`)
	system := strings.Index(dashboardHTML, `data-view="system"`)
	navEnd := strings.Index(dashboardHTML, `</nav>`)
	if protection < 0 || system < protection || navEnd < system || strings.LastIndex(dashboardHTML[:navEnd], `data-view="`) != system {
		t.Fatal("Protection must appear in the sidebar before System, with System last")
	}
	if !strings.Contains(dashboardHTML, `<section class="view" id="protection">`) ||
		!strings.Contains(dashboardHTML, `id="protectionIncidentSelect"`) {
		t.Fatal("Protection view must have its own detector incident picker")
	}
	for _, required := range []string{`id="protectionBlocks"`, `id="protectionBlockList"`, `id="protectionBlockRows"`, `data-unblock-index`} {
		if !strings.Contains(dashboardHTML, required) {
			t.Fatalf("blocked-IP list is missing %q", required)
		}
	}
	if strings.Contains(dashboardHTML, `id="protectionUndo"`) {
		t.Fatal("the single-block Undo button should be replaced by the blocked-IP list")
	}
}

func TestDashboardHTMLIsNotCached(t *testing.T) {
	handler := dashboardHandler(newDashboardStore("test0"), modelapi.NewClient("", ""))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("dashboard Cache-Control = %q, want no-store", got)
	}
	if !strings.Contains(response.Body.String(), `id="protectionFacts"`) {
		t.Fatal("dashboard must show verified incident facts separately from the response guide")
	}
}

func TestOfflineUploadAndShortRolloutControls(t *testing.T) {
	for _, required := range []string{`id="offlineUpload"`, `id="offlineStepTabs"`, `id="offlinePast"`, `id="offlineFuture"`, `id="offlineGraph"`, `Math.min(3,Number(w.rollout_steps||0))`} {
		if !strings.Contains(dashboardHTML, required) {
			t.Fatalf("offline dashboard is missing %q", required)
		}
	}
	if strings.Contains(dashboardHTML, `id="offlineJumpToUpload"`) {
		t.Fatal("offline dashboard must not show the floating upload shortcut")
	}
}

func TestDashboardReloadStartsOnOverview(t *testing.T) {
	if !strings.Contains(dashboardHTML, `reloaded?'overview'`) || !strings.Contains(dashboardHTML, `window.scrollTo(0,0)`) {
		t.Fatal("a browser reload should return the dashboard to the top of Overview")
	}
}

func TestDashboardServesNeueMachina(t *testing.T) {
	handler := dashboardHandler(newDashboardStore("test0"), modelapi.NewClient("", ""))
	request := httptest.NewRequest(http.MethodGet, "/assets/NeueMachina-Regular.woff2", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("font status = %d; want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "font/woff2" {
		t.Fatalf("font content type = %q; want font/woff2", got)
	}
	if recorder.Body.Len() == 0 {
		t.Fatal("font response is empty")
	}
}

func TestOfflinePageAndCaptureHeaderValidation(t *testing.T) {
	handler := dashboardHandler(newDashboardStore("test0"), modelapi.NewClient("", ""))
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/offline", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Analyze a PCAP") {
		t.Fatalf("offline page: %d", page.Code)
	}
	for _, tc := range []struct {
		magic []byte
		want  string
	}{
		{[]byte{0xd4, 0xc3, 0xb2, 0xa1}, ".pcap"},
		{[]byte{0x0a, 0x0d, 0x0d, 0x0a}, ".pcapng"},
		{[]byte("text"), ""},
	} {
		if got := offlineCaptureFormat(tc.magic); got != tc.want {
			t.Fatalf("magic %x: got %q, want %q", tc.magic, got, tc.want)
		}
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("file", "not-a-capture.pcap")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("not a capture"))
	_ = writer.Close()
	request := httptest.NewRequest(http.MethodPost, "/api/offline/jobs", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid capture status: %d", response.Code)
	}
}
