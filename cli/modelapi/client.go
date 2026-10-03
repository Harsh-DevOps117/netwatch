package modelapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxResponseBytes = 16 << 20

type Client struct {
	ForecastURL   string
	DetectionsURL string
	HTTPClient    *http.Client
	ruleMu        sync.Mutex
	ruleCache     map[string]cachedRuleIncident
}

func NewClient(forecastURL, detectionsURL string) *Client {
	return &Client{
		ForecastURL:   forecastURL,
		DetectionsURL: detectionsURL,
		HTTPClient:    &http.Client{Timeout: 5 * time.Second},
	}
}

func URLsForService(service string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "", "lag":
		return "http://127.0.0.1:8901/forecast", "http://127.0.0.1:8902/detections", nil
	case "live":
		return "http://127.0.0.1:8902/forecast", "http://127.0.0.1:8902/detections", nil
	case "replay":
		return "http://127.0.0.1:8900/forecast", "", nil
	default:
		return "", "", fmt.Errorf("unknown model service %q (use lag, live, or replay)", service)
	}
}

func ValidateEndpoint(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid HTTP endpoint %q", raw)
	}
	return nil
}

func (c *Client) Forecast(ctx context.Context) (*ForecastResponse, error) {
	var response ForecastResponse
	if err := c.getJSON(ctx, c.ForecastURL, &response); err != nil {
		return nil, err
	}
	if response.Status == "" {
		return nil, fmt.Errorf("forecast service returned a payload without status")
	}
	return &response, nil
}

func (c *Client) Detections(ctx context.Context) (*DetectionsResponse, error) {
	if c.DetectionsURL == "" {
		return nil, fmt.Errorf("detections are not available for this service")
	}
	var response DetectionsResponse
	if err := c.getJSON(ctx, c.DetectionsURL, &response); err != nil {
		return nil, err
	}
	if response.Status == "NOT_CONNECTED" {
		return nil, fmt.Errorf("detection service is not connected: %s", response.Reason)
	}
	return &response, nil
}

// IncidentEvents fetches only the scored crossings assigned to one detector incident.
func (c *Client) IncidentEvents(ctx context.Context, family string, incident int, openedAt float64) (*IncidentEventsResponse, error) {
	if c.DetectionsURL == "" {
		return nil, fmt.Errorf("detections are not available for this service")
	}
	if err := ValidateEndpoint(c.DetectionsURL); err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.DetectionsURL)
	u.Path = "/incident-events"
	q := u.Query()
	q.Set("family", family)
	q.Set("incident", fmt.Sprint(incident))
	q.Set("opened_at", fmt.Sprint(openedAt))
	u.RawQuery = q.Encode()
	var response IncidentEventsResponse
	if err := c.getJSON(ctx, u.String(), &response); err != nil {
		return nil, err
	}
	annotateIncidentEvents(response.Events)
	return &response, nil
}

// SetThresholdMode changes only a local model service's operating threshold.
// Checkpoint weights and saved calibration are never modified.
func (c *Client) SetThresholdMode(ctx context.Context, kind, mode string) (int, []byte, error) {
	if mode != "checkpoint" && mode != "live" {
		return 0, nil, fmt.Errorf("mode must be checkpoint or live")
	}
	endpoint := c.ForecastURL
	if kind == "detection" {
		endpoint = c.DetectionsURL
	} else if kind != "world" {
		return 0, nil, fmt.Errorf("unknown threshold kind %q", kind)
	}
	if err := ValidateEndpoint(endpoint); err != nil {
		return 0, nil, err
	}
	u, _ := url.Parse(endpoint)
	host := u.Hostname()
	if !strings.EqualFold(host, "localhost") && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
		return 0, nil, fmt.Errorf("threshold changes require a loopback model service")
	}
	u.Path = "/threshold-mode"
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewBufferString(`{"mode":"`+mode+`"}`))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return resp.StatusCode, body, err
}

func (c *Client) getJSON(ctx context.Context, endpoint string, target interface{}) error {
	if err := ValidateEndpoint(endpoint); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("model service %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body := io.LimitReader(resp.Body, maxResponseBytes)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(body, 2048))
		if detail := strings.TrimSpace(string(message)); detail != "" {
			return fmt.Errorf("model service %s returned %s: %s", endpoint, resp.Status, detail)
		}
		return fmt.Errorf("model service %s returned %s", endpoint, resp.Status)
	}
	if err := json.NewDecoder(body).Decode(target); err != nil {
		return fmt.Errorf("decode model response from %s: %w", endpoint, err)
	}
	return nil
}
