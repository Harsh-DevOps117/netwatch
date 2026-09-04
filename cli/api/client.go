package api

import (
	"net/http"
	"time"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type ModelStatus struct {
	Status  string `json:"status"`
	Uptime  string `json:"uptime"`
	Version string `json:"version"`
}

func (c *Client) GetStatus() (*ModelStatus, error) {
	return &ModelStatus{
		Status:  "Operational (Mock)",
		Uptime:  "24h 12m",
		Version: "v1.0.0-mock",
	}, nil
}
