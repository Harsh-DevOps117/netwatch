package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"detector/modelapi"
	"detector/protection"
)

func registerProtectionRoutes(mux *http.ServeMux, models *modelapi.Client) {
	service := protection.New(models)
	post := func(w http.ResponseWriter, r *http.Request, value interface{}) bool {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return false
		}
		if r.Header.Get("X-Netwatch-Action") != "protection" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "local protection request required", http.StatusForbidden)
			return false
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Scheme != "http" || !strings.EqualFold(parsed.Host, r.Host) {
				http.Error(w, "cross-origin protection request refused", http.StatusForbidden)
				return false
			}
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
			return false
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(value); err != nil {
			http.Error(w, "invalid protection request", http.StatusBadRequest)
			return false
		}
		var trailing interface{}
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			http.Error(w, "trailing request data", http.StatusBadRequest)
			return false
		}
		return true
	}
	write := func(w http.ResponseWriter, value interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("/api/protection/key", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		_, err := protection.LoadAPIKey()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(w, "saved Groq API key is unavailable", http.StatusInternalServerError)
			return
		}
		write(w, map[string]bool{"saved": err == nil})
	})
	mux.HandleFunc("/api/protection/key/save", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			APIKey string `json:"api_key"`
		}
		if !post(w, r, &request) {
			return
		}
		if err := protection.SaveAPIKey(request.APIKey); err != nil {
			http.Error(w, "could not save Groq API key: "+err.Error(), http.StatusBadRequest)
			return
		}
		write(w, map[string]bool{"saved": true})
	})
	mux.HandleFunc("/api/protection/key/clear", func(w http.ResponseWriter, r *http.Request) {
		var request struct{}
		if !post(w, r, &request) {
			return
		}
		if err := protection.ClearAPIKey(); err != nil {
			http.Error(w, "could not clear Groq API key", http.StatusInternalServerError)
			return
		}
		write(w, map[string]bool{"saved": false})
	})
	mux.HandleFunc("/api/protection/advice", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			protection.Identity
			APIKey string `json:"api_key"`
		}
		if !post(w, r, &request) {
			return
		}
		if request.APIKey == "" {
			var err error
			request.APIKey, err = protection.LoadAPIKey()
			if err != nil {
				http.Error(w, "save a Groq API key before requesting guidance", http.StatusBadRequest)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		plan, err := service.Advise(ctx, request.Identity, request.APIKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		write(w, plan)
	})
	mux.HandleFunc("/api/protection/execute", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Token        string `json:"token"`
			Confirmation string `json:"confirmation"`
		}
		if !post(w, r, &request) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		result, err := service.Execute(ctx, request.Token, request.Confirmation)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write(w, result)
	})
	mux.HandleFunc("/api/protection/blocks", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		blocks, err := service.ListBlocks(ctx)
		if err != nil {
			http.Error(w, "could not list Netwatch firewall blocks: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		write(w, map[string]interface{}{"blocks": blocks})
	})
	mux.HandleFunc("/api/protection/blocks/unblock", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			SourceIP string `json:"source_ip"`
			Rule     string `json:"rule"`
		}
		if !post(w, r, &request) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		if err := service.UnblockRule(ctx, request.SourceIP, request.Rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write(w, map[string]string{"status": "removed"})
	})
	mux.HandleFunc("/api/protection/undo", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			UndoToken string `json:"undo_token"`
		}
		if !post(w, r, &request) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		if err := service.Undo(ctx, request.UndoToken); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write(w, map[string]string{"status": "removed"})
	})
}
