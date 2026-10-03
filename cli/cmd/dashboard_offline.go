package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"detector/modelapi"
)

const maxOfflineUpload = 128 << 20

var offlineJobID = regexp.MustCompile(`^[a-f0-9]{24}$`)

type offlineManager struct {
	repo   string
	mu     sync.Mutex
	active string
	errors map[string]string
}

func offlineRepo() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "models", "serving", "analyze_pcap.py")); err == nil {
			return dir
		}
		if filepath.Dir(dir) == dir {
			return ""
		}
	}
}

func (m *offlineManager) register(mux *http.ServeMux) {
	mux.HandleFunc("/api/offline/jobs", m.upload)
	mux.HandleFunc("/api/offline/jobs/", m.job)
}

func offlineCaptureFormat(magic []byte) string {
	if len(magic) < 4 {
		return ""
	}
	switch hex.EncodeToString(magic[:4]) {
	case "d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d":
		return ".pcap"
	case "0a0d0d0a":
		return ".pcapng"
	default:
		return ""
	}
}

func (m *offlineManager) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if m.repo == "" {
		http.Error(w, "Netwatch repository not found", http.StatusServiceUnavailable)
		return
	}
	m.mu.Lock()
	if m.active != "" {
		m.mu.Unlock()
		http.Error(w, "An offline analysis is already running", http.StatusConflict)
		return
	}
	m.active = "uploading"
	m.mu.Unlock()
	accepted := false
	defer func() {
		if !accepted {
			m.mu.Lock()
			m.active = ""
			m.mu.Unlock()
		}
	}()
	r.Body = http.MaxBytesReader(w, r.Body, maxOfflineUpload+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, "Invalid or oversized PCAP upload", http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Choose a PCAP or PCAPNG file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if header.Size == 0 || header.Size > maxOfflineUpload {
		http.Error(w, "PCAP must be 1 byte to 128 MiB", http.StatusBadRequest)
		return
	}
	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		http.Error(w, "Capture header is incomplete", http.StatusBadRequest)
		return
	}
	ext := offlineCaptureFormat(magic[:])
	if ext == "" {
		http.Error(w, "Not a PCAP or PCAPNG capture", http.StatusBadRequest)
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "Capture cannot be read", http.StatusBadRequest)
		return
	}
	var entropy [12]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		http.Error(w, "Cannot create job ID", http.StatusInternalServerError)
		return
	}
	id := hex.EncodeToString(entropy[:])
	jobDir := filepath.Join(m.repo, "artifacts", "runtime", "offline", id)
	if err := os.MkdirAll(jobDir, 0700); err != nil {
		http.Error(w, "Cannot create offline workspace", http.StatusInternalServerError)
		return
	}
	capture := filepath.Join(jobDir, "capture"+ext)
	dst, err := os.OpenFile(capture, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		http.Error(w, "Cannot save capture", http.StatusInternalServerError)
		return
	}
	written, copyErr := io.Copy(dst, io.LimitReader(file, maxOfflineUpload+1))
	closeErr := dst.Close()
	if copyErr != nil || closeErr != nil || written > maxOfflineUpload {
		http.Error(w, "Capture upload failed or exceeded 128 MiB", http.StatusBadRequest)
		return
	}
	name := filepath.Base(strings.ReplaceAll(header.Filename, "\\", "/"))
	if name == "." || name == "" {
		name = "capture" + ext
	}
	accepted = true
	m.mu.Lock()
	m.active = id
	m.mu.Unlock()
	go m.run(id, capture, name)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "running"})
}

func (m *offlineManager) run(id, capture, name string) {
	defer func() { m.mu.Lock(); m.active = ""; m.mu.Unlock() }()
	jobDir := filepath.Dir(capture)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	python := filepath.Join(m.repo, ".venv", "Scripts", "python.exe")
	if runtime.GOOS != "windows" {
		python = filepath.Join(m.repo, ".venv", "bin", "python")
	}
	if _, err := os.Stat(python); err != nil {
		python = "python"
		if runtime.GOOS != "windows" {
			python = "python3"
		}
	}
	cmd := exec.CommandContext(ctx, python, "-m", "models.serving.analyze_pcap", "--pcap", capture,
		"--work", jobDir, "--out", filepath.Join(jobDir, "result.json"), "--name", name)
	cmd.Dir = m.repo
	log, err := os.OpenFile(filepath.Join(jobDir, "analysis.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err == nil {
		defer log.Close()
		cmd.Stdout = log
		cmd.Stderr = log
	}
	err = cmd.Run()
	if err != nil {
		message := err.Error()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			message = "Analysis exceeded 30 minutes"
		}
		m.mu.Lock()
		m.errors[id] = message
		m.mu.Unlock()
	}
}

func (m *offlineManager) job(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/offline/jobs/")
	if !offlineJobID.MatchString(id) || m.repo == "" {
		http.NotFound(w, r)
		return
	}
	jobDir := filepath.Join(m.repo, "artifacts", "runtime", "offline", id)
	if _, err := os.Stat(jobDir); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if data, err := os.ReadFile(filepath.Join(jobDir, "result.json")); err == nil {
		if enriched, enrichErr := enrichOfflineResult(data); enrichErr == nil {
			data = enriched
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`{"id":%q,"status":"complete","result":%s}`, id, data)))
		return
	}
	m.mu.Lock()
	active, jobError := m.active == id, m.errors[id]
	m.mu.Unlock()
	if !active && jobError == "" {
		jobError = "Analysis stopped before producing a result"
	}
	stage := "Preparing capture"
	if data, err := os.ReadFile(filepath.Join(jobDir, "progress.json")); err == nil {
		var progress struct {
			Stage string `json:"stage"`
		}
		if json.Unmarshal(data, &progress) == nil && progress.Stage != "" {
			stage = progress.Stage
		}
	}
	status := "running"
	if jobError != "" {
		status = "failed"
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "status": status, "stage": stage, "error": jobError})
}

func enrichOfflineResult(data []byte) ([]byte, error) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	if string(result["detection"]) == "null" || len(result["detection"]) == 0 {
		return data, nil
	}
	var detection map[string]json.RawMessage
	if err := json.Unmarshal(result["detection"], &detection); err != nil {
		return nil, err
	}
	var incidents []modelapi.OfflineIncident
	if err := json.Unmarshal(detection["incidents"], &incidents); err != nil {
		return nil, err
	}
	visible, suppressed := modelapi.ApplyOfflineRules(incidents)
	var err error
	if detection["incidents"], err = json.Marshal(visible); err != nil {
		return nil, err
	}
	if detection["raw_incidents"], err = json.Marshal(incidents); err != nil {
		return nil, err
	}
	if detection["suppressed_incidents"], err = json.Marshal(suppressed); err != nil {
		return nil, err
	}
	if result["detection"], err = json.Marshal(detection); err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
