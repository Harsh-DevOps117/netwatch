package window

import (
	"sync"
	"time"

	"detector/features"
	"detector/parser"
)

type Manager struct {
	mu             sync.Mutex
	windowDuration time.Duration
	windowIndex    int
	windowStart    time.Time
	windowEnd      time.Time
	aggregator     *features.FeatureAggregator
	flowTracker    *features.FlowTracker
	onWindowClosed func(feat *features.WindowFeatures)
	initialized    bool
}

func NewManager(duration time.Duration, flowIdleTimeout time.Duration, maxFlows int, onWindowClosed func(feat *features.WindowFeatures)) *Manager {
	if duration <= 0 {
		duration = 10 * time.Second
	}
	return &Manager{
		windowDuration: duration,
		flowTracker:    features.NewFlowTracker(flowIdleTimeout, maxFlows),
		onWindowClosed: onWindowClosed,
	}
}

func (m *Manager) ProcessPacket(p *parser.ParsedPacket) {
	if p == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		m.windowStart = p.Timestamp
		m.windowEnd = m.windowStart.Add(m.windowDuration)
		m.aggregator = features.NewAggregator(m.windowIndex, m.windowStart, m.windowEnd, m.flowTracker)
		m.initialized = true
	}

	for !p.Timestamp.Before(m.windowEnd) {
		m.closeCurrentWindow()
		m.windowIndex++
		m.windowStart = m.windowEnd
		m.windowEnd = m.windowStart.Add(m.windowDuration)
		m.aggregator = features.NewAggregator(m.windowIndex, m.windowStart, m.windowEnd, m.flowTracker)
	}

	m.aggregator.AddPacket(p)
}

func (m *Manager) Tick(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		m.windowStart = now
		m.windowEnd = now.Add(m.windowDuration)
		m.aggregator = features.NewAggregator(m.windowIndex, m.windowStart, m.windowEnd, m.flowTracker)
		m.initialized = true
		return
	}

	for !now.Before(m.windowEnd) {
		m.closeCurrentWindow()
		m.windowIndex++
		m.windowStart = m.windowEnd
		m.windowEnd = m.windowStart.Add(m.windowDuration)
		m.aggregator = features.NewAggregator(m.windowIndex, m.windowStart, m.windowEnd, m.flowTracker)
	}
}

func (m *Manager) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized && m.aggregator != nil {
		m.closeCurrentWindow()
		m.aggregator = nil
	}
}

func (m *Manager) closeCurrentWindow() {
	if m.aggregator == nil {
		return
	}
	feat := m.aggregator.ComputeFinalFeatures()
	if m.onWindowClosed != nil {
		m.onWindowClosed(feat)
	}
}
