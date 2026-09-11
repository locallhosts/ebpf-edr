package main

import (
    "sync"
)

// AlertStore keeps a bounded, in-memory history of recent alerts.
type AlertStore struct {
    mu     sync.Mutex
    cap    int
    alerts []Alert
}

// NewAlertStore initializes the store with a fixed capacity.
func NewAlertStore(capacity int) *AlertStore {
    return &AlertStore{
        cap:    capacity,
        alerts: make([]Alert, 0, capacity),
    }
}

// Add appends a new alert to the store and updates Prometheus metrics.
func (s *AlertStore) Add(a Alert) {
    s.mu.Lock()
    defer s.mu.Unlock()

    if len(s.alerts) >= s.cap {
        // Drop the oldest alert (FIFO) if we hit capacity
        s.alerts = s.alerts[1:]
    }
    s.alerts = append(s.alerts, a)

    // Increment Prometheus counter
    alertsTotal.WithLabelValues(a.Severity, a.Rule).Inc()
}

// Snapshot returns a copy of the current alerts to prevent race conditions
// when the HTTP handler is marshaling the data to JSON.
func (s *AlertStore) Snapshot() []Alert {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    cp := make([]Alert, len(s.alerts))
    copy(cp, s.alerts)
    return cp
}