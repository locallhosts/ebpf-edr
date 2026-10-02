package main

import (
    "encoding/json"
    "log"
    "net/http"

    "github.com/prometheus/client_golang/prometheus/promhttp"
)

// ServeHTTP starts the metrics + alerts API. Blocks; run in a goroutine.
func ServeHTTP(addr string, store *AlertStore, network *NetworkStore) {
    mux := http.NewServeMux()
    
    // Prometheus metrics endpoint for Grafana
    mux.Handle("/metrics", promhttp.Handler())
    
    // REST API for the TypeScript React Dashboard
    mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Header().Set("Access-Control-Allow-Origin", "*") // demo dashboard runs on a different port
        if err := json.NewEncoder(w).Encode(store.Snapshot()); err != nil {
            log.Printf("encoding alerts response: %v", err)
        }
    })
    
    // Bounded network telemetry API. Payloads are never captured.
    mux.HandleFunc("/api/network", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Header().Set("Access-Control-Allow-Origin", "*")
        if err := json.NewEncoder(w).Encode(network.Snapshot()); err != nil {
            log.Printf("encoding network response: %v", err)
        }
    })

    // Simple health check for load balancers / Docker
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("ok"))
    })

    log.Printf("HTTP API listening on %s (/metrics, /api/alerts, /api/network, /healthz)", addr)
    if err := http.ListenAndServe(addr, mux); err != nil {
        log.Fatalf("HTTP server failed: %v", err)
    }
}