package main

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    eventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "edr_events_total",
        Help: "Total kernel events processed, by type.",
    }, []string{"type"})

    alertsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "edr_alerts_total",
        Help: "Total detections fired, by rule and severity.",
    }, []string{"rule", "severity"})

    ringbufLoss = promauto.NewCounter(prometheus.CounterOpts{
        Name: "edr_ringbuf_lost_total",
        Help: "Events dropped because userspace couldn't keep up with the ring buffer.",
    })

    eventProcessLatency = promauto.NewHistogram(prometheus.HistogramOpts{
        Name:    "edr_event_process_seconds",
        Help:    "Time from kernel timestamp to userspace processing completion.",
        Buckets: prometheus.ExponentialBuckets(0.00001, 2, 16),
    })
)