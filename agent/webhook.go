package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

type WebhookSink struct {
	url   string
	token string
	queue chan Alert
}

func NewWebhookSink(url, token string) *WebhookSink {
	if url == "" {
		return nil
	}
	s := &WebhookSink{url: url, token: token, queue: make(chan Alert, 256)}
	go s.worker()
	return s
}

func (s *WebhookSink) worker() {
	client := &http.Client{Timeout: 5 * time.Second}
	for alert := range s.queue {
		body, err := json.Marshal(alert)
		if err != nil {
			webhookFailures.Inc()
			continue
		}
		req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
		if err != nil {
			webhookFailures.Inc()
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if s.token != "" {
			req.Header.Set("Authorization", "Bearer "+s.token)
		}
		resp, err := client.Do(req)
		if err != nil {
			webhookFailures.Inc()
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			webhookFailures.Inc()
		} else {
			webhookDelivered.Inc()
		}
	}
}

func (s *WebhookSink) Publish(a Alert) {
	if s == nil {
		return
	}
	select {
	case s.queue <- a:
	default:
		webhookDropped.Inc()
	}
}
