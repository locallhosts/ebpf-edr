package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config controls userspace detection policy and optional integrations.
// All settings are environment-driven so the agent remains dependency-free.
type Config struct {
	DisabledRules       map[string]bool
	AllowedComms        map[string]bool
	AllowedExecutables  map[string]bool
	NetworkDedupWindow  time.Duration
	WebhookURL          string
	WebhookToken        string
	ContainerContext    bool
}

func LoadConfig() Config {
	return Config{
		DisabledRules:      csvSet(os.Getenv("EDR_DISABLED_RULES")),
		AllowedComms:       csvSet(os.Getenv("EDR_ALLOW_COMMS")),
		AllowedExecutables: csvSet(os.Getenv("EDR_ALLOW_EXECUTABLES")),
		NetworkDedupWindow: durationEnv("EDR_NETWORK_DEDUP_WINDOW", 250*time.Millisecond),
		WebhookURL:         strings.TrimSpace(os.Getenv("EDR_WEBHOOK_URL")),
		WebhookToken:       os.Getenv("EDR_WEBHOOK_TOKEN"),
		ContainerContext:   boolEnv("EDR_CONTAINER_CONTEXT", true),
	}
}

func csvSet(raw string) map[string]bool {
	out := make(map[string]bool)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out[item] = true
		}
	}
	return out
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return fallback
	}
	return d
}

func boolEnv(name string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}
