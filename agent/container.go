package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// containerContext returns a best-effort cgroup/container identifier.
// It never makes container identity a prerequisite for processing an event.
func containerContext(pid uint32) string {
	f, err := os.Open(filepath.Join("/proc", itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := strings.TrimSuffix(parts[2], "/")
		if path == "" || path == "/" {
			continue
		}
		segments := strings.Split(path, "/")
		for i := len(segments) - 1; i >= 0; i-- {
			seg := segments[i]
			if seg == "" {
				continue
			}
			if id := extractContainerID(seg); id != "" {
				return id
			}
		}
	}
	return ""
}

func extractContainerID(segment string) string {
	for _, prefix := range []string{"docker-", "crio-", "cri-containerd-"} {
		if strings.HasPrefix(segment, prefix) {
			v := strings.TrimSuffix(strings.TrimPrefix(segment, prefix), ".scope")
			if isHexID(v) {
				return v
			}
		}
	}
	v := strings.TrimSuffix(segment, ".scope")
	if isHexID(v) {
		return v
	}
	return ""
}

func isHexID(s string) bool {
	if len(s) < 12 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
