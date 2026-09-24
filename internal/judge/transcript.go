package judge

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
)

type transcriptEntry struct {
	Type    string `json:"type"`
	Source  string `json:"source"`
	Content string `json:"content"`
}

type transcriptCache struct {
	mu     sync.Mutex
	pinned map[string][]string
}

var cache = transcriptCache{
	pinned: make(map[string][]string),
}

// ReadTranscript reads the transcript, extracts user requests, applies pinning,
// and returns the last 8 requests, truncated to 1500 chars each, up to 6000 chars total.
func ReadTranscript(path string, convID string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var requests []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry transcriptEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Type == "USER_INPUT" && entry.Source == "USER_EXPLICIT" {
			req := extractUserRequest(entry.Content)
			if req != "" {
				requests = append(requests, req)
			}
		}
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	pinned, ok := cache.pinned[convID]
	if !ok {
		// First time seeing this conversation, pin what we have
		pinned = make([]string, len(requests))
		copy(pinned, requests)
		cache.pinned[convID] = pinned
	} else {
		// Check prefix
		if len(requests) < len(pinned) {
			return nil, errors.New("transcript tampered: shorter than pinned")
		}
		for i, p := range pinned {
			if requests[i] != p {
				return nil, errors.New("transcript tampered: prefix changed")
			}
		}
		// Update pinned to include new requests
		pinned = make([]string, len(requests))
		copy(pinned, requests)
		cache.pinned[convID] = pinned
	}

	// Last 8 requests
	start := 0
	if len(requests) > 8 {
		start = len(requests) - 8
	}
	requests = requests[start:]

	// Truncate to 1500 chars each, and 6000 chars total
	var result []string
	total := 0
	for i := len(requests) - 1; i >= 0; i-- {
		req := requests[i]
		if len(req) > 1500 {
			req = req[:1500] + "..."
		}
		if total+len(req) > 6000 && len(result) > 0 {
			break
		}
		total += len(req)
		// insert at beginning
		result = append([]string{req}, result...)
	}

	return result, nil
}

func extractUserRequest(content string) string {
	start := strings.Index(content, "<USER_REQUEST>")
	if start == -1 {
		return ""
	}
	start += len("<USER_REQUEST>")
	end := strings.Index(content[start:], "</USER_REQUEST>")
	if end == -1 {
		return content[start:] // or return ""? The arch says it's inside the tags.
	}
	return strings.TrimSpace(content[start : start+end])
}
