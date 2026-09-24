package probe

import (
	"bufio"
	"encoding/json"
	"os"
)

type transcriptEntry struct {
	StepIndex int    `json:"step_index"`
	Type      string `json:"type"`
	Content   string `json:"content"`
}

// ScanTranscript reads the transcript, scans GENERIC entries with stepIndex > hwm.
// Returns the matched pattern, the stepIndex where it matched, and true if matched.
// Returns the new high-water mark (the maximum stepIndex seen).
func ScanTranscript(path string, hwm int) (pattern string, matchStep int, newHwm int, matched bool) {
	newHwm = hwm
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Some tool outputs might be large, use a larger buffer if needed,
	// but default scanner is usually fine for JSONL unless lines are huge.
	// Actually transcript lines can be huge. We should increase max token size.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024) // 10MB max line

	for scanner.Scan() {
		var entry transcriptEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.StepIndex > newHwm {
			newHwm = entry.StepIndex
		}
		if entry.Type == "GENERIC" && entry.StepIndex > hwm && !matched {
			pat, found := Scan(entry.Content)
			if found {
				pattern = pat
				matchStep = entry.StepIndex
				matched = true
				// We continue scanning to update newHwm to the end of the file
			}
		}
	}
	return
}
