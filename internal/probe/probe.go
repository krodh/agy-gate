package probe

import (
	"strings"
)

// patterns are phrases that tool output has no reason to contain unless it is
// trying to steer the agent. Matching is case-insensitive. Shell idioms such as
// "| sh" are deliberately absent: install instructions in READMEs are full of
// them, and a probe that warns on ordinary output teaches the agent to ignore it.
var patterns = []string{
	"ignore previous instructions", "ignore all previous", "disregard the above", "disregard previous",
	"new instructions:", "your new task", // attempts to replace the task
	"you are now", "developer mode", // role or jailbreak framing
	"system prompt", "<system>", "[system]", // spoofed system messages
	"do not tell the user", "don't tell the user", "without asking the user", // concealment
	"--dangerously-skip-permissions", // asks for the gate to be bypassed
	"base64 -d |", "exfiltrate",      // obfuscated execution, data theft
}

// Scan reports the first pattern found in the first 64 KiB of text.
func Scan(text string) (string, bool) {
	if len(text) > 65536 {
		text = text[:65536]
	}
	textLower := strings.ToLower(text)
	for _, p := range patterns {
		if strings.Contains(textLower, p) {
			return p, true
		}
	}
	return "", false
}
