package judge

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/krodh/agy-gate/internal/policy"
)

type Decision struct {
	Allow  bool
	Reason string
}

func BuildRequest(call *policy.Call, transcript []string, notes string) string {
	var sb strings.Builder
	sb.WriteString("Please judge the following pending tool call against the user's request.\n\n")

	sb.WriteString("<user_messages>\n")
	for _, t := range transcript {
		sb.WriteString(escapeEndTags(t))
		sb.WriteString("\n\n")
	}
	sb.WriteString("</user_messages>\n\n")

	sb.WriteString("<pending_call>\n")
	sb.WriteString(fmt.Sprintf("Tool: %s\n", call.Tool))
	argsJSON := string(call.RawArgs)
	if len(argsJSON) > 4000 {
		argsJSON = argsJSON[:4000] + "... (truncated)"
	}
	sb.WriteString(fmt.Sprintf("Args: %s\n", escapeEndTags(argsJSON)))
	sb.WriteString(fmt.Sprintf("Cwd: %s\n", escapeEndTags(call.Cwd)))
	sb.WriteString(fmt.Sprintf("Workspace: %v\n", call.Workspace))
	sb.WriteString("</pending_call>\n\n")

	sb.WriteString("<gate_notes>\n")
	sb.WriteString(escapeEndTags(notes))
	sb.WriteString("\n</gate_notes>\n")

	return sb.String()
}

func escapeEndTags(s string) string {
	return strings.ReplaceAll(s, "</", "<\\/")
}

func ParseReply(reply string) (*Decision, error) {
	// Strip code fences
	reply = strings.TrimSpace(reply)
	if strings.HasPrefix(reply, "```json") {
		reply = strings.TrimPrefix(reply, "```json")
	} else if strings.HasPrefix(reply, "```") {
		reply = strings.TrimPrefix(reply, "```")
	}
	if strings.HasSuffix(reply, "```") {
		reply = strings.TrimSuffix(reply, "```")
	}

	// Find balanced {...}
	start := strings.Index(reply, "{")
	if start == -1 {
		return nil, fmt.Errorf("no JSON object found")
	}

	end := -1
	depth := 0
	for i := start; i < len(reply); i++ {
		if reply[i] == '{' {
			depth++
		} else if reply[i] == '}' {
			depth--
			if depth == 0 {
				end = i
				break
			}
		}
	}

	if end == -1 {
		return nil, fmt.Errorf("no balanced JSON object found")
	}

	jsonStr := reply[start : end+1]

	var res struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &res); err != nil {
		return nil, err
	}

	res.Decision = strings.ToLower(res.Decision)
	if res.Decision != "allow" && res.Decision != "deny" {
		return nil, fmt.Errorf("invalid decision: %s", res.Decision)
	}

	return &Decision{
		Allow:  res.Decision == "allow",
		Reason: res.Reason,
	}, nil
}
