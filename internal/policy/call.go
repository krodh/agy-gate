package policy

import (
	"encoding/json"
)

// Call represents a decoded tool call payload from the hook.
type Call struct {
	Tool           string
	StepIdx        int
	ConversationID string
	Workspace      []string
	TranscriptPath string
	ModelName      string

	// Pre-decoded args for all known tools
	CommandLine     string
	Cwd             string
	TargetFile      string
	CodeContent     string
	AbsolutePath    string
	DirectoryPath   string
	SearchPath      string
	SearchDirectory string
	Url             string

	RawArgs []byte // Kept for cache key generation
}

type payload struct {
	ToolCall struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"args"`
	} `json:"toolCall"`
	StepIdx        int      `json:"stepIdx"`
	ConversationID string   `json:"conversationId"`
	WorkspacePaths []string `json:"workspacePaths"`
	TranscriptPath string   `json:"transcriptPath"`
	ModelName      string   `json:"modelName"`
}

type knownArgs struct {
	CommandLine     string `json:"CommandLine"`
	Cwd             string `json:"Cwd"`
	TargetFile      string `json:"TargetFile"`
	CodeContent     string `json:"CodeContent"`
	AbsolutePath    string `json:"AbsolutePath"`
	DirectoryPath   string `json:"DirectoryPath"`
	SearchPath      string `json:"SearchPath"`
	SearchDirectory string `json:"SearchDirectory"`
	Url             string `json:"Url"`
}

// DecodeCall parses the hook payload. The hook provides the run's headerWorkspace
// which overrides payload.WorkspacePaths if non-empty.
func DecodeCall(data []byte, headerWorkspace []string) (*Call, error) {
	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	var args knownArgs
	if len(p.ToolCall.Args) > 0 {
		if err := json.Unmarshal(p.ToolCall.Args, &args); err != nil {
			return nil, err
		}
	}

	ws := p.WorkspacePaths
	if len(headerWorkspace) > 0 {
		ws = headerWorkspace
	}

	return &Call{
		Tool:            p.ToolCall.Name,
		StepIdx:         p.StepIdx,
		ConversationID:  p.ConversationID,
		Workspace:       ws,
		TranscriptPath:  p.TranscriptPath,
		ModelName:       p.ModelName,
		CommandLine:     args.CommandLine,
		Cwd:             args.Cwd,
		TargetFile:      args.TargetFile,
		CodeContent:     args.CodeContent,
		AbsolutePath:    args.AbsolutePath,
		DirectoryPath:   args.DirectoryPath,
		SearchPath:      args.SearchPath,
		SearchDirectory: args.SearchDirectory,
		Url:             args.Url,
		RawArgs:         p.ToolCall.Args,
	}, nil
}
