package judge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTranscript(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transcript.jsonl")

	// write some transcript
	content := `{"type":"USER_INPUT","source":"USER_EXPLICIT","content":"<USER_REQUEST>\nfirst request\n</USER_REQUEST>"}` + "\n"
	os.WriteFile(path, []byte(content), 0644)

	convID := "conv-1"

	reqs, err := ReadTranscript(path, convID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0] != "first request" {
		t.Fatalf("unexpected reqs: %v", reqs)
	}

	// add another request
	content += `{"type":"USER_INPUT","source":"USER_EXPLICIT","content":"<USER_REQUEST>\nsecond request\n</USER_REQUEST>"}` + "\n"
	os.WriteFile(path, []byte(content), 0644)

	reqs, err = ReadTranscript(path, convID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 || reqs[1] != "second request" {
		t.Fatalf("unexpected reqs: %v", reqs)
	}

	// tamper the first request
	tampered := strings.Replace(content, "first", "tampered", 1)
	os.WriteFile(path, []byte(tampered), 0644)

	_, err = ReadTranscript(path, convID)
	if err == nil {
		t.Fatal("expected error on tampered transcript")
	}

	// short transcript
	short := `{"type":"USER_INPUT","source":"USER_EXPLICIT","content":"<USER_REQUEST>\ntampered\n</USER_REQUEST>"}` + "\n"
	os.WriteFile(path, []byte(short), 0644)

	_, err = ReadTranscript(path, convID)
	if err == nil {
		t.Fatal("expected error on shortened transcript")
	}
}
