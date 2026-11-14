package ws

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCappedWriterBoundsMemory(t *testing.T) {
	const limit = 1024
	var w cappedWriter
	w.limit = limit
	chunk := bytes.Repeat([]byte("a"), 300)
	for i := 0; i < 100; i++ {
		n, err := w.Write(chunk)
		if err != nil || n != len(chunk) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if got := len(w.String()); got != limit {
		t.Errorf("buffered = %d, want %d", got, limit)
	}
	if !w.truncated {
		t.Error("truncated = false, want true")
	}
}

func TestCappedWriterKeepsSmallOutput(t *testing.T) {
	var w cappedWriter
	w.limit = 1024
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := w.String(); got != "hello" || w.truncated {
		t.Errorf("buf = %q, truncated = %v", got, w.truncated)
	}
}

func TestTruncateCheckOutputUTF8(t *testing.T) {
	// A multi-byte rune straddles the 64KB cut; the truncation must back up
	// to a rune boundary and append the 64KB marker.
	s := strings.Repeat("a", MaxCheckOutput-1) + "汉"
	got := truncateCheckOutput(s)
	if !strings.Contains(got, "[output truncated at 64KB]") {
		t.Errorf("missing truncation marker: %q", got[len(got)-80:])
	}
	if !strings.HasPrefix(s, strings.TrimSuffix(got, "\n[output truncated at 64KB]\n")) {
		t.Error("truncated output is not a prefix of the original")
	}
	cut := strings.TrimSuffix(got, "\n[output truncated at 64KB]\n")
	if len(cut) > MaxCheckOutput {
		t.Errorf("kept %d bytes, want <= %d", len(cut), MaxCheckOutput)
	}
	if !utf8.ValidString(got) {
		t.Error("truncated output is not valid UTF-8")
	}
}
