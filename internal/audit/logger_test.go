package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"wsbridge/internal/audit"
)

func TestLoggerWritesJSONLinesAndMergesFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.jsonl")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()
	fixed := time.Date(2026, 11, 13, 10, 15, 30, 123e6, time.UTC)
	l.SetClock(func() time.Time { return fixed })
	if err := l.Log("tool_call", map[string]any{
		"grant_id": "wsb_grt_x", "tool": "read_file", "status": "ok",
		"event": "spoofed", "ts": "spoofed",
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := l.Log("token_issue", nil); err != nil {
		t.Fatalf("Log nil fields: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var records []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var m map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
			t.Fatalf("line is not JSON: %q: %v", scanner.Text(), err)
		}
		records = append(records, m)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if records[0]["event"] != "tool_call" || records[0]["tool"] != "read_file" {
		t.Errorf("record[0] = %v", records[0])
	}
	if got := records[0]["ts"]; got != "2026-11-13T10:15:30.123Z" {
		t.Errorf("ts = %v", got)
	}
	if records[1]["event"] != "token_issue" {
		t.Errorf("record[1] = %v", records[1])
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("mode = %o, want 600", got)
		}
	}
}

func TestLoggerConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := l.Log("tool_call", map[string]any{"n": i}); err != nil {
				t.Errorf("Log: %v", err)
			}
		}(i)
	}
	wg.Wait()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 50 {
		t.Errorf("lines = %d, want 50", lines)
	}
}

func TestNilLoggerIsNoop(t *testing.T) {
	var l *audit.Logger
	if err := l.Log("x", nil); err != nil {
		t.Errorf("nil Log: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("nil Close: %v", err)
	}
}
