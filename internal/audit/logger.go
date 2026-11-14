// Package audit appends security-sensitive events to a JSONL file.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger is a concurrency-safe JSONL audit writer. Callers must never place
// passwords, authorization codes, or token values in fields.
type Logger struct {
	mu  sync.Mutex
	f   *os.File
	now func() time.Time
}

// Open creates or appends to path with mode 0600, creating its parent
// directory with mode 0700. A nil logger is valid and drops events.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %q: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: secure %q: %w", path, err)
	}
	return &Logger{f: f, now: time.Now}, nil
}

// SetClock overrides the timestamp source (tests only).
func (l *Logger) SetClock(now func() time.Time) {
	if l == nil || now == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// Log writes one event. Fields are merged with ts and event; reserved keys are
// overwritten by the logger to prevent spoofing.
func (l *Logger) Log(event string, fields map[string]any) error {
	if l == nil {
		return nil
	}
	record := make(map[string]any, len(fields)+2)
	for k, v := range fields {
		record[k] = v
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	record["ts"] = l.now().UTC().Format(time.RFC3339Nano)
	record["event"] = event
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("audit: encode event %q: %w", event, err)
	}
	data = append(data, '\n')
	if _, err := l.f.Write(data); err != nil {
		return fmt.Errorf("audit: write event %q: %w", event, err)
	}
	return nil
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
