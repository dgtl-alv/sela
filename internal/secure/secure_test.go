package secure

import (
	"errors"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestRandomAndUUIDFailClosedWhenEntropyFails(t *testing.T) {
	old := randomReader
	randomReader = failingReader{}
	t.Cleanup(func() { randomReader = old })
	if value, err := Random(32); err == nil || value != "" {
		t.Fatalf("Random value=%q err=%v", value, err)
	}
	if value, err := UUID(); err == nil || value != "" {
		t.Fatalf("UUID value=%q err=%v", value, err)
	}
}
