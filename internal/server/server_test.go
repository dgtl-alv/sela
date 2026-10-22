package server_test

import (
	"net/http"
	"testing"

	"github.com/dgtl-alv/sela/internal/server"
)

func TestNewConfiguresBoundedTimeouts(t *testing.T) {
	httpServer := server.New(":8080", http.NewServeMux())
	if httpServer.ReadHeaderTimeout <= 0 || httpServer.ReadTimeout <= 0 || httpServer.WriteTimeout <= 0 || httpServer.IdleTimeout <= 0 {
		t.Fatal("all server timeouts must be positive")
	}
	if httpServer.MaxHeaderBytes <= 0 {
		t.Fatal("MaxHeaderBytes must be bounded")
	}
}
