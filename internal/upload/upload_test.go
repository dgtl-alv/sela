package upload

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func part(t *testing.T, name string, b []byte) *multipart.Part {
	t.Helper()
	var out bytes.Buffer
	w := multipart.NewWriter(&out)
	p, e := w.CreateFormFile("files", name)
	if e != nil {
		t.Fatal(e)
	}
	p.Write(b)
	w.Close()
	r := multipart.NewReader(&out, w.Boundary())
	x, e := r.NextPart()
	if e != nil {
		t.Fatal(e)
	}
	return x
}
func TestRemoteScannerAuthenticatesReadyAndScan(t *testing.T) {
	const token = "scanner-test-token"
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("%s Authorization=%q", r.URL.Path, got)
		}
		paths = append(paths, r.URL.Path)
		w.Header().Set("X-Scanner-Engine", "shared-scanner")
		w.Header().Set("X-Scanner-Version", "1")
		if r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("X-Scan-Result", "clean")
	}))
	defer server.Close()

	file := filepath.Join(t.TempDir(), "upload")
	if err := os.WriteFile(file, []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	scanner := RemoteScanner{URL: server.URL, Token: token, Client: server.Client()}
	if err := scanner.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Scan(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "/readyz" || paths[1] != "/scan" {
		t.Fatalf("paths=%v", paths)
	}
}

func TestRemoteScannerRejectsRedirectWithoutForwardingToken(t *testing.T) {
	const token = "scanner-test-token"
	tokenForwarded := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenForwarded = r.Header.Get("Authorization") != ""
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	scanner := RemoteScanner{URL: server.URL, Token: token, Client: server.Client()}
	if err := scanner.Ready(context.Background()); err == nil {
		t.Fatal("scanner redirect accepted")
	}
	if tokenForwarded {
		t.Fatal("scanner token forwarded across redirect")
	}
}

func TestRemoteScannerAcceptsReadinessContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Scanner-Engine", "shared-scanner")
		w.Header().Set("X-Scanner-Version", "1")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := RemoteScanner{URL: server.URL, Token: "token", Client: server.Client()}
	if err := scanner.Ready(context.Background()); err != nil {
		t.Fatalf("valid readiness response rejected: %v", err)
	}
}

func TestRemoteScannerFailsClosedOnReadinessOutage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	scanner := RemoteScanner{URL: server.URL, Token: "token", Client: server.Client()}
	if err := scanner.Ready(context.Background()); err == nil {
		t.Fatal("readiness outage accepted")
	}
}

func TestRemoteScannerRejectsMalformedReadinessResponses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		headers map[string]string
	}{
		{name: "legacy no content", status: http.StatusNoContent, headers: map[string]string{"X-Scanner-Engine": "engine", "X-Scanner-Version": "1"}},
		{name: "missing engine", status: http.StatusOK, headers: map[string]string{"X-Scanner-Version": "1"}},
		{name: "missing version", status: http.StatusOK, headers: map[string]string{"X-Scanner-Engine": "engine"}},
		{name: "oversized engine", status: http.StatusOK, headers: map[string]string{"X-Scanner-Engine": string(bytes.Repeat([]byte("x"), 81)), "X-Scanner-Version": "1"}},
		{name: "oversized version", status: http.StatusOK, headers: map[string]string{"X-Scanner-Engine": "engine", "X-Scanner-Version": string(bytes.Repeat([]byte("x"), 81))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for name, value := range tc.headers {
					w.Header().Set(name, value)
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()

			scanner := RemoteScanner{URL: server.URL, Token: "token", Client: server.Client()}
			if err := scanner.Ready(context.Background()); err == nil {
				t.Fatal("malformed readiness response accepted")
			}
		})
	}
}

func TestRemoteScannerRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		headers map[string]string
		body    []byte
	}{
		{name: "wrong status", status: http.StatusNoContent, headers: map[string]string{"X-Scan-Result": "clean", "X-Scanner-Engine": "engine", "X-Scanner-Version": "1"}},
		{name: "missing result", status: http.StatusOK, headers: map[string]string{"X-Scanner-Engine": "engine", "X-Scanner-Version": "1"}},
		{name: "unknown result", status: http.StatusOK, headers: map[string]string{"X-Scan-Result": "unknown", "X-Scanner-Engine": "engine", "X-Scanner-Version": "1"}},
		{name: "missing engine", status: http.StatusOK, headers: map[string]string{"X-Scan-Result": "clean", "X-Scanner-Version": "1"}},
		{name: "missing version", status: http.StatusOK, headers: map[string]string{"X-Scan-Result": "clean", "X-Scanner-Engine": "engine"}},
		{name: "oversized engine", status: http.StatusOK, headers: map[string]string{"X-Scan-Result": "clean", "X-Scanner-Engine": string(bytes.Repeat([]byte("x"), 81)), "X-Scanner-Version": "1"}},
		{name: "oversized response", status: http.StatusOK, headers: map[string]string{"X-Scan-Result": "clean", "X-Scanner-Engine": "engine", "X-Scanner-Version": "1"}, body: bytes.Repeat([]byte("x"), 1025)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for name, value := range tc.headers {
					w.Header().Set(name, value)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()

			file := filepath.Join(t.TempDir(), "upload")
			if err := os.WriteFile(file, []byte("content"), 0600); err != nil {
				t.Fatal(err)
			}
			scanner := RemoteScanner{URL: server.URL, Token: "token", Client: server.Client()}
			if result, err := scanner.Scan(context.Background(), file); err == nil {
				t.Fatalf("malformed response accepted: %+v", result)
			}
		})
	}
}

func TestRemoteScannerReportsInfected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Scan-Result", "infected")
		w.Header().Set("X-Scanner-Engine", "engine")
		w.Header().Set("X-Scanner-Version", "1")
	}))
	defer server.Close()

	file := filepath.Join(t.TempDir(), "upload")
	if err := os.WriteFile(file, []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := (RemoteScanner{URL: server.URL, Token: "token", Client: server.Client()}).Scan(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	if result.Clean {
		t.Fatal("infected response reported clean")
	}
}

func TestRemoteScannerRejectsOversizedFileBeforeRequest(t *testing.T) {
	requested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requested = true
		w.Header().Set("X-Scan-Result", "clean")
		w.Header().Set("X-Scanner-Engine", "engine")
		w.Header().Set("X-Scanner-Version", "1")
	}))
	defer server.Close()

	file := filepath.Join(t.TempDir(), "upload")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(MaxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = (RemoteScanner{URL: server.URL, Token: "token", Client: server.Client()}).Scan(context.Background(), file); err == nil {
		t.Fatal("oversized file accepted")
	}
	if requested {
		t.Fatal("oversized file sent to scanner")
	}
}

func TestIngestWebPPrivateQuarantine(t *testing.T) {
	root := filepath.Join(t.TempDir(), "q")
	f, e := Ingest(root, part(t, "photo.webp", MagicFixture("image/webp")))
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(f.Path)
	info, _ := os.Stat(root)
	if info.Mode().Perm() != 0700 {
		t.Fatalf("dir mode %o", info.Mode().Perm())
	}
	info, _ = os.Stat(f.Path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("file mode %o", info.Mode().Perm())
	}
	if f.MediaType != "image/webp" || f.Size == 0 || len(f.SHA256) != 32 {
		t.Fatalf("bad metadata %+v", f)
	}
}
func TestRejectsMismatchAndTraversalName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "q")
	if _, e := Ingest(root, part(t, "x.jpg", MagicFixture("video/mp4"))); e == nil {
		t.Fatal("mismatch accepted")
	}
	f, e := Ingest(root, part(t, "../ok.webp", MagicFixture("image/webp")))
	if e != nil {
		t.Fatal(e)
	}
	if f.DisplayName != "ok.webp" {
		t.Fatalf("name=%q", f.DisplayName)
	}
}
