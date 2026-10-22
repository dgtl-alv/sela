package upload

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dgtl-alv/sela/internal/secure"
)

const MaxFileBytes int64 = 25 << 20
const MaxFiles = 4
const MaxRequestBytes int64 = (MaxFileBytes * MaxFiles) + (1 << 20)

type File struct {
	ID, Path, StorageKey, DisplayName, MediaType string
	Size                                         int64
	SHA256                                       []byte
}
type ScanResult struct {
	Clean           bool
	Engine, Version string
}
type Scanner interface {
	Ready(context.Context) error
	Scan(context.Context, string) (ScanResult, error)
}
type DevelopmentScanner struct{}

func (DevelopmentScanner) Ready(context.Context) error { return nil }
func (DevelopmentScanner) Scan(context.Context, string) (ScanResult, error) {
	return ScanResult{Clean: true, Engine: "development-validator", Version: "1"}, nil
}

type RemoteScanner struct {
	URL, Token string
	Client     *http.Client
}

func (s RemoteScanner) authorize(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+s.Token)
}

func (s RemoteScanner) do(req *http.Request) (*http.Response, error) {
	client := *s.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client.Do(req)
}

func (s RemoteScanner) Ready(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+"/readyz", nil)
	s.authorize(req)
	res, e := s.do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("scanner unavailable")
	}
	if _, ok := strictHeader(res.Header, "X-Scanner-Engine", 80); !ok {
		return errors.New("scanner returned invalid engine")
	}
	if _, ok := strictHeader(res.Header, "X-Scanner-Version", 80); !ok {
		return errors.New("scanner returned invalid version")
	}
	return nil
}
func (s RemoteScanner) Scan(ctx context.Context, path string) (ScanResult, error) {
	f, e := os.Open(path)
	if e != nil {
		return ScanResult{}, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return ScanResult{}, e
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxFileBytes {
		return ScanResult{}, errors.New("scanner input outside allowed range")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, s.URL+"/scan", f)
	if e != nil {
		return ScanResult{}, e
	}
	req.ContentLength = info.Size()
	req.Header.Set("Content-Type", "application/octet-stream")
	s.authorize(req)
	res, e := s.do(req)
	if e != nil {
		return ScanResult{}, e
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ScanResult{}, errors.New("scanner rejected request")
	}
	body, e := io.ReadAll(io.LimitReader(res.Body, 1025))
	if e != nil || len(body) > 1024 {
		return ScanResult{}, errors.New("scanner response exceeds limit")
	}
	result, ok := strictHeader(res.Header, "X-Scan-Result", 8)
	if !ok || (result != "clean" && result != "infected") {
		return ScanResult{}, errors.New("scanner returned invalid result")
	}
	engine, ok := strictHeader(res.Header, "X-Scanner-Engine", 80)
	if !ok {
		return ScanResult{}, errors.New("scanner returned invalid engine")
	}
	version, ok := strictHeader(res.Header, "X-Scanner-Version", 80)
	if !ok {
		return ScanResult{}, errors.New("scanner returned invalid version")
	}
	return ScanResult{Clean: result == "clean", Engine: engine, Version: version}, nil
}

func strictHeader(header http.Header, name string, limit int) (string, bool) {
	values := header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != "" && len(returnValue) <= limit && strings.TrimSpace(returnValue) == returnValue
}

func Ingest(root string, part *multipart.Part) (File, error) {
	name := sanitize(part.FileName())
	ext := strings.ToLower(filepath.Ext(name))
	if name == "" {
		return File{}, errors.New("filename required")
	}
	id, e := secure.UUID()
	if e != nil {
		return File{}, e
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return File{}, e
	}
	if e = os.Chmod(root, 0700); e != nil {
		return File{}, e
	}
	path := filepath.Join(root, id+".quarantine")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return File{}, e
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	h := sha256.New()
	br := bufio.NewReader(io.LimitReader(part, MaxFileBytes+1))
	prefix, e := br.Peek(512)
	if e != nil && e != io.EOF && e != bufio.ErrBufferFull {
		return File{}, e
	}
	detected := http.DetectContentType(prefix)
	allowed := map[string][]string{"image/jpeg": {".jpg", ".jpeg"}, "image/png": {".png"}, "image/webp": {".webp"}, "video/mp4": {".mp4"}, "video/quicktime": {".mov"}}
	if !contains(allowed[detected], ext) {
		return File{}, errors.New("file type and extension do not match allowlist")
	}
	n, e := io.Copy(io.MultiWriter(f, h), br)
	if e != nil {
		return File{}, e
	}
	if n == 0 || n > MaxFileBytes {
		return File{}, errors.New("file size outside allowed range")
	}
	if e = f.Sync(); e != nil {
		return File{}, e
	}
	if e = f.Close(); e != nil {
		return File{}, e
	}
	if e = validateStructure(path, detected); e != nil {
		return File{}, e
	}
	ok = true
	return File{ID: id, Path: path, StorageKey: id + ".quarantine", DisplayName: name, MediaType: detected, Size: n, SHA256: h.Sum(nil)}, nil
}
func validateStructure(path, typ string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	if strings.HasPrefix(typ, "image/") && typ != "image/webp" {
		cfg, _, e := image.DecodeConfig(io.LimitReader(f, MaxFileBytes))
		if e != nil {
			return errors.New("malformed image")
		}
		if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > 40_000_000 {
			return errors.New("image dimensions exceed limit")
		}
		return nil
	}
	b := make([]byte, 64)
	n, _ := io.ReadFull(f, b)
	b = b[:n]
	if typ == "image/webp" {
		if len(b) < 12 || string(b[:4]) != "RIFF" || string(b[8:12]) != "WEBP" {
			return errors.New("malformed WebP")
		}
		return nil
	}
	if len(b) < 12 {
		return errors.New("malformed video")
	}
	size := int(binary.BigEndian.Uint32(b[:4]))
	if size < 8 || string(b[4:8]) != "ftyp" {
		return errors.New("malformed ISO media")
	}
	brand := string(b[8:12])
	if typ == "video/quicktime" && brand != "qt  " {
		return errors.New("QuickTime structure mismatch")
	}
	if typ == "video/mp4" && brand == "qt  " {
		return errors.New("MP4 structure mismatch")
	}
	return nil
}
func sanitize(s string) string {
	s = filepath.Base(strings.TrimSpace(s))
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r == '/' || r == '\\' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}
func contains(a []string, x string) bool {
	for _, v := range a {
		if v == x {
			return true
		}
	}
	return false
}
func MagicFixture(typ string) []byte {
	switch typ {
	case "image/webp":
		return append([]byte("RIFF\x14\x00\x00\x00WEBPVP8 \x08\x00\x00\x00"), bytes.Repeat([]byte{0}, 8)...)
	case "video/mp4":
		return []byte("\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isomiso2")
	default:
		return []byte(fmt.Sprint(typ))
	}
}
