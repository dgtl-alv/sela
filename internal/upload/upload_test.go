package upload

import (
	"bytes"
	"mime/multipart"
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
