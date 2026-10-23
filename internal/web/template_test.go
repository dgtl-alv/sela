package web

import (
	"strings"
	"testing"
)

func TestServiceUploadBlockerExplainsBikeIssueValidation(t *testing.T) {
	body, err := assets.ReadFile("templates/service.html")
	if err != nil {
		t.Fatal(err)
	}
	want := "Validasi minimal satu Bike Issue dengan Suspect Masalah terisi di EMICA, lalu muat ulang halaman."
	if !strings.Contains(string(body), want) {
		t.Fatalf("service upload blocker missing %q", want)
	}
}

func TestServiceUploadOffersCameraAndGalleryInputs(t *testing.T) {
	body, err := assets.ReadFile("templates/service.html")
	if err != nil {
		t.Fatal(err)
	}
	markup := string(body)
	for _, want := range []string{
		`id="camera-photo" name="files" type="file" accept="image/jpeg,image/png,image/webp" capture="environment"`,
		`id="camera-video" name="files" type="file" accept="video/mp4,video/quicktime" capture="environment"`,
		`id="gallery-files" name="files" type="file" accept="image/jpeg,image/png,image/webp,video/mp4,video/quicktime" multiple`,
	} {
		if !strings.Contains(markup, want) {
			t.Fatalf("service upload markup missing %q", want)
		}
	}
	galleryStart := strings.Index(markup, `id="gallery-files"`)
	if galleryStart < 0 {
		t.Fatal("gallery input missing")
	}
	galleryEnd := strings.Index(markup[galleryStart:], ">")
	if galleryEnd < 0 {
		t.Fatal("gallery input malformed")
	}
	if strings.Contains(markup[galleryStart:galleryStart+galleryEnd], "capture=") {
		t.Fatal("gallery input must not force camera capture")
	}
}
