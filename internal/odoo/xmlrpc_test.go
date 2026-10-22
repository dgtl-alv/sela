package odoo

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type rt func(*http.Request) (*http.Response, error)

func (f rt) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestXMLRoundTripEscapesAndParses(t *testing.T) {
	var body string
	c, _ := New(Config{URL: "https://odoo.test", DB: "d", Username: "u", APIKey: "secret"}, &http.Client{Transport: rt(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`<?xml version="1.0"?><methodResponse><params><param><value><int>7</int></value></param></params></methodResponse>`)), Header: http.Header{}}, nil
	})})
	v, e := c.call(context.Background(), "common", "x<&", []Value{"a<&"})
	if e != nil || asInt(v) != 7 {
		t.Fatalf("v=%v err=%v", v, e)
	}
	if !strings.Contains(body, "x&lt;&amp;") || !strings.Contains(body, "a&lt;&amp;") {
		t.Fatalf("unsafe XML %s", body)
	}
}
func TestCredentialsFromContextReturnsOnlyCompleteOverride(t *testing.T) {
	ctx := WithCredentials(context.Background(), Credentials{Username: "user@example.test", APIKey: "user-secret"})
	credentials, ok := CredentialsFromContext(ctx)
	if !ok || credentials.Username != "user@example.test" || credentials.APIKey != "user-secret" {
		t.Fatalf("credentials=%+v ok=%v", credentials, ok)
	}
	if _, ok = CredentialsFromContext(WithCredentials(context.Background(), Credentials{Username: "user@example.test"})); ok {
		t.Fatal("incomplete credentials accepted")
	}
}

func TestPerUserCredentialsOverrideServiceCredential(t *testing.T) {
	var body string
	c, _ := New(Config{URL: "https://odoo.test", DB: "d", Username: "service", APIKey: "service-key"}, &http.Client{Transport: rt(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`<?xml version="1.0"?><methodResponse><params><param><value><int>7</int></value></param></params></methodResponse>`)), Header: http.Header{}}, nil
	})})
	ctx := WithCredentials(context.Background(), Credentials{Username: "person@example.test", APIKey: "personal-key"})
	if err := c.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "person@example.test") || !strings.Contains(body, "personal-key") || strings.Contains(body, "service-key") {
		t.Fatalf("wrong authentication body: %s", body)
	}
}

func TestSearchResolvesBookingNumberBeforeDiagnose(t *testing.T) {
	var bodies []string
	c, err := New(Config{URL: "https://odoo.test", DB: "d"}, &http.Client{Transport: rt(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		bodies = append(bodies, body)
		response := `<int>7</int>`
		switch {
		case strings.Contains(body, "<string>x.service.booking</string>") && strings.Contains(body, "<string>search_read</string>"):
			response = `<array><data><value><struct><member><name>id</name><value><int>321</int></value></member></struct></value></data></array>`
		case strings.Contains(body, "<string>fleet.diagnose</string>"):
			response = `<array><data><value><struct><member><name>id</name><value><int>654</int></value></member><member><name>name</name><value><string>DG/1</string></value></member><member><name>x_service_booking_id</name><value><array><data><value><int>321</int></value><value><string>SB/D0304/26/08102</string></value></data></array></value></member><member><name>fleet_link_ids</name><value><array><data></data></array></value></member></struct></value></data></array>`
		case strings.Contains(body, "<string>x.service.booking</string>") && strings.Contains(body, "<string>read</string>"):
			response = `<array><data><value><struct><member><name>id</name><value><int>321</int></value></member></struct></value></data></array>`
		}
		xml := `<?xml version="1.0"?><methodResponse><params><param><value>` + response + `</value></param></params></methodResponse>`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(xml)), Header: http.Header{}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithCredentials(context.Background(), Credentials{"user@example.test", "test-key"})
	items, err := c.Search(ctx, "SB/D0304/26/08102", 20)
	if err != nil || len(items) != 1 || items[0].ID != 654 || items[0].BookingID != 321 {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	joined := strings.Join(bodies, "\n")
	if !strings.Contains(joined, "SB/D0304/26/08102") || !strings.Contains(joined, "<string>x_name</string>") || !strings.Contains(joined, "<string>in</string>") || !strings.Contains(joined, "<int>321</int>") {
		t.Fatalf("booking resolution missing: %s", joined)
	}
}

func TestRejectsOversizedResponse(t *testing.T) {
	c, _ := New(Config{URL: "https://odoo.test"}, &http.Client{Transport: rt(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(make([]byte, maxResponse+2))), Header: http.Header{}}, nil
	})})
	if _, e := c.call(context.Background(), "common", "x", nil); e == nil {
		t.Fatal("expected error")
	}
}
func TestSafeSharePointLinks(t *testing.T) {
	c, _ := New(Config{URL: "https://odoo.test", AllowedSharePointHosts: []string{"tenant.sharepoint.com"}}, nil)
	if !c.safeLink("https://tenant.sharepoint.com/a") || c.safeLink("https://tenant.sharepoint.com.evil/a") || c.safeLink("http://tenant.sharepoint.com/a") {
		t.Fatal("link validation failed")
	}
}

func TestEvidenceMatchesOdooNormalizedOperationID(t *testing.T) {
	operationID := "9f211f86-ed0c-4fce-9819-27bf78294fc3"
	liveName := "SD_D0306_26_04148_9f211f86_ed0c_4fce_9819_27bf78294fc3_evidence.png"
	if !evidenceMatchesOperation(liveName, operationID) {
		t.Fatal("normalized operation ID was not matched")
	}
	if evidenceMatchesOperation("SD_D0306_26_04148_unrelated_evidence.png", operationID) {
		t.Fatal("unrelated evidence was matched")
	}
	if evidenceMatchesOperation(liveName, "") {
		t.Fatal("empty operation ID was matched")
	}
}
