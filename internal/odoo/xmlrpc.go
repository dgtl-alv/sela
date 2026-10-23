package odoo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxResponse = 4 << 20

type Value any
type Credentials struct{ Username, APIKey string }
type credentialKey struct{}

func WithCredentials(ctx context.Context, credentials Credentials) context.Context {
	return context.WithValue(ctx, credentialKey{}, credentials)
}
func CredentialsFromContext(ctx context.Context) (Credentials, bool) {
	credentials, ok := ctx.Value(credentialKey{}).(Credentials)
	return credentials, ok && credentials.Username != "" && credentials.APIKey != ""
}
func credentialsFromContext(ctx context.Context, fallback Credentials) Credentials {
	if credentials, ok := CredentialsFromContext(ctx); ok {
		return credentials
	}
	return fallback
}

type Config struct {
	URL, DB, Username, APIKey string
	Production                bool
	AllowedSharePointHosts    []string
}
type Client struct {
	cfg  Config
	http *http.Client
	mu   sync.Mutex
	uid  int
}
type Service struct {
	ID                  int64  `json:"id"`
	Name                string `json:"name"`
	Customer            string `json:"customer,omitempty"`
	VIN                 string `json:"vin,omitempty"`
	Location            string `json:"location,omitempty"`
	State               string `json:"state,omitempty"`
	EvidenceCount       int    `json:"evidence_count"`
	SuspectMasalahReady bool   `json:"suspect_masalah_ready"`
	BookingID           int64  `json:"-"`
	bikeIssueIDs        []int
}
type Evidence struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

func New(cfg Config, client *http.Client) (*Client, error) {
	u, e := url.Parse(cfg.URL)
	if e != nil || u.Host == "" {
		return nil, errors.New("invalid Odoo URL")
	}
	if cfg.Production && u.Scheme != "https" {
		return nil, errors.New("Odoo requires HTTPS")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{cfg: cfg, http: client}, nil
}
func (c *Client) Ready(ctx context.Context) error { _, e := c.authenticate(ctx, true); return e }
func (c *Client) Search(ctx context.Context, q string, limit int) ([]Service, error) {
	q = strings.TrimSpace(q)
	if len(q) < 3 || len(q) > 80 {
		return nil, errors.New("query must contain 3-80 characters")
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	bookingIDs, e := c.searchBookingIDs(ctx, q, limit)
	if e != nil {
		return nil, e
	}
	domain := []Value{[]Value{"name", "ilike", q}}
	if len(bookingIDs) > 0 {
		domain = []Value{"|", []Value{"name", "ilike", q}, []Value{"x_service_booking_id", "in", bookingIDs}}
	}
	v, e := c.execute(ctx, "fleet.diagnose", "search_read", []Value{domain}, map[string]Value{"fields": []Value{"id", "name", "x_service_booking_id", "contact_name", "x_vin_number", "fleet_link_ids", "fleet_suspect_masalah", "x_service_tag_his_ids"}, "limit": limit, "order": "id desc"})
	if e != nil {
		return nil, e
	}
	items := services(v)
	if e := c.addBikeIssueDetails(ctx, items); e != nil {
		return nil, e
	}
	if e := c.addBookingDetails(ctx, items); e != nil {
		return nil, e
	}
	return items, nil
}
func (c *Client) searchBookingIDs(ctx context.Context, q string, limit int) ([]Value, error) {
	v, err := c.execute(ctx, "x.service.booking", "search_read", []Value{[]Value{[]Value{"x_name", "ilike", q}}}, map[string]Value{"fields": []Value{"id"}, "limit": limit, "order": "id desc"})
	if err != nil {
		return nil, err
	}
	ids := make([]Value, 0, len(asArray(v)))
	for _, raw := range asArray(v) {
		row, _ := raw.(map[string]Value)
		if id := asInt(row["id"]); id > 0 {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (c *Client) Read(ctx context.Context, id int64) (*Service, error) {
	if id <= 0 {
		return nil, errors.New("invalid diagnose ID")
	}
	v, e := c.execute(ctx, "fleet.diagnose", "read", []Value{[]Value{id}}, map[string]Value{"fields": []Value{"id", "name", "x_service_booking_id", "contact_name", "x_vin_number", "fleet_link_ids", "fleet_suspect_masalah", "x_service_tag_his_ids"}})
	if e != nil {
		return nil, e
	}
	s := services(v)
	if len(s) != 1 {
		return nil, nil
	}
	if e := c.addBikeIssueDetails(ctx, s); e != nil {
		return nil, e
	}
	if e := c.addBookingDetails(ctx, s); e != nil {
		return nil, e
	}
	return &s[0], nil
}
func (c *Client) addBikeIssueDetails(ctx context.Context, items []Service) error {
	ids := make([]Value, 0)
	for _, item := range items {
		for _, id := range item.bikeIssueIDs {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		for i := range items {
			items[i].SuspectMasalahReady = false
		}
		return nil
	}
	v, err := c.execute(ctx, "x.service.tag.his", "read", []Value{ids}, map[string]Value{"fields": []Value{"fleet_diagnose_id", "validate_status", "x_suspect_list_ids"}})
	if err != nil {
		return err
	}
	readyByDiagnose := map[int]bool{}
	for _, raw := range asArray(v) {
		row, _ := raw.(map[string]Value)
		if asString(row["validate_status"]) == "valid" && len(asArray(row["x_suspect_list_ids"])) > 0 {
			readyByDiagnose[manyID(row["fleet_diagnose_id"])] = true
		}
	}
	for i := range items {
		items[i].SuspectMasalahReady = readyByDiagnose[int(items[i].ID)]
	}
	return nil
}

func (c *Client) addBookingDetails(ctx context.Context, items []Service) error {
	ids := []Value{}
	for _, item := range items {
		if item.BookingID > 0 {
			ids = append(ids, item.BookingID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	v, err := c.execute(ctx, "x.service.booking", "read", []Value{ids}, map[string]Value{"fields": []Value{"x_service_loc", "x_state"}})
	if err != nil {
		return err
	}
	byID := map[int]map[string]Value{}
	for _, raw := range asArray(v) {
		m, _ := raw.(map[string]Value)
		byID[asInt(m["id"])] = m
	}
	for i := range items {
		m := byID[int(items[i].BookingID)]
		items[i].Location = many(m["x_service_loc"])
		items[i].State = stateLabel(asString(m["x_state"]))
	}
	return nil
}
func stateLabel(value string) string {
	labels := map[string]string{"draft": "Draft", "wait_date": "Menunggu Konfirmasi Tanggal", "upcoming": "Terjadwal", "on_diagnostic": "On Diagnostic", "wait_customer": "Menunggu Konfirmasi Customer", "on_service": "On Service", "wait_payment": "Menunggu Pembayaran", "paid": "Paid", "completed": "Selesai", "pending": "Pending", "cancel": "Batal"}
	if label := labels[value]; label != "" {
		return label
	}
	return value
}
func (c *Client) Evidence(ctx context.Context, id int64) ([]Evidence, error) {
	s, e := c.execute(ctx, "fleet.diagnose", "read", []Value{[]Value{id}}, map[string]Value{"fields": []Value{"fleet_link_ids"}})
	if e != nil {
		return nil, e
	}
	rows, _ := s.([]Value)
	if len(rows) == 0 {
		return []Evidence{}, nil
	}
	m, _ := rows[0].(map[string]Value)
	ids, _ := m["fleet_link_ids"].([]Value)
	if len(ids) == 0 {
		return []Evidence{}, nil
	}
	v, e := c.execute(ctx, "fleet.link", "read", []Value{ids}, map[string]Value{"fields": []Value{"link", "file_name"}})
	if e != nil {
		return nil, e
	}
	out := []Evidence{}
	for _, r := range asArray(v) {
		m, _ := r.(map[string]Value)
		link, _ := m["link"].(string)
		if !c.safeLink(link) {
			continue
		}
		out = append(out, Evidence{ID: int64(asInt(m["id"])), Name: asString(m["file_name"]), URL: link})
	}
	return out, nil
}

var ErrTargetNotFound = errors.New("EMICA target not found")
var ErrEvidencePending = errors.New("EMICA evidence reconciliation pending")
var ErrSuspectMasalahRequired = errors.New("Suspect Masalah wajib diisi di EMICA sebelum upload evidence")

func (c *Client) Upload(ctx context.Context, id int64, operationID, name string, data []byte) (*Evidence, error) {
	target, e := c.Read(ctx, id)
	if e != nil {
		return nil, fmt.Errorf("Odoo target lookup failed: %w", e)
	}
	if target == nil {
		return nil, ErrTargetNotFound
	}
	if !target.SuspectMasalahReady {
		return nil, ErrSuspectMasalahRequired
	}
	operationName := operationID + "--" + name
	before, e := c.Evidence(ctx, id)
	if e != nil {
		return nil, e
	}
	for _, x := range before {
		if evidenceMatchesOperation(x.Name, operationID) {
			return &x, nil
		}
	}
	v, e := c.execute(ctx, "fleet.diagnose", "write", []Value{[]Value{id}, map[string]Value{"sharepoint_file": base64.StdEncoding.EncodeToString(data), "document_upload_name": operationName}}, nil)
	if e != nil {
		return nil, e
	}
	ok, _ := v.(bool)
	if !ok {
		return nil, errors.New("Odoo rejected evidence")
	}
	for i := 0; i < 5; i++ {
		items, e := c.Evidence(ctx, id)
		if e == nil {
			for _, x := range items {
				if evidenceMatchesOperation(x.Name, operationID) {
					return &x, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1500 * time.Millisecond):
		}
	}
	return nil, ErrEvidencePending
}
func evidenceMatchesOperation(name, operationID string) bool {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return false
	}
	normalizedName := strings.ToLower(strings.ReplaceAll(name, "-", "_"))
	normalizedOperation := strings.ToLower(strings.ReplaceAll(operationID, "-", "_"))
	return strings.Contains(normalizedName, normalizedOperation)
}
func (c *Client) safeLink(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	for _, h := range c.cfg.AllowedSharePointHosts {
		if strings.EqualFold(u.Hostname(), h) {
			return true
		}
	}
	return false
}
func (c *Client) execute(ctx context.Context, model, method string, args []Value, kw map[string]Value) (Value, error) {
	allowed := map[string]map[string]bool{"fleet.diagnose": {"search_read": true, "read": true, "write": true}, "fleet.link": {"read": true}, "x.service.booking": {"search_read": true, "read": true}, "x.service.tag.his": {"read": true}}
	if !allowed[model][method] {
		return nil, errors.New("unsupported Odoo operation")
	}
	credentials := credentialsFromContext(ctx, Credentials{Username: c.cfg.Username, APIKey: c.cfg.APIKey})
	uid, e := c.authenticate(ctx, false)
	if e != nil {
		return nil, e
	}
	v, e := c.call(ctx, "object", "execute_kw", []Value{c.cfg.DB, uid, credentials.APIKey, model, method, args, kw})
	if e != nil && (strings.Contains(strings.ToLower(e.Error()), "session") || strings.Contains(strings.ToLower(e.Error()), "access denied")) {
		uid, e = c.authenticate(ctx, true)
		if e == nil {
			v, e = c.call(ctx, "object", "execute_kw", []Value{c.cfg.DB, uid, credentials.APIKey, model, method, args, kw})
		}
	}
	return v, e
}
func (c *Client) authenticate(ctx context.Context, refresh bool) (int, error) {
	credentials := credentialsFromContext(ctx, Credentials{Username: c.cfg.Username, APIKey: c.cfg.APIKey})
	perUser := credentials.Username != c.cfg.Username || credentials.APIKey != c.cfg.APIKey
	if perUser {
		v, e := c.call(ctx, "common", "authenticate", []Value{c.cfg.DB, credentials.Username, credentials.APIKey, map[string]Value{}})
		if e != nil {
			return 0, e
		}
		uid := asInt(v)
		if uid <= 0 {
			return 0, errors.New("Odoo authentication failed")
		}
		return uid, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.uid > 0 && !refresh {
		return c.uid, nil
	}
	v, e := c.call(ctx, "common", "authenticate", []Value{c.cfg.DB, credentials.Username, credentials.APIKey, map[string]Value{}})
	if e != nil {
		return 0, e
	}
	uid := asInt(v)
	if uid <= 0 {
		return 0, errors.New("Odoo authentication failed")
	}
	c.uid = uid
	return uid, nil
}
func (c *Client) call(ctx context.Context, endpoint, method string, params []Value) (Value, error) {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?><methodCall><methodName>`)
	_ = xml.EscapeText(&b, []byte(method))
	b.WriteString(`</methodName><params>`)
	for _, p := range params {
		b.WriteString("<param>")
		encode(&b, p)
		b.WriteString("</param>")
	}
	b.WriteString("</params></methodCall>")
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.URL, "/")+"/xmlrpc/2/"+endpoint, &b)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "text/xml")
	res, e := c.http.Do(req)
	if e != nil {
		return nil, fmt.Errorf("Odoo request: %w", e)
	}
	defer res.Body.Close()
	body, e := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if e != nil {
		return nil, e
	}
	if len(body) > maxResponse {
		return nil, errors.New("Odoo response too large")
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Odoo status %d", res.StatusCode)
	}
	return decode(body)
}
func encode(b *bytes.Buffer, v Value) {
	b.WriteString("<value>")
	switch x := v.(type) {
	case string:
		b.WriteString("<string>")
		_ = xml.EscapeText(b, []byte(x))
		b.WriteString("</string>")
	case int:
		b.WriteString("<int>" + strconv.Itoa(x) + "</int>")
	case int64:
		b.WriteString("<int>" + strconv.FormatInt(x, 10) + "</int>")
	case bool:
		if x {
			b.WriteString("<boolean>1</boolean>")
		} else {
			b.WriteString("<boolean>0</boolean>")
		}
	case []Value:
		b.WriteString("<array><data>")
		for _, i := range x {
			encode(b, i)
		}
		b.WriteString("</data></array>")
	case map[string]Value:
		b.WriteString("<struct>")
		for k, i := range x {
			b.WriteString("<member><name>")
			_ = xml.EscapeText(b, []byte(k))
			b.WriteString("</name>")
			encode(b, i)
			b.WriteString("</member>")
		}
		b.WriteString("</struct>")
	case nil:
		b.WriteString("<nil/>")
	default:
		b.WriteString("<string>")
		_ = xml.EscapeText(b, []byte(fmt.Sprint(x)))
		b.WriteString("</string>")
	}
	b.WriteString("</value>")
}

type node struct {
	XMLName xml.Name
	Text    string   `xml:",chardata"`
	Value   *node    `xml:"value"`
	Data    []node   `xml:"data>value"`
	Members []member `xml:"member"`
	Int     string   `xml:"int"`
	I4      string   `xml:"i4"`
	String  *string  `xml:"string"`
	Bool    string   `xml:"boolean"`
	Base64  string   `xml:"base64"`
	Array   *struct {
		Data []node `xml:"data>value"`
	} `xml:"array"`
	Struct *struct {
		Members []member `xml:"member"`
	} `xml:"struct"`
}
type member struct {
	Name  string `xml:"name"`
	Value node   `xml:"value"`
}
type response struct {
	Params []struct {
		Value node `xml:"value"`
	} `xml:"params>param"`
	Fault *node `xml:"fault>value"`
}

func decode(b []byte) (Value, error) {
	var r response
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	if e := d.Decode(&r); e != nil {
		return nil, errors.New("invalid Odoo XML")
	}
	if r.Fault != nil {
		v := nodeValue(*r.Fault)
		m, _ := v.(map[string]Value)
		return nil, fmt.Errorf("Odoo fault: %s", asString(m["faultString"]))
	}
	if len(r.Params) != 1 {
		return nil, errors.New("invalid Odoo response")
	}
	return nodeValue(r.Params[0].Value), nil
}
func nodeValue(n node) Value {
	if n.String != nil {
		return *n.String
	}
	if n.Int != "" {
		i, _ := strconv.Atoi(strings.TrimSpace(n.Int))
		return i
	}
	if n.I4 != "" {
		i, _ := strconv.Atoi(strings.TrimSpace(n.I4))
		return i
	}
	if n.Bool != "" {
		return strings.TrimSpace(n.Bool) == "1"
	}
	if n.Array != nil {
		a := make([]Value, 0, len(n.Array.Data))
		for _, x := range n.Array.Data {
			a = append(a, nodeValue(x))
		}
		return a
	}
	if n.Struct != nil {
		m := map[string]Value{}
		for _, x := range n.Struct.Members {
			m[x.Name] = nodeValue(x.Value)
		}
		return m
	}
	if n.Base64 != "" {
		return strings.TrimSpace(n.Base64)
	}
	return strings.TrimSpace(n.Text)
}
func services(v Value) []Service {
	out := []Service{}
	for _, r := range asArray(v) {
		m, _ := r.(map[string]Value)
		name := asString(m["name"])
		if b := many(m["x_service_booking_id"]); b != "" && b != name {
			name = b + " · " + name
		}
		suspectReady := true
		if suspect, exists := m["fleet_suspect_masalah"]; exists {
			suspectReady = strings.TrimSpace(asString(suspect)) != ""
		}
		out = append(out, Service{ID: int64(asInt(m["id"])), Name: name, Customer: asString(m["contact_name"]), VIN: many(m["x_vin_number"]), EvidenceCount: len(asArray(m["fleet_link_ids"])), SuspectMasalahReady: suspectReady, BookingID: int64(manyID(m["x_service_booking_id"])), bikeIssueIDs: intIDs(m["x_service_tag_his_ids"])})
	}
	return out
}
func asArray(v Value) []Value { a, _ := v.([]Value); return a }
func intIDs(v Value) []int {
	values := asArray(v)
	ids := make([]int, 0, len(values))
	for _, value := range values {
		if id := asInt(value); id > 0 {
			ids = append(ids, id)
		}
	}
	return ids
}
func asInt(v Value) int       { i, _ := v.(int); return i }
func asString(v Value) string { s, _ := v.(string); return s }
func manyID(v Value) int {
	a := asArray(v)
	if len(a) > 0 {
		return asInt(a[0])
	}
	return 0
}
func many(v Value) string {
	a := asArray(v)
	if len(a) > 1 {
		return asString(a[1])
	}
	return asString(v)
}
