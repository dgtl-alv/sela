package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgtl-alv/sela/internal/auth"
	"github.com/dgtl-alv/sela/internal/config"
	"github.com/dgtl-alv/sela/internal/odoo"
	"github.com/dgtl-alv/sela/internal/secure"
	"github.com/dgtl-alv/sela/internal/store"
	"github.com/dgtl-alv/sela/internal/upload"
	"github.com/dgtl-alv/sela/internal/webhook"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed templates/*.html static/*
var assets embed.FS
var gtmIDPattern = regexp.MustCompile(`^GTM-[A-Z0-9]+$`)

type Odoo interface {
	Ready(context.Context) error
	Search(context.Context, string, int) ([]odoo.Service, error)
	Read(context.Context, int64) (*odoo.Service, error)
	Evidence(context.Context, int64) ([]odoo.Evidence, error)
}
type Human interface {
	Verify(context.Context, string, string, string) error
}
type Dependencies struct {
	Store     *store.Store
	Identity  *auth.Manager
	Odoo      Odoo
	Turnstile Human
	Scanner   upload.Scanner
	Ready     func(context.Context) error
	Now       func() time.Time
}
type App struct {
	cfg       config.Config
	d         Dependencies
	templates map[string]*template.Template
	limits    map[string]*rateLimiter
}

type rateEntry struct {
	window time.Time
	count  int
}
type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	maxKeys int
	now     func() time.Time
	entries map[string]rateEntry
}

func newRateLimiter(limit int, window time.Duration, maxKeys int, now func() time.Time) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, maxKeys: maxKeys, now: now, entries: make(map[string]rateEntry)}
}
func (l *rateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entries[key]
	if e.window.IsZero() || now.Sub(e.window) >= l.window {
		e = rateEntry{window: now}
	}
	if e.count >= l.limit {
		return false
	}
	e.count++
	l.entries[key] = e
	if len(l.entries) > l.maxKeys {
		oldestKey := ""
		var oldest time.Time
		for k, candidate := range l.entries {
			if k == key {
				continue
			}
			if oldestKey == "" || candidate.window.Before(oldest) {
				oldestKey, oldest = k, candidate.window
			}
		}
		delete(l.entries, oldestKey)
	}
	return true
}
func (l *rateLimiter) Len() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.entries) }

type contextKey int

const principalKey contextKey = 1
const sessionKey contextKey = 2

type authKind int

const (
	authInvalid authKind = iota
	authCookie
	authBearer
)

func authorizationKind(h string) (authKind, string, error) {
	if h == "" {
		return authCookie, "", nil
	}
	if strings.Count(h, " ") != 1 {
		return authInvalid, "", errors.New("malformed bearer")
	}
	parts := strings.SplitN(h, " ", 2)
	if parts[0] != "Bearer" || parts[1] == "" {
		return authInvalid, "", errors.New("malformed bearer")
	}
	return authBearer, parts[1], nil
}
func needsCSRF(method string, kind authKind) bool {
	return kind == authCookie && method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}
func idempotencyFingerprint(method, path string, body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write(body)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type responseCapture struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *responseCapture) Header() http.Header { return w.header }
func (w *responseCapture) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *responseCapture) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}
func (w *responseCapture) flush(dst http.ResponseWriter) {
	for k, values := range w.header {
		for _, v := range values {
			dst.Header().Add(k, v)
		}
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	dst.WriteHeader(status)
	_, _ = dst.Write(w.body.Bytes())
}

type pageData struct {
	AppName, Title, Nonce, TurnstileSiteKey, CSRF, RequestID string
	TurnstileEnabled                                         bool
	GTMHead, GTMBody                                         template.HTML
	Principal                                                *auth.Principal
	Services                                                 []odoo.Service
	Service                                                  *odoo.Service
	Evidence                                                 []odoo.Evidence
	Uploads                                                  []store.UploadJob
	RefreshUploads                                           bool
	Message, Error                                           string
	Users                                                    []store.User
	CredentialUsername, CredentialAuthMode                   string
	CredentialConfigured                                     bool
}
type apiError struct {
	Error struct {
		Code      string            `json:"code"`
		Message   string            `json:"message"`
		RequestID string            `json:"request_id"`
		Fields    map[string]string `json:"fields,omitempty"`
	} `json:"error"`
}

func New(cfg config.Config, d Dependencies) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	a := &App{cfg: cfg, d: d, templates: map[string]*template.Template{}, limits: map[string]*rateLimiter{}}
	for name, spec := range map[string]struct {
		n int
		d time.Duration
	}{
		"login": {10, time.Minute}, "pat": {20, time.Minute}, "authfail": {20, time.Minute},
		"search": {60, time.Minute}, "upload": {20, time.Minute}, "webhook": {30, time.Minute},
	} {
		a.limits[name] = newRateLimiter(spec.n, spec.d, 10000, d.Now)
	}
	for _, name := range []string{"login", "home", "service", "tokens", "credentials", "users", "guide", "error"} {
		a.templates[name] = template.Must(template.ParseFS(assets, "templates/layout.html", "templates/"+name+".html"))
	}
	sub, e := fs.Sub(assets, "static")
	if e != nil {
		panic(e)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /readyz", a.ready)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("POST /auth/start", a.authStart)
	mux.HandleFunc("POST /auth/reauth", a.requireSession(a.reauthStart))
	mux.HandleFunc("GET /auth/callback", a.authCallback)
	mux.HandleFunc("POST /logout", a.requireSession(a.logout))
	mux.HandleFunc("GET /{$}", a.requireSession(a.home))
	mux.HandleFunc("GET /guide", a.requireSession(a.guide))
	mux.HandleFunc("GET /services/{id}", a.requireSession(a.service))
	mux.HandleFunc("POST /services/{id}/uploads", a.requireSession(a.browserUpload))
	mux.HandleFunc("GET /settings/tokens", a.requireSession(a.tokens))
	mux.HandleFunc("POST /settings/tokens", a.requireSession(a.browserCreateToken))
	mux.HandleFunc("POST /settings/tokens/{id}/revoke", a.requireSession(a.browserRevokeToken))
	mux.HandleFunc("GET /settings/credentials", a.requireSession(a.browserCredentials))
	mux.HandleFunc("POST /settings/credentials", a.requireSession(a.browserPutCredentials))
	mux.HandleFunc("POST /settings/credentials/delete", a.requireSession(a.browserDeleteCredentials))
	mux.HandleFunc("GET /admin/users", a.requireSession(a.browserUsers))
	mux.HandleFunc("POST /admin/users", a.requireSession(a.browserCreateUser))
	mux.HandleFunc("POST /admin/users/{id}", a.requireSession(a.browserUpdateUser))
	mux.HandleFunc("GET /api/v1/me", a.api(a.apiMe))
	mux.HandleFunc("GET /api/v1/services", a.api(a.apiServices))
	mux.HandleFunc("GET /api/v1/services/{id}", a.api(a.apiService))
	mux.HandleFunc("GET /api/v1/services/{id}/evidence", a.api(a.apiEvidence))
	mux.HandleFunc("POST /api/v1/services/{id}/upload-jobs", a.api(a.apiUpload))
	mux.HandleFunc("GET /api/v1/upload-jobs/{id}", a.api(a.apiUploadStatus))
	mux.HandleFunc("GET /api/v1/personal-access-tokens", a.api(a.apiPATList))
	mux.HandleFunc("POST /api/v1/personal-access-tokens", a.api(a.apiPATCreate))
	mux.HandleFunc("DELETE /api/v1/personal-access-tokens/{id}", a.api(a.apiPATRevoke))
	mux.HandleFunc("GET /api/v1/credentials/emica", a.api(a.credentialStatus))
	mux.HandleFunc("PUT /api/v1/credentials/emica", a.api(a.credentialPut))
	mux.HandleFunc("DELETE /api/v1/credentials/emica", a.api(a.credentialDelete))
	mux.HandleFunc("GET /api/v1/admin/users", a.api(a.userList))
	mux.HandleFunc("POST /api/v1/admin/users", a.api(a.userCreate))
	mux.HandleFunc("PATCH /api/v1/admin/users/{id}", a.api(a.userPatch))
	mux.HandleFunc("GET /api/v1/admin/webhook-events", a.api(a.adminEvents))
	mux.HandleFunc("GET /api/v1/admin/webhook-endpoints", a.api(a.webhookList))
	mux.HandleFunc("POST /api/v1/admin/webhook-endpoints", a.api(a.webhookCreate))
	mux.HandleFunc("PATCH /api/v1/admin/webhook-endpoints/{id}", a.api(a.webhookPatch))
	mux.HandleFunc("DELETE /api/v1/admin/webhook-endpoints/{id}", a.api(a.webhookDelete))
	mux.HandleFunc("POST /api/v1/admin/webhook-endpoints/{id}/rotate-secret", a.api(a.webhookRotate))
	mux.HandleFunc("GET /api/v1/admin/webhook-endpoints/{id}/deliveries", a.api(a.webhookDeliveries))
	mux.HandleFunc("POST /api/v1/admin/webhook-deliveries/{id}/retry", a.api(a.webhookRetry))
	return requestMiddleware(cfg, mux)
}

func (a *App) allow(bucket, key string) bool { return a.limits[bucket].Allow(key) }
func (a *App) rateLimited(w http.ResponseWriter, r *http.Request, api bool) {
	w.Header().Set("Retry-After", "60")
	if api {
		a.apiErr(w, r, 429, "rate_limited", "Too many requests", nil)
		return
	}
	a.renderError(w, r, 429, "Terlalu banyak permintaan")
}
func (a *App) apiRateAllowed(r *http.Request) bool {
	p := principal(r)
	key := p.UserID + ":" + clientIP(r)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/services":
		return a.allow("search", key)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/upload-jobs"):
		return a.allow("upload", key)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/personal-access-tokens":
		return a.allow("pat", key)
	case isMutation(r.Method) && strings.HasPrefix(r.URL.Path, "/api/v1/admin/webhook-"):
		return a.allow("webhook", key)
	default:
		return true
	}
}
func (a *App) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) ready(w http.ResponseWriter, r *http.Request) {
	ctx, c := context.WithTimeout(r.Context(), 2*time.Second)
	defer c()
	if a.d.Ready == nil || a.d.Ready(ctx) != nil {
		writeJSON(w, 503, map[string]bool{"ok": false})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.allow("login", clientIP(r)) {
		a.rateLimited(w, r, false)
		return
	}
	if _, e := a.session(r); e == nil {
		http.Redirect(w, r, "/", 303)
		return
	}
	a.render(w, r, "login", pageData{Title: "Masuk", TurnstileSiteKey: a.cfg.TurnstileSiteKey, TurnstileEnabled: a.cfg.TurnstileEnabled})
}
func (a *App) authStart(w http.ResponseWriter, r *http.Request) {
	if !a.allow("login", clientIP(r)) {
		a.rateLimited(w, r, false)
		return
	}
	if e := r.ParseForm(); e != nil {
		a.renderError(w, r, 400, "Permintaan tidak valid")
		return
	}
	if a.cfg.TurnstileEnabled && (a.d.Turnstile == nil || a.d.Turnstile.Verify(r.Context(), r.Form.Get("cf-turnstile-response"), "login_start", clientIP(r)) != nil) {
		a.renderError(w, r, 400, "Verifikasi manusia gagal. Coba lagi.")
		return
	}
	flow, location, e := a.d.Identity.Begin(r.Form.Get("return_to"))
	if e != nil {
		a.renderError(w, r, 503, "Layanan masuk tidak tersedia")
		return
	}
	value, e := a.signFlow(flow)
	if e != nil {
		a.renderError(w, r, 500, "Tidak dapat memulai sesi")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-sela_auth", Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, location, 303)
}
func (a *App) reauthStart(w http.ResponseWriter, r *http.Request) {
	if !a.validCSRF(r) {
		a.renderError(w, r, 403, "Permintaan ditolak")
		return
	}
	flow, location, err := a.d.Identity.BeginReauthentication(r.FormValue("return_to"))
	if err != nil {
		a.renderError(w, r, 503, "Layanan masuk tidak tersedia")
		return
	}
	value, err := a.signFlow(flow)
	if err != nil {
		a.renderError(w, r, 500, "Tidak dapat memulai sesi")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-sela_auth", Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, location, 303)
}
func (a *App) authCallback(w http.ResponseWriter, r *http.Request) {
	cookie, e := r.Cookie("__Host-sela_auth")
	if e != nil {
		a.renderError(w, r, 400, "Respons masuk tidak valid")
		return
	}
	flow, e := a.parseFlow(cookie.Value)
	if e != nil || !hmac.Equal([]byte(flow.State), []byte(r.URL.Query().Get("state"))) {
		a.renderError(w, r, 400, "Respons masuk tidak valid")
		return
	}
	claims, e := a.d.Identity.Exchange(r.Context(), r.URL.Query().Get("code"), flow)
	if e != nil {
		a.renderError(w, r, 401, "Masuk gagal")
		return
	}
	p, e := a.d.Store.UpsertIdentity(r.Context(), claims.Iss, claims.Tenant, claims.Sub, strings.ToLower(claims.Email), claims.Name)
	if e != nil {
		a.renderError(w, r, 403, "Akun tidak diizinkan")
		return
	}
	token, e := secure.Random(32)
	if e != nil {
		a.renderError(w, r, 500, "Tidak dapat membuat sesi")
		return
	}
	csrf, e := secure.Random(32)
	if e != nil {
		a.renderError(w, r, 500, "Tidak dapat membuat sesi")
		return
	}
	now := a.d.Now()
	if e = a.d.Store.CreateSession(r.Context(), p, secure.Hash(a.cfg.SessionHashKey, token), secure.Hash(a.cfg.SessionHashKey, csrf), now, now.Add(a.cfg.SessionIdle), now.Add(a.cfg.SessionAbsolute), clientIP(r), secure.Hash(a.cfg.SessionHashKey, r.UserAgent())); e != nil {
		a.renderError(w, r, 500, "Tidak dapat membuat sesi")
		return
	}
	http.SetCookie(w, sessionCookie(token, int(a.cfg.SessionAbsolute.Seconds())))
	http.SetCookie(w, &http.Cookie{Name: "sela_csrf", Value: csrf, Path: "/", Secure: true, HttpOnly: false, SameSite: http.SameSiteLaxMode, MaxAge: int(a.cfg.SessionAbsolute.Seconds())})
	http.SetCookie(w, &http.Cookie{Name: "__Host-sela_auth", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, flow.ReturnTo, 303)
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if !a.validCSRF(r) {
		a.renderError(w, r, 403, "Permintaan ditolak")
		return
	}
	if s, ok := r.Context().Value(sessionKey).(store.Session); ok {
		_ = a.d.Store.RevokeSession(r.Context(), s.TokenHash)
	}
	http.SetCookie(w, sessionCookie("", -1))
	http.Redirect(w, r, "/login", 303)
}
func (a *App) guide(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	a.render(w, r, "guide", pageData{Title: "Panduan Penggunaan", Principal: &p})
}
func (a *App) home(w http.ResponseWriter, r *http.Request) {
	odooCtx, credentialErr := a.odooContext(r)
	if credentialErr != nil {
		http.Redirect(w, r, "/settings/credentials?setup=required", http.StatusSeeOther)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	var services []odoo.Service
	var msg string
	if q != "" {
		if !a.allow("search", principal(r).UserID+":"+clientIP(r)) {
			a.rateLimited(w, r, false)
			return
		}
		var e error
		services, e = a.d.Odoo.Search(odooCtx, q, 20)
		if e != nil {
			msg = "Pencarian gagal. Coba lagi."
		}
	}
	p := principal(r)
	a.render(w, r, "home", pageData{Title: "Cari Service Booking", Principal: &p, Services: services, Message: msg})
}
func (a *App) service(w http.ResponseWriter, r *http.Request) {
	odooCtx, credentialErr := a.odooContext(r)
	if credentialErr != nil {
		http.Redirect(w, r, "/settings/credentials?setup=required", http.StatusSeeOther)
		return
	}
	id, e := parseID(r.PathValue("id"))
	if e != nil {
		a.renderError(w, r, 404, "Data tidak ditemukan")
		return
	}
	s, e := a.d.Odoo.Read(odooCtx, id)
	if e != nil || s == nil {
		a.renderError(w, r, 404, "Data tidak ditemukan")
		return
	}
	ev, e := a.d.Odoo.Evidence(odooCtx, id)
	if e != nil {
		a.renderError(w, r, 502, "Evidence tidak dapat dimuat")
		return
	}
	p := principal(r)
	jobs, jobsErr := a.d.Store.RecentUploads(r.Context(), p.UserID, id, 10)
	if jobsErr != nil {
		a.renderError(w, r, 500, "Status unggahan tidak dapat dimuat")
		return
	}
	refresh := false
	for _, job := range jobs {
		if job.Status == "pending" || job.Status == "scanning" || job.Status == "processing" || job.Status == "reconciling" {
			refresh = true
		}
	}
	message := ""
	if queued := r.URL.Query().Get("queued"); queued != "" {
		message = queued + " file berhasil diantrikan. Status dipantau di bawah."
	}
	if refresh {
		w.Header().Set("Refresh", "5")
	}
	a.render(w, r, "service", pageData{Title: s.Name, Principal: &p, Service: s, Evidence: ev, Uploads: jobs, RefreshUploads: refresh, Message: message})
}
func (a *App) browserUpload(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r, a.cfg.PublicURL) {
		a.renderError(w, r, 403, "Permintaan ditolak")
		return
	}
	if !a.allow("upload", principal(r).UserID+":"+clientIP(r)) {
		a.rateLimited(w, r, false)
		return
	}
	odooCtx, credentialErr := a.odooContext(r)
	if credentialErr != nil {
		http.Redirect(w, r, "/settings/credentials?setup=required", http.StatusSeeOther)
		return
	}
	id, e := parseID(r.PathValue("id"))
	if e != nil {
		a.renderError(w, r, 400, "Target tidak valid")
		return
	}
	target, e := a.d.Odoo.Read(odooCtx, id)
	if e != nil {
		a.renderError(w, r, 502, "Target tidak dapat diverifikasi")
		return
	}
	if target == nil {
		a.renderError(w, r, 404, "Target tidak ditemukan")
		return
	}
	if !target.SuspectMasalahReady {
		a.renderError(w, r, 409, "Validasi minimal satu Bike Issue dengan Suspect Masalah terisi di EMICA, lalu muat ulang halaman")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, upload.MaxRequestBytes)
	mr, e := r.MultipartReader()
	if e != nil {
		a.renderError(w, r, 400, "Form unggahan tidak valid")
		return
	}
	if headerCSRF := r.Header.Get("X-CSRF-Token"); headerCSRF != "" {
		if !a.validCSRFToken(r, headerCSRF) {
			a.renderError(w, r, 403, "Permintaan ditolak")
			return
		}
	} else {
		csrfPart, partErr := mr.NextPart()
		if partErr != nil || csrfPart.FormName() != "csrf_token" || csrfPart.FileName() != "" {
			if csrfPart != nil {
				csrfPart.Close()
			}
			a.renderError(w, r, 403, "Permintaan ditolak")
			return
		}
		providedCSRF, readErr := io.ReadAll(io.LimitReader(csrfPart, 513))
		csrfPart.Close()
		if readErr != nil || len(providedCSRF) == 0 || len(providedCSRF) > 512 || !a.validCSRFToken(r, string(providedCSRF)) {
			a.renderError(w, r, 403, "Permintaan ditolak")
			return
		}
	}
	p := principal(r)
	count := 0
	jobs := []store.UploadJob{}
	paths := []string{}
	committed := false
	defer func() {
		if !committed {
			for _, path := range paths {
				_ = removeFile(path)
			}
		}
	}()
	for {
		part, e := mr.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			a.renderError(w, r, 400, "Unggahan tidak valid")
			return
		}
		if part.FormName() != "files" || part.FileName() == "" {
			part.Close()
			a.renderError(w, r, 400, "Bagian form tidak dikenal")
			return
		}
		count++
		if count > upload.MaxFiles {
			part.Close()
			a.renderError(w, r, 400, "Maksimal 4 file")
			return
		}
		f, ingestErr := upload.Ingest(a.cfg.QuarantineDir, part)
		part.Close()
		if ingestErr != nil {
			a.renderError(w, r, 400, "File ditolak: "+ingestErr.Error())
			return
		}
		paths = append(paths, f.Path)
		jobs = append(jobs, store.UploadJob{ID: f.ID, UserID: p.UserID, DiagnoseID: id, DisplayName: f.DisplayName, StorageKey: f.StorageKey, MediaType: f.MediaType, Size: f.Size, SHA256: f.SHA256, Status: "pending", ExternalOperationID: f.ID})
	}
	if count == 0 {
		a.renderError(w, r, 400, "Pilih file")
		return
	}
	if e = a.d.Store.AddUploads(r.Context(), jobs); e != nil {
		a.renderError(w, r, 500, "Unggahan tidak dapat diantrikan")
		return
	}
	committed = true
	http.Redirect(w, r, fmt.Sprintf("/services/%d?queued=%d", id, count), 303)
}
func (a *App) tokens(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	items, e := a.d.Store.ListPATs(r.Context(), p.UserID)
	msg := ""
	if e != nil {
		msg = "Token tidak dapat dimuat"
	}
	_ = items
	a.render(w, r, "tokens", pageData{Title: "Token API", Principal: &p, Message: msg})
}
func (a *App) browserCreateToken(w http.ResponseWriter, r *http.Request) {
	if !a.interactiveCookieSession(r) {
		a.renderError(w, r, 403, "Masuk ulang diperlukan")
		return
	}
	if !a.validCSRF(r) {
		a.renderError(w, r, 403, "Permintaan ditolak")
		return
	}
	if !a.allow("pat", principal(r).UserID+":"+clientIP(r)) {
		a.rateLimited(w, r, false)
		return
	}
	r.ParseForm()
	p := principal(r)
	plain, _, e := a.createPAT(r.Context(), p, r.Form.Get("name"), r.Form["scopes"], 30)
	if e != nil {
		a.renderError(w, r, 400, e.Error())
		return
	}
	p = principal(r)
	a.render(w, r, "tokens", pageData{Title: "Token API", Principal: &p, Message: "Salin token sekarang. Token tidak akan ditampilkan lagi: " + plain})
}
func (a *App) browserRevokeToken(w http.ResponseWriter, r *http.Request) {
	if !a.interactiveCookieSession(r) {
		a.renderError(w, r, 403, "Masuk ulang diperlukan")
		return
	}
	if !a.validCSRF(r) {
		a.renderError(w, r, 403, "Permintaan ditolak")
		return
	}
	p := principal(r)
	_ = a.d.Store.RevokePAT(r.Context(), p.UserID, r.PathValue("id"))
	http.Redirect(w, r, "/settings/tokens", 303)
}

func requiresOdooCredential(path string) bool {
	return path == "/api/v1/services" || strings.HasPrefix(path, "/api/v1/services/")
}
func (a *App) browserCredentials(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	c, err := a.d.Store.UserCredential(r.Context(), p.UserID)
	d := pageData{Title: "Kredensial EMICA", Principal: &p}
	if r.URL.Query().Get("setup") == "required" {
		d.Message = "Selesaikan pengaturan kredensial EMICA sebelum menggunakan SELA."
	}
	if err == nil {
		d.CredentialConfigured = true
		d.CredentialUsername = c.Username
		d.CredentialAuthMode = c.AuthMode
	} else {
		d.CredentialAuthMode = "api_token"
	}
	a.render(w, r, "credentials", d)
}
func (a *App) browserPutCredentials(w http.ResponseWriter, r *http.Request) {
	if !a.credentialOwner(r) || !a.validCSRF(r) {
		a.renderError(w, r, 403, "Permintaan ditolak")
		return
	}
	p := principal(r)
	username := strings.ToLower(strings.TrimSpace(p.Email))
	authMode := r.FormValue("auth_mode")
	secret := r.FormValue("secret")
	if !validCredentialInput(username, authMode, secret) {
		a.renderError(w, r, 400, "Kredensial tidak valid")
		return
	}
	if err := a.d.Odoo.Ready(odoo.WithCredentials(r.Context(), odoo.Credentials{Username: username, APIKey: secret})); err != nil {
		a.renderError(w, r, 400, "Kredensial emica tidak dapat diverifikasi")
		return
	}
	ciphertext, err := webhook.EncryptWithAAD(a.cfg.OdooCredentialEncryptionKey, []byte(secret), []byte(p.UserID))
	if err == nil {
		err = a.d.Store.PutUserCredentialWithMode(r.Context(), p.UserID, username, authMode, ciphertext)
	}
	if err != nil {
		a.renderError(w, r, 500, "Kredensial tidak dapat disimpan")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *App) browserDeleteCredentials(w http.ResponseWriter, r *http.Request) {
	if !a.credentialOwner(r) || !a.validCSRF(r) {
		a.renderError(w, r, 403, "Permintaan ditolak")
		return
	}
	_ = a.d.Store.DeleteUserCredential(r.Context(), principal(r).UserID)
	http.Redirect(w, r, "/settings/credentials", 303)
}
func (a *App) browserUsers(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.renderError(w, r, 403, "Admin diperlukan")
		return
	}
	p := principal(r)
	users, err := a.d.Store.ListUsers(r.Context(), 100)
	if err != nil {
		a.renderError(w, r, 500, "Pengguna tidak dapat dimuat")
		return
	}
	a.render(w, r, "users", pageData{Title: "Pengguna", Principal: &p, Users: users})
}
func (a *App) browserCreateUser(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) || !a.validCSRF(r) {
		a.renderError(w, r, 403, "Permintaan ditolak")
		return
	}
	_, err := a.d.Store.CreateUser(r.Context(), principal(r).UserID, strings.ToLower(strings.TrimSpace(r.FormValue("email"))), strings.TrimSpace(r.FormValue("display_name")), r.FormValue("role"))
	if err != nil {
		a.renderError(w, r, 400, "Pengguna tidak dapat ditambahkan")
		return
	}
	http.Redirect(w, r, "/admin/users", 303)
}
func (a *App) browserUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) || !a.validCSRF(r) {
		a.renderError(w, r, 403, "Permintaan ditolak")
		return
	}
	active := r.FormValue("active") == "true"
	_, err := a.d.Store.UpdateUser(r.Context(), principal(r).UserID, r.PathValue("id"), r.FormValue("role"), active)
	if err != nil {
		a.renderError(w, r, 409, err.Error())
		return
	}
	http.Redirect(w, r, "/admin/users", 303)
}

func (a *App) api(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind, _, parseErr := authorizationKind(r.Header.Get("Authorization"))
		if parseErr != nil {
			if !a.allow("authfail", clientIP(r)) {
				a.rateLimited(w, r, true)
				return
			}
			a.apiErr(w, r, 401, "unauthorized", "Authentication required", nil)
			return
		}
		p, e := a.apiPrincipal(r)
		if e != nil {
			if !a.allow("authfail", clientIP(r)) {
				a.rateLimited(w, r, true)
				return
			}
			a.apiErr(w, r, 401, "unauthorized", "Authentication required", nil)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, p)
		if requiresOdooCredential(r.URL.Path) {
			credential, credentialErr := a.d.Store.UserCredential(r.Context(), p.UserID)
			if credentialErr != nil {
				a.apiErr(w, r, 403, "credentials_required", "emica credentials required", nil)
				return
			}
			secret, decryptErr := webhook.DecryptWithAAD(a.cfg.OdooCredentialEncryptionKey, credential.SecretCiphertext, []byte(p.UserID))
			if decryptErr != nil {
				a.apiErr(w, r, 503, "credentials_unavailable", "emica credentials unavailable", nil)
				return
			}
			ctx = odoo.WithCredentials(ctx, odoo.Credentials{Username: credential.Username, APIKey: string(secret)})
		}
		if kind == authCookie {
			s, e := a.session(r)
			if e != nil {
				a.apiErr(w, r, 401, "unauthorized", "Authentication required", nil)
				return
			}
			ctx = context.WithValue(ctx, sessionKey, s)
		}
		r = r.WithContext(ctx)
		if needsCSRF(r.Method, kind) && !a.validCSRF(r) {
			a.apiErr(w, r, 403, "csrf_rejected", "Request rejected", nil)
			return
		}
		if !a.apiRateAllowed(r) {
			a.rateLimited(w, r, true)
			return
		}
		capture := &responseCapture{header: make(http.Header)}
		if isMutation(r.Method) {
			if !a.idempotent(capture, r, next) {
				capture.flush(w)
				return
			}
		} else {
			next(capture, r)
		}
		if p.ViaPAT && capture.status != http.StatusUnauthorized && capture.status != http.StatusForbidden {
			_ = a.d.Store.TouchPAT(r.Context(), p.PATID, clientIP(r))
		}
		capture.flush(w)
	}
}
func (a *App) apiPrincipal(r *http.Request) (auth.Principal, error) {
	kind, token, e := authorizationKind(r.Header.Get("Authorization"))
	if e != nil {
		return auth.Principal{}, e
	}
	if kind == authBearer {
		if r.TLS == nil && a.cfg.Environment == "production" {
			return auth.Principal{}, errors.New("HTTPS required")
		}
		return a.d.Store.AuthenticatePAT(r.Context(), secure.Hash(a.cfg.PATHashKey, token))
	}
	s, e := a.session(r)
	return s.Principal, e
}
func isMutation(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}
func (a *App) idempotent(w *responseCapture, r *http.Request, next http.HandlerFunc) bool {
	key := r.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 200 {
		a.apiErr(w, r, 400, "idempotency_key_required", "Valid Idempotency-Key required", nil)
		return false
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, upload.MaxRequestBytes))
	if e != nil {
		a.apiErr(w, r, 413, "request_too_large", "Request too large", nil)
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	fingerprint := idempotencyFingerprint(r.Method, r.URL.Path, body)
	p := principal(r)
	tx, e := a.d.Store.Begin(r.Context())
	if e != nil {
		a.apiErr(w, r, 503, "idempotency_unavailable", "Request cannot be processed", nil)
		return false
	}
	defer tx.Rollback(r.Context())
	rec, created, e := a.d.Store.BeginIdempotencyTx(r.Context(), tx, p.UserID, key, r.Method, r.URL.Path, fingerprint[:])
	if e != nil {
		a.apiErr(w, r, 503, "idempotency_unavailable", "Request cannot be processed", nil)
		return false
	}
	if !created {
		if rec.Method != r.Method || rec.Path != r.URL.Path || !hmac.Equal(rec.BodyHash, fingerprint[:]) {
			a.apiErr(w, r, 409, "idempotency_mismatch", "Idempotency key reused for different request", nil)
			return false
		}
		if rec.State == "processing" {
			a.apiErr(w, r, 409, "idempotency_in_flight", "Request still processing", nil)
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.StatusCode)
		_, _ = w.Write(rec.ResponseBody)
		return false
	}
	r = r.WithContext(store.WithTx(r.Context(), tx))
	next(w, r)
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	if status >= 500 {
		return true
	}
	if e = a.d.Store.CompleteIdempotency(r.Context(), p.UserID, key, r.Method, r.URL.Path, rec.OwnerToken, status, w.body.Bytes()); e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		w.header = make(http.Header)
		w.body.Reset()
		w.status = 0
		a.apiErr(w, r, 503, "idempotency_unavailable", "Response cannot be persisted", nil)
	}
	return true
}
func (a *App) apiMe(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	writeJSON(w, 200, map[string]any{"id": p.UserID, "role": p.Role, "scopes": p.Scopes})
}
func (a *App) apiServices(w http.ResponseWriter, r *http.Request) {
	if !scope(r, "services:read") {
		a.apiErr(w, r, 403, "forbidden", "Permission denied", nil)
		return
	}
	limit := boundedLimit(r)
	items, e := a.d.Odoo.Search(r.Context(), r.URL.Query().Get("q"), limit)
	if e != nil {
		a.apiErr(w, r, 400, "invalid_search", "Search failed", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "limit": limit})
}
func (a *App) apiService(w http.ResponseWriter, r *http.Request) {
	if !scope(r, "services:read") {
		a.apiErr(w, r, 403, "forbidden", "Permission denied", nil)
		return
	}
	id, e := parseID(r.PathValue("id"))
	if e != nil {
		a.apiErr(w, r, 400, "invalid_id", "Invalid service ID", nil)
		return
	}
	s, e := a.d.Odoo.Read(r.Context(), id)
	if e != nil || s == nil {
		a.apiErr(w, r, 404, "not_found", "Service not found", nil)
		return
	}
	writeJSON(w, 200, s)
}
func (a *App) apiEvidence(w http.ResponseWriter, r *http.Request) {
	if !scope(r, "evidence:read") {
		a.apiErr(w, r, 403, "forbidden", "Permission denied", nil)
		return
	}
	id, e := parseID(r.PathValue("id"))
	if e != nil {
		a.apiErr(w, r, 400, "invalid_id", "Invalid service ID", nil)
		return
	}
	if s, _ := a.d.Odoo.Read(r.Context(), id); s == nil {
		a.apiErr(w, r, 404, "not_found", "Service not found", nil)
		return
	}
	items, e := a.d.Odoo.Evidence(r.Context(), id)
	if e != nil {
		a.apiErr(w, r, 502, "upstream_error", "Evidence unavailable", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (a *App) apiUpload(w http.ResponseWriter, r *http.Request) {
	if !scope(r, "evidence:write") {
		a.apiErr(w, r, 403, "forbidden", "Permission denied", nil)
		return
	}
	id, e := parseID(r.PathValue("id"))
	if e != nil {
		a.apiErr(w, r, 400, "invalid_id", "Invalid service ID", nil)
		return
	}
	target, targetErr := a.d.Odoo.Read(r.Context(), id)
	if targetErr != nil {
		a.apiErr(w, r, 502, "upstream_error", "Service unavailable", nil)
		return
	}
	if target == nil {
		a.apiErr(w, r, 404, "not_found", "Service not found", nil)
		return
	}
	if !target.SuspectMasalahReady {
		a.apiErr(w, r, 409, "suspect_masalah_required", "Suspect Masalah must be completed in EMICA before evidence upload", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, upload.MaxFileBytes+(1<<20))
	mr, e := r.MultipartReader()
	if e != nil {
		a.apiErr(w, r, 400, "invalid_multipart", "Multipart body required", nil)
		return
	}
	part, e := mr.NextPart()
	if e != nil || part.FormName() != "file" || part.FileName() == "" {
		a.apiErr(w, r, 400, "file_required", "One file required", nil)
		return
	}
	f, e := upload.Ingest(a.cfg.QuarantineDir, part)
	part.Close()
	if e != nil {
		a.apiErr(w, r, 400, "invalid_file", e.Error(), nil)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = removeFile(f.Path)
		}
	}()
	if next, nextErr := mr.NextPart(); nextErr != io.EOF || next != nil {
		if next != nil {
			next.Close()
		}
		a.apiErr(w, r, 400, "too_many_files", "One file required", nil)
		return
	}
	p := principal(r)
	if _, credentialErr := a.d.Store.UserCredential(r.Context(), p.UserID); credentialErr != nil {
		a.apiErr(w, r, 403, "credentials_required", "emica credentials required", nil)
		return
	}
	j := store.UploadJob{ID: f.ID, UserID: p.UserID, DiagnoseID: id, DisplayName: f.DisplayName, StorageKey: f.StorageKey, MediaType: f.MediaType, Size: f.Size, SHA256: f.SHA256, Status: "pending", ExternalOperationID: f.ID}
	if e = a.d.Store.AddUploads(r.Context(), []store.UploadJob{j}); e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to queue upload", nil)
		return
	}
	committed = true
	writeJSONStatus(w, 202, j)
}
func (a *App) apiUploadStatus(w http.ResponseWriter, r *http.Request) {
	if !scope(r, "evidence:read") {
		a.apiErr(w, r, 403, "forbidden", "Permission denied", nil)
		return
	}
	p := principal(r)
	j, e := a.d.Store.Upload(r.Context(), r.PathValue("id"), p.UserID)
	if e != nil {
		a.apiErr(w, r, 404, "not_found", "Upload job not found", nil)
		return
	}
	writeJSON(w, 200, j)
}
func (a *App) apiPATList(w http.ResponseWriter, r *http.Request) {
	if !a.interactiveCookieSession(r) {
		a.apiErr(w, r, 403, "interactive_login_required", "Interactive login required", nil)
		return
	}
	p := principal(r)
	items, e := a.d.Store.ListPATs(r.Context(), p.UserID)
	if e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to list tokens", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (a *App) apiPATCreate(w http.ResponseWriter, r *http.Request) {
	if !a.interactiveCookieSession(r) {
		a.apiErr(w, r, 403, "interactive_login_required", "Interactive login required", nil)
		return
	}
	if principal(r).ViaPAT {
		a.apiErr(w, r, 403, "interactive_login_required", "Interactive login required", nil)
		return
	}
	var in struct {
		Name          string   `json:"name"`
		Scopes        []string `json:"scopes"`
		ExpiresInDays int      `json:"expires_in_days"`
	}
	if !a.decodeJSON(w, r, &in) {
		return
	}
	plain, p, e := a.createPAT(r.Context(), principal(r), in.Name, in.Scopes, in.ExpiresInDays)
	if e != nil {
		a.apiErr(w, r, 400, "invalid_token", e.Error(), nil)
		return
	}
	writeJSONStatus(w, 201, map[string]any{"token": plain, "metadata": p})
}
func (a *App) apiPATRevoke(w http.ResponseWriter, r *http.Request) {
	if !a.interactiveCookieSession(r) {
		a.apiErr(w, r, 403, "interactive_login_required", "Interactive login required", nil)
		return
	}
	if principal(r).ViaPAT {
		a.apiErr(w, r, 403, "interactive_login_required", "Interactive login required", nil)
		return
	}
	p := principal(r)
	if e := a.d.Store.RevokePAT(r.Context(), p.UserID, r.PathValue("id")); e != nil {
		a.apiErr(w, r, 404, "not_found", "Token not found", nil)
		return
	}
	w.WriteHeader(204)
}

func (a *App) interactiveCookieSession(r *http.Request) bool {
	if principal(r).ViaPAT {
		return false
	}
	_, ok := r.Context().Value(sessionKey).(store.Session)
	return ok
}
func (a *App) admin(r *http.Request) bool {
	return principal(r).Role == "admin" && a.interactiveCookieSession(r)
}
func (a *App) credentialOwner(r *http.Request) bool { return a.interactiveCookieSession(r) }
func (a *App) odooContext(r *http.Request) (context.Context, error) {
	credential, err := a.d.Store.UserCredential(r.Context(), principal(r).UserID)
	if err != nil {
		return nil, err
	}
	secret, err := webhook.DecryptWithAAD(a.cfg.OdooCredentialEncryptionKey, credential.SecretCiphertext, []byte(principal(r).UserID))
	if err != nil {
		return nil, err
	}
	return odoo.WithCredentials(r.Context(), odoo.Credentials{Username: credential.Username, APIKey: string(secret)}), nil
}

func (a *App) userList(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	items, err := a.d.Store.ListUsers(r.Context(), boundedLimit(r))
	if err != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to list users", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (a *App) userCreate(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	var in struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	if !a.decodeJSON(w, r, &in) {
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if !validEmail(in.Email) || len(in.DisplayName) < 1 || len(in.DisplayName) > 200 || !validRole(in.Role) {
		a.apiErr(w, r, 400, "invalid_user", "User fields are invalid", nil)
		return
	}
	u, err := a.d.Store.CreateUser(r.Context(), principal(r).UserID, in.Email, in.DisplayName, in.Role)
	if isUniquePG(err) {
		a.apiErr(w, r, 409, "email_exists", "Email already allowlisted", nil)
		return
	}
	if err != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to create user", nil)
		return
	}
	writeJSONStatus(w, 201, u)
}

func (a *App) userPatch(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	var in struct {
		Role   string `json:"role"`
		Active *bool  `json:"active"`
	}
	if !a.decodeJSON(w, r, &in) {
		return
	}
	if !validRole(in.Role) || in.Active == nil {
		a.apiErr(w, r, 400, "invalid_user", "Role and active are required", nil)
		return
	}
	u, err := a.d.Store.UpdateUser(r.Context(), principal(r).UserID, r.PathValue("id"), in.Role, *in.Active)
	switch {
	case errors.Is(err, store.ErrSelfAdminChange), errors.Is(err, store.ErrLastAdmin):
		a.apiErr(w, r, 409, "admin_required", err.Error(), nil)
	case errors.Is(err, pgx.ErrNoRows):
		a.apiErr(w, r, 404, "not_found", "User not found", nil)
	case err != nil:
		a.apiErr(w, r, 500, "internal_error", "Unable to update user", nil)
	default:
		writeJSON(w, 200, u)
	}
}

func (a *App) credentialStatus(w http.ResponseWriter, r *http.Request) {
	if !a.credentialOwner(r) {
		a.apiErr(w, r, 403, "interactive_login_required", "Interactive login required", nil)
		return
	}
	c, err := a.d.Store.UserCredential(r.Context(), principal(r).UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, 200, map[string]bool{"configured": false})
		return
	}
	if err != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to read credential status", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"configured": true, "updated_at": c.UpdatedAt})
}

func (a *App) credentialPut(w http.ResponseWriter, r *http.Request) {
	if !a.credentialOwner(r) {
		a.apiErr(w, r, 403, "interactive_login_required", "Interactive login required", nil)
		return
	}
	var in struct {
		AuthMode string `json:"auth_mode"`
		Secret   string `json:"secret"`
		APIKey   string `json:"api_key"`
	}
	if !a.decodeJSON(w, r, &in) {
		return
	}
	if in.AuthMode == "" && in.Secret == "" && in.APIKey != "" {
		in.AuthMode, in.Secret = "api_token", in.APIKey
	}
	p := principal(r)
	username := strings.ToLower(strings.TrimSpace(p.Email))
	if !validCredentialInput(username, in.AuthMode, in.Secret) {
		a.apiErr(w, r, 400, "invalid_credentials", "Credential mode and secret are required", nil)
		return
	}
	if err := a.d.Odoo.Ready(odoo.WithCredentials(r.Context(), odoo.Credentials{Username: username, APIKey: in.Secret})); err != nil {
		a.apiErr(w, r, 400, "credential_verification_failed", "Credentials could not be verified", nil)
		return
	}
	ciphertext, err := webhook.EncryptWithAAD(a.cfg.OdooCredentialEncryptionKey, []byte(in.Secret), []byte(p.UserID))
	if err != nil {
		a.apiErr(w, r, 503, "credential_storage_unavailable", "Unable to store credentials", nil)
		return
	}
	if err = a.d.Store.PutUserCredentialWithMode(r.Context(), p.UserID, username, in.AuthMode, ciphertext); err != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to store credentials", nil)
		return
	}
	writeJSON(w, 200, map[string]bool{"configured": true})
}

func (a *App) credentialDelete(w http.ResponseWriter, r *http.Request) {
	if !a.credentialOwner(r) {
		a.apiErr(w, r, 403, "interactive_login_required", "Interactive login required", nil)
		return
	}
	err := a.d.Store.DeleteUserCredential(r.Context(), principal(r).UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		a.apiErr(w, r, 404, "not_found", "Credentials not configured", nil)
		return
	}
	if err != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to delete credentials", nil)
		return
	}
	w.WriteHeader(204)
}

func normalizeUserInput(email, displayName, role string) (string, string, string, bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	displayName = strings.TrimSpace(displayName)
	return email, displayName, role, validEmail(email) && len(displayName) >= 1 && len(displayName) <= 200 && validRole(role)
}
func validRole(role string) bool { return role == "technician" || role == "admin" }
func validCredentialInput(username, authMode, secret string) bool {
	return validEmail(username) && (authMode == "api_token" || authMode == "password") && len(secret) >= 1 && len(secret) <= 4096
}
func validEmail(email string) bool {
	address, err := mail.ParseAddress(email)
	return err == nil && address.Address == email && len(email) <= 320
}
func isUniquePG(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (a *App) adminEvents(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"items": []string{"evidence.upload.queued.v1", "evidence.upload.succeeded.v1", "evidence.upload.failed.v1", "pat.created.v1", "pat.revoked.v1"}})
}
func (a *App) webhookList(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	rows, e := a.d.Store.Query(r.Context(), `SELECT id,description,url,enabled,created_at,updated_at FROM webhook_endpoints WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1`, boundedLimit(r))
	if e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to list endpoints", nil)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, d, u string
		var enabled bool
		var c, up time.Time
		_ = rows.Scan(&id, &d, &u, &enabled, &c, &up)
		items = append(items, map[string]any{"id": id, "description": d, "url": u, "enabled": enabled, "created_at": c, "updated_at": up})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (a *App) webhookCreate(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	var in struct {
		Description, URL string
		Events           []string
	}
	if !a.decodeJSON(w, r, &in) {
		return
	}
	if _, _, e := (webhook.Deliverer{}).Validate(r.Context(), in.URL); e != nil {
		a.apiErr(w, r, 400, "unsafe_destination", "Destination rejected", nil)
		return
	}
	secret, e := secure.Random(32)
	if e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to create endpoint", nil)
		return
	}
	cipher, e := webhook.Encrypt(a.cfg.WebhookEncryptionKey, []byte(secret))
	if e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to create endpoint", nil)
		return
	}
	if len(in.Events) == 0 {
		a.apiErr(w, r, 400, "invalid_events", "At least one known event required", nil)
		return
	}
	seen := make(map[string]bool, len(in.Events))
	for _, ev := range in.Events {
		if !validEvent(ev) || seen[ev] {
			a.apiErr(w, r, 400, "invalid_events", "Unknown or duplicate webhook event", nil)
			return
		}
		seen[ev] = true
	}
	id, e := secure.UUID()
	if e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to create endpoint", nil)
		return
	}
	_, e = a.d.Store.Exec(r.Context(), `INSERT INTO webhook_endpoints(id,description,url,secret_ciphertext,created_by) VALUES($1,$2,$3,$4,$5)`, id, in.Description, in.URL, cipher, principal(r).UserID)
	for _, ev := range in.Events {
		if e == nil {
			_, e = a.d.Store.Exec(r.Context(), `INSERT INTO webhook_subscriptions(endpoint_id,event_name) VALUES($1,$2)`, id, ev)
		}
	}
	if e != nil {
		a.apiErr(w, r, 400, "invalid_endpoint", "Endpoint rejected", nil)
		return
	}
	writeJSONStatus(w, 201, map[string]any{"id": id, "secret": secret})
}
func (a *App) webhookPatch(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	var in struct {
		Description string
		Enabled     *bool
	}
	if !a.decodeJSON(w, r, &in) {
		return
	}
	e := a.d.Store.DisableWebhookEndpoint(r.Context(), r.PathValue("id"), in.Description, in.Enabled)
	if errors.Is(e, pgx.ErrNoRows) {
		a.apiErr(w, r, 404, "not_found", "Endpoint not found", nil)
		return
	}
	if e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to update endpoint", nil)
		return
	}
	writeJSON(w, 200, map[string]bool{"updated": true})
}
func (a *App) webhookDelete(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	e := a.d.Store.DeleteWebhookEndpoint(r.Context(), r.PathValue("id"))
	if errors.Is(e, pgx.ErrNoRows) {
		a.apiErr(w, r, 404, "not_found", "Endpoint not found", nil)
		return
	}
	if e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to delete endpoint", nil)
		return
	}
	w.WriteHeader(204)
}
func (a *App) webhookRotate(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	secret, e := secure.Random(32)
	if e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to rotate secret", nil)
		return
	}
	cipher, e := webhook.Encrypt(a.cfg.WebhookEncryptionKey, []byte(secret))
	if e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to rotate secret", nil)
		return
	}
	tag, e := a.d.Store.Exec(r.Context(), `UPDATE webhook_endpoints SET secret_ciphertext=$2,updated_at=now() WHERE id=$1`, r.PathValue("id"), cipher)
	if e != nil || tag.RowsAffected() != 1 {
		a.apiErr(w, r, 404, "not_found", "Endpoint not found", nil)
		return
	}
	writeJSON(w, 200, map[string]string{"secret": secret})
}
func (a *App) webhookDeliveries(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	rows, e := a.d.Store.Query(r.Context(), `SELECT id,event_id,status,attempts,available_at,last_status_code,last_error,delivered_at,created_at FROM webhook_deliveries WHERE endpoint_id=$1 ORDER BY created_at DESC LIMIT $2`, r.PathValue("id"), boundedLimit(r))
	if e != nil {
		a.apiErr(w, r, 500, "internal_error", "Unable to list deliveries", nil)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, event, status string
		var attempts int
		var available, created time.Time
		var code *int
		var last *string
		var delivered *time.Time
		_ = rows.Scan(&id, &event, &status, &attempts, &available, &code, &last, &delivered, &created)
		items = append(items, map[string]any{"id": id, "event_id": event, "status": status, "attempts": attempts, "available_at": available, "last_status_code": code, "last_error": last, "delivered_at": delivered, "created_at": created})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (a *App) webhookRetry(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.apiErr(w, r, 403, "forbidden", "Admin required", nil)
		return
	}
	tag, e := a.d.Store.Exec(r.Context(), `UPDATE webhook_deliveries SET status='pending',available_at=now(),lease_owner=NULL,lease_expires_at=NULL WHERE id=$1 AND status='failed'`, r.PathValue("id"))
	if e != nil || tag.RowsAffected() != 1 {
		a.apiErr(w, r, 409, "not_retryable", "Delivery not retryable", nil)
		return
	}
	writeJSONStatus(w, 202, map[string]bool{"queued": true})
}

func (a *App) queuePart(ctx context.Context, p auth.Principal, id int64, part *multipart.Part) (store.UploadJob, error) {
	f, e := upload.Ingest(a.cfg.QuarantineDir, part)
	if e != nil {
		return store.UploadJob{}, e
	}
	j := store.UploadJob{ID: f.ID, UserID: p.UserID, DiagnoseID: id, DisplayName: f.DisplayName, StorageKey: f.StorageKey, MediaType: f.MediaType, Size: f.Size, SHA256: f.SHA256, Status: "pending"}
	if e = a.d.Store.AddUpload(ctx, j); e != nil {
		_ = removeFile(f.Path)
		return store.UploadJob{}, errors.New("unable to queue upload")
	}
	return j, nil
}
func (a *App) createPAT(ctx context.Context, p auth.Principal, name string, scopes []string, days int) (string, store.PAT, error) {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 80 {
		return "", store.PAT{}, errors.New("name must contain 1-80 characters")
	}
	if days < 1 || days > 90 {
		return "", store.PAT{}, errors.New("expiration must be 1-90 days")
	}
	allowed := map[string]bool{"services:read": true, "evidence:read": true, "evidence:write": true}
	seen := map[string]bool{}
	for _, s := range scopes {
		if !allowed[s] || seen[s] {
			return "", store.PAT{}, errors.New("invalid scopes")
		}
		seen[s] = true
	}
	if len(scopes) == 0 {
		return "", store.PAT{}, errors.New("at least one scope required")
	}
	id, e := secure.UUID()
	if e != nil {
		return "", store.PAT{}, errors.New("secure token generation unavailable")
	}
	secret, e := secure.Random(32)
	if e != nil {
		return "", store.PAT{}, errors.New("secure token generation unavailable")
	}
	plain := "sela_" + id + "_" + secret
	pat, e := a.d.Store.CreatePAT(ctx, p.UserID, name, secure.Hash(a.cfg.PATHashKey, plain), scopes, a.d.Now().Add(time.Duration(days)*24*time.Hour))
	return plain, pat, e
}
func (a *App) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, e := a.session(r)
		if e != nil {
			http.Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.RequestURI()), 303)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, s.Principal)
		ctx = context.WithValue(ctx, sessionKey, s)
		next(w, r.WithContext(ctx))
	}
}
func (a *App) session(r *http.Request) (store.Session, error) {
	if a.d.Store == nil {
		return store.Session{}, errors.New("session unavailable")
	}
	c, e := r.Cookie("__Host-sela_session")
	if e != nil {
		return store.Session{}, e
	}
	now := a.d.Now()
	return a.d.Store.Session(r.Context(), secure.Hash(a.cfg.SessionHashKey, c.Value), now, now.Add(a.cfg.SessionIdle))
}
func (a *App) validCSRF(r *http.Request) bool {
	if !sameOrigin(r, a.cfg.PublicURL) {
		return false
	}
	provided := r.Header.Get("X-CSRF-Token")
	if provided == "" {
		provided = r.FormValue("csrf_token")
	}
	return a.validCSRFToken(r, provided)
}
func (a *App) validCSRFToken(r *http.Request, provided string) bool {
	c, e := r.Cookie("sela_csrf")
	if e != nil {
		return false
	}
	s, ok := r.Context().Value(sessionKey).(store.Session)
	return ok && secure.Equal(secure.Hash(a.cfg.SessionHashKey, c.Value), s.CSRFHash) && hmac.Equal([]byte(c.Value), []byte(provided))
}
func (a *App) signFlow(f auth.Flow) (string, error) {
	b, e := json.Marshal(f)
	if e != nil {
		return "", e
	}
	payload := base64.RawURLEncoding.EncodeToString(b)
	sig := base64.RawURLEncoding.EncodeToString(secure.Hash(a.cfg.SessionHashKey, payload))
	return payload + "." + sig, nil
}
func (a *App) parseFlow(v string) (auth.Flow, error) {
	p := strings.Split(v, ".")
	if len(p) != 2 {
		return auth.Flow{}, errors.New("bad flow")
	}
	want := secure.Hash(a.cfg.SessionHashKey, p[0])
	got, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil || !secure.Equal(want, got) {
		return auth.Flow{}, errors.New("bad flow")
	}
	b, e := base64.RawURLEncoding.DecodeString(p[0])
	var f auth.Flow
	if e != nil || json.Unmarshal(b, &f) != nil || a.d.Now().After(f.Expires) {
		return f, errors.New("expired flow")
	}
	return f, nil
}
func (a *App) render(w http.ResponseWriter, r *http.Request, name string, d pageData) {
	nonce, err := secure.Random(18)
	if err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	d.AppName = a.cfg.AppName
	d.Nonce = nonce
	d.CSRF = csrfCookie(r)
	d.RequestID = requestID(r)
	d.GTMHead, d.GTMBody = gtmMarkup(a.cfg.GTMContainerID, nonce)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	formAction := "'self'"
	if u, e := url.Parse(a.cfg.EntraAuthURL); e == nil && u.Scheme == "https" && u.Hostname() == "login.microsoftonline.com" && u.Port() == "" {
		formAction += " https://login.microsoftonline.com"
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-"+nonce+"' https://www.googletagmanager.com https://challenges.cloudflare.com; frame-src https://www.googletagmanager.com https://challenges.cloudflare.com; style-src 'self'; img-src 'self' data:; connect-src 'self' https://www.googletagmanager.com https://challenges.cloudflare.com; base-uri 'none'; form-action "+formAction+"; frame-ancestors 'none'")
	if e := a.templates[name].ExecuteTemplate(w, "layout", d); e != nil {
		slog.Error("render failed", "request_id", requestID(r), "error", e)
	}
}
func (a *App) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	w.WriteHeader(status)
	a.render(w, r, "error", pageData{Title: "Terjadi masalah", Error: msg})
}
func (a *App) apiErr(w http.ResponseWriter, r *http.Request, status int, code, msg string, fields map[string]string) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = msg
	e.Error.RequestID = requestID(r)
	e.Error.Fields = fields
	writeJSONStatus(w, status, e)
}
func principal(r *http.Request) auth.Principal {
	p, _ := r.Context().Value(principalKey).(auth.Principal)
	return p
}
func scope(r *http.Request, want string) bool {
	p := principal(r)
	if !p.ViaPAT {
		return p.Role == "technician" || p.Role == "admin"
	}
	for _, s := range p.Scopes {
		if s == want {
			return true
		}
	}
	return false
}
func (a *App) decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		a.apiErr(w, r, 400, "invalid_json", "Invalid JSON request", nil)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		a.apiErr(w, r, 400, "invalid_json", "Invalid JSON request", nil)
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) { writeJSONStatus(w, status, v) }
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func gtmMarkup(id, nonce string) (template.HTML, template.HTML) {
	if !gtmIDPattern.MatchString(id) {
		return "", ""
	}
	head := `<script nonce="` + nonce + `">window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}gtag('consent','default',{'analytics_storage':'denied','ad_storage':'denied'});</script><script nonce="` + nonce + `">(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],j=d.createElement(s);j.async=true;j.src='https://www.googletagmanager.com/gtm.js?id='+i;f.parentNode.insertBefore(j,f)})(window,document,'script','dataLayer','` + id + `');</script>`
	body := `<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=` + id + `" height="0" width="0" class="gtm-frame" title="Google Tag Manager"></iframe></noscript>`
	return template.HTML(head), template.HTML(body) // #nosec G203 -- ID allowlisted, nonce generated server-side.
}
func requestMiddleware(cfg config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if len(id) < 8 || len(id) > 128 {
			var err error
			id, err = secure.Random(16)
			if err != nil {
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		ctx := context.WithValue(r.Context(), contextKey(9), id)
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
		if cfg.Environment == "production" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func requestID(r *http.Request) string { s, _ := r.Context().Value(contextKey(9)).(string); return s }
func csrfCookie(r *http.Request) string {
	c, _ := r.Cookie("sela_csrf")
	if c == nil {
		return ""
	}
	return c.Value
}
func sessionCookie(v string, max int) *http.Cookie {
	return &http.Cookie{Name: "__Host-sela_session", Value: v, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: max}
}
func clientIP(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return host
	}
	return r.RemoteAddr
}
func sameOrigin(r *http.Request, public string) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, e := url.Parse(public)
	v, e2 := url.Parse(o)
	return e == nil && e2 == nil && strings.EqualFold(u.Scheme, v.Scheme) && strings.EqualFold(u.Host, v.Host)
}
func parseID(s string) (int64, error) {
	i, e := strconv.ParseInt(s, 10, 64)
	if e != nil || i <= 0 {
		return 0, errors.New("invalid id")
	}
	return i, nil
}
func boundedLimit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n < 1 {
		n = 20
	}
	if n > 100 {
		n = 100
	}
	return n
}
func validEvent(s string) bool {
	switch s {
	case "evidence.upload.queued.v1", "evidence.upload.succeeded.v1", "evidence.upload.failed.v1", "pat.created.v1", "pat.revoked.v1":
		return true
	}
	return false
}
func removeFile(p string) error { return os.Remove(p) }

var _ = pgx.ErrNoRows
