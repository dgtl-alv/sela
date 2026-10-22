package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Verifier struct {
	Secret, URL string
	Hostnames   []string
	Client      *http.Client
	mu          sync.Mutex
	used        map[string]time.Time
}

func (v *Verifier) Verify(ctx context.Context, token, action, ip string) error {
	if len(token) < 1 || len(token) > 2048 {
		return errors.New("human verification failed")
	}
	v.mu.Lock()
	if v.used == nil {
		v.used = map[string]time.Time{}
	}
	if _, ok := v.used[token]; ok {
		v.mu.Unlock()
		return errors.New("human verification replayed")
	}
	v.mu.Unlock()
	c := v.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	form := url.Values{"secret": {v.Secret}, "response": {token}}
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, v.URL, strings.NewReader(form.Encode()))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, e := c.Do(req)
	if e != nil {
		return errors.New("human verification unavailable")
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if e != nil || len(b) >= 64<<10 {
		return errors.New("human verification invalid")
	}
	var out struct {
		Success          bool `json:"success"`
		Hostname, Action string
		ChallengeTS      time.Time `json:"challenge_ts"`
	}
	if json.Unmarshal(b, &out) != nil || !out.Success || out.Action != action || !contains(v.Hostnames, out.Hostname) || time.Since(out.ChallengeTS) > 10*time.Minute {
		return errors.New("human verification failed")
	}
	v.mu.Lock()
	v.used[token] = time.Now()
	for k, t := range v.used {
		if time.Since(t) > 15*time.Minute {
			delete(v.used, k)
		}
	}
	v.mu.Unlock()
	return nil
}
func contains(a []string, x string) bool {
	for _, v := range a {
		if strings.EqualFold(v, x) {
			return true
		}
	}
	return false
}
