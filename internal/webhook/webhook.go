package webhook

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func Encrypt(key, plain []byte) ([]byte, error) { return EncryptWithAAD(key, plain, nil) }
func EncryptWithAAD(key, plain, aad []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return append(n, g.Seal(nil, n, plain, aad)...), nil
}
func Decrypt(key, data []byte) ([]byte, error) { return DecryptWithAAD(key, data, nil) }
func DecryptWithAAD(key, data, aad []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if len(data) < g.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}
	return g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], aad)
}
func Signature(secret []byte, timestamp int64, body []byte) string {
	h := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(h, strconv.FormatInt(timestamp, 10)+".")
	_, _ = h.Write(body)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func Verify(secret []byte, timestamp int64, body []byte, sig string) bool {
	got, e := base64.RawURLEncoding.DecodeString(sig)
	if e != nil {
		return false
	}
	want, e := base64.RawURLEncoding.DecodeString(Signature(secret, timestamp, body))
	return e == nil && hmac.Equal(got, want)
}

type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}
type Deliverer struct {
	Resolver Resolver
	Timeout  time.Duration
	Now      func() time.Time
}

func (d Deliverer) Validate(ctx context.Context, raw string) (*url.URL, net.IP, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, nil, errors.New("webhook URL must be HTTPS without credentials")
	}
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	ips, e := r.LookupIP(ctx, "ip", u.Hostname())
	if e != nil || len(ips) == 0 {
		return nil, nil, errors.New("webhook DNS resolution failed")
	}
	for _, ip := range ips {
		if blocked(ip) {
			return nil, nil, errors.New("webhook destination resolves to blocked network")
		}
	}
	return u, ips[0], nil
}
func (d Deliverer) Deliver(ctx context.Context, raw string, secret, body []byte, eventID string) (int, error) {
	u, ip, e := d.Validate(ctx, raw)
	if e != nil {
		return 0, e
	}
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port(u)))
	}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(string(body)))
	if e != nil {
		return 0, e
	}
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	ts := now.Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sela-webhook/1")
	req.Header.Set("X-SELA-Event-ID", eventID)
	req.Header.Set("X-SELA-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-SELA-Signature-Version", "v1")
	req.Header.Set("X-SELA-Signature", Signature(secret, ts, body))
	res, e := client.Do(req)
	if e != nil {
		return 0, e
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return res.StatusCode, fmt.Errorf("webhook status %d", res.StatusCode)
	}
	return res.StatusCode, nil
}
func blocked(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0 || ip4[0] >= 224 || ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}
	return false
}
func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "443"
}
