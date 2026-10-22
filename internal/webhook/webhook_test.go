package webhook

import (
	"context"
	"net"
	"testing"
)

type resolver struct{ ips []net.IP }

func (r resolver) LookupIP(context.Context, string, string) ([]net.IP, error) { return r.ips, nil }
func TestSignatureVector(t *testing.T) {
	got := Signature([]byte("secret"), 1700000000, []byte(`{"id":"1"}`))
	const want = "CG9q_3vQhMmGeYJRKcWmTbrYjHYAFtbSwPsSPyeVHVQ"
	if got != want {
		t.Fatalf("got %s", got)
	}
	if !Verify([]byte("secret"), 1700000000, []byte(`{"id":"1"}`), got) {
		t.Fatal("verify failed")
	}
}
func TestSSRFBlocksPrivateAndAllowsPublic(t *testing.T) {
	d := Deliverer{Resolver: resolver{[]net.IP{net.ParseIP("127.0.0.1")}}}
	if _, _, e := d.Validate(context.Background(), "https://example.com/h"); e == nil {
		t.Fatal("private allowed")
	}
	d.Resolver = resolver{[]net.IP{net.ParseIP("93.184.216.34")}}
	if _, _, e := d.Validate(context.Background(), "https://example.com/h"); e != nil {
		t.Fatal(e)
	}
}
func TestEncryption(t *testing.T) {
	key := make([]byte, 32)
	c, e := Encrypt(key, []byte("secret"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := Decrypt(key, c)
	if e != nil || string(p) != "secret" {
		t.Fatalf("%q %v", p, e)
	}
}
