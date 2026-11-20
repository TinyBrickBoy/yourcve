package notify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrPrivateTarget is returned when a channel points into a private network.
var ErrPrivateTarget = errors.New("target address is in a private or reserved network")

var blocked = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32",
	"fc00::/7", "fe80::/10", "ff00::/8",
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s))
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// IsPrivate reports whether the address must not be contacted.
func IsPrivate(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range blocked {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Guard controls outbound connections to user supplied targets.
type Guard struct{ AllowPrivate bool }

// control runs after DNS resolution for every dialed address, so DNS
// rebinding cannot sneak a private address past a pre-check.
func (g Guard) control(network, address string, _ syscall.RawConn) error {
	if g.AllowPrivate {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if IsPrivate(a) {
		return fmt.Errorf("%w (%s)", ErrPrivateTarget, a)
	}
	return nil
}

// Transport returns an HTTP transport that refuses private targets, never
// uses a proxy for user targets and has short timeouts.
func (g Guard) Transport() *http.Transport {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: g.control}
	return &http.Transport{
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          20,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// Client is the HTTP client for webhooks: HTTPS only (unless private targets
// are explicitly allowed for self hosters), no redirects, 10 s timeout.
func (g Guard) Client() *http.Client {
	return &http.Client{
		Transport: g.Transport(),
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// CheckURL validates a user supplied URL before it is stored.
func (g Guard) CheckURL(ctx context.Context, raw string, requireHTTPS bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("invalid URL")
	}
	if requireHTTPS && u.Scheme != "https" && !(g.AllowPrivate && u.Scheme == "http") {
		return errors.New("only https:// URLs are allowed")
	}
	if u.User != nil && requireHTTPS {
		return errors.New("credentials in the URL are not allowed")
	}
	return g.CheckHost(ctx, u.Hostname())
}

// CheckHost resolves a host and rejects private addresses.
func (g Guard) CheckHost(ctx context.Context, host string) error {
	if g.AllowPrivate {
		return nil
	}
	host = strings.Trim(host, "[]")
	if host == "" || strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return ErrPrivateTarget
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if IsPrivate(a) {
			return ErrPrivateTarget
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("cannot resolve %s", host)
	}
	for _, a := range addrs {
		if IsPrivate(a) {
			return fmt.Errorf("%w (%s → %s)", ErrPrivateTarget, host, a)
		}
	}
	return nil
}
