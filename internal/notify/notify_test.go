package notify

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestSealRoundTrip(t *testing.T) {
	s, _ := NewSealer("a-very-long-secret-key-for-testing-1234")
	b, err := s.Seal(map[string]string{"webhook_url": "https://discord.com/api/webhooks/1/x"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := s.Open(b, &out); err != nil || out["webhook_url"] == "" {
		t.Fatal(err, out)
	}
	other, _ := NewSealer("another-secret-key-for-testing-5678-xx")
	if other.Open(b, &out) == nil {
		t.Fatal("opened with wrong key")
	}
	b[len(b)-1] ^= 1
	if s.Open(b, &out) == nil {
		t.Fatal("tampered data accepted")
	}
}

func TestPrivateRanges(t *testing.T) {
	for _, a := range []string{"10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254", "::1", "fd00::1", "::ffff:127.0.0.1", "100.64.1.1", "0.0.0.0"} {
		if !IsPrivate(netip.MustParseAddr(a)) {
			t.Errorf("%s should be private", a)
		}
	}
	for _, a := range []string{"1.1.1.1", "8.8.8.8", "2606:4700::1111"} {
		if IsPrivate(netip.MustParseAddr(a)) {
			t.Errorf("%s should be public", a)
		}
	}
}

func TestCheckURL(t *testing.T) {
	g := Guard{}
	ctx := context.Background()
	for _, u := range []string{"http://example.com/x", "https://127.0.0.1/x", "https://localhost/x", "https://[::1]/", "https://10.0.0.1/", "ftp://x"} {
		if g.CheckURL(ctx, u, true) == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestValidateDiscord(t *testing.T) {
	s := NewSender(Guard{}, nil)
	if err := s.Validate(context.Background(), "discord", map[string]string{"webhook_url": "https://evil.example/api/webhooks/1/x"}); err == nil {
		t.Fatal("non discord url accepted")
	}
	cfg := map[string]string{"webhook_url": "https://discord.com/api/webhooks/123/abc-DEF", "junk": "x"}
	if err := s.Validate(context.Background(), "discord", cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["junk"]; ok {
		t.Fatal("unknown field kept")
	}
	if Mask("discord", cfg)["webhook_url"] != "••••" {
		t.Fatal("secret not masked")
	}
}

func TestQuietHours(t *testing.T) {
	s, e, tz := "22:00", "07:00", "Europe/Berlin"
	loc, _ := time.LoadLocation(tz)
	in, until := QuietUntil(time.Date(2026, 11, 20, 23, 30, 0, 0, loc), &s, &e, &tz)
	if !in || until.In(loc).Hour() != 7 || until.In(loc).Day() != 21 {
		t.Fatal(in, until)
	}
	if in, _ := QuietUntil(time.Date(2026, 11, 20, 12, 0, 0, 0, loc), &s, &e, &tz); in {
		t.Fatal("noon is not quiet")
	}
	in, until = QuietUntil(time.Date(2026, 11, 20, 6, 0, 0, 0, loc), &s, &e, &tz)
	if !in || until.In(loc).Day() != 20 {
		t.Fatal(in, until)
	}
}

func TestShoutrrrURLs(t *testing.T) {
	u, host, err := shoutrrrURL("ntfy", map[string]string{"topic": "alerts"})
	if err != nil || u != "ntfy://ntfy.sh/alerts" || host != "ntfy.sh" {
		t.Fatal(u, host, err)
	}
	u, _, _ = shoutrrrURL("telegram", map[string]string{"bot_token": "1:AA", "chat_id": "@chan"})
	if u != "telegram://1:AA@telegram?chats=%40chan&parsemode=None&preview=No" {
		t.Fatal(u)
	}
}
