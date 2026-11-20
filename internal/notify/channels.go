package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/containrrr/shoutrrr"
	"github.com/containrrr/shoutrrr/pkg/types"
)

type Field struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Secret      bool   `json:"secret"`
	Required    bool   `json:"required"`
	Help        string `json:"help,omitempty"`
}

type ChannelType struct {
	Type      string  `json:"type"`
	Label     string  `json:"label"`
	Class     string  `json:"class"` // free, paid
	Available bool    `json:"available"`
	Fields    []Field `json:"fields"`
}

const comingSoon = "Coming soon: Plus for 9.99 €/month"

var Types = []ChannelType{
	{Type: "discord", Label: "Discord", Class: "free", Available: true, Fields: []Field{
		{Key: "webhook_url", Label: "Webhook URL", Placeholder: "https://discord.com/api/webhooks/…", Secret: true, Required: true,
			Help: "Server settings → Integrations → Webhooks → New Webhook → Copy URL"}}},
	{Type: "slack", Label: "Slack", Class: "free", Available: true, Fields: []Field{
		{Key: "webhook_url", Label: "Incoming webhook URL", Placeholder: "https://hooks.slack.com/services/…", Secret: true, Required: true}}},
	{Type: "teams", Label: "Microsoft Teams", Class: "free", Available: true, Fields: []Field{
		{Key: "webhook_url", Label: "Workflows webhook URL", Placeholder: "https://….webhook.office.com/… or https://prod-….logic.azure.com/…", Secret: true, Required: true,
			Help: "Teams channel → Workflows → \"Post to a channel when a webhook request is received\""}}},
	{Type: "mattermost", Label: "Mattermost", Class: "free", Available: true, Fields: []Field{
		{Key: "webhook_url", Label: "Incoming webhook URL", Placeholder: "https://mattermost.example.com/hooks/…", Secret: true, Required: true}}},
	{Type: "telegram", Label: "Telegram", Class: "free", Available: true, Fields: []Field{
		{Key: "bot_token", Label: "Bot token", Placeholder: "123456:ABC…", Secret: true, Required: true, Help: "Create a bot with @BotFather"},
		{Key: "chat_id", Label: "Chat ID or @channel", Placeholder: "@mychannel or -100123…", Required: true}}},
	{Type: "matrix", Label: "Matrix", Class: "free", Available: true, Fields: []Field{
		{Key: "homeserver", Label: "Homeserver", Placeholder: "matrix.example.org", Required: true},
		{Key: "user", Label: "User", Placeholder: "cvebot", Required: true},
		{Key: "password", Label: "Password", Secret: true, Required: true},
		{Key: "room", Label: "Room", Placeholder: "!roomid:example.org or #alias:example.org", Required: true}}},
	{Type: "ntfy", Label: "ntfy", Class: "free", Available: true, Fields: []Field{
		{Key: "server", Label: "Server", Placeholder: "ntfy.sh", Required: false, Help: "Default ntfy.sh"},
		{Key: "topic", Label: "Topic", Placeholder: "my-cve-alerts", Required: true},
		{Key: "token", Label: "Access token", Secret: true}}},
	{Type: "gotify", Label: "Gotify", Class: "free", Available: true, Fields: []Field{
		{Key: "server", Label: "Server", Placeholder: "gotify.example.com", Required: true},
		{Key: "app_token", Label: "Application token", Secret: true, Required: true}}},
	{Type: "pushover", Label: "Pushover", Class: "free", Available: true, Fields: []Field{
		{Key: "api_token", Label: "Application API token", Secret: true, Required: true},
		{Key: "user_key", Label: "User key", Secret: true, Required: true}}},
	{Type: "webhook", Label: "Generic webhook", Class: "free", Available: true, Fields: []Field{
		{Key: "url", Label: "URL", Placeholder: "https://example.com/hooks/cve", Required: true, Help: "HTTPS only. JSON POST, signed with X-Yourcve-Signature: sha256=HMAC(secret, body)"},
		{Key: "secret", Label: "Signing secret", Secret: true, Help: "Leave empty to generate one"}}},
	{Type: "email", Label: "Email", Class: "free", Available: true, Fields: []Field{
		{Key: "address", Label: "Email address", Placeholder: "security@example.com", Required: true, Help: "You will get a confirmation link (double opt-in)"}}},
	{Type: "sms", Label: "SMS", Class: "paid", Available: false, Fields: []Field{
		{Key: "phone", Label: "Phone number", Placeholder: "+49…", Required: true, Help: comingSoon}}},
	{Type: "whatsapp", Label: "WhatsApp", Class: "paid", Available: false, Fields: []Field{
		{Key: "phone", Label: "Phone number", Placeholder: "+49…", Required: true, Help: comingSoon}}},
	{Type: "voice", Label: "Voice call", Class: "paid", Available: false, Fields: []Field{
		{Key: "phone", Label: "Phone number", Placeholder: "+49…", Required: true, Help: comingSoon + " (critical CVEs only)"}}},
}

func TypeByName(t string) (ChannelType, bool) {
	for _, ct := range Types {
		if ct.Type == t {
			return ct, true
		}
	}
	return ChannelType{}, false
}

// Mask hides secret config values for API output.
func Mask(typ string, cfg map[string]string) map[string]string {
	ct, _ := TypeByName(typ)
	out := map[string]string{}
	for _, f := range ct.Fields {
		v, ok := cfg[f.Key]
		if !ok || v == "" {
			continue
		}
		if f.Secret {
			v = "••••"
		}
		out[f.Key] = v
	}
	return out
}

// Message is what a channel renders.
type Message struct {
	Title    string
	Text     string // plain text body
	URL      string // link to the CVE / delivery log
	Severity string // critical, high, ... (for colors)
	Items    []Item // structured CVEs (digest has several)
	Unsub    string // unsubscribe link (email)
}

type Item struct {
	CVEID    string   `json:"cve_id"`
	Severity string   `json:"severity"`
	CVSS     *float64 `json:"cvss"`
	KEV      bool     `json:"kev"`
	EPSS     *float64 `json:"epss"`
	Stack    string   `json:"stack"`
	Reason   string   `json:"reason"`
	Summary  string   `json:"summary"`
	AI       bool     `json:"ai_generated"`
	Occasion string   `json:"occasion"`
	URL      string   `json:"url"`
}

// Sender delivers messages.
type Sender struct {
	Guard  Guard
	Mailer *Mailer
	client *http.Client
}

func NewSender(g Guard, m *Mailer) *Sender { return &Sender{Guard: g, Mailer: m, client: g.Client()} }

var (
	discordRe = regexp.MustCompile(`^https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(\d+)/([\w-]+)`)
	slackRe   = regexp.MustCompile(`^https://hooks\.slack\.com/(services|triggers|workflows)/`)
)

// Validate checks and normalizes a channel config before it is stored.
func (s *Sender) Validate(ctx context.Context, typ string, cfg map[string]string) error {
	ct, ok := TypeByName(typ)
	if !ok {
		return errors.New("unknown channel type")
	}
	for k, v := range cfg {
		cfg[k] = strings.TrimSpace(v)
	}
	for _, f := range ct.Fields {
		if f.Required && cfg[f.Key] == "" {
			return fmt.Errorf("%s is required", f.Label)
		}
	}
	for k := range cfg {
		known := false
		for _, f := range ct.Fields {
			known = known || f.Key == k
		}
		if !known {
			delete(cfg, k)
		}
	}
	switch typ {
	case "discord":
		if !discordRe.MatchString(cfg["webhook_url"]) {
			return errors.New("not a Discord webhook URL")
		}
	case "slack":
		if !slackRe.MatchString(cfg["webhook_url"]) {
			return errors.New("not a Slack webhook URL (https://hooks.slack.com/…)")
		}
	case "teams", "mattermost":
		return s.Guard.CheckURL(ctx, cfg["webhook_url"], true)
	case "webhook":
		if cfg["secret"] == "" {
			b := make([]byte, 24)
			rand.Read(b)
			cfg["secret"] = hex.EncodeToString(b)
		}
		return s.Guard.CheckURL(ctx, cfg["url"], true)
	case "email":
		a, err := mail.ParseAddress(cfg["address"])
		if err != nil || !strings.Contains(a.Address, "@") {
			return errors.New("invalid email address")
		}
		cfg["address"] = strings.ToLower(a.Address)
	case "ntfy":
		if cfg["server"] == "" {
			cfg["server"] = "ntfy.sh"
		}
		return s.Guard.CheckHost(ctx, hostOnly(cfg["server"]))
	case "gotify":
		return s.Guard.CheckHost(ctx, hostOnly(cfg["server"]))
	case "matrix":
		return s.Guard.CheckHost(ctx, hostOnly(cfg["homeserver"]))
	}
	return nil
}

func hostOnly(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/"); i >= 0 {
		s = s[:i]
	}
	if h, _, ok := strings.Cut(s, ":"); ok && !strings.Contains(h, "[") {
		return h
	}
	return s
}

func hostPort(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/"); i >= 0 {
		s = s[:i]
	}
	return s
}

// Send delivers one message. Errors are returned for retry.
func (s *Sender) Send(ctx context.Context, typ string, cfg map[string]string, m Message) error {
	switch typ {
	case "discord":
		return s.discord(ctx, cfg["webhook_url"], m)
	case "slack", "mattermost":
		return s.postJSON(ctx, cfg["webhook_url"], map[string]any{"text": "*" + m.Title + "*\n" + m.Text + "\n" + m.URL}, nil)
	case "teams":
		return s.teams(ctx, cfg["webhook_url"], m)
	case "webhook":
		return s.webhook(ctx, cfg, m)
	case "email":
		if s.Mailer == nil {
			return errors.New("email is not configured on this instance (SMTP_URL)")
		}
		return s.Mailer.SendNotification(ctx, cfg["address"], m)
	case "telegram", "matrix", "ntfy", "gotify", "pushover":
		return s.shoutrrr(ctx, typ, cfg, m)
	case "sms", "whatsapp", "voice":
		return errors.New("paid channels are not available yet (Plus plan coming soon)")
	}
	return fmt.Errorf("unknown channel type %q", typ)
}

// shoutrrrURL builds the Shoutrrr service URL from the form fields.
func shoutrrrURL(typ string, c map[string]string) (string, string, error) {
	esc := url.PathEscape
	switch typ {
	case "telegram":
		return "telegram://" + c["bot_token"] + "@telegram?chats=" + url.QueryEscape(c["chat_id"]) + "&parsemode=None&preview=No", "api.telegram.org", nil
	case "matrix":
		return "matrix://" + url.UserPassword(c["user"], c["password"]).String() + "@" + hostPort(c["homeserver"]) +
			"/?rooms=" + url.QueryEscape(c["room"]), hostOnly(c["homeserver"]), nil
	case "ntfy":
		server := c["server"]
		if server == "" {
			server = "ntfy.sh"
		}
		auth := ""
		if c["token"] != "" {
			auth = ":" + esc(c["token"]) + "@"
		}
		return "ntfy://" + auth + hostPort(server) + "/" + esc(c["topic"]), hostOnly(server), nil
	case "gotify":
		return "gotify://" + hostPort(c["server"]) + "/" + esc(c["app_token"]), hostOnly(c["server"]), nil
	case "pushover":
		return "pushover://shoutrrr:" + esc(c["api_token"]) + "@" + esc(c["user_key"]) + "/", "api.pushover.net", nil
	}
	return "", "", errors.New("unsupported")
}

func (s *Sender) shoutrrr(ctx context.Context, typ string, cfg map[string]string, m Message) error {
	u, host, err := shoutrrrURL(typ, cfg)
	if err != nil {
		return err
	}
	// Shoutrrr dials itself: re-check the resolved host right before sending
	if err := s.Guard.CheckHost(ctx, host); err != nil {
		return err
	}
	sender, err := shoutrrr.CreateSender(u)
	if err != nil {
		return fmt.Errorf("invalid %s settings: %w", typ, err)
	}
	params := types.Params{"title": m.Title}
	if typ == "ntfy" && m.URL != "" {
		params["click"] = m.URL
		if m.Severity == "critical" {
			params["priority"] = "5"
		}
	}
	text := m.Text + "\n" + m.URL
	done := make(chan []error, 1)
	go func() { done <- sender.Send(text, &params) }()
	select {
	case errs := <-done:
		return errors.Join(errs...)
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(30 * time.Second):
		return errors.New("timeout")
	}
}

var severityColor = map[string]int{"critical": 0xB91C1C, "high": 0xEA580C, "medium": 0xCA8A04, "low": 0x2563EB}

func (s *Sender) discord(ctx context.Context, hook string, m Message) error {
	embeds := []map[string]any{}
	for i, it := range m.Items {
		if i >= 10 {
			break
		}
		desc := it.Summary
		if it.AI {
			desc += "\n*AI generated*"
		}
		fields := []map[string]any{{"name": "Stack", "value": nz(it.Stack), "inline": true},
			{"name": "Severity", "value": scoreText(it), "inline": true}}
		if it.Reason != "" {
			fields = append(fields, map[string]any{"name": "Match", "value": truncate(it.Reason, 1000)})
		}
		embeds = append(embeds, map[string]any{
			"title": it.CVEID + occasionSuffix(it.Occasion), "url": it.URL, "description": truncate(desc, 3500),
			"color": severityColor[it.Severity], "fields": fields,
		})
	}
	body := map[string]any{"content": truncate(m.Title, 1900), "embeds": embeds, "allowed_mentions": map[string]any{"parse": []string{}}}
	if len(m.Items) > 10 {
		body["content"] = truncate(m.Title+fmt.Sprintf(" (+%d more, see %s)", len(m.Items)-10, m.URL), 1900)
	}
	return s.postJSON(ctx, hook, body, nil)
}

func (s *Sender) teams(ctx context.Context, hook string, m Message) error {
	blocks := []map[string]any{{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": m.Title, "wrap": true},
		{"type": "TextBlock", "text": m.Text, "wrap": true}}
	card := map[string]any{"type": "message", "attachments": []map[string]any{{
		"contentType": "application/vnd.microsoft.card.adaptive",
		"content": map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
			"version": "1.4", "body": blocks,
			"actions": []map[string]any{{"type": "Action.OpenUrl", "title": "Open in yourcve", "url": m.URL}}},
	}}}
	return s.postJSON(ctx, hook, card, nil)
}

// WebhookPayload is the JSON body of the generic webhook.
type WebhookPayload struct {
	Event string    `json:"event"` // cve.match, cve.digest, test
	Title string    `json:"title"`
	Text  string    `json:"text"`
	URL   string    `json:"url"`
	Items []Item    `json:"items"`
	Sent  time.Time `json:"sent_at"`
}

func (s *Sender) webhook(ctx context.Context, cfg map[string]string, m Message) error {
	ev := "cve.match"
	if len(m.Items) > 1 {
		ev = "cve.digest"
	}
	if len(m.Items) == 0 {
		ev = "test"
	}
	body, _ := json.Marshal(WebhookPayload{Event: ev, Title: m.Title, Text: m.Text, URL: m.URL, Items: m.Items, Sent: time.Now().UTC()})
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(cfg["secret"]))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	hdr := map[string]string{
		"X-Yourcve-Event":     ev,
		"X-Yourcve-Timestamp": ts,
		"X-Yourcve-Signature": "sha256=" + hex.EncodeToString(mac.Sum(nil)),
	}
	return s.postRaw(ctx, cfg["url"], body, hdr)
}

func (s *Sender) postJSON(ctx context.Context, u string, v any, hdr map[string]string) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.postRaw(ctx, u, b, hdr)
}

// PermanentError marks failures that will not succeed on retry.
type PermanentError struct{ Err error }

func (e PermanentError) Error() string { return e.Err.Error() }
func (e PermanentError) Unwrap() error { return e.Err }

func (s *Sender) postRaw(ctx context.Context, u string, body []byte, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return PermanentError{err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "yourcve-notifier/1.0")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		if errors.Is(err, ErrPrivateTarget) {
			return PermanentError{err}
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	err = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		return PermanentError{err}
	}
	return err
}

func scoreText(it Item) string {
	s := strings.ToUpper(it.Severity)
	if it.CVSS != nil {
		s += fmt.Sprintf(" %.1f", *it.CVSS)
	}
	if it.KEV {
		s += " · KEV"
	}
	if it.EPSS != nil {
		s += fmt.Sprintf(" · EPSS %.1f%%", *it.EPSS*100)
	}
	return s
}

func occasionSuffix(o string) string {
	switch o {
	case "kev_added":
		return " — now actively exploited (KEV)"
	case "cvss_raised":
		return " — severity raised"
	}
	return ""
}

func nz(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
