package notify

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// Mailer sends email over SMTP. SMTP_URL forms:
//
//	smtp://user:pass@host:587   (STARTTLS, required)
//	smtps://user:pass@host:465  (implicit TLS)
//	smtp://host:25?insecure=1   (no TLS, local relay only)
//
// SPF, DKIM and DMARC are configured at the mail server / DNS level for the
// From domain (see docs/operations.md).
type Mailer struct {
	host, addr string
	auth       smtp.Auth
	implicit   bool
	insecure   bool
	From       string
	fromAddr   string
	domain     string
}

func NewMailer(rawURL, from string) (*Mailer, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("SMTP_URL: %w", err)
	}
	m := &Mailer{host: u.Hostname(), From: from}
	port := u.Port()
	switch u.Scheme {
	case "smtps":
		m.implicit = true
		if port == "" {
			port = "465"
		}
	case "smtp":
		if port == "" {
			port = "587"
		}
	default:
		return nil, errors.New("SMTP_URL must start with smtp:// or smtps://")
	}
	m.insecure = u.Query().Get("insecure") == "1"
	m.addr = net.JoinHostPort(m.host, port)
	if u.User != nil {
		pw, _ := u.User.Password()
		m.auth = smtp.PlainAuth("", u.User.Username(), pw, m.host)
	}
	fa, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("SMTP_FROM: %w", err)
	}
	m.fromAddr = fa.Address
	m.domain = fa.Address[strings.LastIndex(fa.Address, "@")+1:]
	return m, nil
}

type Mail struct {
	To      string
	Subject string
	Text    string
	HTML    string
	Unsub   string // https link for List-Unsubscribe
}

func (m *Mailer) Send(ctx context.Context, msg Mail) error {
	if _, err := mail.ParseAddress(msg.To); err != nil {
		return PermanentError{fmt.Errorf("invalid recipient: %w", err)}
	}
	raw := m.build(msg)
	done := make(chan error, 1)
	go func() { done <- m.deliver(msg.To, raw) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(60 * time.Second):
		return errors.New("smtp timeout")
	}
}

func (m *Mailer) deliver(to string, raw []byte) error {
	var c *smtp.Client
	tlsCfg := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}
	if m.implicit {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", m.addr, tlsCfg)
		if err != nil {
			return err
		}
		c, err = smtp.NewClient(conn, m.host)
		if err != nil {
			return err
		}
	} else {
		conn, err := net.DialTimeout("tcp", m.addr, 15*time.Second)
		if err != nil {
			return err
		}
		c, err = smtp.NewClient(conn, m.host)
		if err != nil {
			return err
		}
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				c.Close()
				return err
			}
		} else if !m.insecure {
			c.Close()
			return errors.New("smtp server does not offer STARTTLS (add ?insecure=1 for a local relay)")
		}
	}
	defer c.Close()
	if m.auth != nil {
		if err := c.Auth(m.auth); err != nil {
			return err
		}
	}
	if err := c.Mail(m.fromAddr); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		var te *textproto.Error
		if errors.As(err, &te) && te.Code >= 500 {
			return PermanentError{err}
		}
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (m *Mailer) build(msg Mail) []byte {
	var b strings.Builder
	id := make([]byte, 12)
	rand.Read(id)
	boundary := "yc-" + hex.EncodeToString(id)
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", m.From)
	h("To", msg.To)
	h("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	h("Date", time.Now().Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id)+"@"+m.domain+">")
	h("MIME-Version", "1.0")
	h("Auto-Submitted", "auto-generated")
	if msg.Unsub != "" {
		h("List-Unsubscribe", "<"+msg.Unsub+">")
		h("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
	}
	h("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	part := func(ct, body string) {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + ct + "; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
		qp := quotedprintable.NewWriter(&b)
		qp.Write([]byte(body))
		qp.Close()
		b.WriteString("\r\n")
	}
	part("text/plain", msg.Text)
	if msg.HTML != "" {
		part("text/html", msg.HTML)
	}
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

// SendNotification renders a CVE notification.
func (m *Mailer) SendNotification(ctx context.Context, to string, msg Message) error {
	var t, hb strings.Builder
	t.WriteString(msg.Title + "\n\n")
	hb.WriteString(`<div style="font-family:system-ui,sans-serif;max-width:640px">`)
	hb.WriteString("<h2>" + html.EscapeString(msg.Title) + "</h2>")
	if len(msg.Items) == 0 {
		t.WriteString(msg.Text + "\n")
		hb.WriteString("<p>" + html.EscapeString(msg.Text) + "</p>")
	}
	for _, it := range msg.Items {
		t.WriteString(it.CVEID + occasionSuffix(it.Occasion) + " — " + scoreText(it) + "\n")
		t.WriteString("Stack: " + it.Stack + "\n")
		if it.Reason != "" {
			t.WriteString("Match: " + it.Reason + "\n")
		}
		t.WriteString(it.Summary + "\n")
		if it.AI {
			t.WriteString("(AI generated)\n")
		}
		t.WriteString(it.URL + "\n\n")
		color := fmt.Sprintf("#%06x", severityColor[it.Severity])
		hb.WriteString(`<div style="border-left:4px solid ` + color + `;padding:4px 12px;margin:12px 0">`)
		hb.WriteString(`<a href="` + html.EscapeString(it.URL) + `"><b>` + html.EscapeString(it.CVEID) + "</b></a>" +
			html.EscapeString(occasionSuffix(it.Occasion)) + " · " + html.EscapeString(scoreText(it)) + "<br>")
		hb.WriteString("<small>Stack: " + html.EscapeString(it.Stack) + " · " + html.EscapeString(it.Reason) + "</small>")
		hb.WriteString("<p>" + html.EscapeString(it.Summary))
		if it.AI {
			hb.WriteString(` <small style="color:#666">(AI generated)</small>`)
		}
		hb.WriteString("</p></div>")
	}
	if msg.URL != "" {
		t.WriteString(msg.URL + "\n")
	}
	if msg.Unsub != "" {
		t.WriteString("\nUnsubscribe: " + msg.Unsub + "\n")
		hb.WriteString(`<p style="color:#666;font-size:12px">You receive this because this address is a notification channel in yourcve. <a href="` +
			html.EscapeString(msg.Unsub) + `">Unsubscribe</a></p>`)
	}
	hb.WriteString("</div>")
	return m.Send(ctx, Mail{To: to, Subject: msg.Title, Text: t.String(), HTML: hb.String(), Unsub: msg.Unsub})
}

// SendLink sends a magic link / confirmation link.
func (m *Mailer) SendLink(ctx context.Context, to, subject, intro, link, action string) error {
	text := intro + "\n\n" + link + "\n\nThe link is valid for 30 minutes. If you did not request this, ignore this email.\n"
	htm := `<div style="font-family:system-ui,sans-serif;max-width:560px"><p>` + html.EscapeString(intro) +
		`</p><p><a href="` + html.EscapeString(link) + `" style="display:inline-block;padding:10px 18px;background:#111;color:#fff;border-radius:6px;text-decoration:none">` +
		html.EscapeString(action) + `</a></p><p style="color:#666;font-size:12px">The link is valid for 30 minutes. If you did not request this, ignore this email.</p></div>`
	return m.Send(ctx, Mail{To: to, Subject: subject, Text: text, HTML: htm})
}
