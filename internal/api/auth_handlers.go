package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/tinybrickboy/yourcve/internal/auth"
	"github.com/tinybrickboy/yourcve/internal/notify"
)

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"base_url":          s.Cfg.BaseURL,
		"ai_enabled":        s.AI != nil,
		"email_enabled":     s.Mailer != nil,
		"registration_open": s.Cfg.RegistrationOpen,
		"free_limits":       map[string]int{"stacks": s.Cfg.FreeStacks, "channels": s.Cfg.FreeChannels},
		"imprint_html":      s.imprint,
		"privacy_html":      s.privacy,
	})
}

func (s *Server) getPlans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, []map[string]any{
		{"id": "free", "name": "Free", "price": "0 €", "available": true, "coming_soon": false, "features": []string{
			"Up to " + itoa(s.Cfg.FreeStacks) + " stacks", "Up to " + itoa(s.Cfg.FreeChannels) + " channels",
			"Discord, Slack, Teams, Mattermost, Telegram, Matrix, ntfy, Gotify, Pushover, webhook, email",
			"Unlimited notifications (technical rate limits only)", "REST API and MCP for your local AI"}},
		{"id": "plus", "name": "Plus", "price": "9.99 €/month", "available": false, "coming_soon": true, "features": []string{
			"Everything in Free", "SMS, WhatsApp and voice call alerts", "Monthly credit included", "Automatic fallback to free channels"}},
	})
}

func (s *Server) getChannelTypes(w http.ResponseWriter, r *http.Request) {
	out := []notify.ChannelType{}
	for _, t := range notify.Types {
		if t.Type == "email" && s.Mailer == nil {
			continue
		}
		out = append(out, t)
	}
	writeJSON(w, 200, out)
}

func (s *Server) altcha(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.Allow("altcha:"+s.ip(r), 2*time.Second, 20) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	ch, err := s.Auth.Challenge()
	if err != nil {
		s.internal(w, r, err)
		return
	}
	// the widget reads "maxnumber", the Go library writes "maxNumber": send both
	writeJSON(w, 200, map[string]any{"algorithm": ch.Algorithm, "challenge": ch.Challenge, "maxnumber": ch.MaxNumber,
		"maxNumber": ch.MaxNumber, "salt": ch.Salt, "signature": ch.Signature})
}

type emailCaptcha struct {
	Email  string `json:"email"`
	Altcha string `json:"altcha"`
}

func (s *Server) checkEmailCaptcha(w http.ResponseWriter, r *http.Request, kind string) (string, bool) {
	var in emailCaptcha
	if !decode(w, r, &in) {
		return "", false
	}
	ip := s.ip(r)
	if !s.Auth.Allow(kind+":"+ip, time.Minute, 5) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again in a minute")
		return "", false
	}
	email, err := auth.NormalizeEmail(in.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	if !s.Auth.Allow(kind+"-mail:"+email, 2*time.Minute, 3) {
		writeErr(w, http.StatusTooManyRequests, "too many emails for this address, try again later")
		return "", false
	}
	if !s.Auth.VerifyCaptcha(r.Context(), in.Altcha) {
		writeErr(w, http.StatusBadRequest, "captcha failed, please try again")
		return "", false
	}
	return email, true
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.RegistrationOpen {
		writeErr(w, http.StatusForbidden, "registration is closed")
		return
	}
	email, ok := s.checkEmailCaptcha(w, r, "register")
	if !ok {
		return
	}
	exists, err := s.Auth.UserExists(r.Context(), email)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	purpose, subject, intro, action := "register", "Confirm your yourcve account",
		"Welcome to yourcve! Confirm your email address to finish the registration.", "Confirm email"
	if exists { // same response either way, no account enumeration
		purpose, subject, intro, action = "login", "Your yourcve login link", "Use this link to sign in to yourcve.", "Sign in"
	}
	s.sendLink(r.Context(), email, purpose, subject, intro, action)
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) magicLink(w http.ResponseWriter, r *http.Request) {
	email, ok := s.checkEmailCaptcha(w, r, "login")
	if !ok {
		return
	}
	exists, err := s.Auth.UserExists(r.Context(), email)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if exists {
		s.sendLink(r.Context(), email, "login", "Your yourcve login link", "Use this link to sign in to yourcve.", "Sign in")
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) sendLink(ctx context.Context, email, purpose, subject, intro, action string) {
	link, err := s.Auth.CreateMagicLink(ctx, email, purpose)
	if err != nil {
		s.Log.Error("magic link", "err", err)
		return
	}
	if s.Mailer == nil {
		// no SMTP configured: the operator finds the link in the log
		s.Log.Warn("SMTP_URL not set, login link written to log", "email", email, "purpose", purpose, "link", link)
		return
	}
	go func() { // don't leak timing / block the request on SMTP
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := s.Mailer.SendLink(ctx, email, subject, intro, link, action); err != nil {
			s.Log.Error("send login email", "err", err)
		}
	}()
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if !s.Auth.Allow("verify:"+s.ip(r), 5*time.Second, 10) {
		http.Redirect(w, r, "/login?error=rate_limited", http.StatusFound)
		return
	}
	u, err := s.Auth.ConsumeMagicLink(r.Context(), tok)
	if err != nil {
		http.Redirect(w, r, "/login?error=invalid_link", http.StatusFound)
		return
	}
	if err := s.Auth.StartSession(r.Context(), w, r, u.ID); err != nil {
		s.internal(w, r, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.Auth.EndSession(r.Context(), w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.Allow("passkey:"+s.ip(r), 3*time.Second, 10) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	opts, err := s.Auth.BeginPasskeyLogin(r.Context(), w)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, opts)
}

func (s *Server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	u, err := s.Auth.FinishPasskeyLogin(r.Context(), r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.Auth.StartSession(r.Context(), w, r, u.ID); err != nil {
		s.internal(w, r, err)
		return
	}
	s.writeMe(w, r, u)
}

func (s *Server) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	opts, err := s.Auth.BeginPasskeyRegistration(r.Context(), w, userFrom(r.Context()))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, opts)
}

func (s *Server) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if err := s.Auth.FinishPasskeyRegistration(r.Context(), r, userFrom(r.Context()), r.URL.Query().Get("name")); err != nil {
		writeErr(w, http.StatusBadRequest, "passkey registration failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (s *Server) getMe(w http.ResponseWriter, r *http.Request) {
	s.writeMe(w, r, userFrom(r.Context()))
}

func (s *Server) writeMe(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var stacks, channels int
	_ = s.Pool.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM stacks WHERE user_id=$1), (SELECT count(*) FROM channels WHERE user_id=$1)`, u.ID).
		Scan(&stacks, &channels)
	ls, lc := s.limits(u)
	writeJSON(w, 200, map[string]any{
		"id": u.ID, "email": u.Email, "role": u.Role, "plan": u.Plan, "created_at": u.CreatedAt,
		"limits": map[string]int{"stacks": ls, "channels": lc},
		"usage":  map[string]int{"stacks": stacks, "channels": channels},
	})
}

func (s *Server) limits(u *auth.User) (stacks, channels int) {
	if u.Plan == "plus" || u.Role == "admin" {
		return 100, 100
	}
	return s.Cfg.FreeStacks, s.Cfg.FreeChannels
}

func (s *Server) deleteMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if _, err := s.Pool.Exec(r.Context(), `DELETE FROM users WHERE id=$1`, u.ID); err != nil {
		s.internal(w, r, err)
		return
	}
	_, _ = s.Pool.Exec(r.Context(), `DELETE FROM magic_links WHERE email=$1`, u.Email)
	s.Auth.EndSession(r.Context(), w, r)
	s.Log.Info("account deleted", "user", u.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	list, err := s.Auth.ListPasskeys(r.Context(), userFrom(r.Context()).ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if list == nil {
		list = []auth.Passkey{}
	}
	writeJSON(w, 200, list)
}

func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	_, err := s.Pool.Exec(r.Context(), `DELETE FROM passkeys WHERE id=$1 AND user_id=$2`, id, userFrom(r.Context()).ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	list, err := s.Auth.ListAPIKeys(r.Context(), userFrom(r.Context()).ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if list == nil {
		list = []auth.APIKey{}
	}
	writeJSON(w, 200, list)
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Name == "" || len(in.Name) > 60 {
		writeErr(w, http.StatusBadRequest, "name is required (max 60 characters)")
		return
	}
	u := userFrom(r.Context())
	var n int
	_ = s.Pool.QueryRow(r.Context(), `SELECT count(*) FROM api_keys WHERE user_id=$1`, u.ID).Scan(&n)
	if n >= 20 {
		writeErr(w, http.StatusForbidden, "at most 20 API keys")
		return
	}
	k, err := s.Auth.CreateAPIKey(r.Context(), u.ID, in.Name)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, k)
}

func (s *Server) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	_, err := s.Pool.Exec(r.Context(), `DELETE FROM api_keys WHERE id=$1 AND user_id=$2`, id, userFrom(r.Context()).ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func itoa(i int) string { return strconv.Itoa(i) }
