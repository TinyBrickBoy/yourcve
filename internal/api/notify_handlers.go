package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tinybrickboy/yourcve/internal/auth"
	"github.com/tinybrickboy/yourcve/internal/jobs"
	"github.com/tinybrickboy/yourcve/internal/notify"
)

func readAll(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) >= limit {
		return nil, errors.New("too large")
	}
	return b, nil
}

type channelOut struct {
	ID        int64             `json:"id"`
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	Class     string            `json:"class"`
	Verified  bool              `json:"verified"`
	Enabled   bool              `json:"enabled"`
	Config    map[string]string `json:"config"`
	CreatedAt time.Time         `json:"created_at"`
}

func (s *Server) loadChannels(r *http.Request, userID int64, id int64) ([]channelOut, error) {
	q := `SELECT id, type, name, class, verified, enabled, config, created_at FROM channels WHERE user_id=$1`
	args := []any{userID}
	if id > 0 {
		q += ` AND id=$2`
		args = append(args, id)
	}
	rows, err := s.Pool.Query(r.Context(), q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []channelOut{}
	for rows.Next() {
		var c channelOut
		var sealed []byte
		if err := rows.Scan(&c.ID, &c.Type, &c.Name, &c.Class, &c.Verified, &c.Enabled, &sealed, &c.CreatedAt); err != nil {
			return nil, err
		}
		var cfg map[string]string
		if err := s.Sealer.Open(sealed, &cfg); err != nil {
			cfg = map[string]string{}
		}
		c.Config = notify.Mask(c.Type, cfg)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Server) listChannels(w http.ResponseWriter, r *http.Request) {
	list, err := s.loadChannels(r, userFrom(r.Context()).ID, 0)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (s *Server) createChannel(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Type   string            `json:"type"`
		Name   string            `json:"name"`
		Config map[string]string `json:"config"`
	}
	if !decode(w, r, &in) {
		return
	}
	ct, ok := notify.TypeByName(in.Type)
	if !ok {
		writeErr(w, http.StatusBadRequest, "unknown channel type")
		return
	}
	if !ct.Available {
		writeErr(w, http.StatusPaymentRequired, "paid channel: coming soon with Plus for 9.99 €/month")
		return
	}
	if in.Type == "email" && s.Mailer == nil {
		writeErr(w, http.StatusBadRequest, "email is not configured on this instance")
		return
	}
	name, ok := validName(in.Name)
	if !ok {
		name = ct.Label
	}
	if in.Config == nil {
		in.Config = map[string]string{}
	}
	u := userFrom(r.Context())
	if !s.Auth.Allow(fmt.Sprintf("channel-create:%d", u.ID), 10*time.Second, 10) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	if err := s.Sender.Validate(r.Context(), in.Type, in.Config); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sealed, err := s.Sealer.Seal(in.Config)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	_, maxCh := s.limits(u)
	var id int64
	var unsub string
	verifyTok := ""
	if in.Type == "email" {
		verifyTok = auth.RandomToken(32)
	}
	err = pgx.BeginFunc(r.Context(), s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `SELECT 1 FROM users WHERE id=$1 FOR UPDATE`, u.ID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM channels WHERE user_id=$1`, u.ID).Scan(&n); err != nil {
			return err
		}
		if n >= maxCh {
			return errLimit
		}
		var vt []byte
		if verifyTok != "" {
			vt = auth.Hash(verifyTok)
		}
		return tx.QueryRow(r.Context(), `INSERT INTO channels (user_id, type, class, name, config, verify_token) VALUES ($1,$2,$3,$4,$5,$6)
			RETURNING id, unsub_token`, u.ID, in.Type, ct.Class, name, sealed, vt).Scan(&id, &unsub)
	})
	if errors.Is(err, errLimit) {
		writeErr(w, http.StatusForbidden, "plan limit reached: at most "+itoa(maxCh)+" channels on the free plan")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if in.Type == "email" {
		link := s.Cfg.BaseURL + "/v1/channels/confirm?token=" + verifyTok
		addr := in.Config["address"]
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			err := s.Mailer.SendLink(ctx, addr, "Confirm CVE notifications from yourcve",
				"Someone ("+u.Email+") wants to send CVE notifications to this address. Confirm to start receiving them.", link, "Confirm notifications")
			if err != nil {
				s.Log.Error("send channel confirmation", "err", err)
			}
		}()
	}
	list, err := s.loadChannels(r, u.ID, id)
	if err != nil || len(list) == 0 {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, list[0])
}

func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if _, err := s.Pool.Exec(r.Context(), `DELETE FROM channels WHERE id=$1 AND user_id=$2`, id, userFrom(r.Context()).ID); err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	u := userFrom(r.Context())
	if !s.Auth.Allow(fmt.Sprintf("channel-test:%d", u.ID), 10*time.Second, 5) {
		writeErr(w, http.StatusTooManyRequests, "too many test messages, wait a moment")
		return
	}
	var typ, unsub string
	var sealed []byte
	var verified bool
	err := s.Pool.QueryRow(r.Context(), `SELECT type, config, verified, unsub_token FROM channels WHERE id=$1 AND user_id=$2`, id, u.ID).
		Scan(&typ, &sealed, &verified, &unsub)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "channel not found")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if typ == "email" && !verified {
		writeErr(w, http.StatusConflict, "confirm the address first (check the inbox for the confirmation link)")
		return
	}
	var cfg map[string]string
	if err := s.Sealer.Open(sealed, &cfg); err != nil {
		s.internal(w, r, err)
		return
	}
	unsubLink := ""
	if typ == "email" {
		unsubLink = s.Cfg.BaseURL + "/v1/unsubscribe?token=" + unsub
	}
	if err := s.Notifier.SendTest(r.Context(), typ, cfg, unsubLink); err != nil {
		writeErr(w, http.StatusBadGateway, "delivery failed: "+err.Error())
		return
	}
	if typ != "email" {
		_, _ = s.Pool.Exec(r.Context(), `UPDATE channels SET verified=true WHERE id=$1`, id)
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) confirmChannel(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	tag, err := s.Pool.Exec(r.Context(), `UPDATE channels SET verified=true, enabled=true, verify_token=NULL WHERE verify_token=$1`, auth.Hash(tok))
	if err != nil || tag.RowsAffected() == 0 || tok == "" {
		http.Redirect(w, r, "/channels?confirmed=0", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/channels?confirmed=1", http.StatusFound)
}

func (s *Server) unsubscribe(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok != "" {
		_, _ = s.Pool.Exec(r.Context(), `UPDATE channels SET enabled=false WHERE unsub_token=$1`, tok)
	}
	if r.Method == http.MethodPost {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/unsubscribed", http.StatusFound)
}

// ---------------------------------------------------------------- rules

type ruleIO struct {
	ID                 int64    `json:"id,omitempty"`
	StackID            *int64   `json:"stack_id"`
	ChannelID          *int64   `json:"channel_id"`
	MinCVSS            *float64 `json:"min_cvss"`
	KEVOnly            *bool    `json:"kev_only"`
	MinEPSS            *float64 `json:"min_epss"`
	Mode               *string  `json:"mode"`
	QuietStart         *string  `json:"quiet_start"`
	QuietEnd           *string  `json:"quiet_end"`
	Timezone           *string  `json:"timezone"`
	IncludeUnconfirmed *bool    `json:"include_unconfirmed"`
	Enabled            *bool    `json:"enabled"`
	StackName          string   `json:"stack_name,omitempty"`
	ChannelName        string   `json:"channel_name,omitempty"`
	ChannelType        string   `json:"channel_type,omitempty"`
}

const ruleSelect = `SELECT r.id, r.stack_id, r.channel_id, r.min_cvss::float8, r.kev_only, r.min_epss, r.mode, r.quiet_start, r.quiet_end,
	r.timezone, r.include_unconfirmed, r.enabled, s.name, c.name, c.type
	FROM notification_rules r JOIN stacks s ON s.id = r.stack_id JOIN channels c ON c.id = r.channel_id
	WHERE s.user_id = $1`

func scanRule(row pgx.Row) (ruleIO, error) {
	var x ruleIO
	x.StackID, x.ChannelID, x.MinCVSS, x.KEVOnly, x.MinEPSS = new(int64), new(int64), new(float64), new(bool), new(float64)
	x.Mode, x.Timezone, x.IncludeUnconfirmed, x.Enabled = new(string), new(string), new(bool), new(bool)
	err := row.Scan(&x.ID, x.StackID, x.ChannelID, x.MinCVSS, x.KEVOnly, x.MinEPSS, x.Mode, &x.QuietStart, &x.QuietEnd,
		x.Timezone, x.IncludeUnconfirmed, x.Enabled, &x.StackName, &x.ChannelName, &x.ChannelType)
	return x, err
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	q := ruleSelect
	args := []any{userFrom(r.Context()).ID}
	if sid := queryInt(r, "stack_id", 0); sid > 0 {
		q += ` AND r.stack_id = $2`
		args = append(args, sid)
	}
	rows, err := s.Pool.Query(r.Context(), q+` ORDER BY r.id`, args...)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ruleIO, error) { return scanRule(r) })
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if list == nil {
		list = []ruleIO{}
	}
	writeJSON(w, 200, list)
}

func validateRule(in *ruleIO) string {
	if in.MinCVSS != nil && (*in.MinCVSS < 0 || *in.MinCVSS > 10) {
		return "min_cvss must be between 0 and 10"
	}
	if in.MinEPSS != nil && (*in.MinEPSS < 0 || *in.MinEPSS > 1) {
		return "min_epss must be between 0 and 1"
	}
	if in.Mode != nil && *in.Mode != "instant" && *in.Mode != "hourly" && *in.Mode != "daily" {
		return "mode must be instant, hourly or daily"
	}
	for _, t := range []*string{in.QuietStart, in.QuietEnd} {
		if t != nil && *t != "" {
			var h, m int
			if _, err := fmt.Sscanf(*t, "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 || len(*t) != 5 {
				return "quiet hours must be HH:MM"
			}
		}
	}
	if in.Timezone != nil && *in.Timezone != "" {
		if _, err := time.LoadLocation(*in.Timezone); err != nil {
			return "unknown timezone"
		}
	}
	return ""
}

func emptyNil(p *string) *string {
	if p == nil || strings.TrimSpace(*p) == "" {
		return nil
	}
	return p
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var in ruleIO
	if !decode(w, r, &in) {
		return
	}
	if msg := validateRule(&in); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	u := userFrom(r.Context())
	if in.StackID == nil || in.ChannelID == nil || !s.ownsStack(r, u.ID, *in.StackID) {
		writeErr(w, http.StatusBadRequest, "stack_id and channel_id of your own stack and channel are required")
		return
	}
	var owns bool
	_ = s.Pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM channels WHERE id=$1 AND user_id=$2)`, *in.ChannelID, u.ID).Scan(&owns)
	if !owns {
		writeErr(w, http.StatusBadRequest, "channel not found")
		return
	}
	def := func(p *float64) float64 {
		if p == nil {
			return 0
		}
		return *p
	}
	defB := func(p *bool, d bool) bool {
		if p == nil {
			return d
		}
		return *p
	}
	defS := func(p *string, d string) string {
		if p == nil || *p == "" {
			return d
		}
		return *p
	}
	var id int64
	err := s.Pool.QueryRow(r.Context(), `INSERT INTO notification_rules (stack_id, channel_id, min_cvss, kev_only, min_epss, mode,
			quiet_start, quiet_end, timezone, include_unconfirmed, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
		*in.StackID, *in.ChannelID, def(in.MinCVSS), defB(in.KEVOnly, false), def(in.MinEPSS), defS(in.Mode, "instant"),
		emptyNil(in.QuietStart), emptyNil(in.QuietEnd), defS(in.Timezone, "UTC"), defB(in.IncludeUnconfirmed, true), defB(in.Enabled, true)).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			writeErr(w, http.StatusConflict, "a rule for this stack and channel already exists")
			return
		}
		s.internal(w, r, err)
		return
	}
	s.writeRule(w, r, id, http.StatusCreated)
}

func (s *Server) writeRule(w http.ResponseWriter, r *http.Request, id int64, code int) {
	x, err := scanRule(s.Pool.QueryRow(r.Context(), ruleSelect+` AND r.id = $2`, userFrom(r.Context()).ID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, code, x)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in ruleIO
	if !decode(w, r, &in) {
		return
	}
	if msg := validateRule(&in); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	u := userFrom(r.Context())
	if in.ChannelID != nil {
		var owns bool
		_ = s.Pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM channels WHERE id=$1 AND user_id=$2)`, *in.ChannelID, u.ID).Scan(&owns)
		if !owns {
			writeErr(w, http.StatusBadRequest, "channel not found")
			return
		}
	}
	// quiet hours: "" clears, null keeps
	clearQ := in.QuietStart != nil && *in.QuietStart == ""
	tag, err := s.Pool.Exec(r.Context(), `UPDATE notification_rules r SET
			channel_id = coalesce($3, r.channel_id), min_cvss = coalesce($4, r.min_cvss), kev_only = coalesce($5, r.kev_only),
			min_epss = coalesce($6, r.min_epss), mode = coalesce($7, r.mode),
			quiet_start = CASE WHEN $12 THEN NULL ELSE coalesce($8, r.quiet_start) END,
			quiet_end = CASE WHEN $12 THEN NULL ELSE coalesce($9, r.quiet_end) END,
			timezone = coalesce($10, r.timezone), include_unconfirmed = coalesce($11, r.include_unconfirmed),
			enabled = coalesce($13, r.enabled)
		FROM stacks s WHERE r.id = $1 AND s.id = r.stack_id AND s.user_id = $2`,
		id, u.ID, in.ChannelID, in.MinCVSS, in.KEVOnly, in.MinEPSS, in.Mode, emptyNil(in.QuietStart), emptyNil(in.QuietEnd),
		emptyNil(in.Timezone), in.IncludeUnconfirmed, clearQ, in.Enabled)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}
	s.writeRule(w, r, id, 200)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	_, err := s.Pool.Exec(r.Context(), `DELETE FROM notification_rules r USING stacks s WHERE r.id=$1 AND s.id=r.stack_id AND s.user_id=$2`,
		id, userFrom(r.Context()).ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- deliveries

type deliveryOut struct {
	ID            int64      `json:"id"`
	CVEID         string     `json:"cve_id"`
	StackID       int64      `json:"stack_id"`
	StackName     string     `json:"stack_name"`
	ChannelID     int64      `json:"channel_id"`
	ChannelName   string     `json:"channel_name"`
	ChannelType   string     `json:"channel_type"`
	Occasion      string     `json:"occasion"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	LastError     *string    `json:"last_error"`
	NextAttemptAt *time.Time `json:"next_attempt_at"`
	SentAt        *time.Time `json:"sent_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

const deliverySelect = `SELECT d.id, d.cve_id, d.stack_id, s.name, d.channel_id, c.name, c.type, d.occasion, d.status, d.attempts,
	d.last_error, d.next_attempt_at, d.sent_at, d.created_at
	FROM deliveries d JOIN stacks s ON s.id = d.stack_id JOIN channels c ON c.id = d.channel_id`

func collectDeliveries(rows pgx.Rows) ([]deliveryOut, error) {
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (deliveryOut, error) {
		var d deliveryOut
		err := r.Scan(&d.ID, &d.CVEID, &d.StackID, &d.StackName, &d.ChannelID, &d.ChannelName, &d.ChannelType, &d.Occasion,
			&d.Status, &d.Attempts, &d.LastError, &d.NextAttemptAt, &d.SentAt, &d.CreatedAt)
		return d, err
	})
	if list == nil {
		list = []deliveryOut{}
	}
	return list, err
}

func (s *Server) listDeliveries(w http.ResponseWriter, r *http.Request) {
	q := deliverySelect + ` WHERE s.user_id = $1`
	args := []any{userFrom(r.Context()).ID}
	if st := r.URL.Query().Get("status"); st != "" {
		args = append(args, st)
		q += ` AND d.status = $2`
	}
	limit := min(max(queryInt(r, "limit", 50), 1), 200)
	q += fmt.Sprintf(` ORDER BY d.id DESC LIMIT %d OFFSET %d`, limit, max(queryInt(r, "offset", 0), 0))
	rows, err := s.Pool.Query(r.Context(), q, args...)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	list, err := collectDeliveries(rows)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (s *Server) retryDelivery(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	err := pgx.BeginFunc(r.Context(), s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE deliveries d SET status='pending', last_error=NULL, attempts=0
			FROM stacks s WHERE d.id=$1 AND s.id=d.stack_id AND s.user_id=$2 AND d.status='failed'`, id, userFrom(r.Context()).ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		_, err = s.River.InsertTx(r.Context(), tx, jobs.Deliver{DeliveryID: id}, nil)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "no failed delivery with this id")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) getCredits(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	var balance int
	_ = s.Pool.QueryRow(r.Context(), `SELECT coalesce(sum(amount),0) FROM credit_ledger WHERE user_id=$1`, u.ID).Scan(&balance)
	rows, err := s.Pool.Query(r.Context(), `SELECT id, kind, amount, coalesce(note,''), created_at FROM credit_ledger WHERE user_id=$1 ORDER BY id DESC LIMIT 100`, u.ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	type entry struct {
		ID        int64     `json:"id"`
		Kind      string    `json:"kind"`
		Amount    int       `json:"amount"`
		Note      string    `json:"note"`
		CreatedAt time.Time `json:"created_at"`
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (entry, error) {
		var e entry
		err := r.Scan(&e.ID, &e.Kind, &e.Amount, &e.Note, &e.CreatedAt)
		return e, err
	})
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if list == nil {
		list = []entry{}
	}
	writeJSON(w, 200, map[string]any{"balance": balance, "entries": list, "coming_soon": true})
}

// ---------------------------------------------------------------- admin

func (s *Server) adminStatus(w http.ResponseWriter, r *http.Request) {
	if userFrom(r.Context()).Role != "admin" {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	ctx := r.Context()
	type source struct {
		Source      string     `json:"source"`
		Cursor      string     `json:"cursor"`
		LastRun     *time.Time `json:"last_run"`
		LastSuccess *time.Time `json:"last_success"`
		LastError   *string    `json:"last_error"`
		LagSeconds  *float64   `json:"lag_seconds"`
		ItemsTotal  int64      `json:"items_total"`
	}
	rows, err := s.Pool.Query(ctx, `SELECT source, cursor, last_run, last_success, last_error,
		extract(epoch FROM now() - newest_item)::float8, items_total FROM sync_state ORDER BY source`)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	sources, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (source, error) {
		var x source
		err := r.Scan(&x.Source, &x.Cursor, &x.LastRun, &x.LastSuccess, &x.LastError, &x.LagSeconds, &x.ItemsTotal)
		return x, err
	})
	if err != nil {
		s.internal(w, r, err)
		return
	}
	queue := map[string]int{"available": 0, "running": 0, "retryable": 0, "scheduled": 0}
	qrows, err := s.Pool.Query(ctx, `SELECT state::text, count(*) FROM river_job WHERE state IN ('available','running','retryable','scheduled') GROUP BY state`)
	if err == nil {
		for qrows.Next() {
			var st string
			var n int
			if qrows.Scan(&st, &n) == nil {
				queue[st] = n
			}
		}
		qrows.Close()
	}
	var pending, failed24, sent24 int
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status IN ('pending','digest')),
		count(*) FILTER (WHERE status='failed' AND created_at > now() - interval '24 hours'),
		count(*) FILTER (WHERE status='sent' AND sent_at > now() - interval '24 hours') FROM deliveries`).Scan(&pending, &failed24, &sent24)
	frows, err := s.Pool.Query(ctx, deliverySelect+` WHERE d.status='failed' ORDER BY d.id DESC LIMIT 20`)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	failures, err := collectDeliveries(frows)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	counts := map[string]int64{}
	var c1, c2, c3, c4, c5, c6 int64
	_ = s.Pool.QueryRow(ctx, `SELECT
		(SELECT reltuples::bigint FROM pg_class WHERE relname='cves'),
		(SELECT reltuples::bigint FROM pg_class WHERE relname='products'),
		(SELECT count(*) FROM users), (SELECT count(*) FROM stacks),
		(SELECT count(*) FROM cve_ai WHERE summary_en IS NOT NULL), (SELECT count(*) FROM cve_embeddings)`).Scan(&c1, &c2, &c3, &c4, &c5, &c6)
	counts["cves"], counts["products"], counts["users"], counts["stacks"], counts["ai_summaries"], counts["embeddings"] = max(c1, 0), max(c2, 0), c3, c4, c5, c6
	writeJSON(w, 200, map[string]any{
		"sources": sources, "queue": queue,
		"deliveries":      map[string]int{"pending": pending, "failed_24h": failed24, "sent_24h": sent24},
		"recent_failures": failures, "counts": counts,
	})
}
