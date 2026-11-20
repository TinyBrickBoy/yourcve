package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/riverqueue/river"

	"github.com/tinybrickboy/yourcve/internal/jobs"
)

var metricDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "yourcve_deliveries_total", Help: "Notification deliveries by channel type and result."}, []string{"type", "result"})

func init() { prometheus.MustRegister(metricDeliveries) }

// Notifier works the outbox (deliveries) with River.
type Notifier struct {
	Pool              *pgxpool.Pool
	Sealer            *Sealer
	Sender            *Sender
	Log               *slog.Logger
	BaseURL           string
	MaxPerChannelHour int
	EmailPerUserHour  int
	AIEnabled         bool
}

type deliveryRow struct {
	id, channelID, stackID, userID int64
	cveID, occasion, status        string
	createdAt                      time.Time
	chType, chClass                string
	chEnabled                      bool
	chConfig                       []byte
	unsubToken                     string
	stackName                      string
	quietStart, quietEnd, tz       *string
	assessed                       bool
}

func (n *Notifier) loadDelivery(ctx context.Context, id int64) (*deliveryRow, error) {
	var d deliveryRow
	err := n.Pool.QueryRow(ctx, `SELECT d.id, d.channel_id, d.stack_id, s.user_id, d.cve_id, d.occasion, d.status, d.created_at,
			c.type, c.class, c.enabled, c.config, c.unsub_token, s.name, r.quiet_start, r.quiet_end, r.timezone,
			EXISTS (SELECT 1 FROM stack_cve_status x WHERE x.stack_id = d.stack_id AND x.cve_id = d.cve_id)
		FROM deliveries d JOIN channels c ON c.id = d.channel_id JOIN stacks s ON s.id = d.stack_id
		LEFT JOIN notification_rules r ON r.id = d.rule_id
		WHERE d.id = $1`, id).Scan(&d.id, &d.channelID, &d.stackID, &d.userID, &d.cveID, &d.occasion, &d.status, &d.createdAt,
		&d.chType, &d.chClass, &d.chEnabled, &d.chConfig, &d.unsubToken, &d.stackName, &d.quietStart, &d.quietEnd, &d.tz, &d.assessed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &d, err
}

// QuietUntil reports whether now is inside the quiet window and when it ends.
func QuietUntil(now time.Time, start, end, tz *string) (bool, time.Time) {
	if start == nil || end == nil || *start == "" || *end == "" || *start == *end {
		return false, time.Time{}
	}
	loc := time.UTC
	if tz != nil && *tz != "" {
		if l, err := time.LoadLocation(*tz); err == nil {
			loc = l
		}
	}
	parse := func(s string) (int, bool) {
		var h, m int
		if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
			return 0, false
		}
		return h*60 + m, true
	}
	s, ok1 := parse(*start)
	e, ok2 := parse(*end)
	if !ok1 || !ok2 {
		return false, time.Time{}
	}
	local := now.In(loc)
	cur := local.Hour()*60 + local.Minute()
	in := false
	if s < e {
		in = cur >= s && cur < e
	} else { // over midnight, e.g. 22:00–07:00
		in = cur >= s || cur < e
	}
	if !in {
		return false, time.Time{}
	}
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	until := day.Add(time.Duration(e) * time.Minute)
	if !until.After(local) {
		until = until.Add(24 * time.Hour)
	}
	return true, until
}

type DeliverWorker struct {
	river.WorkerDefaults[jobs.Deliver]
	N *Notifier
}

func (w *DeliverWorker) Timeout(*river.Job[jobs.Deliver]) time.Duration { return 90 * time.Second }

func (w *DeliverWorker) NextRetry(job *river.Job[jobs.Deliver]) time.Time {
	// 30s, 2m, 8m, 30m, 2h, 6h, 12h
	steps := []time.Duration{30 * time.Second, 2 * time.Minute, 8 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour}
	i := min(max(job.Attempt-1, 0), len(steps)-1)
	return time.Now().Add(steps[i])
}

func (w *DeliverWorker) Work(ctx context.Context, job *river.Job[jobs.Deliver]) error {
	n := w.N
	d, err := n.loadDelivery(ctx, job.Args.DeliveryID)
	if err != nil || d == nil {
		return err
	}
	if d.status != "pending" && d.status != "failed" {
		return nil // already sent, suppressed or moved to a digest
	}
	if !d.chEnabled || d.assessed || d.chClass != "free" {
		_, err := n.Pool.Exec(ctx, `UPDATE deliveries SET status='suppressed' WHERE id=$1`, d.id)
		return err
	}
	if quiet, until := QuietUntil(time.Now(), d.quietStart, d.quietEnd, d.tz); quiet {
		_, _ = n.Pool.Exec(ctx, `UPDATE deliveries SET next_attempt_at=$2 WHERE id=$1`, d.id, until)
		return river.JobSnooze(time.Until(until))
	}
	if n.AIEnabled && time.Since(d.createdAt) < 25*time.Second {
		var has bool
		_ = n.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cve_ai WHERE cve_id=$1)`, d.cveID).Scan(&has)
		if !has {
			return river.JobSnooze(5 * time.Second) // give the summary a moment, then send without it
		}
	}
	// flood protection: above the hourly limit, the rest goes into a digest
	var sentHour int
	if err := n.Pool.QueryRow(ctx, `SELECT count(*) FROM deliveries WHERE channel_id=$1 AND status='sent' AND sent_at > now() - interval '1 hour'`,
		d.channelID).Scan(&sentHour); err != nil {
		return err
	}
	limit := n.MaxPerChannelHour
	if d.chType == "email" {
		var userHour int
		_ = n.Pool.QueryRow(ctx, `SELECT count(*) FROM deliveries d JOIN channels c ON c.id=d.channel_id
			WHERE c.user_id=$1 AND c.type='email' AND d.status='sent' AND d.sent_at > now() - interval '1 hour'`, d.userID).Scan(&userHour)
		if n.EmailPerUserHour > 0 && userHour >= n.EmailPerUserHour {
			sentHour = limit
		}
	}
	if limit > 0 && sentHour >= limit {
		_, err := n.Pool.Exec(ctx, `UPDATE deliveries SET status='digest' WHERE id=$1 AND status IN ('pending','failed')`, d.id)
		return err
	}

	items, err := n.items(ctx, []int64{d.id})
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}
	msg := n.single(items[0])
	if d.chType == "email" {
		msg.Unsub = n.BaseURL + "/v1/unsubscribe?token=" + d.unsubToken
	}
	var cfg map[string]string
	if err := n.Sealer.Open(d.chConfig, &cfg); err != nil {
		return n.fail(ctx, d, job.Attempt, job.MaxAttempts, PermanentError{err})
	}
	sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = n.Sender.Send(sctx, d.chType, cfg, msg)
	cancel()
	if err != nil {
		return n.fail(ctx, d, job.Attempt, job.MaxAttempts, err)
	}
	metricDeliveries.WithLabelValues(d.chType, "sent").Inc()
	_, err = n.Pool.Exec(context.WithoutCancel(ctx), `UPDATE deliveries SET status='sent', sent_at=now(), attempts=attempts+1,
		last_error=NULL, next_attempt_at=NULL WHERE id=$1`, d.id)
	return err
}

func (n *Notifier) fail(ctx context.Context, d *deliveryRow, attempt, maxAttempts int, sendErr error) error {
	var perm PermanentError
	final := errors.As(sendErr, &perm) || attempt >= maxAttempts
	status := "pending"
	if final {
		status = "failed"
	}
	metricDeliveries.WithLabelValues(d.chType, "error").Inc()
	_, err := n.Pool.Exec(context.WithoutCancel(ctx), `UPDATE deliveries SET status=$2, attempts=attempts+1, last_error=$3,
		next_attempt_at = CASE WHEN $2='failed' THEN NULL ELSE now() + interval '30 seconds' * power(4, least(attempts, 6)) END
		WHERE id=$1`, d.id, status, truncate(sendErr.Error(), 500))
	if err != nil {
		return err
	}
	n.Log.Warn("delivery failed", "delivery", d.id, "type", d.chType, "attempt", attempt, "final", final, "err", sendErr)
	if final {
		return river.JobCancel(sendErr)
	}
	return sendErr
}

// items loads the message content for deliveries.
func (n *Notifier) items(ctx context.Context, ids []int64) ([]Item, error) {
	rows, err := n.Pool.Query(ctx, `SELECT d.cve_id, c.severity, c.cvss::float8, c.kev, c.epss, s.name, coalesce(m.reason,''),
			coalesce(a.summary_en, ''), c.description, d.occasion
		FROM deliveries d JOIN cves c ON c.id = d.cve_id JOIN stacks s ON s.id = d.stack_id
		LEFT JOIN matches m ON m.cve_id = d.cve_id AND m.stack_id = d.stack_id
		LEFT JOIN cve_ai a ON a.cve_id = d.cve_id
		WHERE d.id = ANY($1) ORDER BY c.cvss DESC NULLS LAST, d.id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		var ai, desc string
		if err := rows.Scan(&it.CVEID, &it.Severity, &it.CVSS, &it.KEV, &it.EPSS, &it.Stack, &it.Reason, &ai, &desc, &it.Occasion); err != nil {
			return nil, err
		}
		if ai != "" {
			it.Summary, it.AI = ai, true
		} else {
			it.Summary = truncate(desc, 400)
		}
		it.URL = n.BaseURL + "/cves/" + it.CVEID
		out = append(out, it)
	}
	return out, rows.Err()
}

func (n *Notifier) single(it Item) Message {
	sev := strings.ToUpper(it.Severity)
	if it.CVSS != nil {
		sev += fmt.Sprintf(" %.1f", *it.CVSS)
	}
	title := fmt.Sprintf("[%s] %s affects %s", sev, it.CVEID, it.Stack)
	switch it.Occasion {
	case "kev_added":
		title = fmt.Sprintf("[KEV] %s is now actively exploited (%s)", it.CVEID, it.Stack)
	case "cvss_raised":
		title = fmt.Sprintf("[%s] severity of %s raised (%s)", sev, it.CVEID, it.Stack)
	}
	text := it.Summary
	if it.AI {
		text += " (AI generated)"
	}
	text += "\n" + scoreText(it) + "\nMatch: " + it.Reason
	return Message{Title: title, Text: text, URL: it.URL, Severity: it.Severity, Items: []Item{it}}
}

// SendTest sends a test message to a channel.
func (n *Notifier) SendTest(ctx context.Context, typ string, cfg map[string]string, unsub string) error {
	cvss := 9.8
	msg := Message{
		Title:    "yourcve test message",
		Text:     "This channel is set up correctly. You will be notified here when a new CVE affects your stack.",
		URL:      n.BaseURL + "/channels",
		Severity: "critical",
		Unsub:    unsub,
	}
	if typ != "webhook" {
		msg.Items = []Item{{CVEID: "CVE-0000-0000", Severity: "critical", CVSS: &cvss, Stack: "Example stack",
			Reason: "example 1.0 in range < 1.1 (test)", Summary: "Test notification from yourcve.", URL: n.BaseURL + "/channels"}}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return n.Sender.Send(ctx, typ, cfg, msg)
}

// ---------------------------------------------------------------- digest

type DigestWorker struct {
	river.WorkerDefaults[jobs.Digest]
	N *Notifier
}

func (w *DigestWorker) Timeout(*river.Job[jobs.Digest]) time.Duration { return 10 * time.Minute }

// Work sends all due digests: hourly/daily rules, and overflow of instant
// rules (at most once per hour per rule).
func (w *DigestWorker) Work(ctx context.Context, job *river.Job[jobs.Digest]) error {
	n := w.N
	rows, err := n.Pool.Query(ctx, `SELECT d.rule_id, array_agg(d.id ORDER BY d.id), r.mode, r.last_digest_at,
			r.quiet_start, r.quiet_end, r.timezone, c.type, c.config, c.unsub_token, c.enabled, s.name
		FROM deliveries d JOIN notification_rules r ON r.id = d.rule_id
		JOIN channels c ON c.id = d.channel_id JOIN stacks s ON s.id = d.stack_id
		WHERE d.status = 'digest'
		GROUP BY d.rule_id, r.mode, r.last_digest_at, r.quiet_start, r.quiet_end, r.timezone, c.type, c.config, c.unsub_token, c.enabled, s.name`)
	if err != nil {
		return err
	}
	type group struct {
		ruleID     int64
		ids        []int64
		mode       string
		last       *time.Time
		qs, qe, tz *string
		typ        string
		config     []byte
		unsub      string
		enabled    bool
		stack      string
	}
	var groups []group
	for rows.Next() {
		var g group
		if err := rows.Scan(&g.ruleID, &g.ids, &g.mode, &g.last, &g.qs, &g.qe, &g.tz, &g.typ, &g.config, &g.unsub, &g.enabled, &g.stack); err != nil {
			rows.Close()
			return err
		}
		groups = append(groups, g)
	}
	rows.Close()
	now := time.Now()
	for _, g := range groups {
		period := time.Hour
		if g.mode == "daily" {
			period = 24 * time.Hour
		}
		if g.last != nil && now.Sub(*g.last) < period-time.Minute {
			continue
		}
		if quiet, _ := QuietUntil(now, g.qs, g.qe, g.tz); quiet {
			continue
		}
		if !g.enabled {
			_, _ = n.Pool.Exec(ctx, `UPDATE deliveries SET status='suppressed' WHERE id = ANY($1)`, g.ids)
			continue
		}
		items, err := n.items(ctx, g.ids)
		if err != nil {
			return err
		}
		var cfg map[string]string
		if err := n.Sealer.Open(g.config, &cfg); err != nil {
			n.Log.Error("digest: cannot open channel config", "rule", g.ruleID, "err", err)
			continue
		}
		label := map[string]string{"hourly": "Hourly", "daily": "Daily"}[g.mode]
		if label == "" {
			label = "Summary"
		}
		msg := Message{
			Title: fmt.Sprintf("%s digest: %d CVE(s) affect %s", label, len(items), g.stack),
			URL:   n.BaseURL + "/deliveries",
			Items: items,
		}
		var lines []string
		for i, it := range items {
			if i >= 50 {
				lines = append(lines, fmt.Sprintf("… and %d more", len(items)-50))
				break
			}
			lines = append(lines, fmt.Sprintf("%s (%s) %s", it.CVEID, scoreText(it), truncate(it.Summary, 160)))
		}
		msg.Text = strings.Join(lines, "\n")
		if len(items) > 0 {
			msg.Severity = items[0].Severity
		}
		if g.typ == "email" {
			msg.Unsub = n.BaseURL + "/v1/unsubscribe?token=" + g.unsub
		}
		sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		err = n.Sender.Send(sctx, g.typ, cfg, msg)
		cancel()
		if err != nil {
			metricDeliveries.WithLabelValues(g.typ, "error").Inc()
			_, _ = n.Pool.Exec(ctx, `UPDATE deliveries SET attempts=attempts+1, last_error=$2,
				status = CASE WHEN attempts >= 23 THEN 'failed' ELSE status END WHERE id = ANY($1)`, g.ids, truncate(err.Error(), 500))
			n.Log.Warn("digest failed", "rule", g.ruleID, "err", err)
			continue
		}
		metricDeliveries.WithLabelValues(g.typ, "sent").Add(float64(len(g.ids)))
		if err := pgx.BeginFunc(ctx, n.Pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE deliveries SET status='sent', sent_at=now(), attempts=attempts+1, last_error=NULL WHERE id = ANY($1)`, g.ids); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE notification_rules SET last_digest_at=now() WHERE id=$1`, g.ruleID)
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}
