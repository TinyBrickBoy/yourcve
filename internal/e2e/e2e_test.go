// Package e2e tests the pipeline ingest → matcher → outbox → webhook against
// a real PostgreSQL (set TEST_DATABASE_URL, the database is wiped).
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/tinybrickboy/yourcve/internal/catalog"
	"github.com/tinybrickboy/yourcve/internal/cvedb"
	"github.com/tinybrickboy/yourcve/internal/db"
	"github.com/tinybrickboy/yourcve/internal/ingest"
	"github.com/tinybrickboy/yourcve/internal/jobs"
	"github.com/tinybrickboy/yourcve/internal/matcher"
	"github.com/tinybrickboy/yourcve/internal/notify"
)

func ptr[T any](v T) *T { return &v }

type hook struct {
	mu   sync.Mutex
	got  []notify.WebhookPayload
	recv chan struct{}
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var p notify.WebhookPayload
	_ = json.Unmarshal(b, &p)
	h.mu.Lock()
	h.got = append(h.got, p)
	h.mu.Unlock()
	h.recv <- struct{}{}
}

func (h *hook) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.got)
}

func setup(t *testing.T) (*pgxpool.Pool, context.Context) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool, slog.Default()); err != nil {
		t.Fatal(err)
	}
	return pool, ctx
}

func startRiver(t *testing.T, ctx context.Context, pool *pgxpool.Pool, n *notify.Notifier, m *matcher.Matcher) *jobs.Client {
	w := river.NewWorkers()
	river.AddWorker(w, &matcher.CVEWorker{M: m})
	river.AddWorker(w, &matcher.StackWorker{M: m})
	river.AddWorker(w, &notify.DeliverWorker{N: n})
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:            map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 2}, jobs.QueueMatch: {MaxWorkers: 2}, jobs.QueueNotify: {MaxWorkers: 2}},
		Workers:           w,
		FetchPollInterval: 200 * time.Millisecond,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	m.River = rc
	if err := rc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return rc
}

func TestNewCVEReachesWebhookOnce(t *testing.T) {
	pool, ctx := setup(t)
	h := &hook{recv: make(chan struct{}, 10)}
	srv := httptest.NewServer(h)
	defer srv.Close()

	sealer, _ := notify.NewSealer("test-secret-test-secret-test-secret-12")
	n := &notify.Notifier{Pool: pool, Sealer: sealer, Sender: notify.NewSender(notify.Guard{AllowPrivate: true}, nil),
		Log: slog.Default(), BaseURL: "http://localhost", MaxPerChannelHour: 20}
	m := &matcher.Matcher{Pool: pool, Log: slog.Default(), NotifyMaxAge: 30 * 24 * time.Hour}
	rc := startRiver(t, ctx, pool, n, m)

	// user, stack "Webshop" with nginx 1.24.0, webhook channel, rule min CVSS 7
	var uid, sid, cid int64
	must(t, pool.QueryRow(ctx, `INSERT INTO users (email, verified) VALUES ('a@example.com', true) RETURNING id`).Scan(&uid))
	must(t, pool.QueryRow(ctx, `INSERT INTO stacks (user_id, name) VALUES ($1, 'Webshop') RETURNING id`, uid).Scan(&sid))
	pid, err := catalog.EnsureCPE(ctx, pool, nil, "a", "f5", "nginx")
	must(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO stack_items (stack_id, product_id, version) VALUES ($1,$2,'1.24.0')`, sid, pid)
	must(t, err)
	cfg, _ := sealer.Seal(map[string]string{"url": srv.URL, "secret": "s"})
	must(t, pool.QueryRow(ctx, `INSERT INTO channels (user_id, type, name, config, verified) VALUES ($1,'webhook','hook',$2,true) RETURNING id`, uid, cfg).Scan(&cid))
	_, err = pool.Exec(ctx, `INSERT INTO notification_rules (stack_id, channel_id, min_cvss) VALUES ($1,$2,7)`, sid, cid)
	must(t, err)

	env := &ingest.Env{Pool: pool, River: rc, Log: slog.Default()}
	now := time.Now()
	rec := ingest.Record{
		Patch: cvedb.Patch{ID: "CVE-2099-0001", Source: "nvd", Description: ptr("Heap overflow in nginx resolver"),
			CVSS: ptr(9.8), CVSSVersion: ptr("3.1"), Published: &now},
		Affects: []cvedb.Affect{{ProductID: pid, Source: "nvd", StartIncluding: "1.0.0", EndExcluding: "1.25.4", Confirmed: true}},
	}
	low := ingest.Record{ // below min CVSS: match, but no message
		Patch:   cvedb.Patch{ID: "CVE-2099-0002", Source: "nvd", Description: ptr("minor issue"), CVSS: ptr(3.1), Published: &now},
		Affects: []cvedb.Affect{{ProductID: pid, Source: "nvd", EndExcluding: "2.0", Confirmed: true}},
	}
	other := ingest.Record{ // fixed in our version: no match
		Patch:   cvedb.Patch{ID: "CVE-2099-0003", Source: "nvd", Description: ptr("old bug"), CVSS: ptr(9.0), Published: &now},
		Affects: []cvedb.Affect{{ProductID: pid, Source: "nvd", EndExcluding: "1.20.0", Confirmed: true}},
	}
	start := time.Now()
	must(t, env.Write(ctx, []ingest.Record{rec, low, other}, false))

	select {
	case <-h.recv:
		t.Logf("delivered %s after %s", h.got[0].Items[0].CVEID, time.Since(start))
	case <-time.After(20 * time.Second):
		t.Fatal("no webhook delivery within 20s")
	}
	if got := h.got[0].Items[0].CVEID; got != "CVE-2099-0001" {
		t.Fatalf("delivered %s", got)
	}
	var matches int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM matches WHERE stack_id=$1`, sid).Scan(&matches))
	if matches != 2 {
		t.Fatalf("want 2 matches (0001, 0002), got %d", matches)
	}

	// the same data again (source re-sync, restart) must not send twice
	must(t, env.Write(ctx, []ingest.Record{rec}, false))
	rec2 := rec
	rec2.Patch.References = []string{"https://example.com/advisory"}
	must(t, env.Write(ctx, []ingest.Record{rec2}, false))
	time.Sleep(2 * time.Second)
	if c := h.count(); c != 1 {
		t.Fatalf("expected exactly 1 delivery after re-import, got %d", c)
	}

	// KEV addition is a new occasion → one more message
	must(t, env.Write(ctx, []ingest.Record{{Patch: cvedb.Patch{ID: "CVE-2099-0001", Source: "kev", KEV: ptr(true)}}}, false))
	select {
	case <-h.recv:
	case <-time.After(20 * time.Second):
		t.Fatal("no KEV delivery")
	}
	if h.got[1].Items[0].Occasion != "kev_added" {
		t.Fatalf("occasion %q", h.got[1].Items[0].Occasion)
	}

	// marked as patched → further events stay silent
	_, err = pool.Exec(ctx, `INSERT INTO stack_cve_status (stack_id, cve_id, status) VALUES ($1,'CVE-2099-0001','patched')`, sid)
	must(t, err)
	must(t, env.Write(ctx, []ingest.Record{{Patch: cvedb.Patch{ID: "CVE-2099-0001", Source: "nvd", CVSS: ptr(10.0)}}}, false))
	time.Sleep(2 * time.Second)
	if c := h.count(); c != 2 {
		t.Fatalf("patched CVE must not notify, got %d deliveries", c)
	}
	var sent int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM deliveries WHERE status='sent'`).Scan(&sent))
	if sent != 2 {
		t.Fatalf("deliveries sent = %d", sent)
	}
	_ = rc.Stop(ctx)
}

// A restart while a delivery is queued must deliver it after the restart.
func TestQueuedDeliverySurvivesRestart(t *testing.T) {
	pool, ctx := setup(t)
	h := &hook{recv: make(chan struct{}, 10)}
	srv := httptest.NewServer(h)
	defer srv.Close()
	sealer, _ := notify.NewSealer("test-secret-test-secret-test-secret-12")
	n := &notify.Notifier{Pool: pool, Sealer: sealer, Sender: notify.NewSender(notify.Guard{AllowPrivate: true}, nil),
		Log: slog.Default(), BaseURL: "http://localhost", MaxPerChannelHour: 20}

	var uid, sid, cid int64
	must(t, pool.QueryRow(ctx, `INSERT INTO users (email, verified) VALUES ('b@example.com', true) RETURNING id`).Scan(&uid))
	must(t, pool.QueryRow(ctx, `INSERT INTO stacks (user_id, name) VALUES ($1, 'S') RETURNING id`, uid).Scan(&sid))
	pid, _ := catalog.EnsurePackage(ctx, pool, nil, "npm", "lodash")
	_, _ = pool.Exec(ctx, `INSERT INTO stack_items (stack_id, product_id, version) VALUES ($1,$2,'4.17.20')`, sid, pid)
	cfg, _ := sealer.Seal(map[string]string{"url": srv.URL, "secret": "s"})
	must(t, pool.QueryRow(ctx, `INSERT INTO channels (user_id, type, name, config, verified) VALUES ($1,'webhook','hook',$2,true) RETURNING id`, uid, cfg).Scan(&cid))
	_, _ = pool.Exec(ctx, `INSERT INTO notification_rules (stack_id, channel_id) VALUES ($1,$2)`, sid, cid)

	// "process 1" only ingests (no workers running) and dies
	rcInsertOnly, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	must(t, err)
	env := &ingest.Env{Pool: pool, River: rcInsertOnly, Log: slog.Default()}
	now := time.Now()
	must(t, env.Write(ctx, []ingest.Record{{
		Patch:   cvedb.Patch{ID: "CVE-2099-0100", Source: "osv", Description: ptr("prototype pollution"), Published: &now},
		Affects: []cvedb.Affect{{ProductID: pid, Source: "osv", EndExcluding: "4.17.21", Confirmed: true}},
	}}, false))

	// "process 2" starts workers and picks up the queued jobs from PostgreSQL
	m := &matcher.Matcher{Pool: pool, Log: slog.Default(), NotifyMaxAge: 30 * 24 * time.Hour}
	rc := startRiver(t, ctx, pool, n, m)
	select {
	case <-h.recv:
	case <-time.After(20 * time.Second):
		t.Fatal("queued job not processed after restart")
	}
	time.Sleep(time.Second)
	if h.count() != 1 {
		t.Fatalf("got %d deliveries", h.count())
	}
	_ = rc.Stop(ctx)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
