// Package ingest pulls CVE data from cvelistV5, NVD, CISA KEV, FIRST EPSS and
// OSV into PostgreSQL. Every source keeps its cursor in sync_state, so a
// restart continues where it stopped. Each source runs in its own loop guarded
// by a PostgreSQL advisory lock (only one instance works on a source).
package ingest

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/riverqueue/river"
	"golang.org/x/sync/errgroup"

	"github.com/tinybrickboy/yourcve/internal/catalog"
	"github.com/tinybrickboy/yourcve/internal/cvedb"
	"github.com/tinybrickboy/yourcve/internal/jobs"
)

const userAgent = "yourcve/1.0 (self-hosted CVE notifier)"

var (
	metricRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "yourcve_ingest_runs_total", Help: "Ingest runs per source and result."}, []string{"source", "result"})
	metricItems = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "yourcve_ingest_items_total", Help: "Records processed per source."}, []string{"source"})
	metricLag = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "yourcve_ingest_lag_seconds", Help: "Age of the newest item seen per source."}, []string{"source"})
)

func init() { prometheus.MustRegister(metricRuns, metricItems, metricLag) }

// Source is one upstream feed.
type Source interface {
	Name() string
	Interval() time.Duration
	// Run does one sync step. It reads and writes its own cursor via st.
	Run(ctx context.Context, st *State) error
}

// ErrRateLimited makes the scheduler back off.
type ErrRateLimited struct{ RetryAfter time.Duration }

func (e ErrRateLimited) Error() string {
	return fmt.Sprintf("rate limited, retry after %s", e.RetryAfter)
}

// Env bundles what sources need.
type Env struct {
	Pool  *pgxpool.Pool
	River *jobs.Client
	Log   *slog.Logger
	HTTP  *http.Client
	Cache *catalog.Cache
}

func NewHTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 8
	t.ResponseHeaderTimeout = 60 * time.Second
	return &http.Client{Transport: t, Timeout: 30 * time.Minute}
}

func (e *Env) get(ctx context.Context, url string, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		resp.Body.Close()
		ra, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		d := time.Duration(ra) * time.Second
		if d <= 0 {
			d = 30 * time.Second
		}
		return nil, ErrRateLimited{RetryAfter: d}
	}
	return resp, nil
}

func statusErr(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	return fmt.Errorf("GET %s: HTTP %d: %s", resp.Request.URL.Redacted(), resp.StatusCode, b)
}

// ---------------------------------------------------------------- state

type State struct {
	Source     string
	Cursor     string
	ETag       string
	NewestItem *time.Time
	pool       *pgxpool.Pool
	itemsAdded int64
}

func loadState(ctx context.Context, pool *pgxpool.Pool, source string) (*State, error) {
	st := &State{Source: source, pool: pool}
	var etag *string
	err := pool.QueryRow(ctx, `SELECT cursor, etag, newest_item FROM sync_state WHERE source=$1`, source).
		Scan(&st.Cursor, &etag, &st.NewestItem)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = pool.Exec(ctx, `INSERT INTO sync_state (source) VALUES ($1) ON CONFLICT DO NOTHING`, source)
	}
	if etag != nil {
		st.ETag = *etag
	}
	return st, err
}

// Save persists cursor and etag immediately (call after each committed batch).
func (s *State) Save(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE sync_state SET cursor=$2, etag=NULLIF($3,''), newest_item=$4,
		items_total = items_total + $5 WHERE source=$1`, s.Source, s.Cursor, s.ETag, s.NewestItem, s.itemsAdded)
	if err == nil {
		s.itemsAdded = 0
	}
	return err
}

// Seen records processed items and the newest timestamp (for lag metrics).
func (s *State) Seen(n int, newest *time.Time) {
	s.itemsAdded += int64(n)
	metricItems.WithLabelValues(s.Source).Add(float64(n))
	if newest != nil && (s.NewestItem == nil || newest.After(*s.NewestItem)) {
		t := *newest
		s.NewestItem = &t
	}
}

// ---------------------------------------------------------------- scheduler

type Scheduler struct {
	Env     *Env
	Sources []Source
	wg      sync.WaitGroup
}

func lockKey(name string) int64 {
	h := fnv.New64a()
	h.Write([]byte("yourcve-ingest-" + name))
	return int64(h.Sum64() >> 1)
}

func (s *Scheduler) Start(ctx context.Context) {
	for _, src := range s.Sources {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.loop(ctx, src)
		}()
	}
}

func (s *Scheduler) Wait() { s.wg.Wait() }

func (s *Scheduler) loop(ctx context.Context, src Source) {
	log := s.Env.Log.With("source", src.Name())
	// small random offset so sources don't fire at the same instant
	wait := time.Duration(rand.IntN(3000)) * time.Millisecond
	backoff := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		start := time.Now()
		err := s.runOnce(ctx, src)
		wait = src.Interval() - time.Since(start)
		var rl ErrRateLimited
		switch {
		case err == nil:
			backoff = 0
		case errors.Is(err, errLocked):
			wait = src.Interval()
		case errors.As(err, &rl):
			backoff = max(rl.RetryAfter, backoff*2)
			wait = backoff
			log.Warn("rate limited", "retry_in", wait)
		case ctx.Err() != nil:
			return
		default:
			backoff = min(max(backoff*2, 30*time.Second), 30*time.Minute)
			wait = max(wait, backoff)
			log.Error("sync failed", "err", err, "retry_in", wait)
		}
		if wait < time.Second {
			wait = time.Second
		}
	}
}

var errLocked = errors.New("locked by another instance")

func (s *Scheduler) runOnce(ctx context.Context, src Source) (err error) {
	conn, err := s.Env.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	var ok bool
	key := lockKey(src.Name())
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return errLocked
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key) //nolint:errcheck

	st, err := loadState(ctx, s.Env.Pool, src.Name())
	if err != nil {
		return err
	}
	_, _ = s.Env.Pool.Exec(ctx, `UPDATE sync_state SET last_run=now() WHERE source=$1`, src.Name())
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
		if saveErr := st.Save(context.WithoutCancel(ctx)); err == nil {
			err = saveErr
		}
		bg := context.WithoutCancel(ctx)
		if err != nil && ctx.Err() == nil {
			metricRuns.WithLabelValues(src.Name(), "error").Inc()
			_, _ = s.Env.Pool.Exec(bg, `UPDATE sync_state SET last_error=$2 WHERE source=$1`, src.Name(), truncate(err.Error(), 1000))
		} else if err == nil {
			metricRuns.WithLabelValues(src.Name(), "ok").Inc()
			_, _ = s.Env.Pool.Exec(bg, `UPDATE sync_state SET last_success=now(), last_error=NULL WHERE source=$1`, src.Name())
		}
		if st.NewestItem != nil {
			metricLag.WithLabelValues(src.Name()).Set(time.Since(*st.NewestItem).Seconds())
		}
	}()
	return src.Run(ctx, st)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---------------------------------------------------------------- write helpers

// Record is what a source produced for one CVE.
type Record struct {
	Patch   cvedb.Patch
	Affects []cvedb.Affect // nil = source has no affects info
	// AffectSource is the cve_affects.source to replace (defaults to Patch.Source)
	AffectSource string
}

// Write stores records in one transaction and enqueues match jobs. bulk
// disables notifications (initial import).
func (e *Env) Write(ctx context.Context, recs []Record, bulk bool) error {
	if len(recs) == 0 {
		return nil
	}
	return pgx.BeginFunc(ctx, e.Pool, func(tx pgx.Tx) error {
		var params []jobsInsert
		for _, r := range recs {
			events, err := cvedb.Apply(ctx, tx, r.Patch)
			if err != nil {
				return fmt.Errorf("%s: %w", r.Patch.ID, err)
			}
			changed := len(events) > 0
			if r.Affects != nil {
				src := r.AffectSource
				if src == "" {
					src = r.Patch.Source
				}
				ch, err := cvedb.ReplaceAffects(ctx, tx, r.Patch.ID, src, r.Affects)
				if err != nil {
					return fmt.Errorf("%s affects: %w", r.Patch.ID, err)
				}
				changed = changed || ch
			}
			if changed && !bulk {
				params = append(params, jobsInsert{args: jobs.MatchCVE{CVEID: r.Patch.ID, Events: events, Notify: true}})
			}
		}
		if len(params) > 0 && e.River != nil {
			p := make([]river.InsertManyParams, 0, len(params))
			for _, j := range params {
				p = append(p, river.InsertManyParams{Args: j.args})
			}
			if _, err := e.River.InsertManyTx(ctx, tx, p); err != nil {
				return err
			}
		}
		return nil
	})
}

type jobsInsert struct{ args jobs.MatchCVE }

// RematchAllStacks is used after bulk imports.
func (e *Env) RematchAllStacks(ctx context.Context) error {
	rows, err := e.Pool.Query(ctx, `SELECT id FROM stacks`)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil || e.River == nil {
		return err
	}
	for _, id := range ids {
		if _, err := e.River.Insert(ctx, jobs.MatchStack{StackID: id}, nil); err != nil {
			return err
		}
	}
	return nil
}

func ptr[T any](v T) *T { return &v }

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// parallel runs fn for 0..n-1 with 8 workers and concatenates the results in order.
func parallel(ctx context.Context, n int, fn func(ctx context.Context, i int) ([]Record, error)) ([]Record, error) {
	out := make([][]Record, n)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(8)
	for i := 0; i < n; i++ {
		g.Go(func() error {
			r, err := fn(gctx, i)
			out[i] = r
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	var all []Record
	for _, r := range out {
		all = append(all, r...)
	}
	return all, nil
}
