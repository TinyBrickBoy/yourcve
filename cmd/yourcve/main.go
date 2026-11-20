// Command yourcve is the single binary: web UI, REST API, MCP, ingest,
// matcher, AI worker and notification delivery.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata" // timezones for quiet hours in the distroless image

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/tinybrickboy/yourcve/internal/ai"
	"github.com/tinybrickboy/yourcve/internal/api"
	"github.com/tinybrickboy/yourcve/internal/auth"
	"github.com/tinybrickboy/yourcve/internal/catalog"
	"github.com/tinybrickboy/yourcve/internal/config"
	"github.com/tinybrickboy/yourcve/internal/cvedb"
	"github.com/tinybrickboy/yourcve/internal/db"
	"github.com/tinybrickboy/yourcve/internal/ingest"
	"github.com/tinybrickboy/yourcve/internal/jobs"
	"github.com/tinybrickboy/yourcve/internal/matcher"
	"github.com/tinybrickboy/yourcve/internal/notify"
	"github.com/tinybrickboy/yourcve/web"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck": // for Docker HEALTHCHECK in the distroless image (no curl)
			os.Exit(healthcheck())
		case "version":
			fmt.Println(version)
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "yourcve:", err)
		os.Exit(1)
	}
}

func healthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		return 1
	}
	return 0
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	log.Info("starting yourcve", "version", version, "ai", cfg.AIEnabled(), "email", cfg.EmailEnabled())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool, log); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	sealer, err := notify.NewSealer(cfg.SecretKey)
	if err != nil {
		return err
	}
	var mailer *notify.Mailer
	if cfg.EmailEnabled() {
		if mailer, err = notify.NewMailer(cfg.SMTPURL, cfg.SMTPFrom); err != nil {
			return err
		}
	}
	guard := notify.Guard{AllowPrivate: cfg.AllowPrivateWebhooks}
	// Shoutrrr services use the default transport: route it through the SSRF guard.
	http.DefaultTransport = guard.Transport()
	sender := notify.NewSender(guard, mailer)
	notifier := &notify.Notifier{Pool: pool, Sealer: sealer, Sender: sender, Log: log, BaseURL: cfg.BaseURL,
		MaxPerChannelHour: cfg.MaxPerChannelHour, EmailPerUserHour: cfg.EmailPerUserHour, AIEnabled: cfg.AIEnabled()}

	authSvc, err := auth.NewService(pool, cfg.BaseURL, cfg.SecretKey, cfg.SecureCookies(), cfg.IsAdminEmail)
	if err != nil {
		return err
	}

	var enricher *ai.Enricher
	if cfg.AIEnabled() {
		enricher = &ai.Enricher{Pool: pool, Log: log, RecentYears: cfg.AIRecentYears,
			Client: ai.NewClient(cfg.OllamaURL, cfg.OllamaModel, cfg.EmbedModel, cfg.SummaryLang)}
	}

	// ---- River (jobs in PostgreSQL)
	m := &matcher.Matcher{Pool: pool, Log: log, NotifyMaxAge: 30 * 24 * time.Hour, AIEnabled: cfg.AIEnabled()}
	workers := river.NewWorkers()
	river.AddWorker(workers, &matcher.CVEWorker{M: m})
	river.AddWorker(workers, &matcher.StackWorker{M: m})
	river.AddWorker(workers, &notify.DeliverWorker{N: notifier})
	river.AddWorker(workers, &notify.DigestWorker{N: notifier})
	river.AddWorker(workers, &maintenanceWorker{pool: pool, auth: authSvc, log: log})
	backfill := &ai.BackfillWorker{E: enricher}
	if enricher != nil {
		river.AddWorker(workers, &ai.EnrichWorker{E: enricher})
		river.AddWorker(workers, backfill)
	}
	periodic := []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(time.Minute), func() (river.JobArgs, *river.InsertOpts) { return jobs.Digest{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
		river.NewPeriodicJob(river.PeriodicInterval(time.Hour), func() (river.JobArgs, *river.InsertOpts) { return jobs.Maintenance{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}
	queues := map[string]river.QueueConfig{
		river.QueueDefault: {MaxWorkers: 2},
		jobs.QueueMatch:    {MaxWorkers: 4},
		jobs.QueueNotify:   {MaxWorkers: 10},
	}
	if enricher != nil {
		queues[jobs.QueueAI] = river.QueueConfig{MaxWorkers: max(cfg.AIConcurrency, 1)}
		periodic = append(periodic, river.NewPeriodicJob(river.PeriodicInterval(5*time.Minute),
			func() (river.JobArgs, *river.InsertOpts) { return jobs.AIBackfill{}, nil }, &river.PeriodicJobOpts{RunOnStart: true}))
	}
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:       queues,
		Workers:      workers,
		PeriodicJobs: periodic,
		Logger:       slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})),
		JobTimeout:   5 * time.Minute,
	})
	if err != nil {
		return err
	}
	m.River = rc
	backfill.River = rc
	if err := rc.Start(ctx); err != nil {
		return err
	}

	// ---- ingest
	ienv := &ingest.Env{Pool: pool, River: rc, Log: log, HTTP: ingest.NewHTTPClient(), Cache: catalog.NewCache()}
	var sched *ingest.Scheduler
	if cfg.IngestEnabled {
		sched = &ingest.Scheduler{Env: ienv, Sources: []ingest.Source{
			&ingest.CVEList{Env: ienv, Every: cfg.IntervalCVEList, GitHubToken: cfg.GitHubToken, InitialImport: cfg.InitialImport},
			&ingest.NVD{Env: ienv, Every: cfg.IntervalNVD, APIKey: cfg.NVDAPIKey, InitialImport: cfg.InitialImport},
			&ingest.KEV{Env: ienv, Every: cfg.IntervalKEV},
			&ingest.EPSS{Env: ienv, Every: cfg.IntervalEPSS},
			&ingest.OSV{Env: ienv, Every: cfg.IntervalOSV, Ecosystems: cfg.OSVEcosystems, InitialImport: cfg.InitialImport},
			&ingest.CPEDictionary{Env: ienv, Every: cfg.IntervalCPE, APIKey: cfg.NVDAPIKey, InitialImport: cfg.InitialImport},
		}}
		sched.Start(ctx)
	}

	// ---- HTTP
	hub := api.NewHub(pool, log)
	go hub.Run(ctx)
	var ready atomic.Bool
	srv := &api.Server{Cfg: cfg, Pool: pool, Log: log, Auth: authSvc, CVEs: &cvedb.Store{Pool: pool},
		Catalog: &catalog.Store{Pool: pool}, River: rc, Sealer: sealer, Sender: sender, Notifier: notifier,
		Mailer: mailer, Hub: hub, Web: web.Handler(), Ready: ready.Load}
	if enricher != nil {
		srv.AI = enricher
	}
	srv.MCP = srv.MCPHandler()
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "base_url", cfg.BaseURL)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	ready.Store(true)

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}

	// ---- graceful shutdown: stop taking requests, let running jobs finish
	log.Info("shutting down")
	ready.Store(false)
	sctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	if sched != nil {
		sched.Wait()
	}
	if err := rc.Stop(sctx); err != nil {
		log.Warn("river soft stop timed out, cancelling running jobs", "err", err)
		_ = rc.StopAndCancel(context.Background())
	}
	log.Info("bye")
	return nil
}

type maintenanceWorker struct {
	river.WorkerDefaults[jobs.Maintenance]
	pool *pgxpool.Pool
	auth *auth.Service
	log  *slog.Logger
}

func (w *maintenanceWorker) Work(ctx context.Context, _ *river.Job[jobs.Maintenance]) error {
	if err := w.auth.Cleanup(ctx); err != nil {
		return err
	}
	if err := catalog.RefreshCounts(ctx, w.pool); err != nil {
		return err
	}
	// keep the delivery log for 180 days
	_, err := w.pool.Exec(ctx, `DELETE FROM deliveries WHERE created_at < now() - interval '180 days' AND status IN ('sent','suppressed','failed')`)
	return err
}
