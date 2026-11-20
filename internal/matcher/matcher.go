// Package matcher connects CVEs to stacks: stack → product → CVE affects.
// It runs as River jobs right after each import (MatchCVE) and after a stack
// was edited (MatchStack). New matches create outbox rows in deliveries in the
// same transaction, so nothing is lost and nothing is sent twice.
package matcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/tinybrickboy/yourcve/internal/cvedb"
	"github.com/tinybrickboy/yourcve/internal/jobs"
	"github.com/tinybrickboy/yourcve/internal/version"
)

type Matcher struct {
	Pool         *pgxpool.Pool
	River        *jobs.Client
	Log          *slog.Logger
	NotifyMaxAge time.Duration // only CVEs published within this window trigger "new" notifications
	AIEnabled    bool
}

type affect struct {
	productID   int64
	productName string
	ecosystem   string
	source      string
	rng         version.Range
	allVersions bool
	confirmed   bool
}

type item struct {
	id        int64
	stackID   int64
	productID int64
	version   string
}

type result struct {
	reason    string
	confirmed bool
}

// Evaluate checks one stack item against one affect.
func evaluate(it item, a affect) (bool, string) {
	if version.IsAll(it.version) {
		return true, fmt.Sprintf("%s (all versions tracked) listed by %s", a.productName, a.source)
	}
	if a.allVersions {
		return true, fmt.Sprintf("%s %s: all versions affected (%s)", a.productName, it.version, a.source)
	}
	scheme := version.SchemeForEcosystem(a.ecosystem)
	if !a.rng.Contains(scheme, it.version) {
		return false, ""
	}
	return true, fmt.Sprintf("%s %s in %s (%s)", a.productName, it.version, describeRange(a.rng), a.source)
}

func describeRange(r version.Range) string {
	var p []string
	if r.StartIncluding != "" {
		p = append(p, ">= "+r.StartIncluding)
	}
	if r.StartExcluding != "" {
		p = append(p, "> "+r.StartExcluding)
	}
	if r.EndIncluding != "" {
		p = append(p, "<= "+r.EndIncluding)
	}
	if r.EndExcluding != "" {
		p = append(p, "< "+r.EndExcluding)
	}
	if len(p) == 0 && len(r.Versions) > 0 {
		v := r.Versions
		if len(v) > 5 {
			return "affected versions (" + strings.Join(v[:5], ", ") + ", …)"
		}
		return "affected versions (" + strings.Join(v, ", ") + ")"
	}
	return "range " + strings.Join(p, " ")
}

func better(cur result, ok bool, cand result) bool {
	return !ok || (cand.confirmed && !cur.confirmed)
}

func loadAffects(ctx context.Context, tx pgx.Tx, where string, arg any) ([]affect, error) {
	rows, err := tx.Query(ctx, `SELECT a.product_id, p.name, p.ecosystem, a.source,
		coalesce(a.version_start_including,''), coalesce(a.version_start_excluding,''),
		coalesce(a.version_end_including,''), coalesce(a.version_end_excluding,''),
		a.versions, a.all_versions, a.confirmed
		FROM cve_affects a JOIN products p ON p.id = a.product_id WHERE `+where, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []affect
	for rows.Next() {
		var a affect
		if err := rows.Scan(&a.productID, &a.productName, &a.ecosystem, &a.source, &a.rng.StartIncluding,
			&a.rng.StartExcluding, &a.rng.EndIncluding, &a.rng.EndExcluding, &a.rng.Versions,
			&a.allVersions, &a.confirmed); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- MatchCVE

type CVEWorker struct {
	river.WorkerDefaults[jobs.MatchCVE]
	M *Matcher
}

func (w *CVEWorker) Work(ctx context.Context, job *river.Job[jobs.MatchCVE]) error {
	return w.M.MatchCVE(ctx, job.Args)
}

type cveInfo struct {
	state     string
	cvss      *float64
	kev       bool
	epss      *float64
	published *time.Time
}

func (m *Matcher) MatchCVE(ctx context.Context, args jobs.MatchCVE) error {
	return pgx.BeginFunc(ctx, m.Pool, func(tx pgx.Tx) error {
		var ci cveInfo
		err := tx.QueryRow(ctx, `SELECT state, cvss::float8, kev, epss, published FROM cves WHERE id=$1`, args.CVEID).
			Scan(&ci.state, &ci.cvss, &ci.kev, &ci.epss, &ci.published)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if ci.state == "REJECTED" {
			_, err := tx.Exec(ctx, `DELETE FROM matches WHERE cve_id=$1`, args.CVEID)
			return err
		}
		affects, err := loadAffects(ctx, tx, "a.cve_id = $1", args.CVEID)
		if err != nil {
			return err
		}
		byProduct := map[int64][]affect{}
		var pids []int64
		for _, a := range affects {
			if _, ok := byProduct[a.productID]; !ok {
				pids = append(pids, a.productID)
			}
			byProduct[a.productID] = append(byProduct[a.productID], a)
		}
		found := map[int64]result{}
		if len(pids) > 0 {
			rows, err := tx.Query(ctx, `SELECT id, stack_id, product_id, version FROM stack_items WHERE product_id = ANY($1)`, pids)
			if err != nil {
				return err
			}
			var items []item
			for rows.Next() {
				var it item
				if err := rows.Scan(&it.id, &it.stackID, &it.productID, &it.version); err != nil {
					rows.Close()
					return err
				}
				items = append(items, it)
			}
			rows.Close()
			for _, it := range items {
				for _, a := range byProduct[it.productID] {
					if ok, reason := evaluate(it, a); ok {
						cand := result{reason: reason, confirmed: a.confirmed}
						if cur, exists := found[it.stackID]; better(cur, exists, cand) {
							found[it.stackID] = cand
						}
					}
				}
			}
		}

		stackIDs := make([]int64, 0, len(found))
		for sid := range found {
			stackIDs = append(stackIDs, sid)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM matches WHERE cve_id=$1 AND NOT (stack_id = ANY($2))`, args.CVEID, stackIDs); err != nil {
			return err
		}
		recent := ci.published == nil || m.NotifyMaxAge <= 0 || time.Since(*ci.published) <= m.NotifyMaxAge
		enqueueAI := false
		for sid, r := range found {
			var matchID int64
			var inserted bool
			err := tx.QueryRow(ctx, `INSERT INTO matches (cve_id, stack_id, reason, confirmed) VALUES ($1,$2,$3,$4)
				ON CONFLICT (cve_id, stack_id) DO UPDATE SET reason=EXCLUDED.reason, confirmed=EXCLUDED.confirmed,
					updated_at = CASE WHEN matches.reason <> EXCLUDED.reason OR matches.confirmed <> EXCLUDED.confirmed THEN now() ELSE matches.updated_at END
				RETURNING id, (xmax = 0)`, args.CVEID, sid, r.reason, r.confirmed).Scan(&matchID, &inserted)
			if err != nil {
				return err
			}
			if inserted {
				enqueueAI = true
			}
			if !args.Notify {
				continue
			}
			var occasions []string
			if inserted && recent {
				occasions = append(occasions, "new")
			}
			if !inserted {
				for _, e := range args.Events {
					switch e {
					case cvedb.EventKEVAdded:
						occasions = append(occasions, "kev_added")
					case cvedb.EventCVSSRaised:
						occasions = append(occasions, "cvss_raised")
					}
				}
			}
			for _, occ := range occasions {
				if err := m.createDeliveries(ctx, tx, matchID, args.CVEID, sid, occ, r.confirmed, ci); err != nil {
					return err
				}
			}
		}
		if enqueueAI && m.AIEnabled && m.River != nil {
			if _, err := m.River.InsertTx(ctx, tx, jobs.AIEnrich{CVEID: args.CVEID}, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

// createDeliveries writes outbox rows for all matching rules of a stack.
func (m *Matcher) createDeliveries(ctx context.Context, tx pgx.Tx, matchID int64, cveID string, stackID int64,
	occasion string, confirmed bool, ci cveInfo) error {
	var status string
	err := tx.QueryRow(ctx, `SELECT status FROM stack_cve_status WHERE stack_id=$1 AND cve_id=$2`, stackID, cveID).Scan(&status)
	if err == nil {
		return nil // assessed as not affected / patched: no more messages
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var userID int64
	if err := tx.QueryRow(ctx, `SELECT user_id FROM stacks WHERE id=$1`, stackID).Scan(&userID); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"user_id": userID, "stack_id": stackID, "cve_id": cveID, "occasion": occasion})
	if _, err := tx.Exec(ctx, `SELECT pg_notify('yourcve_events', $1)`, string(payload)); err != nil {
		return err
	}

	rows, err := tx.Query(ctx, `SELECT r.id, r.channel_id, r.min_cvss::float8, r.kev_only, r.min_epss, r.mode, r.include_unconfirmed
		FROM notification_rules r JOIN channels c ON c.id = r.channel_id
		WHERE r.stack_id=$1 AND r.enabled AND c.enabled AND c.verified AND c.class = 'free'`, stackID)
	if err != nil {
		return err
	}
	type rule struct {
		id, channelID       int64
		minCVSS, minEPSS    float64
		kevOnly, inclUnconf bool
		mode                string
	}
	var rules []rule
	for rows.Next() {
		var r rule
		if err := rows.Scan(&r.id, &r.channelID, &r.minCVSS, &r.kevOnly, &r.minEPSS, &r.mode, &r.inclUnconf); err != nil {
			rows.Close()
			return err
		}
		rules = append(rules, r)
	}
	rows.Close()
	for _, r := range rules {
		if !RulePasses(r.minCVSS, r.kevOnly, r.minEPSS, r.inclUnconf, ci.cvss, ci.kev, ci.epss, confirmed, occasion) {
			continue
		}
		status := "pending"
		if r.mode != "instant" {
			status = "digest"
		}
		var id int64
		err := tx.QueryRow(ctx, `INSERT INTO deliveries (match_id, cve_id, stack_id, channel_id, rule_id, occasion, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (cve_id, stack_id, channel_id, occasion) DO NOTHING RETURNING id`,
			matchID, cveID, stackID, r.channelID, r.id, occasion, status).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // already queued or sent
		}
		if err != nil {
			return err
		}
		if status == "pending" && m.River != nil {
			if _, err := m.River.InsertTx(ctx, tx, jobs.Deliver{DeliveryID: id}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// RulePasses applies the rule filters. KEV additions always pass the CVSS and
// EPSS thresholds because exploitation in the wild is the stronger signal.
func RulePasses(minCVSS float64, kevOnly bool, minEPSS float64, includeUnconfirmed bool,
	cvss *float64, kev bool, epss *float64, confirmed bool, occasion string) bool {
	if !confirmed && !includeUnconfirmed {
		return false
	}
	if kevOnly && !kev {
		return false
	}
	if occasion == "kev_added" {
		return true
	}
	if minCVSS > 0 && (cvss == nil || *cvss < minCVSS) {
		return false
	}
	if minEPSS > 0 && (epss == nil || *epss < minEPSS) {
		return false
	}
	return true
}

// ---------------------------------------------------------------- MatchStack

type StackWorker struct {
	river.WorkerDefaults[jobs.MatchStack]
	M *Matcher
}

func (w *StackWorker) Work(ctx context.Context, job *river.Job[jobs.MatchStack]) error {
	return w.M.MatchStack(ctx, job.Args.StackID)
}

// MatchStack recomputes all matches of one stack (historic CVEs, no notifications).
func (m *Matcher) MatchStack(ctx context.Context, stackID int64) error {
	return pgx.BeginFunc(ctx, m.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, stack_id, product_id, version FROM stack_items WHERE stack_id=$1`, stackID)
		if err != nil {
			return err
		}
		var items []item
		var pids []int64
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.id, &it.stackID, &it.productID, &it.version); err != nil {
				rows.Close()
				return err
			}
			items = append(items, it)
			pids = append(pids, it.productID)
		}
		rows.Close()
		type key = string
		found := map[key]result{}
		if len(pids) > 0 {
			rows, err := tx.Query(ctx, `SELECT a.cve_id, a.product_id, p.name, p.ecosystem, a.source,
				coalesce(a.version_start_including,''), coalesce(a.version_start_excluding,''),
				coalesce(a.version_end_including,''), coalesce(a.version_end_excluding,''),
				a.versions, a.all_versions, a.confirmed
				FROM cve_affects a JOIN products p ON p.id = a.product_id
				JOIN cves c ON c.id = a.cve_id AND c.state <> 'REJECTED'
				WHERE a.product_id = ANY($1)`, pids)
			if err != nil {
				return err
			}
			byProduct := map[int64][]item{}
			for _, it := range items {
				byProduct[it.productID] = append(byProduct[it.productID], it)
			}
			for rows.Next() {
				var cveID string
				var a affect
				if err := rows.Scan(&cveID, &a.productID, &a.productName, &a.ecosystem, &a.source, &a.rng.StartIncluding,
					&a.rng.StartExcluding, &a.rng.EndIncluding, &a.rng.EndExcluding, &a.rng.Versions,
					&a.allVersions, &a.confirmed); err != nil {
					rows.Close()
					return err
				}
				for _, it := range byProduct[a.productID] {
					if ok, reason := evaluate(it, a); ok {
						cand := result{reason: reason, confirmed: a.confirmed}
						if cur, exists := found[cveID]; better(cur, exists, cand) {
							found[cveID] = cand
						}
					}
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		ids := make([]string, 0, len(found))
		reasons := make([]string, 0, len(found))
		conf := make([]bool, 0, len(found))
		for id, r := range found {
			ids = append(ids, id)
			reasons = append(reasons, r.reason)
			conf = append(conf, r.confirmed)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM matches WHERE stack_id=$1 AND NOT (cve_id = ANY($2))`, stackID, ids); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO matches (cve_id, stack_id, reason, confirmed)
			SELECT u.cve_id, $1, u.reason, u.confirmed FROM unnest($2::text[], $3::text[], $4::bool[]) AS u(cve_id, reason, confirmed)
			ON CONFLICT (cve_id, stack_id) DO UPDATE SET reason=EXCLUDED.reason, confirmed=EXCLUDED.confirmed`,
			stackID, ids, reasons, conf)
		return err
	})
}
