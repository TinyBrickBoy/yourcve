// Package jobs defines the River job arguments shared between producers
// (ingest, API) and the workers (matcher, notify, ai). Keeping them in one
// leaf package avoids import cycles.
package jobs

import (
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// activeStates: a job with the same args that is queued or running blocks a duplicate.
var activeStates = []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending,
	rivertype.JobStateRunning, rivertype.JobStateScheduled, rivertype.JobStateRetryable}

// Client is the River client used to enqueue jobs.
type Client = river.Client[pgx.Tx]

const (
	QueueDefault = river.QueueDefault
	QueueMatch   = "match"
	QueueNotify  = "notify"
	QueueAI      = "ai"
)

// MatchCVE: re-evaluate one CVE against all stacks after it was inserted or changed.
type MatchCVE struct {
	CVEID  string   `json:"cve_id"`
	Events []string `json:"events"` // cvedb.Event*
	Notify bool     `json:"notify"` // false during bulk imports
}

func (MatchCVE) Kind() string { return "match_cve" }
func (MatchCVE) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMatch, MaxAttempts: 10}
}

// MatchStack: recompute all matches of a stack after it was edited (no notifications).
type MatchStack struct {
	StackID int64 `json:"stack_id"`
}

func (MatchStack) Kind() string { return "match_stack" }
func (MatchStack) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMatch, MaxAttempts: 10}
}

// Deliver sends one notification (outbox row in deliveries).
type Deliver struct {
	DeliveryID int64 `json:"delivery_id"`
}

func (Deliver) Kind() string { return "deliver" }
func (Deliver) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueNotify, MaxAttempts: 8,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeStates}}
}

// Digest sends collected deliveries (hourly/daily rules and rate limit overflow).
type Digest struct{}

func (Digest) Kind() string { return "digest" }
func (Digest) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueNotify, MaxAttempts: 3}
}

// AIEnrich creates summary, category and embedding for one CVE.
type AIEnrich struct {
	CVEID string `json:"cve_id"`
}

func (AIEnrich) Kind() string { return "ai_enrich" }
func (AIEnrich) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueAI, MaxAttempts: 5, Priority: 2,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeStates}}
}

// AIBackfill periodically picks CVEs that still need enrichment.
type AIBackfill struct{}

func (AIBackfill) Kind() string { return "ai_backfill" }
func (AIBackfill) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueAI, MaxAttempts: 1}
}

// Maintenance: cleanup of sessions, tokens, product counts.
type Maintenance struct{}

func (Maintenance) Kind() string { return "maintenance" }
func (Maintenance) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 1}
}
