// Package ai talks to an external Ollama instance: English summaries and a
// category per CVE, plus embeddings for the semantic search. Everything is
// optional; without OLLAMA_URL the rest of yourcve works unchanged.
//
// Hallucination guards: the model only sees the CVE description, must answer
// in a fixed JSON schema at low temperature, and its output is validated.
// Facts (CVSS, versions, ids) are never taken from the model.
package ai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"
	"github.com/riverqueue/river"

	"github.com/tinybrickboy/yourcve/internal/jobs"
)

var Categories = []string{"RCE", "Code Injection", "SQL Injection", "XSS", "CSRF", "SSRF", "Path Traversal",
	"Auth Bypass", "Privilege Escalation", "Information Disclosure", "DoS", "Memory Corruption",
	"Deserialization", "XXE", "Open Redirect", "Misconfiguration", "Cryptographic Issue", "Supply Chain", "Other"}

type Client struct {
	URL        string
	Model      string
	EmbedModel string
	Lang       string
	HTTP       *http.Client
}

func NewClient(url, model, embedModel, lang string) *Client {
	t := &http.Transport{Proxy: http.ProxyFromEnvironment, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second}
	return &Client{URL: strings.TrimRight(url, "/"), Model: model, EmbedModel: embedModel, Lang: lang,
		HTTP: &http.Client{Transport: t, Timeout: 5 * time.Minute}}
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	b, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("ollama: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return fmt.Errorf("ollama %s: HTTP %d: %s", path, resp.StatusCode, msg)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Embed returns a 768 dim vector (nomic-embed-text). kind is "search_document" or "search_query".
func (c *Client) Embed(ctx context.Context, kind, text string) ([]float32, error) {
	var res struct {
		Embeddings [][]float32 `json:"embeddings"`
	}
	err := c.post(ctx, "/api/embed", map[string]any{"model": c.EmbedModel, "input": kind + ": " + text, "truncate": true}, &res)
	if err != nil {
		return nil, err
	}
	if len(res.Embeddings) == 0 || len(res.Embeddings[0]) != 768 {
		return nil, fmt.Errorf("ollama: unexpected embedding size (model %s must produce 768 dimensions)", c.EmbedModel)
	}
	return res.Embeddings[0], nil
}

type Summary struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
}

var summarySchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"category": map[string]any{"type": "string", "enum": Categories},
		"summary":  map[string]any{"type": "string"},
	},
	"required": []string{"category", "summary"},
}

const systemPrompt = `You summarize security vulnerabilities for system administrators.
Use ONLY the given description. Do not invent products, versions, scores, CVE ids or exploit details.
Write 1-2 short sentences in plain English (max 280 characters): what is affected and what an attacker can do.
Pick the best matching category. Answer as JSON.`

// Summarize asks the instruct model for summary + category.
func (c *Client) Summarize(ctx context.Context, id, title, description string) (*Summary, error) {
	user := "CVE: " + id + "\n"
	if title != "" {
		user += "Title: " + title + "\n"
	}
	user += "Description: " + truncate(description, 4000)
	var res struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	err := c.post(ctx, "/api/chat", map[string]any{
		"model":    c.Model,
		"stream":   false,
		"format":   summarySchema,
		"options":  map[string]any{"temperature": 0.1, "num_ctx": 4096},
		"messages": []map[string]string{{"role": "system", "content": systemPrompt}, {"role": "user", "content": user}},
	}, &res)
	if err != nil {
		return nil, err
	}
	var s Summary
	if err := json.Unmarshal([]byte(res.Message.Content), &s); err != nil {
		return nil, ErrInvalidOutput
	}
	if err := Validate(id, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

var ErrInvalidOutput = errors.New("ai output rejected")

var (
	cveRe   = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)
	scoreRe = regexp.MustCompile(`(?i)\b(cvss|score|epss)\b`)
)

// Validate rejects output that is malformed or states facts we never take from the model.
func Validate(id string, s *Summary) error {
	s.Summary = strings.TrimSpace(s.Summary)
	if !slices.Contains(Categories, s.Category) {
		s.Category = "Other"
	}
	n := len([]rune(s.Summary))
	if n < 20 || n > 600 {
		return ErrInvalidOutput
	}
	for _, m := range cveRe.FindAllString(s.Summary, -1) {
		if !strings.EqualFold(m, id) {
			return ErrInvalidOutput
		}
	}
	if scoreRe.MatchString(s.Summary) {
		return ErrInvalidOutput
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func hashInput(model, title, desc string) string {
	h := sha256.Sum256([]byte(model + "\x00" + title + "\x00" + desc))
	return hex.EncodeToString(h[:12])
}

// ---------------------------------------------------------------- workers

type Enricher struct {
	Pool        *pgxpool.Pool
	Client      *Client
	Log         *slog.Logger
	RecentYears int
}

type EnrichWorker struct {
	river.WorkerDefaults[jobs.AIEnrich]
	E *Enricher
}

func (w *EnrichWorker) Timeout(*river.Job[jobs.AIEnrich]) time.Duration { return 6 * time.Minute }

func (w *EnrichWorker) Work(ctx context.Context, job *river.Job[jobs.AIEnrich]) error {
	return w.E.Enrich(ctx, job.Args.CVEID)
}

func (e *Enricher) Enrich(ctx context.Context, id string) error {
	var title *string
	var desc, state string
	var aiHash *string
	var hasEmb bool
	err := e.Pool.QueryRow(ctx, `SELECT c.title, c.description, c.state, a.input_hash,
			EXISTS (SELECT 1 FROM cve_embeddings x WHERE x.cve_id = c.id AND x.model = $2)
		FROM cves c LEFT JOIN cve_ai a ON a.cve_id = c.id WHERE c.id = $1`, id, e.Client.EmbedModel).
		Scan(&title, &desc, &state, &aiHash, &hasEmb)
	if errors.Is(err, pgx.ErrNoRows) || state == "REJECTED" || strings.TrimSpace(desc) == "" {
		return nil
	}
	if err != nil {
		return err
	}
	t := ""
	if title != nil {
		t = *title
	}
	h := hashInput(e.Client.Model, t, desc)
	if aiHash == nil || *aiHash != h {
		s, err := e.Client.Summarize(ctx, id, t, desc)
		switch {
		case errors.Is(err, ErrInvalidOutput):
			// keep the original description; remember the attempt so we don't loop
			e.Log.Debug("ai summary rejected", "cve", id)
			_, err = e.Pool.Exec(ctx, `INSERT INTO cve_ai (cve_id, category, summary_en, model, input_hash) VALUES ($1, NULL, NULL, $2, $3)
				ON CONFLICT (cve_id) DO UPDATE SET category=NULL, summary_en=NULL, model=$2, input_hash=$3, created_at=now()`, id, e.Client.Model, h)
			if err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			_, err = e.Pool.Exec(ctx, `INSERT INTO cve_ai (cve_id, category, summary_en, model, input_hash) VALUES ($1,$2,$3,$4,$5)
				ON CONFLICT (cve_id) DO UPDATE SET category=$2, summary_en=$3, model=$4, input_hash=$5, created_at=now()`,
				id, s.Category, s.Summary, e.Client.Model, h)
			if err != nil {
				return err
			}
		}
	}
	if !hasEmb {
		v, err := e.Client.Embed(ctx, "search_document", id+" "+t+"\n"+desc)
		if err != nil {
			return err
		}
		_, err = e.Pool.Exec(ctx, `INSERT INTO cve_embeddings (cve_id, embedding, model) VALUES ($1,$2,$3)
			ON CONFLICT (cve_id) DO UPDATE SET embedding=$2, model=$3, created_at=now()`, id, pgvector.NewVector(v), e.Client.EmbedModel)
		return err
	}
	return nil
}

type BackfillWorker struct {
	river.WorkerDefaults[jobs.AIBackfill]
	E     *Enricher
	River *jobs.Client
}

// Work queues CVEs that need enrichment: all with matches, plus all published
// within the last N years. Newest first, bounded per run.
func (w *BackfillWorker) Work(ctx context.Context, job *river.Job[jobs.AIBackfill]) error {
	e := w.E
	// do not flood the queue: only top up when it is nearly empty
	var queued int
	if err := e.Pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind='ai_enrich' AND state IN ('available','scheduled','retryable','running')`).Scan(&queued); err != nil {
		return err
	}
	if queued > 50 {
		return nil
	}
	rows, err := e.Pool.Query(ctx, `
		SELECT c.id FROM cves c
		LEFT JOIN cve_ai a ON a.cve_id = c.id
		LEFT JOIN cve_embeddings x ON x.cve_id = c.id
		WHERE c.state <> 'REJECTED' AND c.description <> ''
		  AND (a.cve_id IS NULL OR x.cve_id IS NULL OR a.model <> $2)
		  AND (c.published > now() - make_interval(years => $1) OR EXISTS (SELECT 1 FROM matches m WHERE m.cve_id = c.id))
		ORDER BY EXISTS (SELECT 1 FROM matches m WHERE m.cve_id = c.id) DESC, c.published DESC NULLS LAST
		LIMIT 200`, e.RecentYears, e.Client.Model)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	params := make([]river.InsertManyParams, 0, len(ids))
	for _, id := range ids {
		params = append(params, river.InsertManyParams{Args: jobs.AIEnrich{CVEID: id}, InsertOpts: &river.InsertOpts{Priority: 4}})
	}
	_, err = w.River.InsertMany(ctx, params)
	return err
}

// ---------------------------------------------------------------- semantic search

type Hit struct {
	ID       string
	Distance float64
}

// SemanticSearch returns the closest CVEs; stackID > 0 restricts to matches of that stack.
func (e *Enricher) SemanticSearch(ctx context.Context, query string, stackID int64, limit int) ([]Hit, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	v, err := e.Client.Embed(ctx, "search_query", query)
	if err != nil {
		return nil, err
	}
	q := `SELECT x.cve_id, x.embedding <=> $1 AS d FROM cve_embeddings x`
	args := []any{pgvector.NewVector(v), limit}
	if stackID > 0 {
		q += ` JOIN matches m ON m.cve_id = x.cve_id AND m.stack_id = $3`
		args = append(args, stackID)
	}
	q += ` ORDER BY d LIMIT $2`
	rows, err := e.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Hit, error) {
		var h Hit
		err := r.Scan(&h.ID, &h.Distance)
		return h, err
	})
}
