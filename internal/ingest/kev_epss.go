package ingest

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tinybrickboy/yourcve/internal/cvedb"
)

// KEV syncs the CISA Known Exploited Vulnerabilities catalog. Polling every
// minute is cheap: unchanged data returns 304 via If-None-Match.
type KEV struct {
	Env   *Env
	Every time.Duration
	URL   string
}

func (k *KEV) Name() string            { return "kev" }
func (k *KEV) Interval() time.Duration { return k.Every }

type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID             string `json:"cveID"`
		VendorProject     string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		ShortDescription  string `json:"shortDescription"`
		RequiredAction    string `json:"requiredAction"`
		DueDate           string `json:"dueDate"`
	} `json:"vulnerabilities"`
}

func (k *KEV) Run(ctx context.Context, st *State) error {
	if k.URL == "" {
		k.URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	}
	resp, err := k.Env.get(ctx, k.URL, map[string]string{"If-None-Match": st.ETag})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return statusErr(resp)
	}
	var cat kevCatalog
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&cat); err != nil {
		return err
	}
	rows, err := k.Env.Pool.Query(ctx, `SELECT id, coalesce(kev_due::text,'') FROM cves WHERE kev`)
	if err != nil {
		return err
	}
	current := map[string]string{}
	for rows.Next() {
		var id, due string
		if err := rows.Scan(&id, &due); err != nil {
			rows.Close()
			return err
		}
		current[id] = due
	}
	rows.Close()

	var recs []Record
	listed := map[string]bool{}
	var newest *time.Time
	for _, v := range cat.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if !cvedb.ValidID(id) {
			continue
		}
		listed[id] = true
		if due, ok := current[id]; ok && due == v.DueDate {
			continue
		}
		added := parseTime(v.DateAdded)
		if added != nil && (newest == nil || added.After(*newest)) {
			newest = added
		}
		p := cvedb.Patch{ID: id, Source: "kev", KEV: ptr(true), KEVAdded: added, KEVDue: parseTime(v.DueDate),
			KEVAction: ptr(v.RequiredAction)}
		if _, ok := current[id]; !ok {
			// minimal data in case the record is not imported yet
			p.Title = ptr(v.VulnerabilityName)
			p.Description = ptr(v.ShortDescription)
		}
		recs = append(recs, Record{Patch: p})
	}
	for id := range current {
		if !listed[id] {
			recs = append(recs, Record{Patch: cvedb.Patch{ID: id, Source: "kev", KEV: ptr(false)}})
		}
	}
	// first run marks the whole catalog without sending notifications
	bulk := st.Cursor == ""
	for i := 0; i < len(recs); i += 500 {
		if err := k.Env.Write(ctx, recs[i:min(i+500, len(recs))], bulk); err != nil {
			return err
		}
	}
	st.Seen(len(recs), newest)
	st.ETag = resp.Header.Get("ETag")
	st.Cursor = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// EPSS loads the daily FIRST EPSS scores (published once per day). We check
// hourly with conditional requests and only import when the score date changed.
type EPSS struct {
	Env   *Env
	Every time.Duration
	URL   string
}

func (e *EPSS) Name() string            { return "epss" }
func (e *EPSS) Interval() time.Duration { return e.Every }

func (e *EPSS) Run(ctx context.Context, st *State) error {
	if e.URL == "" {
		e.URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	}
	resp, err := e.Env.get(ctx, e.URL, map[string]string{"If-None-Match": st.ETag})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return statusErr(resp)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(gz, 1<<16)
	// first line: #model_version:v2025.03.14,score_date:2026-11-19T12:55:00Z
	first, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	scoreDate := ""
	for _, part := range strings.Split(strings.TrimSpace(strings.TrimPrefix(first, "#")), ",") {
		if v, ok := strings.CutPrefix(part, "score_date:"); ok {
			scoreDate = v
		}
	}
	if scoreDate != "" && scoreDate == st.Cursor {
		st.ETag = resp.Header.Get("ETag")
		return nil
	}
	if _, err := br.ReadString('\n'); err != nil { // header cve,epss,percentile
		return err
	}
	type row struct {
		id         string
		epss, pctl float64
	}
	var all []row
	for {
		line, err := br.ReadString('\n')
		if line = strings.TrimSpace(line); line != "" {
			f := strings.Split(line, ",")
			if len(f) >= 3 {
				s, err1 := strconv.ParseFloat(f[1], 64)
				p, err2 := strconv.ParseFloat(f[2], 64)
				if err1 == nil && err2 == nil {
					all = append(all, row{f[0], s, p})
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if len(all) < 1000 {
		return fmt.Errorf("epss: suspiciously small file (%d rows)", len(all))
	}
	err = pgx.BeginFunc(ctx, e.Env.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE epss_tmp (id text, epss float8, pctl float8) ON COMMIT DROP`); err != nil {
			return err
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"epss_tmp"}, []string{"id", "epss", "pctl"},
			pgx.CopyFromSlice(len(all), func(i int) ([]any, error) {
				return []any{all[i].id, all[i].epss, all[i].pctl}, nil
			}))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE cves c SET epss = t.epss, epss_percentile = t.pctl,
				sources = CASE WHEN 'epss' = ANY(c.sources) THEN c.sources ELSE c.sources || '{epss}' END
			FROM epss_tmp t WHERE c.id = t.id AND (c.epss IS DISTINCT FROM t.epss OR c.epss_percentile IS DISTINCT FROM t.pctl)`)
		return err
	})
	if err != nil {
		return err
	}
	st.Seen(len(all), parseTime(scoreDate))
	st.Cursor = scoreDate
	st.ETag = resp.Header.Get("ETag")
	return nil
}
