package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tinybrickboy/yourcve/internal/catalog"
	"github.com/tinybrickboy/yourcve/internal/cvedb"
)

// NVD syncs CVSS scores, CWEs and CPE configurations from the NVD API 2.0.
// Incremental runs use lastModStartDate = cursor. The initial import pages
// through the whole dataset and remembers its position ("init:<index>|<start>").
type NVD struct {
	Env           *Env
	Every         time.Duration
	APIKey        string
	InitialImport bool
	BaseURL       string // default https://services.nvd.nist.gov/rest/json/cves/2.0
}

func (n *NVD) Name() string            { return "nvd" }
func (n *NVD) Interval() time.Duration { return n.Every }

const nvdPage = 2000

func (n *NVD) pause() time.Duration {
	if n.APIKey != "" {
		return 700 * time.Millisecond // 50 requests / 30 s
	}
	return 6500 * time.Millisecond // 5 requests / 30 s
}

func nvdTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000") + "+00:00" }

func (n *NVD) Run(ctx context.Context, st *State) error {
	if n.BaseURL == "" {
		n.BaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	now := time.Now().UTC()
	switch {
	case st.Cursor == "" && n.InitialImport:
		st.Cursor = "init:0|" + now.Format(time.RFC3339)
		fallthrough
	case strings.HasPrefix(st.Cursor, "init:"):
		return n.initial(ctx, st)
	case st.Cursor == "":
		st.Cursor = now.Add(-24 * time.Hour).Format(time.RFC3339)
	}
	since, err := time.Parse(time.RFC3339, st.Cursor)
	if err != nil {
		return fmt.Errorf("bad cursor %q: %w", st.Cursor, err)
	}
	// overlap by a minute, NVD timestamps are not strictly monotonic on commit
	start := since.Add(-time.Minute)
	for start.Before(now) {
		end := start.Add(119 * 24 * time.Hour)
		if end.After(now) {
			end = now
		}
		q := url.Values{"lastModStartDate": {nvdTime(start)}, "lastModEndDate": {nvdTime(end)}}
		newest, err := n.pageAll(ctx, st, q, 0, false, nil)
		if err != nil {
			return err
		}
		_ = newest
		st.Cursor = end.Format(time.RFC3339)
		if err := st.Save(ctx); err != nil {
			return err
		}
		start = end
	}
	return nil
}

func (n *NVD) initial(ctx context.Context, st *State) error {
	rest := strings.TrimPrefix(st.Cursor, "init:")
	idxStr, startedStr, _ := strings.Cut(rest, "|")
	idx, _ := strconv.Atoi(idxStr)
	log := n.Env.Log.With("source", "nvd")
	log.Info("NVD initial import", "start_index", idx)
	_, err := n.pageAll(ctx, st, url.Values{}, idx, true, func(next int) error {
		st.Cursor = fmt.Sprintf("init:%d|%s", next, startedStr)
		if next%20000 == 0 {
			log.Info("NVD import progress", "index", next)
		}
		return st.Save(ctx)
	})
	if err != nil {
		return err
	}
	started, err := time.Parse(time.RFC3339, startedStr)
	if err != nil {
		started = time.Now().Add(-24 * time.Hour)
	}
	st.Cursor = started.Format(time.RFC3339)
	log.Info("NVD initial import done")
	if err := st.Save(ctx); err != nil {
		return err
	}
	return n.Env.RematchAllStacks(ctx)
}

type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string      `json:"id"`
	Published    string      `json:"published"`
	LastModified string      `json:"lastModified"`
	VulnStatus   string      `json:"vulnStatus"`
	Descriptions []langValue `json:"descriptions"`
	Metrics      map[string][]struct {
		Source   string   `json:"source"`
		Type     string   `json:"type"`
		CVSSData cvssData `json:"cvssData"`
	} `json:"metrics"`
	Weaknesses []struct {
		Type        string      `json:"type"`
		Description []langValue `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			Negate   bool `json:"negate"`
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

// pageAll fetches all pages for the query. progress is called after each
// committed page with the next start index.
func (n *NVD) pageAll(ctx context.Context, st *State, q url.Values, startIndex int, bulk bool, progress func(int) error) (*time.Time, error) {
	var newest *time.Time
	for {
		q.Set("startIndex", strconv.Itoa(startIndex))
		q.Set("resultsPerPage", strconv.Itoa(nvdPage))
		var res nvdResponse
		if err := n.fetch(ctx, n.BaseURL+"?"+strings.ReplaceAll(q.Encode(), "+", "%2B"), &res); err != nil {
			return newest, err
		}
		recs := make([]Record, 0, len(res.Vulnerabilities))
		for _, v := range res.Vulnerabilities {
			rec, err := n.convert(ctx, v.CVE)
			if err != nil {
				return newest, err
			}
			if rec != nil {
				recs = append(recs, *rec)
				if t := rec.Patch.Modified; t != nil && (newest == nil || t.After(*newest)) {
					newest = t
				}
			}
		}
		if err := n.Env.Write(ctx, recs, bulk); err != nil {
			return newest, err
		}
		st.Seen(len(recs), newest)
		startIndex += len(res.Vulnerabilities)
		if progress != nil {
			if err := progress(startIndex); err != nil {
				return newest, err
			}
		}
		if len(res.Vulnerabilities) == 0 || startIndex >= res.TotalResults {
			return newest, nil
		}
		select {
		case <-ctx.Done():
			return newest, ctx.Err()
		case <-time.After(n.pause()):
		}
	}
}

func (n *NVD) fetch(ctx context.Context, u string, out any) error {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		hdr := map[string]string{"apiKey": n.APIKey}
		resp, err := n.Env.get(ctx, u, hdr)
		if err != nil {
			return err // includes rate limit → scheduler backoff
		}
		if resp.StatusCode == http.StatusForbidden {
			// NVD answers 403 when the rolling window is exceeded
			resp.Body.Close()
			return ErrRateLimited{RetryAfter: 35 * time.Second}
		}
		if resp.StatusCode >= 500 {
			lastErr = statusErr(resp)
			resp.Body.Close()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 10 * time.Second):
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			return statusErr(resp)
		}
		err = json.NewDecoder(resp.Body).Decode(out)
		resp.Body.Close()
		return err
	}
	return lastErr
}

func (n *NVD) convert(ctx context.Context, c nvdCVE) (*Record, error) {
	if !cvedb.ValidID(c.ID) {
		return nil, nil
	}
	p := cvedb.Patch{ID: c.ID, Source: "nvd", Published: parseTime(c.Published), Modified: parseTime(c.LastModified)}
	if strings.EqualFold(c.VulnStatus, "Rejected") {
		p.State = ptr("REJECTED")
		return &Record{Patch: p}, nil
	}
	if d := english(c.Descriptions); d != "" {
		// only fills gaps (cvelist text is authoritative, but NVD may be first)
		p.Description = &d
	}
	// Primary NVD score first, then any secondary score; v3.1 > v4.0 > v3.0 > v2
	for _, primary := range []bool{true, false} {
		if p.CVSS != nil {
			break
		}
		for _, key := range []string{"cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"} {
			for _, m := range c.Metrics[key] {
				if (m.Type == "Primary") != primary {
					continue
				}
				d := m.CVSSData
				p.CVSS, p.CVSSVersion, p.CVSSVector = ptr(d.BaseScore), ptr(d.Version), ptr(d.VectorString)
				if !primary {
					p.CVSSSource = "cna" // secondary scores come from the CNA
				}
				break
			}
			if p.CVSS != nil {
				break
			}
		}
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				p.CWE = append(p.CWE, d.Value)
			}
		}
	}
	for _, r := range c.References {
		p.References = append(p.References, r.URL)
	}
	rec := &Record{Patch: p}
	if len(c.Configurations) == 0 {
		return rec, nil // not analyzed yet: keep existing affects
	}
	affects := []cvedb.Affect{}
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			if node.Negate {
				continue
			}
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				parts := splitCPE23(m.Criteria)
				if len(parts) < 7 {
					continue
				}
				part, vendor, product, ver, update := parts[2], parts[3], parts[4], parts[5], parts[6]
				pid, err := catalog.EnsureCPE(ctx, n.Env.Pool, n.Env.Cache, part, vendor, product)
				if err != nil {
					continue
				}
				a := cvedb.Affect{ProductID: pid, Source: "nvd", Confirmed: true,
					StartIncluding: m.VersionStartIncluding, StartExcluding: m.VersionStartExcluding,
					EndIncluding: m.VersionEndIncluding, EndExcluding: m.VersionEndExcluding}
				hasRange := a.StartIncluding != "" || a.StartExcluding != "" || a.EndIncluding != "" || a.EndExcluding != ""
				switch {
				case ver != "*" && ver != "-" && ver != "":
					v := ver
					if update != "*" && update != "-" && update != "" {
						v += update // openssh 8.5 + p1 → 8.5p1
					}
					a.Versions = []string{v}
					a.StartIncluding, a.StartExcluding, a.EndIncluding, a.EndExcluding = "", "", "", ""
				case !hasRange:
					a.AllVersions = true
				}
				affects = append(affects, a)
			}
		}
	}
	rec.Affects = affects
	return rec, nil
}
