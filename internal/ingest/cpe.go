package ingest

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tinybrickboy/yourcve/internal/catalog"
)

// CPEDictionary fills the product catalog from the NVD CPE dictionary (only
// vendor:product pairs, versions are not needed for the catalog). Products
// from CVE configurations and OSV packages are added by the other sources.
type CPEDictionary struct {
	Env           *Env
	Every         time.Duration
	APIKey        string
	InitialImport bool
	BaseURL       string // default https://services.nvd.nist.gov/rest/json/cpes/2.0
}

func (c *CPEDictionary) Name() string            { return "cpe" }
func (c *CPEDictionary) Interval() time.Duration { return c.Every }

type cpeResponse struct {
	TotalResults int `json:"totalResults"`
	Products     []struct {
		CPE struct {
			CPEName    string `json:"cpeName"`
			Deprecated bool   `json:"deprecated"`
		} `json:"cpe"`
	} `json:"products"`
}

func (c *CPEDictionary) Run(ctx context.Context, st *State) error {
	if c.BaseURL == "" {
		c.BaseURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	}
	nvd := &NVD{Env: c.Env, APIKey: c.APIKey}
	now := time.Now().UTC()
	q := url.Values{}
	idx := 0
	started := now
	switch {
	case st.Cursor == "" && !c.InitialImport:
		st.Cursor = now.Format(time.RFC3339)
		return nil
	case st.Cursor == "":
		st.Cursor = "init:0|" + now.Format(time.RFC3339)
		fallthrough
	case strings.HasPrefix(st.Cursor, "init:"):
		a, b, _ := strings.Cut(strings.TrimPrefix(st.Cursor, "init:"), "|")
		idx, _ = strconv.Atoi(a)
		if t, err := time.Parse(time.RFC3339, b); err == nil {
			started = t
		}
	default:
		since, err := time.Parse(time.RFC3339, st.Cursor)
		if err != nil {
			return fmt.Errorf("bad cursor %q", st.Cursor)
		}
		if now.Sub(since) > 119*24*time.Hour {
			since = now.Add(-119 * 24 * time.Hour)
		}
		q.Set("lastModStartDate", nvdTime(since.Add(-time.Hour)))
		q.Set("lastModEndDate", nvdTime(now))
	}
	initial := strings.HasPrefix(st.Cursor, "init:")
	seen := map[string]bool{}
	for {
		q.Set("startIndex", strconv.Itoa(idx))
		q.Set("resultsPerPage", "10000")
		var res cpeResponse
		if err := nvd.fetch(ctx, c.BaseURL+"?"+strings.ReplaceAll(q.Encode(), "+", "%2B"), &res); err != nil {
			return err
		}
		for _, p := range res.Products {
			parts := splitCPE23(p.CPE.CPEName)
			if len(parts) < 5 || p.CPE.Deprecated {
				continue
			}
			key := parts[2] + ":" + parts[3] + ":" + parts[4]
			if seen[key] {
				continue
			}
			seen[key] = true
			if _, err := catalog.EnsureCPE(ctx, c.Env.Pool, c.Env.Cache, parts[2], parts[3], parts[4]); err != nil {
				continue
			}
		}
		st.Seen(len(res.Products), nil)
		idx += len(res.Products)
		if initial {
			st.Cursor = fmt.Sprintf("init:%d|%s", idx, started.Format(time.RFC3339))
			if err := st.Save(ctx); err != nil {
				return err
			}
		}
		if len(res.Products) == 0 || idx >= res.TotalResults {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(nvd.pause()):
		}
	}
	if initial {
		st.Cursor = started.Format(time.RFC3339)
	} else {
		st.Cursor = now.Format(time.RFC3339)
	}
	return catalog.RefreshCounts(ctx, c.Env.Pool)
}
