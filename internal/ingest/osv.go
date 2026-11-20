package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/tinybrickboy/yourcve/internal/catalog"
	"github.com/tinybrickboy/yourcve/internal/cvedb"
)

// OSV syncs package advisories from osv.dev (GHSA, PyPA, Go, RustSec, ...).
//
// Initial import: <ecosystem>/all.zip for each configured ecosystem.
// Incremental: modified_id.csv lists every record newest first
// ("<timestamp>,<ecosystem>/<id>"). We read only its head with range requests
// until we reach the cursor, so a poll every minute costs a few KB.
type OSV struct {
	Env           *Env
	Every         time.Duration
	Ecosystems    []string
	InitialImport bool
	BaseURL       string // default https://storage.googleapis.com/osv-vulnerabilities
}

func (o *OSV) Name() string            { return "osv" }
func (o *OSV) Interval() time.Duration { return o.Every }

func (o *OSV) Run(ctx context.Context, st *State) error {
	if o.BaseURL == "" {
		o.BaseURL = "https://storage.googleapis.com/osv-vulnerabilities"
	}
	if st.Cursor == "" || strings.HasPrefix(st.Cursor, "init:") {
		if err := o.initial(ctx, st); err != nil {
			return err
		}
	}
	since, err := time.Parse(time.RFC3339Nano, st.Cursor)
	if err != nil {
		return fmt.Errorf("bad cursor %q", st.Cursor)
	}
	entries, etag, err := o.changedSince(ctx, since, st.ETag)
	if err != nil {
		return err
	}
	if etag != "" {
		st.ETag = etag
	}
	// process oldest first in chunks; the cursor advances after each committed chunk
	for end := len(entries); end > 0; end -= 32 {
		start := max(end-32, 0)
		chunk := entries[start:end]
		recs, err := parallel(ctx, len(chunk), func(ctx context.Context, i int) ([]Record, error) {
			r, err := o.fetch(ctx, chunk[i].path)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", chunk[i].path, err)
			}
			return r, nil
		})
		if err != nil {
			return err
		}
		if err := o.Env.Write(ctx, recs, false); err != nil {
			return err
		}
		newest := chunk[0].ts // entries are newest first
		st.Seen(len(chunk), &newest)
		st.Cursor = newest.Format(time.RFC3339Nano)
		if err := st.Save(ctx); err != nil {
			return err
		}
	}
	return nil
}

// wanted reports whether "<ecosystem>/<id>" belongs to a configured ecosystem.
func (o *OSV) wanted(p string) bool {
	eco, _, _ := strings.Cut(p, "/")
	eco = catalog.BaseEcosystem(eco)
	for _, e := range o.Ecosystems {
		if strings.EqualFold(e, eco) {
			return true
		}
	}
	return false
}

type osvChange struct {
	ts   time.Time
	path string // "npm/GHSA-xxxx"
}

func (o *OSV) changedSince(ctx context.Context, since time.Time, etag string) ([]osvChange, string, error) {
	size := int64(64 << 10)
	for {
		hdr := map[string]string{"Range": fmt.Sprintf("bytes=0-%d", size-1)}
		if size == 64<<10 {
			hdr["If-None-Match"] = etag
		}
		resp, err := o.Env.get(ctx, o.BaseURL+"/modified_id.csv", hdr)
		if err != nil {
			return nil, "", err
		}
		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			return nil, "", nil
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			defer resp.Body.Close()
			return nil, "", statusErr(resp)
		}
		newETag := resp.Header.Get("ETag")
		b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
		resp.Body.Close()
		if err != nil {
			return nil, "", err
		}
		full := resp.StatusCode == http.StatusOK || int64(len(b)) < size
		if !full {
			if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
				b = b[:i] // drop the partial last line
			}
		}
		var out []osvChange
		reached := false
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			ts, p, ok := strings.Cut(sc.Text(), ",")
			if !ok {
				continue
			}
			t, err := time.Parse(time.RFC3339Nano, ts)
			if err != nil {
				continue
			}
			if !t.After(since) {
				reached = true
				break
			}
			if !o.wanted(p) {
				continue // GIT ranges, Android patch levels etc. have no comparable versions
			}
			out = append(out, osvChange{t, p})
		}
		if reached || full || size >= 256<<20 {
			return out, newETag, nil
		}
		size *= 8
	}
}

func (o *OSV) fetch(ctx context.Context, p string) ([]Record, error) {
	eco, id, ok := strings.Cut(p, "/")
	if !ok {
		return nil, nil
	}
	resp, err := o.Env.get(ctx, o.BaseURL+"/"+url.PathEscape(eco)+"/"+url.PathEscape(id)+".json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr(resp)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	return o.parse(ctx, b)
}

func (o *OSV) initial(ctx context.Context, st *State) error {
	log := o.Env.Log.With("source", "osv")
	start := time.Now().UTC()
	if !o.InitialImport {
		st.Cursor = start.Add(-24 * time.Hour).Format(time.RFC3339Nano)
		return st.Save(ctx)
	}
	done := map[string]bool{}
	startStr := start.Format(time.RFC3339Nano)
	if rest, ok := strings.CutPrefix(st.Cursor, "init:"); ok {
		s, list, _ := strings.Cut(rest, "|")
		startStr = s
		for _, e := range strings.Split(list, ",") {
			done[e] = true
		}
	}
	for _, eco := range o.Ecosystems {
		if done[eco] {
			continue
		}
		log.Info("OSV initial import", "ecosystem", eco)
		f, err := downloadTemp(ctx, o.Env, o.BaseURL+"/"+url.PathEscape(eco)+"/all.zip")
		if err != nil {
			return fmt.Errorf("%s: %w", eco, err)
		}
		var batch []Record
		n := 0
		err = walkZip(f, func(name string, r io.Reader) error {
			b, err := io.ReadAll(io.LimitReader(r, 32<<20))
			if err != nil {
				return err
			}
			recs, err := o.parse(ctx, b)
			if err != nil {
				return nil
			}
			batch = append(batch, recs...)
			if len(batch) >= 300 {
				err := o.Env.Write(ctx, batch, true)
				n += len(batch)
				st.Seen(len(batch), nil)
				batch = batch[:0]
				return err
			}
			return nil
		})
		os.Remove(f)
		if err == nil {
			err = o.Env.Write(ctx, batch, true)
			n += len(batch)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", eco, err)
		}
		done[eco] = true
		var list []string
		for k := range done {
			if k != "" {
				list = append(list, k)
			}
		}
		st.Cursor = "init:" + startStr + "|" + strings.Join(list, ",")
		if err := st.Save(ctx); err != nil {
			return err
		}
		log.Info("OSV ecosystem imported", "ecosystem", eco, "records", n)
	}
	st.Cursor = startStr
	if err := st.Save(ctx); err != nil {
		return err
	}
	return o.Env.RematchAllStacks(ctx)
}

type osvRecord struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Upstream  []string `json:"upstream"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Withdrawn string   `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	DatabaseSpecific struct {
		CWEIDs []string `json:"cwe_ids"`
	} `json:"database_specific"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

// parse converts one OSV record into records for every CVE alias.
func (o *OSV) parse(ctx context.Context, b []byte) ([]Record, error) {
	var r osvRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	var cves []string
	for _, id := range append([]string{r.ID}, r.Aliases...) {
		if cvedb.ValidID(id) {
			cves = append(cves, strings.ToUpper(id))
		}
	}
	if len(cves) == 0 {
		return nil, nil
	}
	affects := []cvedb.Affect{}
	if r.Withdrawn == "" {
		for _, a := range r.Affected {
			if a.Package.Ecosystem == "" || a.Package.Name == "" || !o.wanted(a.Package.Ecosystem+"/") {
				continue
			}
			pid, err := catalog.EnsurePackage(ctx, o.Env.Pool, o.Env.Cache, a.Package.Ecosystem, a.Package.Name)
			if err != nil {
				return nil, err
			}
			hasRange := false
			for _, rg := range a.Ranges {
				if rg.Type != "SEMVER" && rg.Type != "ECOSYSTEM" {
					continue
				}
				hasRange = true
				var cur *cvedb.Affect
				for _, ev := range rg.Events {
					switch {
					case ev["introduced"] != "":
						cur = &cvedb.Affect{ProductID: pid, Source: "osv", Confirmed: true}
						if ev["introduced"] != "0" {
							cur.StartIncluding = ev["introduced"]
						}
					case cur != nil && ev["fixed"] != "":
						cur.EndExcluding = ev["fixed"]
						affects = append(affects, *cur)
						cur = nil
					case cur != nil && ev["last_affected"] != "":
						cur.EndIncluding = ev["last_affected"]
						affects = append(affects, *cur)
						cur = nil
					case cur != nil && ev["limit"] != "":
						cur.EndExcluding = ev["limit"]
						affects = append(affects, *cur)
						cur = nil
					}
				}
				if cur != nil { // introduced without end: all later versions
					if cur.StartIncluding == "" {
						cur.AllVersions = true
					}
					affects = append(affects, *cur)
				}
			}
			if !hasRange && len(a.Versions) > 0 {
				vs := a.Versions
				if len(vs) > 500 {
					vs = vs[:500]
				}
				affects = append(affects, cvedb.Affect{ProductID: pid, Source: "osv", Versions: vs, Confirmed: true})
			}
		}
	}
	desc := r.Summary
	if desc == "" {
		desc = r.Details
	}
	var refs []string
	for _, ref := range r.References {
		refs = append(refs, ref.URL)
	}
	var out []Record
	for _, id := range cves {
		p := cvedb.Patch{ID: id, Source: "osv", Description: ptr(desc), CWE: r.DatabaseSpecific.CWEIDs,
			References: refs, Published: parseTime(r.Published), Modified: parseTime(r.Modified)}
		out = append(out, Record{Patch: p, Affects: affects, AffectSource: "osv:" + r.ID})
	}
	return out, nil
}
