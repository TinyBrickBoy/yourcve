package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tinybrickboy/yourcve/internal/catalog"
	"github.com/tinybrickboy/yourcve/internal/cvedb"
)

// CVEList syncs github.com/CVEProject/cvelistV5.
//
// Initial import: the daily "all_CVEs_at_midnight" release archive.
// Incremental: every interval we ask GitHub over the git protocol (ls-refs,
// a few bytes, no API rate limit) for the current commit of main. When it
// changed, we read the head of cves/deltaLog.json at exactly that commit with
// an HTTP range request (newest entries come first) and fetch the changed
// records. Commit pinned URLs are immutable, so CDN caching never hides news.
type CVEList struct {
	Env           *Env
	Every         time.Duration
	GitHubToken   string
	InitialImport bool

	RepoURL string // default https://github.com/CVEProject/cvelistV5
	RawURL  string // default https://raw.githubusercontent.com/CVEProject/cvelistV5
	APIURL  string // default https://api.github.com/repos/CVEProject/cvelistV5
}

func (c *CVEList) Name() string            { return "cvelist" }
func (c *CVEList) Interval() time.Duration { return c.Every }

func (c *CVEList) defaults() {
	if c.RepoURL == "" {
		c.RepoURL = "https://github.com/CVEProject/cvelistV5"
	}
	if c.RawURL == "" {
		c.RawURL = "https://raw.githubusercontent.com/CVEProject/cvelistV5"
	}
	if c.APIURL == "" {
		c.APIURL = "https://api.github.com/repos/CVEProject/cvelistV5"
	}
}

// cursor format: "<fetchTime RFC3339>|<commit sha>"
func splitCursor(c string) (time.Time, string) {
	ts, sha, _ := strings.Cut(c, "|")
	t, _ := time.Parse(time.RFC3339Nano, ts)
	return t, sha
}

func (c *CVEList) Run(ctx context.Context, st *State) error {
	c.defaults()
	since, lastSHA := splitCursor(st.Cursor)
	if since.IsZero() {
		if !c.InitialImport {
			since = time.Now().Add(-24 * time.Hour)
		} else {
			t, err := c.bulkImport(ctx, st)
			if err != nil {
				return fmt.Errorf("initial import: %w", err)
			}
			since = t
		}
		st.Cursor = since.Format(time.RFC3339Nano) + "|"
		if err := st.Save(ctx); err != nil {
			return err
		}
	}
	sha, err := c.headSHA(ctx)
	if err != nil {
		return err
	}
	if sha == lastSHA {
		return nil
	}
	entries, err := c.deltaSince(ctx, sha, since)
	if err != nil {
		return err
	}
	// oldest first, so the cursor only moves forward over fully processed entries
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		changes := append(e.New, e.Updated...)
		recs, err := parallel(ctx, len(changes), func(ctx context.Context, i int) ([]Record, error) {
			rec, err := c.fetchRecord(ctx, sha, changes[i].CVEID)
			if err != nil || rec == nil {
				return nil, err
			}
			return []Record{*rec}, nil
		})
		if err != nil {
			return err
		}
		if err := c.Env.Write(ctx, recs, false); err != nil {
			return err
		}
		st.Seen(len(recs), parseTime(e.FetchTime))
		st.Cursor = e.FetchTime + "|"
		if err := st.Save(ctx); err != nil {
			return err
		}
	}
	st.Cursor = since.Format(time.RFC3339Nano) + "|" + sha
	if len(entries) > 0 {
		st.Cursor = entries[0].FetchTime + "|" + sha
	}
	return nil
}

// headSHA asks the git server for refs/heads/main (git protocol v2 ls-refs).
func (c *CVEList) headSHA(ctx context.Context) (string, error) {
	body := pktLine("command=ls-refs\n") + "0001" + pktLine("ref-prefix refs/heads/main\n") + "0000"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RepoURL+".git/git-upload-pack", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("User-Agent", "git/2.45.0 "+userAgent)
	resp, err := c.Env.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", statusErr(resp)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	for _, line := range parsePktLines(b) {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "refs/heads/main" && len(f[0]) == 40 {
			return f[0], nil
		}
	}
	return "", errors.New("ls-refs: refs/heads/main not found")
}

func pktLine(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func parsePktLines(b []byte) []string {
	var out []string
	for len(b) >= 4 {
		n, err := strconv.ParseUint(string(b[:4]), 16, 16)
		if err != nil {
			break
		}
		if n < 4 { // flush / delim
			b = b[4:]
			continue
		}
		if int(n) > len(b) {
			break
		}
		out = append(out, strings.TrimRight(string(b[4:n]), "\n"))
		b = b[n:]
	}
	return out
}

type deltaChange struct {
	CVEID       string `json:"cveId"`
	DateUpdated string `json:"dateUpdated"`
}

type deltaEntry struct {
	FetchTime string        `json:"fetchTime"`
	New       []deltaChange `json:"new"`
	Updated   []deltaChange `json:"updated"`
}

// deltaSince returns deltaLog entries newer than since (newest first). It reads
// a growing prefix of the file with range requests and stops at the cursor.
func (c *CVEList) deltaSince(ctx context.Context, sha string, since time.Time) ([]deltaEntry, error) {
	url := c.RawURL + "/" + sha + "/cves/deltaLog.json"
	size := int64(256 << 10)
	for {
		resp, err := c.Env.get(ctx, url, map[string]string{"Range": fmt.Sprintf("bytes=0-%d", size-1)})
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, statusErr(resp)
		}
		full := resp.StatusCode == http.StatusOK
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if int64(len(b)) < size {
			full = true
		}
		entries, complete := decodeDeltaPrefix(b)
		var out []deltaEntry
		reached := false
		for _, e := range entries {
			t := parseTime(e.FetchTime)
			if t == nil {
				continue
			}
			if !t.After(since) {
				reached = true
				break
			}
			out = append(out, e)
		}
		if reached || (full && complete) || full {
			return out, nil
		}
		if size >= 64<<20 {
			return out, nil // cursor older than the log window (30 days); take what we have
		}
		size *= 4
	}
}

// decodeDeltaPrefix decodes as many complete array elements as possible from a
// truncated JSON array.
func decodeDeltaPrefix(b []byte) ([]deltaEntry, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return nil, false
	}
	var out []deltaEntry
	for dec.More() {
		var e deltaEntry
		if err := dec.Decode(&e); err != nil {
			return out, false
		}
		out = append(out, e)
	}
	return out, true
}

var cveNumRe = regexp.MustCompile(`^CVE-(\d{4})-(\d+)$`)

// RecordPath returns cves/2024/6xxx/CVE-2024-6387.json.
func RecordPath(id string) (string, bool) {
	m := cveNumRe.FindStringSubmatch(id)
	if m == nil {
		return "", false
	}
	num := m[2]
	bucket := "0xxx"
	if len(num) > 3 {
		bucket = num[:len(num)-3] + "xxx"
	}
	return path.Join("cves", m[1], bucket, id+".json"), true
}

func (c *CVEList) fetchRecord(ctx context.Context, sha, id string) (*Record, error) {
	p, ok := RecordPath(id)
	if !ok {
		return nil, nil
	}
	resp, err := c.Env.get(ctx, c.RawURL+"/"+sha+"/"+p, nil)
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
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	return c.parse(ctx, b)
}

// ---------------------------------------------------------------- bulk import

func (c *CVEList) bulkImport(ctx context.Context, st *State) (time.Time, error) {
	log := c.Env.Log.With("source", "cvelist")
	url, stamp, err := c.latestArchive(ctx)
	if err != nil {
		return time.Time{}, err
	}
	log.Info("downloading cvelistV5 archive", "url", url)
	f, err := downloadTemp(ctx, c.Env, url)
	if err != nil {
		return time.Time{}, err
	}
	defer os.Remove(f)
	n := 0
	var batch []Record
	flush := func() error {
		if err := c.Env.Write(ctx, batch, true); err != nil {
			return err
		}
		n += len(batch)
		st.Seen(len(batch), nil)
		batch = batch[:0]
		if n%20000 < 500 {
			log.Info("cvelist import progress", "records", n)
		}
		return st.Save(ctx)
	}
	err = walkZip(f, func(name string, r io.Reader) error {
		if !strings.HasSuffix(name, ".json") || !strings.Contains(path.Base(name), "CVE-") {
			return nil
		}
		b, err := io.ReadAll(io.LimitReader(r, 16<<20))
		if err != nil {
			return err
		}
		rec, err := c.parse(ctx, b)
		if err != nil {
			log.Debug("skip record", "file", name, "err", err)
			return nil
		}
		if rec != nil {
			batch = append(batch, *rec)
		}
		if len(batch) >= 500 {
			return flush()
		}
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	if err := flush(); err != nil {
		return time.Time{}, err
	}
	log.Info("cvelist initial import done", "records", n)
	return stamp, c.Env.RematchAllStacks(ctx)
}

// latestArchive finds the newest "all_CVEs_at_midnight" release asset.
func (c *CVEList) latestArchive(ctx context.Context) (string, time.Time, error) {
	hdr := map[string]string{"Accept": "application/vnd.github+json"}
	if c.GitHubToken != "" {
		hdr["Authorization"] = "Bearer " + c.GitHubToken
	}
	resp, err := c.Env.get(ctx, c.APIURL+"/releases?per_page=5", hdr)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, statusErr(resp)
	}
	var rels []struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rels); err != nil {
		return "", time.Time{}, err
	}
	for _, r := range rels {
		for _, a := range r.Assets {
			if strings.Contains(a.Name, "all_CVEs_at_midnight") {
				// name starts with YYYY-MM-DD; the archive reflects 00:00 UTC of that day
				t, err := time.Parse("2006-01-02", a.Name[:min(10, len(a.Name))])
				if err != nil {
					t = time.Now().Add(-25 * time.Hour)
				}
				return a.URL, t, nil
			}
		}
	}
	return "", time.Time{}, errors.New("no all_CVEs_at_midnight asset found in recent releases")
}

func downloadTemp(ctx context.Context, env *Env, url string) (string, error) {
	resp, err := env.get(ctx, url, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", statusErr(resp)
	}
	f, err := os.CreateTemp("", "yourcve-*.zip")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), f.Close()
}

// walkZip visits all files, descending into nested zip archives (the
// cvelistV5 release is a zip inside a zip).
func walkZip(file string, fn func(name string, r io.Reader) error) error {
	zr, err := zip.OpenReader(file)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(f.Name), ".zip") {
			tmp, err := os.CreateTemp("", "yourcve-inner-*.zip")
			if err != nil {
				return err
			}
			rc, err := f.Open()
			if err == nil {
				_, err = io.Copy(tmp, rc)
				rc.Close()
			}
			tmp.Close()
			if err == nil {
				err = walkZip(tmp.Name(), fn)
			}
			os.Remove(tmp.Name())
			if err != nil {
				return err
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = fn(f.Name, rc)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- parse CVE JSON 5

type cveRecord struct {
	Metadata struct {
		ID            string `json:"cveId"`
		State         string `json:"state"`
		DatePublished string `json:"datePublished"`
		DateUpdated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cnaContainer   `json:"cna"`
		ADP []cnaContainer `json:"adp"`
	} `json:"containers"`
}

type cnaContainer struct {
	Title           string      `json:"title"`
	Descriptions    []langValue `json:"descriptions"`
	RejectedReasons []langValue `json:"rejectedReasons"`
	Affected        []struct {
		Vendor        string   `json:"vendor"`
		Product       string   `json:"product"`
		PackageName   string   `json:"packageName"`
		CollectionURL string   `json:"collectionURL"`
		CPEs          []string `json:"cpes"`
		DefaultStatus string   `json:"defaultStatus"`
		Versions      []struct {
			Version         string `json:"version"`
			Status          string `json:"status"`
			LessThan        string `json:"lessThan"`
			LessThanOrEqual string `json:"lessThanOrEqual"`
			VersionType     string `json:"versionType"`
		} `json:"versions"`
	} `json:"affected"`
	Metrics      []map[string]json.RawMessage `json:"metrics"`
	ProblemTypes []struct {
		Descriptions []struct {
			CWEID string `json:"cweId"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type langValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

func english(list []langValue) string {
	first := ""
	for _, v := range list {
		if first == "" {
			first = v.Value
		}
		if strings.HasPrefix(strings.ToLower(v.Lang), "en") {
			return v.Value
		}
	}
	return first
}

type cvssData struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
	Version      string  `json:"version"`
}

// bestCVSS picks v3.1 > v4.0 > v3.0 > v2 from CVE JSON 5 metrics.
func bestCVSS(metrics []map[string]json.RawMessage) (*cvssData, string) {
	for _, key := range []string{"cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"} {
		for _, m := range metrics {
			raw, ok := m[key]
			if !ok {
				continue
			}
			var d cvssData
			if json.Unmarshal(raw, &d) == nil && (d.BaseScore > 0 || d.VectorString != "") {
				ver := strings.ReplaceAll(strings.TrimPrefix(key, "cvssV"), "_", ".")
				return &d, ver
			}
		}
	}
	return nil, ""
}

var collectionEcosystems = map[string]string{
	"pypi.org": "PyPI", "npmjs": "npm", "pkg.go.dev": "Go", "proxy.golang.org": "Go", "repo.maven": "Maven",
	"repo1.maven": "Maven", "crates.io": "crates.io", "nuget.org": "NuGet", "packagist.org": "Packagist",
	"rubygems.org": "RubyGems", "hex.pm": "Hex", "pub.dev": "Pub",
}

func ecosystemForCollection(u string) string {
	for k, v := range collectionEcosystems {
		if strings.Contains(u, k) {
			return v
		}
	}
	return ""
}

func isUnbounded(v string) bool {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "", "*", "0", "n/a", "unspecified", "all", "-":
		return true
	}
	return false
}

func (c *CVEList) parse(ctx context.Context, b []byte) (*Record, error) {
	var r cveRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	id := strings.ToUpper(r.Metadata.ID)
	if !cvedb.ValidID(id) {
		return nil, nil
	}
	cna := r.Containers.CNA
	p := cvedb.Patch{ID: id, Source: "cvelist", State: ptr(r.Metadata.State),
		Published: parseTime(r.Metadata.DatePublished), Modified: parseTime(r.Metadata.DateUpdated)}
	if r.Metadata.State == "REJECTED" {
		p.Description = ptr(english(cna.RejectedReasons))
		return &Record{Patch: p}, nil
	}
	if cna.Title != "" {
		p.Title = ptr(cna.Title)
	}
	p.Description = ptr(english(cna.Descriptions))
	metrics := cna.Metrics
	for _, adp := range r.Containers.ADP {
		metrics = append(metrics, adp.Metrics...)
	}
	if d, ver := bestCVSS(metrics); d != nil {
		// CNA scores rank below NVD primary scores
		p.CVSSSource = "cna"
		p.CVSS, p.CVSSVersion, p.CVSSVector = ptr(d.BaseScore), ptr(ver), ptr(d.VectorString)
	}
	for _, cont := range append([]cnaContainer{cna}, r.Containers.ADP...) {
		for _, pt := range cont.ProblemTypes {
			for _, d := range pt.Descriptions {
				if strings.HasPrefix(d.CWEID, "CWE-") {
					p.CWE = append(p.CWE, d.CWEID)
				}
			}
		}
	}
	for _, ref := range cna.References {
		p.References = append(p.References, ref.URL)
	}
	rec := &Record{Patch: p, AffectSource: "cna"}

	var affects []cvedb.Affect
	for _, a := range cna.Affected {
		var pids []int64
		confirmed := false
		for _, cpe := range a.CPEs {
			if vendor, prod, part, ok := parseAnyCPE(cpe); ok {
				if id, err := catalog.EnsureCPE(ctx, c.Env.Pool, c.Env.Cache, part, vendor, prod); err == nil {
					pids = append(pids, id)
					confirmed = true
				}
			}
		}
		if eco := ecosystemForCollection(a.CollectionURL); eco != "" && a.PackageName != "" {
			if id, err := catalog.EnsurePackage(ctx, c.Env.Pool, c.Env.Cache, eco, a.PackageName); err == nil {
				pids = append(pids, id)
				confirmed = true
			}
		}
		if len(pids) == 0 {
			name := a.Product
			if name == "" {
				name = a.PackageName
			}
			ids, err := catalog.FindByName(ctx, c.Env.Pool, c.Env.Cache, a.Vendor, name)
			if err != nil {
				return nil, err
			}
			pids = ids
		}
		if len(pids) == 0 {
			continue
		}
		var ranges []cvedb.Affect
		for _, v := range a.Versions {
			if v.Status != "affected" {
				continue
			}
			af := cvedb.Affect{Source: "cna", Confirmed: confirmed}
			switch {
			case v.LessThan != "":
				if !isUnbounded(v.Version) {
					af.StartIncluding = v.Version
				}
				if !isUnbounded(v.LessThan) {
					af.EndExcluding = v.LessThan
				}
			case v.LessThanOrEqual != "":
				if !isUnbounded(v.Version) {
					af.StartIncluding = v.Version
				}
				if !isUnbounded(v.LessThanOrEqual) {
					af.EndIncluding = v.LessThanOrEqual
				}
			case isUnbounded(v.Version):
				af.AllVersions = true
			default:
				af.Versions = []string{v.Version}
			}
			if af.StartIncluding == "" && af.EndExcluding == "" && af.EndIncluding == "" && len(af.Versions) == 0 {
				af.AllVersions = true
			}
			ranges = append(ranges, af)
		}
		if len(ranges) == 0 && a.DefaultStatus == "affected" {
			ranges = append(ranges, cvedb.Affect{Source: "cna", AllVersions: true, Confirmed: confirmed})
		}
		for _, pid := range pids {
			for _, af := range ranges {
				af.ProductID = pid
				affects = append(affects, af)
			}
		}
	}
	if affects == nil {
		affects = []cvedb.Affect{}
	}
	rec.Affects = affects
	return rec, nil
}

// parseAnyCPE accepts cpe:2.3:a:vendor:product:... and cpe:/a:vendor:product.
func parseAnyCPE(s string) (vendor, product, part string, ok bool) {
	var parts []string
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		parts = splitCPE23(s)
		if len(parts) < 5 {
			return
		}
		part, vendor, product = parts[2], parts[3], parts[4]
	case strings.HasPrefix(s, "cpe:/"):
		parts = strings.Split(strings.TrimPrefix(s, "cpe:/"), ":")
		if len(parts) < 3 {
			return
		}
		part, vendor, product = parts[0], parts[1], parts[2]
	default:
		return
	}
	if vendor == "" || product == "" || vendor == "*" || product == "*" {
		return
	}
	return vendor, product, part, true
}

// splitCPE23 splits on ':' but respects backslash escapes.
func splitCPE23(s string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}
