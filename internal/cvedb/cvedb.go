// Package cvedb stores CVE records and answers search queries.
//
// Every source (cvelistV5, NVD, OSV, KEV, EPSS) contributes a Patch. Patches are
// merged into the stored row inside a transaction, and the merge reports which
// notification relevant events happened (new KEV entry, higher severity).
package cvedb

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CVE struct {
	ID             string     `json:"id"`
	Title          *string    `json:"title,omitempty"`
	Description    string     `json:"description"`
	CVSS           *float64   `json:"cvss"`
	CVSSVersion    *string    `json:"cvss_version"`
	CVSSVector     *string    `json:"cvss_vector,omitempty"`
	CVSSSource     *string    `json:"-"`
	Severity       string     `json:"severity"`
	CWE            []string   `json:"cwe"`
	KEV            bool       `json:"kev"`
	KEVAdded       *time.Time `json:"kev_added,omitempty"`
	KEVDue         *time.Time `json:"kev_due,omitempty"`
	KEVAction      *string    `json:"kev_action,omitempty"`
	EPSS           *float64   `json:"epss"`
	EPSSPercentile *float64   `json:"epss_percentile"`
	References     []string   `json:"references,omitempty"`
	State          string     `json:"-"`
	Sources        []string   `json:"sources,omitempty"`
	Published      *time.Time `json:"published"`
	Modified       *time.Time `json:"modified"`
	// AI enrichment (read only, joined)
	Category *string `json:"category"`
	Summary  *string `json:"summary"`
	AIModel  *string `json:"ai_model,omitempty"`
}

// Patch carries the fields one source knows. nil means "unknown, keep".
type Patch struct {
	ID          string
	Source      string // cvelist, nvd, osv, kev
	CVSSSource  string // priority of the score: nvd > cna > osv (defaults to Source)
	Title       *string
	Description *string
	CVSS        *float64
	CVSSVersion *string
	CVSSVector  *string
	CWE         []string
	References  []string
	State       *string
	Published   *time.Time
	Modified    *time.Time
	KEV         *bool
	KEVAdded    *time.Time
	KEVDue      *time.Time
	KEVAction   *string
}

// Event types that can trigger notifications for existing matches.
const (
	EventCreated    = "created"
	EventKEVAdded   = "kev_added"
	EventCVSSRaised = "cvss_raised"
	EventChanged    = "changed"
	EventRejected   = "rejected"
)

var idRe = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

func ValidID(id string) bool { return idRe.MatchString(id) }

// Severity derives the qualitative rating from a CVSS base score.
func Severity(score *float64) string {
	if score == nil {
		return "unknown"
	}
	s := *score
	switch {
	case s == 0:
		return "none"
	case s < 4:
		return "low"
	case s < 7:
		return "medium"
	case s < 9:
		return "high"
	default:
		return "critical"
	}
}

func SeverityRank(s string) int {
	switch s {
	case "none":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	}
	return 0
}

// cvss priority: nvd beats cna beats osv
func sourceRank(s *string) int {
	if s == nil {
		return 0
	}
	switch *s {
	case "nvd":
		return 3
	case "cna":
		return 2
	case "osv":
		return 1
	}
	return 0
}

const cveCols = `id, title, description, cvss::float8, cvss_version, cvss_vector, cvss_source, severity, cwe,
	kev, kev_added, kev_due, kev_action, epss, epss_percentile, references_, state, sources, published, modified`

func scanCVE(row pgx.Row, c *CVE, extra ...any) error {
	var kevAdded, kevDue *time.Time
	dest := []any{&c.ID, &c.Title, &c.Description, &c.CVSS, &c.CVSSVersion, &c.CVSSVector, &c.CVSSSource,
		&c.Severity, &c.CWE, &c.KEV, &kevAdded, &kevDue, &c.KEVAction, &c.EPSS, &c.EPSSPercentile,
		&c.References, &c.State, &c.Sources, &c.Published, &c.Modified}
	dest = append(dest, extra...)
	if err := row.Scan(dest...); err != nil {
		return err
	}
	c.KEVAdded, c.KEVDue = kevAdded, kevDue
	return nil
}

// Apply merges a patch into the stored CVE (insert if missing) and returns the
// events. Must run inside a transaction.
func Apply(ctx context.Context, tx pgx.Tx, p Patch) (events []string, err error) {
	if !ValidID(p.ID) {
		return nil, fmt.Errorf("invalid cve id %q", p.ID)
	}
	p.ID = strings.ToUpper(p.ID)
	var old CVE
	err = scanCVE(tx.QueryRow(ctx, `SELECT `+cveCols+` FROM cves WHERE id=$1 FOR UPDATE`, p.ID), &old)
	isNew := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !isNew {
		return nil, err
	}
	n := old
	if isNew {
		n = CVE{ID: p.ID, State: "PUBLISHED", Severity: "unknown", CWE: []string{}, References: []string{}, Sources: []string{}}
	}
	if p.Title != nil && *p.Title != "" {
		n.Title = p.Title
	}
	if p.Description != nil && *p.Description != "" {
		// OSV and NVD text only fill gaps, cvelist (CNA) text wins
		if (p.Source != "osv" && p.Source != "nvd") || n.Description == "" {
			n.Description = *p.Description
		}
	}
	cvssSrc := p.CVSSSource
	if cvssSrc == "" {
		cvssSrc = p.Source
	}
	if p.CVSS != nil && sourceRank(&cvssSrc) >= sourceRank(n.CVSSSource) {
		n.CVSS, n.CVSSVersion, n.CVSSVector = p.CVSS, p.CVSSVersion, p.CVSSVector
		n.CVSSSource = &cvssSrc
	}
	n.Severity = Severity(n.CVSS)
	if len(p.CWE) > 0 {
		n.CWE = mergeUnique(n.CWE, p.CWE)
	}
	if len(p.References) > 0 {
		n.References = mergeUnique(n.References, p.References)
		if len(n.References) > 100 {
			n.References = n.References[:100]
		}
	}
	if p.State != nil {
		n.State = *p.State
	}
	if p.Published != nil && (n.Published == nil || p.Source == "cvelist") {
		n.Published = p.Published
	}
	if p.Modified != nil && (n.Modified == nil || p.Modified.After(*n.Modified)) {
		n.Modified = p.Modified
	}
	if p.KEV != nil {
		n.KEV = *p.KEV
		n.KEVAdded, n.KEVDue, n.KEVAction = p.KEVAdded, p.KEVDue, p.KEVAction
	}
	if p.Source != "" && !slices.Contains(n.Sources, p.Source) {
		n.Sources = append(n.Sources, p.Source)
	}

	if isNew {
		events = append(events, EventCreated)
	} else {
		if n.KEV && !old.KEV {
			events = append(events, EventKEVAdded)
		}
		if old.CVSS != nil && SeverityRank(n.Severity) > SeverityRank(old.Severity) {
			events = append(events, EventCVSSRaised)
		}
		if n.State == "REJECTED" && old.State != "REJECTED" {
			events = append(events, EventRejected)
		}
		if !equalCVE(old, n) {
			events = append(events, EventChanged)
		}
		if len(events) == 0 {
			return nil, nil // nothing changed
		}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO cves (id, title, description, cvss, cvss_version, cvss_vector, cvss_source, severity, cwe,
			kev, kev_added, kev_due, kev_action, references_, state, sources, published, modified)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (id) DO UPDATE SET title=$2, description=$3, cvss=$4, cvss_version=$5, cvss_vector=$6,
			cvss_source=$7, severity=$8, cwe=$9, kev=$10, kev_added=$11, kev_due=$12, kev_action=$13,
			references_=$14, state=$15, sources=$16, published=$17, modified=$18, updated_at=now()`,
		n.ID, n.Title, n.Description, n.CVSS, n.CVSSVersion, n.CVSSVector, n.CVSSSource, n.Severity, n.CWE,
		n.KEV, n.KEVAdded, n.KEVDue, n.KEVAction, n.References, n.State, n.Sources, n.Published, n.Modified)
	return events, err
}

func equalCVE(a, b CVE) bool {
	return ptrEq(a.Title, b.Title) && a.Description == b.Description && ptrEq(a.CVSS, b.CVSS) &&
		ptrEq(a.CVSSVector, b.CVSSVector) && slices.Equal(a.CWE, b.CWE) && a.KEV == b.KEV &&
		slices.Equal(a.References, b.References) && a.State == b.State && slices.Equal(a.Sources, b.Sources) &&
		timeEq(a.Published, b.Published) && timeEq(a.Modified, b.Modified) && timeEq(a.KEVDue, b.KEVDue)
}

func ptrEq[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func timeEq(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func mergeUnique(a, b []string) []string {
	out := slices.Clone(a)
	for _, v := range b {
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// Affect is one affected product range of a CVE.
type Affect struct {
	ProductID      int64
	Source         string
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
	Versions       []string
	AllVersions    bool
	Confirmed      bool
}

// ReplaceAffects replaces all affects of one source for a CVE. Reports whether
// anything changed.
func ReplaceAffects(ctx context.Context, tx pgx.Tx, cveID, source string, affects []Affect) (bool, error) {
	old, err := loadAffectKeys(ctx, tx, cveID, source)
	if err != nil {
		return false, err
	}
	newKeys := make([]string, 0, len(affects))
	for _, a := range affects {
		newKeys = append(newKeys, affectKey(a))
	}
	slices.Sort(newKeys)
	newKeys = slices.Compact(newKeys)
	if slices.Equal(old, newKeys) {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cve_affects WHERE cve_id=$1 AND source=$2`, cveID, source); err != nil {
		return false, err
	}
	seen := map[string]bool{}
	for _, a := range affects {
		k := affectKey(a)
		if seen[k] {
			continue
		}
		seen[k] = true
		if a.Versions == nil {
			a.Versions = []string{}
		}
		_, err := tx.Exec(ctx, `INSERT INTO cve_affects (cve_id, product_id, source, version_start_including,
			version_start_excluding, version_end_including, version_end_excluding, versions, all_versions, confirmed)
			VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),$8,$9,$10)`,
			cveID, a.ProductID, source, a.StartIncluding, a.StartExcluding, a.EndIncluding, a.EndExcluding,
			a.Versions, a.AllVersions, a.Confirmed)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func affectKey(a Affect) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s|%s|%t|%t", a.ProductID, a.StartIncluding, a.StartExcluding,
		a.EndIncluding, a.EndExcluding, strings.Join(a.Versions, ","), a.AllVersions, a.Confirmed)
}

func loadAffectKeys(ctx context.Context, tx pgx.Tx, cveID, source string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT product_id, coalesce(version_start_including,''), coalesce(version_start_excluding,''),
		coalesce(version_end_including,''), coalesce(version_end_excluding,''), versions, all_versions, confirmed
		FROM cve_affects WHERE cve_id=$1 AND source=$2`, cveID, source)
	if err != nil {
		return nil, err
	}
	var keys []string
	for rows.Next() {
		var a Affect
		if err := rows.Scan(&a.ProductID, &a.StartIncluding, &a.StartExcluding, &a.EndIncluding, &a.EndExcluding,
			&a.Versions, &a.AllVersions, &a.Confirmed); err != nil {
			return nil, err
		}
		keys = append(keys, affectKey(a))
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	return keys, rows.Err()
}

// ---------------------------------------------------------------- queries

type Filter struct {
	Q        string
	Severity []string
	KEV      *bool
	CWE      string
	MinEPSS  *float64
	MinCVSS  *float64
	Since    *time.Time
	Limit    int
	Offset   int
}

type Store struct{ Pool *pgxpool.Pool }

const aiJoin = ` LEFT JOIN cve_ai a ON a.cve_id = c.id `
const selectCols = `c.id, c.title, c.description, c.cvss::float8, c.cvss_version, c.cvss_vector, c.cvss_source, c.severity, c.cwe,
	c.kev, c.kev_added, c.kev_due, c.kev_action, c.epss, c.epss_percentile, c.references_, c.state, c.sources, c.published, c.modified,
	a.category, a.summary_en, a.model`

func scanFull(row pgx.Row, c *CVE, extra ...any) error {
	return scanCVE(row, c, append([]any{&c.Category, &c.Summary, &c.AIModel}, extra...)...)
}

// ScanFull scans a row selected with SelectCols (exported for other packages).
func ScanFull(row pgx.Row, c *CVE, extra ...any) error { return scanFull(row, c, extra...) }

// SelectCols are the columns ScanFull expects (tables aliased c and a).
const SelectCols = selectCols

// AIJoin joins the AI enrichment as alias a.
const AIJoin = aiJoin

func (s *Store) Search(ctx context.Context, f Filter) ([]CVE, int, error) {
	var where []string
	var args []any
	arg := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
	order := "c.published DESC NULLS LAST"
	where = append(where, "c.state <> 'REJECTED'")
	q := strings.TrimSpace(f.Q)
	if q != "" {
		if ValidID(q) {
			where = append(where, "c.id = "+arg(strings.ToUpper(q)))
		} else if strings.HasPrefix(strings.ToUpper(q), "CVE-") {
			where = append(where, "c.id LIKE "+arg(strings.ToUpper(q)+"%"))
		} else {
			p := arg(q)
			where = append(where, "c.search @@ websearch_to_tsquery('english', "+p+")")
			order = "ts_rank(c.search, websearch_to_tsquery('english', " + p + ")) DESC, c.published DESC NULLS LAST"
		}
	}
	if len(f.Severity) > 0 {
		where = append(where, "c.severity = ANY("+arg(f.Severity)+")")
	}
	if f.KEV != nil {
		where = append(where, "c.kev = "+arg(*f.KEV))
	}
	if f.CWE != "" {
		where = append(where, arg(strings.ToUpper(f.CWE))+" = ANY(c.cwe)")
	}
	if f.MinEPSS != nil {
		where = append(where, "c.epss >= "+arg(*f.MinEPSS))
	}
	if f.MinCVSS != nil {
		where = append(where, "c.cvss >= "+arg(*f.MinCVSS))
	}
	if f.Since != nil {
		where = append(where, "c.published >= "+arg(*f.Since))
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 25
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM cves c WHERE `+w+` LIMIT 10000) t`, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+selectCols+` FROM cves c`+aiJoin+` WHERE `+w+
		` ORDER BY `+order+fmt.Sprintf(` LIMIT %d OFFSET %d`, f.Limit, max(f.Offset, 0)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []CVE{}
	for rows.Next() {
		var c CVE
		if err := scanFull(rows, &c); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func (s *Store) Get(ctx context.Context, id string) (*CVE, error) {
	var c CVE
	err := scanFull(s.Pool.QueryRow(ctx, `SELECT `+selectCols+` FROM cves c`+aiJoin+` WHERE c.id=$1`, strings.ToUpper(id)), &c)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &c, err
}

type AffectView struct {
	Product        ProductRef `json:"product"`
	StartIncluding *string    `json:"version_start_including"`
	StartExcluding *string    `json:"version_start_excluding"`
	EndIncluding   *string    `json:"version_end_including"`
	EndExcluding   *string    `json:"version_end_excluding"`
	Versions       []string   `json:"versions"`
	AllVersions    bool       `json:"all_versions"`
	Source         string     `json:"source"`
	Advisory       string     `json:"advisory,omitempty"`
	Confirmed      bool       `json:"confirmed"`
}

type ProductRef struct {
	ID        int64    `json:"id"`
	Vendor    string   `json:"vendor"`
	Name      string   `json:"name"`
	Ecosystem string   `json:"ecosystem"`
	CPE       *string  `json:"cpe"`
	PURL      *string  `json:"purl"`
	Aliases   []string `json:"aliases"`
}

func (s *Store) Affects(ctx context.Context, id string) ([]AffectView, error) {
	rows, err := s.Pool.Query(ctx, `SELECT p.id, p.vendor, p.name, p.ecosystem, p.cpe, p.purl, p.aliases,
		a.version_start_including, a.version_start_excluding, a.version_end_including, a.version_end_excluding,
		a.versions, a.all_versions, a.source, a.confirmed
		FROM cve_affects a JOIN products p ON p.id=a.product_id WHERE a.cve_id=$1
		ORDER BY a.confirmed DESC, p.vendor, p.name LIMIT 500`, strings.ToUpper(id))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AffectView{}
	for rows.Next() {
		var a AffectView
		if err := rows.Scan(&a.Product.ID, &a.Product.Vendor, &a.Product.Name, &a.Product.Ecosystem, &a.Product.CPE,
			&a.Product.PURL, &a.Product.Aliases, &a.StartIncluding, &a.StartExcluding, &a.EndIncluding,
			&a.EndExcluding, &a.Versions, &a.AllVersions, &a.Source, &a.Confirmed); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
