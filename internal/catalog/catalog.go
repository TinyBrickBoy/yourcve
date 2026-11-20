// Package catalog manages the product catalog (CPE products from NVD and
// packages from OSV ecosystems) used by the stack builder and the matcher.
package catalog

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tinybrickboy/yourcve/internal/importer"
)

// Querier is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Product struct {
	ID        int64    `json:"id"`
	Vendor    string   `json:"vendor"`
	Name      string   `json:"name"`
	Ecosystem string   `json:"ecosystem"`
	CPE       *string  `json:"cpe"`
	PURL      *string  `json:"purl"`
	Aliases   []string `json:"aliases"`
	CVECount  int      `json:"cve_count"`
}

const cols = `id, vendor, name, ecosystem, cpe, purl, aliases, cve_count`

func scan(row pgx.Row, p *Product) error {
	return row.Scan(&p.ID, &p.Vendor, &p.Name, &p.Ecosystem, &p.CPE, &p.PURL, &p.Aliases, &p.CVECount)
}

// CPEKey builds the vendor:product prefix used as product identity.
func CPEKey(vendor, product string) string {
	return "cpe:2.3:a:" + strings.ToLower(vendor) + ":" + strings.ToLower(product)
}

// HumanName turns a CPE product token into a display name (nginx, http_server → http server).
func HumanName(s string) string {
	s = strings.ReplaceAll(s, `\`, "")
	return strings.ReplaceAll(s, "_", " ")
}

func aliasesFor(names ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		for _, v := range []string{n, strings.ReplaceAll(n, "_", " "), strings.ReplaceAll(n, "_", "-"), strings.ReplaceAll(n, " ", "-")} {
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

// Cache memoizes product ids during bulk imports.
type Cache struct {
	mu sync.Mutex
	m  map[string]int64
}

func NewCache() *Cache { return &Cache{m: map[string]int64{}} }

func (c *Cache) get(k string) (int64, bool) {
	if c == nil {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 200000 {
		clear(c.m)
	}
	v, ok := c.m[k]
	return v, ok
}

func (c *Cache) put(k string, v int64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.m[k] = v
	c.mu.Unlock()
}

// EnsureCPE returns the product for a CPE vendor:product pair, creating it.
// part is the CPE part (a, o, h); hardware products are stored too.
func EnsureCPE(ctx context.Context, q Querier, cache *Cache, part, vendor, product string) (int64, error) {
	if part == "" {
		part = "a"
	}
	vendor, product = strings.ToLower(vendor), strings.ToLower(product)
	if vendor == "" || product == "" || vendor == "*" || product == "*" {
		return 0, errors.New("empty cpe vendor/product")
	}
	key := "cpe:2.3:" + part + ":" + vendor + ":" + product
	if id, ok := cache.get(key); ok {
		return id, nil
	}
	eco := "cpe"
	switch part {
	case "o":
		eco = "os"
	case "h":
		eco = "hardware"
	}
	var id int64
	err := q.QueryRow(ctx, `INSERT INTO products (vendor, name, ecosystem, cpe, aliases)
		VALUES ($1, $2, $5, $3, $4)
		ON CONFLICT (cpe) DO UPDATE SET cpe = EXCLUDED.cpe RETURNING id`,
		HumanName(vendor), HumanName(product), key, aliasesFor(product), eco).Scan(&id)
	if err == nil {
		cache.put(key, id)
	}
	return id, err
}

// EnsurePackage returns the product for an ecosystem package, creating it.
func EnsurePackage(ctx context.Context, q Querier, cache *Cache, ecosystem, name string) (int64, error) {
	eco := BaseEcosystem(ecosystem)
	purl := importer.PURLFor(eco, name)
	if purl == "" {
		purl = "pkg:generic/" + strings.ToLower(eco) + "/" + name
	}
	if id, ok := cache.get(purl); ok {
		return id, nil
	}
	vendor := ""
	display := name
	switch {
	case strings.Contains(name, ":") && eco == "Maven": // group:artifact
		i := strings.LastIndex(name, ":")
		vendor, display = name[:i], name[i+1:]
	case strings.HasPrefix(name, "@") && strings.Contains(name, "/"): // npm scope
		i := strings.Index(name, "/")
		vendor, display = name[:i], name[i+1:]
	case eco == "Go" && strings.Count(name, "/") >= 2:
		i := strings.LastIndex(name, "/")
		vendor, display = name[:i], name[i+1:]
	}
	var id int64
	err := q.QueryRow(ctx, `INSERT INTO products (vendor, name, ecosystem, purl, aliases)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (purl) DO UPDATE SET purl = EXCLUDED.purl RETURNING id`,
		vendor, display, eco, purl, aliasesFor(display, name)).Scan(&id)
	if err == nil {
		cache.put(purl, id)
	}
	return id, err
}

// BaseEcosystem strips OSV ecosystem suffixes like "Debian:12" → "Debian".
func BaseEcosystem(e string) string {
	if i := strings.Index(e, ":"); i > 0 {
		return e[:i]
	}
	return e
}

// FindByName looks up existing products by vendor/product name (used for CNA
// data without CPE). Returns ids of good candidates; empty if unsure.
func FindByName(ctx context.Context, q Querier, cache *Cache, vendor, product string) ([]int64, error) {
	product = strings.ToLower(strings.TrimSpace(product))
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	if product == "" || product == "n/a" || len(product) < 2 {
		return nil, nil
	}
	key := "name:" + vendor + "|" + product
	if id, ok := cache.get(key); ok {
		if id == 0 {
			return nil, nil
		}
		return []int64{id}, nil
	}
	// exact CPE with vendor first
	normV := strings.ReplaceAll(strings.ReplaceAll(vendor, " ", "_"), ",", "")
	normP := strings.ReplaceAll(product, " ", "_")
	var id int64
	err := q.QueryRow(ctx, `SELECT id FROM products WHERE cpe = $1 OR cpe = $2 LIMIT 1`,
		CPEKey(normV, normP), "cpe:2.3:o:"+normV+":"+normP).Scan(&id)
	if err == nil {
		cache.put(key, id)
		return []int64{id}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	// alias match, require vendor similarity when the alias is ambiguous
	rows, err := q.Query(ctx, `SELECT id, lower(vendor) FROM products WHERE $1 = ANY(aliases) AND ecosystem IN ('cpe','os') LIMIT 5`, product)
	if err != nil {
		return nil, err
	}
	type cand struct {
		id     int64
		vendor string
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.vendor); err != nil {
			rows.Close()
			return nil, err
		}
		cands = append(cands, c)
	}
	rows.Close()
	var pick int64
	if len(cands) == 1 {
		pick = cands[0].id
	} else {
		for _, c := range cands {
			if vendor != "" && (strings.Contains(c.vendor, vendor) || strings.Contains(vendor, c.vendor)) {
				pick = c.id
				break
			}
		}
	}
	cache.put(key, pick)
	if pick == 0 {
		return nil, nil
	}
	return []int64{pick}, nil
}

type Store struct{ Pool *pgxpool.Pool }

// Search is the autocomplete for the stack builder.
func (s *Store) Search(ctx context.Context, q string, limit int) ([]Product, error) {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return []Product{}, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 15
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT `+cols+` FROM (
			SELECT *, CASE
				WHEN lower(name) = $1 OR $1 = ANY(aliases) THEN 3
				WHEN lower(name) LIKE $2 THEN 2
				ELSE 1 END AS rank,
				similarity(search_text, $1) AS sim
			FROM products
			WHERE search_text % $1 OR search_text LIKE $3 OR $1 = ANY(aliases) OR lower(coalesce(purl,'')) LIKE $3
			LIMIT 2000
		) t
		ORDER BY rank DESC, (cve_count > 0) DESC, sim DESC, cve_count DESC, length(name)
		LIMIT $4`, q, likeEscape(q)+"%", "%"+likeEscape(q)+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Product{}
	for rows.Next() {
		var p Product
		if err := scan(rows, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) Get(ctx context.Context, id int64) (*Product, error) {
	var p Product
	err := scan(s.Pool.QueryRow(ctx, `SELECT `+cols+` FROM products WHERE id=$1`, id), &p)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &p, err
}

// FindForImport resolves an imported component to a product id. Packages with
// a known ecosystem are created on demand so future advisories match them.
func FindForImport(ctx context.Context, q Querier, ecosystem, name, cpe string) (int64, error) {
	if cpe != "" {
		parts := strings.Split(cpe, ":")
		if len(parts) >= 5 {
			return EnsureCPE(ctx, q, nil, parts[2], parts[3], parts[4])
		}
	}
	if ecosystem != "" && importer.PURLFor(ecosystem, name) != "" {
		return EnsurePackage(ctx, q, nil, ecosystem, name)
	}
	// unknown ecosystem (docker image names): best catalog match by name
	var id int64
	err := q.QueryRow(ctx, `SELECT id FROM products
		WHERE lower(name) = lower($1) OR lower($1) = ANY(aliases)
		ORDER BY (ecosystem IN ('cpe','os')) DESC, cve_count DESC LIMIT 1`, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// RefreshCounts recomputes cve_count for autocomplete ranking.
func RefreshCounts(ctx context.Context, q Querier) error {
	_, err := q.Exec(ctx, `
		UPDATE products p SET cve_count = c.n
		FROM (SELECT product_id, count(DISTINCT cve_id)::int AS n FROM cve_affects GROUP BY product_id) c
		WHERE p.id = c.product_id AND p.cve_count <> c.n`)
	return err
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
