package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tinybrickboy/yourcve/internal/catalog"
	"github.com/tinybrickboy/yourcve/internal/cvedb"
	"github.com/tinybrickboy/yourcve/internal/importer"
	"github.com/tinybrickboy/yourcve/internal/jobs"
	"github.com/tinybrickboy/yourcve/internal/version"
)

func (s *Server) searchCVEs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := cvedb.Filter{Q: q.Get("q"), CWE: q.Get("cwe"), MinEPSS: queryFloat(r, "min_epss"), MinCVSS: queryFloat(r, "min_cvss"),
		Limit: queryInt(r, "limit", 25), Offset: queryInt(r, "offset", 0)}
	if v := q.Get("severity"); v != "" {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
				f.Severity = append(f.Severity, p)
			}
		}
	}
	if v := q.Get("kev"); v != "" {
		b := v == "true" || v == "1"
		f.KEV = &b
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t, err = time.Parse("2006-01-02", v)
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, "since must be RFC 3339 or YYYY-MM-DD")
			return
		}
		f.Since = &t
	}
	if f.Offset > 10000 {
		writeErr(w, http.StatusBadRequest, "offset too large")
		return
	}
	items, total, err := s.CVEs.Search(r.Context(), f)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	for i := range items {
		items[i].References = nil
		items[i].Sources = nil
	}
	writeJSON(w, 200, map[string]any{"total": total, "items": items})
}

func (s *Server) getCVE(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !cvedb.ValidID(id) {
		writeErr(w, http.StatusNotFound, "unknown CVE")
		return
	}
	c, err := s.CVEs.Get(r.Context(), id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "unknown CVE")
		return
	}
	affects, err := s.CVEs.Affects(r.Context(), id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	for i := range affects {
		if adv, ok := strings.CutPrefix(affects[i].Source, "osv:"); ok {
			affects[i].Source = "osv"
			affects[i].Advisory = adv
		}
	}
	writeJSON(w, 200, struct {
		*cvedb.CVE
		Affects []cvedb.AffectView `json:"affects"`
	}{c, affects})
}

func (s *Server) semanticSearch(w http.ResponseWriter, r *http.Request) {
	if s.AI == nil {
		writeErr(w, http.StatusServiceUnavailable, "AI is not configured on this instance (OLLAMA_URL)")
		return
	}
	var in struct {
		Query   string `json:"query"`
		StackID int64  `json:"stack_id"`
		Limit   int    `json:"limit"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Query) == "" {
		writeErr(w, http.StatusBadRequest, "query is required")
		return
	}
	u := userFrom(r.Context())
	if in.StackID > 0 && !s.ownsStack(r, u.ID, in.StackID) {
		writeErr(w, http.StatusNotFound, "stack not found")
		return
	}
	items, err := s.SemanticItems(r, in.Query, in.StackID, in.Limit)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "semantic search failed: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

type semanticItem struct {
	cvedb.CVE
	Distance float64 `json:"distance"`
}

// SemanticItems is shared with the MCP server.
func (s *Server) SemanticItems(r *http.Request, query string, stackID int64, limit int) ([]semanticItem, error) {
	hits, err := s.AI.SemanticSearch(r.Context(), query, stackID, limit)
	if err != nil {
		return nil, err
	}
	out := []semanticItem{}
	for _, h := range hits {
		c, err := s.CVEs.Get(r.Context(), h.ID)
		if err != nil {
			return nil, err
		}
		if c != nil {
			c.References, c.Sources = nil, nil
			out = append(out, semanticItem{*c, h.Distance})
		}
	}
	return out, nil
}

func (s *Server) searchProducts(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.Allow("products:"+s.ip(r), 50*time.Millisecond, 40) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	list, err := s.Catalog.Search(r.Context(), r.URL.Query().Get("q"), queryInt(r, "limit", 15))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

// ---------------------------------------------------------------- stacks

type stackOut struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	CreatedAt    time.Time `json:"created_at"`
	ItemCount    int       `json:"item_count"`
	OpenCVEs     int       `json:"open_cves"`
	CriticalCVEs int       `json:"critical_cves"`
	Items        []itemOut `json:"items,omitempty"`
}

type itemOut struct {
	ID      int64           `json:"id"`
	Product catalog.Product `json:"product"`
	Version string          `json:"version"`
}

const stackSelect = `SELECT s.id, s.name, s.created_at,
	(SELECT count(*) FROM stack_items i WHERE i.stack_id = s.id),
	(SELECT count(*) FROM matches m WHERE m.stack_id = s.id AND NOT EXISTS
		(SELECT 1 FROM stack_cve_status x WHERE x.stack_id = s.id AND x.cve_id = m.cve_id)),
	(SELECT count(*) FROM matches m JOIN cves c ON c.id = m.cve_id WHERE m.stack_id = s.id AND c.severity = 'critical' AND NOT EXISTS
		(SELECT 1 FROM stack_cve_status x WHERE x.stack_id = s.id AND x.cve_id = m.cve_id))
	FROM stacks s`

func scanStack(row pgx.Row) (stackOut, error) {
	var st stackOut
	err := row.Scan(&st.ID, &st.Name, &st.CreatedAt, &st.ItemCount, &st.OpenCVEs, &st.CriticalCVEs)
	return st, err
}

func (s *Server) ownsStack(r *http.Request, userID, stackID int64) bool {
	var ok bool
	_ = s.Pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM stacks WHERE id=$1 AND user_id=$2)`, stackID, userID).Scan(&ok)
	return ok
}

func (s *Server) listStacks(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Pool.Query(r.Context(), stackSelect+` WHERE s.user_id=$1 ORDER BY s.id`, userFrom(r.Context()).ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (stackOut, error) { return scanStack(r) })
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if list == nil {
		list = []stackOut{}
	}
	writeJSON(w, 200, list)
}

func validName(n string) (string, bool) {
	n = strings.TrimSpace(n)
	return n, n != "" && len(n) <= 80
}

func (s *Server) createStack(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	name, ok := validName(in.Name)
	if !ok {
		writeErr(w, http.StatusBadRequest, "name is required (max 80 characters)")
		return
	}
	u := userFrom(r.Context())
	maxStacks, _ := s.limits(u)
	var id int64
	err := pgx.BeginFunc(r.Context(), s.Pool, func(tx pgx.Tx) error {
		// lock the user row so parallel requests can't exceed the limit
		if _, err := tx.Exec(r.Context(), `SELECT 1 FROM users WHERE id=$1 FOR UPDATE`, u.ID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM stacks WHERE user_id=$1`, u.ID).Scan(&n); err != nil {
			return err
		}
		if n >= maxStacks {
			return errLimit
		}
		return tx.QueryRow(r.Context(), `INSERT INTO stacks (user_id, name) VALUES ($1,$2) RETURNING id`, u.ID, name).Scan(&id)
	})
	if errors.Is(err, errLimit) {
		writeErr(w, http.StatusForbidden, "plan limit reached: at most "+itoa(maxStacks)+" stacks on the free plan")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.writeStack(w, r, id, http.StatusCreated)
}

var errLimit = errors.New("limit")

func (s *Server) writeStack(w http.ResponseWriter, r *http.Request, id int64, code int) {
	st, err := scanStack(s.Pool.QueryRow(r.Context(), stackSelect+` WHERE s.id=$1`, id))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	rows, err := s.Pool.Query(r.Context(), `SELECT i.id, i.version, p.id, p.vendor, p.name, p.ecosystem, p.cpe, p.purl, p.aliases, p.cve_count
		FROM stack_items i JOIN products p ON p.id = i.product_id WHERE i.stack_id=$1 ORDER BY lower(p.name), i.id`, id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	st.Items, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (itemOut, error) {
		var it itemOut
		p := &it.Product
		err := r.Scan(&it.ID, &it.Version, &p.ID, &p.Vendor, &p.Name, &p.Ecosystem, &p.CPE, &p.PURL, &p.Aliases, &p.CVECount)
		if it.Version == "" {
			it.Version = "*"
		}
		return it, err
	})
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if st.Items == nil {
		st.Items = []itemOut{}
	}
	writeJSON(w, code, st)
}

func (s *Server) stackParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return 0, false
	}
	if !s.ownsStack(r, userFrom(r.Context()).ID, id) {
		writeErr(w, http.StatusNotFound, "stack not found")
		return 0, false
	}
	return id, true
}

func (s *Server) getStack(w http.ResponseWriter, r *http.Request) {
	if id, ok := s.stackParam(w, r); ok {
		s.writeStack(w, r, id, 200)
	}
}

func (s *Server) renameStack(w http.ResponseWriter, r *http.Request) {
	id, ok := s.stackParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	name, ok := validName(in.Name)
	if !ok {
		writeErr(w, http.StatusBadRequest, "name is required (max 80 characters)")
		return
	}
	if _, err := s.Pool.Exec(r.Context(), `UPDATE stacks SET name=$2 WHERE id=$1`, id, name); err != nil {
		s.internal(w, r, err)
		return
	}
	s.writeStack(w, r, id, 200)
}

func (s *Server) deleteStack(w http.ResponseWriter, r *http.Request) {
	id, ok := s.stackParam(w, r)
	if !ok {
		return
	}
	if _, err := s.Pool.Exec(r.Context(), `DELETE FROM stacks WHERE id=$1`, id); err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rematch(r *http.Request, tx pgx.Tx, stackID int64) error {
	if tx != nil {
		_, err := s.River.InsertTx(r.Context(), tx, jobs.MatchStack{StackID: stackID}, nil)
		return err
	}
	_, err := s.River.Insert(r.Context(), jobs.MatchStack{StackID: stackID}, nil)
	return err
}

const maxItems = 2000

func (s *Server) addItem(w http.ResponseWriter, r *http.Request) {
	id, ok := s.stackParam(w, r)
	if !ok {
		return
	}
	var in struct {
		ProductID int64  `json:"product_id"`
		Version   string `json:"version"`
	}
	if !decode(w, r, &in) {
		return
	}
	ver := version.Normalize(in.Version)
	if version.IsAll(in.Version) {
		ver = ""
	}
	if len(ver) > 100 {
		writeErr(w, http.StatusBadRequest, "version too long")
		return
	}
	var itemID int64
	err := pgx.BeginFunc(r.Context(), s.Pool, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM stack_items WHERE stack_id=$1`, id).Scan(&n); err != nil {
			return err
		}
		if n >= maxItems {
			return errLimit
		}
		err := tx.QueryRow(r.Context(), `INSERT INTO stack_items (stack_id, product_id, version)
			SELECT $1, p.id, $3 FROM products p WHERE p.id=$2
			ON CONFLICT (stack_id, product_id, version) DO UPDATE SET version = EXCLUDED.version RETURNING id`, id, in.ProductID, ver).Scan(&itemID)
		if err != nil {
			return err
		}
		return s.rematch(r, tx, id)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		writeErr(w, http.StatusBadRequest, "unknown product")
		return
	case errors.Is(err, errLimit):
		writeErr(w, http.StatusForbidden, "at most 2000 products per stack")
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	s.writeItem(w, r, itemID, http.StatusCreated)
}

func (s *Server) writeItem(w http.ResponseWriter, r *http.Request, itemID int64, code int) {
	var it itemOut
	p := &it.Product
	err := s.Pool.QueryRow(r.Context(), `SELECT i.id, i.version, p.id, p.vendor, p.name, p.ecosystem, p.cpe, p.purl, p.aliases, p.cve_count
		FROM stack_items i JOIN products p ON p.id = i.product_id WHERE i.id=$1`, itemID).
		Scan(&it.ID, &it.Version, &p.ID, &p.Vendor, &p.Name, &p.Ecosystem, &p.CPE, &p.PURL, &p.Aliases, &p.CVECount)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if it.Version == "" {
		it.Version = "*"
	}
	writeJSON(w, code, it)
}

func (s *Server) updateItem(w http.ResponseWriter, r *http.Request) {
	id, ok := s.stackParam(w, r)
	if !ok {
		return
	}
	itemID, ok := pathID(w, r, "item")
	if !ok {
		return
	}
	var in struct {
		Version string `json:"version"`
	}
	if !decode(w, r, &in) {
		return
	}
	ver := version.Normalize(in.Version)
	if version.IsAll(in.Version) {
		ver = ""
	}
	err := pgx.BeginFunc(r.Context(), s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE stack_items SET version=$3 WHERE id=$1 AND stack_id=$2`, itemID, id, ver)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return s.rematch(r, tx, id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "item not found")
		return
	}
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			writeErr(w, http.StatusConflict, "this product and version is already in the stack")
			return
		}
		s.internal(w, r, err)
		return
	}
	s.writeItem(w, r, itemID, 200)
}

func (s *Server) deleteItem(w http.ResponseWriter, r *http.Request) {
	id, ok := s.stackParam(w, r)
	if !ok {
		return
	}
	itemID, ok := pathID(w, r, "item")
	if !ok {
		return
	}
	err := pgx.BeginFunc(r.Context(), s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `DELETE FROM stack_items WHERE id=$1 AND stack_id=$2`, itemID, id); err != nil {
			return err
		}
		return s.rematch(r, tx, id)
	})
	if err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) importStack(w http.ResponseWriter, r *http.Request) {
	id, ok := s.stackParam(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, importer.MaxInputSize+(1<<20))
	var filename string
	var data []byte
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		f, hdr, err := r.FormFile("file")
		if err != nil {
			writeErr(w, http.StatusBadRequest, "multipart field 'file' missing or too large (max 5 MB)")
			return
		}
		defer f.Close()
		filename = hdr.Filename
		data, err = readAll(f, importer.MaxInputSize+1)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "cannot read file")
			return
		}
	} else {
		filename = r.URL.Query().Get("filename")
		var err error
		data, err = readAll(r.Body, importer.MaxInputSize+1)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "body too large (max 5 MB)")
			return
		}
	}
	res, err := importer.Parse(filename, data)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "import failed: "+err.Error())
		return
	}
	added := 0
	skipped := append([]string{}, res.Skipped...)
	var itemIDs []int64
	err = pgx.BeginFunc(r.Context(), s.Pool, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM stack_items WHERE stack_id=$1`, id).Scan(&n); err != nil {
			return err
		}
		for _, c := range res.Components {
			label := c.Name
			if c.Version != "" {
				label += " " + c.Version
			}
			if n >= maxItems {
				skipped = append(skipped, label+": stack limit reached")
				continue
			}
			pid, err := catalog.FindForImport(r.Context(), tx, c.Ecosystem, c.Name, c.CPE)
			if err != nil {
				return err
			}
			if pid == 0 {
				skipped = append(skipped, label+": product not found in catalog")
				continue
			}
			var itemID int64
			err = tx.QueryRow(r.Context(), `INSERT INTO stack_items (stack_id, product_id, version) VALUES ($1,$2,$3)
				ON CONFLICT (stack_id, product_id, version) DO NOTHING RETURNING id`, id, pid, version.Normalize(c.Version)).Scan(&itemID)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			added++
			n++
			itemIDs = append(itemIDs, itemID)
		}
		return s.rematch(r, tx, id)
	})
	if err != nil {
		s.internal(w, r, err)
		return
	}
	items := []itemOut{}
	if len(itemIDs) > 0 {
		rows, err := s.Pool.Query(r.Context(), `SELECT i.id, i.version, p.id, p.vendor, p.name, p.ecosystem, p.cpe, p.purl, p.aliases, p.cve_count
			FROM stack_items i JOIN products p ON p.id = i.product_id WHERE i.id = ANY($1) ORDER BY lower(p.name)`, itemIDs)
		if err == nil {
			items, _ = pgx.CollectRows(rows, func(r pgx.CollectableRow) (itemOut, error) {
				var it itemOut
				p := &it.Product
				err := r.Scan(&it.ID, &it.Version, &p.ID, &p.Vendor, &p.Name, &p.Ecosystem, &p.CPE, &p.PURL, &p.Aliases, &p.CVECount)
				if it.Version == "" {
					it.Version = "*"
				}
				return it, err
			})
		}
	}
	writeJSON(w, 200, map[string]any{"format": res.Format, "added": added, "skipped": skipped, "items": items})
}

type stackCVE struct {
	cvedb.CVE
	Reason    string    `json:"reason"`
	Confirmed bool      `json:"confirmed"`
	Status    string    `json:"status"`
	MatchedAt time.Time `json:"matched_at"`
}

// StackCVEs is shared with the MCP server.
func (s *Server) StackCVEs(r *http.Request, stackID int64, includeResolved bool, minCVSS *float64) ([]stackCVE, error) {
	q := `SELECT ` + cvedb.SelectCols + `, m.reason, m.confirmed, coalesce(x.status, 'open'), m.created_at
		FROM matches m JOIN cves c ON c.id = m.cve_id ` + cvedb.AIJoin + `
		LEFT JOIN stack_cve_status x ON x.stack_id = m.stack_id AND x.cve_id = m.cve_id
		WHERE m.stack_id = $1 AND c.state <> 'REJECTED'`
	args := []any{stackID}
	if !includeResolved {
		q += ` AND x.status IS NULL`
	}
	if minCVSS != nil {
		args = append(args, *minCVSS)
		q += ` AND c.cvss >= $2`
	}
	q += ` ORDER BY (x.status IS NULL) DESC, c.kev DESC, c.cvss DESC NULLS LAST, c.published DESC NULLS LAST LIMIT 5000`
	rows, err := s.Pool.Query(r.Context(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []stackCVE{}
	for rows.Next() {
		var c stackCVE
		if err := cvedb.ScanFull(rows, &c.CVE, &c.Reason, &c.Confirmed, &c.Status, &c.MatchedAt); err != nil {
			return nil, err
		}
		c.References, c.Sources = nil, nil
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Server) stackCVEs(w http.ResponseWriter, r *http.Request) {
	id, ok := s.stackParam(w, r)
	if !ok {
		return
	}
	incl := r.URL.Query().Get("include_resolved")
	list, err := s.StackCVEs(r, id, incl == "true" || incl == "1", queryFloat(r, "min_cvss"))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (s *Server) setCVEStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := s.stackParam(w, r)
	if !ok {
		return
	}
	cve := strings.ToUpper(r.PathValue("cve"))
	var in struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if !decode(w, r, &in) {
		return
	}
	var err error
	switch in.Status {
	case "open":
		_, err = s.Pool.Exec(r.Context(), `DELETE FROM stack_cve_status WHERE stack_id=$1 AND cve_id=$2`, id, cve)
	case "not_affected", "patched":
		_, err = s.Pool.Exec(r.Context(), `INSERT INTO stack_cve_status (stack_id, cve_id, status, note) VALUES ($1,$2,$3,NULLIF($4,''))
			ON CONFLICT (stack_id, cve_id) DO UPDATE SET status=$3, note=NULLIF($4,''), updated_at=now()`, id, cve, in.Status, in.Note)
		if err == nil {
			// assessed CVEs don't notify anymore: drop queued messages
			_, err = s.Pool.Exec(r.Context(), `UPDATE deliveries SET status='suppressed' WHERE stack_id=$1 AND cve_id=$2 AND status IN ('pending','digest')`, id, cve)
		}
	default:
		writeErr(w, http.StatusBadRequest, "status must be open, not_affected or patched")
		return
	}
	if err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			writeErr(w, http.StatusNotFound, "unknown CVE")
			return
		}
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
