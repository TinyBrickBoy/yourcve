package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tinybrickboy/yourcve/internal/cvedb"
)

// MCPHandler serves the MCP endpoint (Streamable HTTP, stateless). Every
// request gets a server bound to the API key's user. All tools are read-only,
// so the AI can't change settings.
func (s *Server) MCPHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		if userFrom(r.Context()) == nil {
			return nil
		}
		return s.newMCPServer(r)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
}

type searchIn struct {
	Query    string   `json:"query,omitempty" jsonschema:"full text query or CVE id, e.g. 'openssl buffer overflow'"`
	Severity []string `json:"severity,omitempty" jsonschema:"allowed severities: low, medium, high, critical"`
	KEV      *bool    `json:"kev,omitempty" jsonschema:"only CVEs in the CISA KEV catalog (actively exploited)"`
	MinCVSS  *float64 `json:"min_cvss,omitempty" jsonschema:"minimum CVSS base score 0-10"`
	Since    string   `json:"since,omitempty" jsonschema:"published on or after this date (YYYY-MM-DD)"`
	Limit    int      `json:"limit,omitempty" jsonschema:"max results (default 10, max 50)"`
}

type idIn struct {
	ID string `json:"id" jsonschema:"CVE id, e.g. CVE-2024-6387"`
}

type semanticIn struct {
	Query   string `json:"query" jsonschema:"natural language description of the vulnerability"`
	StackID int64  `json:"stack_id,omitempty" jsonschema:"optional: only CVEs affecting this stack"`
	Limit   int    `json:"limit,omitempty" jsonschema:"max results (default 10)"`
}

type stackIn struct {
	StackID         int64    `json:"stack_id,omitempty" jsonschema:"stack id from list_stacks"`
	StackName       string   `json:"stack_name,omitempty" jsonschema:"alternatively the stack name (case insensitive)"`
	MinCVSS         *float64 `json:"min_cvss,omitempty" jsonschema:"minimum CVSS score, e.g. 9 for critical"`
	Severity        []string `json:"severity,omitempty" jsonschema:"filter by severity: low, medium, high, critical"`
	KEVOnly         bool     `json:"kev_only,omitempty" jsonschema:"only actively exploited CVEs"`
	IncludeResolved bool     `json:"include_resolved,omitempty" jsonschema:"include CVEs marked not_affected or patched"`
	Limit           int      `json:"limit,omitempty" jsonschema:"max results (default 50)"`
}

type noIn struct{}

type mcpCVE struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	CVSS        *float64 `json:"cvss"`
	KEV         bool     `json:"kev"`
	EPSS        *float64 `json:"epss,omitempty"`
	Published   string   `json:"published,omitempty"`
	Description string   `json:"description"`
	Summary     string   `json:"ai_summary,omitempty"`
	Category    string   `json:"ai_category,omitempty"`
	Reason      string   `json:"match_reason,omitempty"`
	Status      string   `json:"status,omitempty"`
	Unconfirmed bool     `json:"unconfirmed_match,omitempty"`
}

func toMCP(c cvedb.CVE, descLen int) mcpCVE {
	m := mcpCVE{ID: c.ID, Severity: c.Severity, CVSS: c.CVSS, KEV: c.KEV, EPSS: c.EPSS, Description: shorten(c.Description, descLen)}
	if c.Published != nil {
		m.Published = c.Published.Format("2006-01-02")
	}
	if c.Summary != nil {
		m.Summary = *c.Summary
	}
	if c.Category != nil {
		m.Category = *c.Category
	}
	return m
}

func shorten(s string, n int) string {
	if n <= 0 || len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func (s *Server) newMCPServer(r *http.Request) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "yourcve", Version: "1.0.0"}, &mcp.ServerOptions{
		Instructions: "yourcve knows CVEs (cvelistV5, NVD, OSV, CISA KEV, EPSS) and the user's tech stacks. " +
			"To answer which vulnerabilities affect the user, call list_stacks first, then cves_for_stack. " +
			"Facts like CVSS, KEV and versions come from the data; ai_summary fields are AI generated.",
	})
	u := userFrom(r.Context())
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true}

	mcp.AddTool(srv, &mcp.Tool{Name: "search_cves", Description: "Full text search over all CVEs with filters.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in searchIn) (*mcp.CallToolResult, any, error) {
			f := cvedb.Filter{Q: in.Query, Severity: in.Severity, KEV: in.KEV, MinCVSS: in.MinCVSS, Limit: in.Limit}
			if f.Limit <= 0 || f.Limit > 50 {
				f.Limit = 10
			}
			if in.Since != "" {
				if t := parseDate(in.Since); t != nil {
					f.Since = t
				}
			}
			items, total, err := s.CVEs.Search(ctx, f)
			if err != nil {
				return nil, nil, err
			}
			out := make([]mcpCVE, 0, len(items))
			for _, c := range items {
				out = append(out, toMCP(c, 400))
			}
			return nil, map[string]any{"total": total, "items": out}, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "get_cve", Description: "Details of one CVE: scores, KEV, EPSS, affected products and versions, references.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in idIn) (*mcp.CallToolResult, any, error) {
			return s.mcpCVEDetail(ctx, u.ID, in.ID)
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "explain_cve", Description: "Explain a CVE for the user: plain summary, why it matters, which of the user's stacks it affects and why.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in idIn) (*mcp.CallToolResult, any, error) {
			return s.mcpCVEDetail(ctx, u.ID, in.ID)
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "list_stacks", Description: "The user's tech stacks with product counts and open/critical CVE counts.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noIn) (*mcp.CallToolResult, any, error) {
			rows, err := s.Pool.Query(ctx, stackSelect+` WHERE s.user_id=$1 ORDER BY s.id`, u.ID)
			if err != nil {
				return nil, nil, err
			}
			list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (stackOut, error) { return scanStack(r) })
			if err != nil {
				return nil, nil, err
			}
			type item struct {
				ID       int64    `json:"id"`
				Name     string   `json:"name"`
				Products []string `json:"products"`
				Open     int      `json:"open_cves"`
				Critical int      `json:"critical_cves"`
			}
			out := []item{}
			for _, st := range list {
				prows, err := s.Pool.Query(ctx, `SELECT p.name || CASE WHEN i.version = '' THEN '' ELSE ' ' || i.version END
					FROM stack_items i JOIN products p ON p.id = i.product_id WHERE i.stack_id=$1 ORDER BY 1 LIMIT 200`, st.ID)
				if err != nil {
					return nil, nil, err
				}
				prods, _ := pgx.CollectRows(prows, pgx.RowTo[string])
				out = append(out, item{st.ID, st.Name, prods, st.OpenCVEs, st.CriticalCVEs})
			}
			return nil, map[string]any{"stacks": out}, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "cves_for_stack", Description: "CVEs affecting one of the user's stacks (by id or name), most severe first.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in stackIn) (*mcp.CallToolResult, any, error) {
			id := in.StackID
			if id == 0 && in.StackName != "" {
				err := s.Pool.QueryRow(ctx, `SELECT id FROM stacks WHERE user_id=$1 AND (lower(name)=lower($2) OR name ILIKE '%'||$2||'%')
					ORDER BY (lower(name)=lower($2)) DESC LIMIT 1`, u.ID, in.StackName).Scan(&id)
				if err != nil {
					return nil, nil, errors.New("no stack with this name; call list_stacks")
				}
			}
			if id == 0 || !s.ownsStack(r.WithContext(ctx), u.ID, id) {
				return nil, nil, errors.New("unknown stack; call list_stacks")
			}
			list, err := s.StackCVEs(r.WithContext(ctx), id, in.IncludeResolved, in.MinCVSS)
			if err != nil {
				return nil, nil, err
			}
			limit := in.Limit
			if limit <= 0 || limit > 200 {
				limit = 50
			}
			out := []mcpCVE{}
			for _, c := range list {
				if in.KEVOnly && !c.KEV {
					continue
				}
				if len(in.Severity) > 0 && !containsFold(in.Severity, c.Severity) {
					continue
				}
				m := toMCP(c.CVE, 300)
				m.Reason, m.Status, m.Unconfirmed = c.Reason, c.Status, !c.Confirmed
				out = append(out, m)
				if len(out) >= limit {
					break
				}
			}
			return nil, map[string]any{"stack_id": id, "count": len(out), "cves": out}, nil
		})

	if s.AI != nil {
		mcp.AddTool(srv, &mcp.Tool{Name: "semantic_search", Description: "Semantic (meaning based) CVE search, optionally limited to a stack.", Annotations: ro},
			func(ctx context.Context, _ *mcp.CallToolRequest, in semanticIn) (*mcp.CallToolResult, any, error) {
				if in.StackID > 0 && !s.ownsStack(r.WithContext(ctx), u.ID, in.StackID) {
					return nil, nil, errors.New("unknown stack")
				}
				if in.Limit <= 0 || in.Limit > 50 {
					in.Limit = 10
				}
				items, err := s.SemanticItems(r.WithContext(ctx), in.Query, in.StackID, in.Limit)
				if err != nil {
					return nil, nil, err
				}
				out := []mcpCVE{}
				for _, it := range items {
					out = append(out, toMCP(it.CVE, 300))
				}
				return nil, map[string]any{"items": out}, nil
			})
	}
	return srv
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func (s *Server) mcpCVEDetail(ctx context.Context, userID int64, id string) (*mcp.CallToolResult, any, error) {
	if !cvedb.ValidID(id) {
		return nil, nil, errors.New("invalid CVE id")
	}
	c, err := s.CVEs.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if c == nil {
		return nil, nil, errors.New("unknown CVE")
	}
	affects, err := s.CVEs.Affects(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	type aff struct {
		Product string `json:"product"`
		Range   string `json:"versions"`
		Source  string `json:"source"`
	}
	var af []aff
	for i, a := range affects {
		if i >= 50 {
			break
		}
		rg := ""
		if a.AllVersions {
			rg = "all versions"
		}
		if a.StartIncluding != nil {
			rg += ">=" + *a.StartIncluding + " "
		}
		if a.StartExcluding != nil {
			rg += ">" + *a.StartExcluding + " "
		}
		if a.EndIncluding != nil {
			rg += "<=" + *a.EndIncluding
		}
		if a.EndExcluding != nil {
			rg += "<" + *a.EndExcluding
		}
		if len(a.Versions) > 0 {
			rg += strings.Join(a.Versions[:min(len(a.Versions), 10)], ", ")
		}
		name := strings.TrimSpace(a.Product.Vendor + " " + a.Product.Name)
		af = append(af, aff{name, strings.TrimSpace(rg), a.Source})
	}
	rows, err := s.Pool.Query(ctx, `SELECT s.name, m.reason, coalesce(x.status,'open') FROM matches m JOIN stacks s ON s.id = m.stack_id
		LEFT JOIN stack_cve_status x ON x.stack_id = m.stack_id AND x.cve_id = m.cve_id
		WHERE m.cve_id = $1 AND s.user_id = $2`, c.ID, userID)
	if err != nil {
		return nil, nil, err
	}
	type hit struct {
		Stack  string `json:"stack"`
		Reason string `json:"reason"`
		Status string `json:"status"`
	}
	hits, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (hit, error) {
		var h hit
		err := r.Scan(&h.Stack, &h.Reason, &h.Status)
		return h, err
	})
	if err != nil {
		return nil, nil, err
	}
	out := map[string]any{
		"cve":                 toMCP(*c, 0),
		"title":               c.Title,
		"cwe":                 c.CWE,
		"cvss_vector":         c.CVSSVector,
		"kev_due":             c.KEVDue,
		"kev_required_action": c.KEVAction,
		"affected_products":   af,
		"your_stacks":         hits,
		"references":          c.References[:min(len(c.References), 15)],
		"url":                 s.Cfg.BaseURL + "/cves/" + c.ID,
	}
	return nil, out, nil
}
