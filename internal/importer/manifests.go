package importer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/tinybrickboy/yourcve/internal/version"
)

// ---- package.json ----

func npmVersion(spec string) string {
	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, ":") || strings.Contains(spec, "/") {
		// workspace:*, file:, link:, npm: aliases, git URLs, github shorthand
		return ""
	}
	return version.Normalize(spec)
}

func parsePackageJSON(data []byte, res *Result) ([]Component, error) {
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}
	var out []Component
	for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		raw, ok := pkg[section]
		if !ok {
			continue
		}
		var deps map[string]any
		if err := json.Unmarshal(raw, &deps); err != nil {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: not an object", section))
			continue
		}
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			spec, ok := deps[n].(string)
			name := strings.TrimSpace(n)
			if !ok || name == "" {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %q has an invalid version", section, n))
				continue
			}
			out = append(out, Component{
				Ecosystem: "npm",
				Name:      name,
				Version:   npmVersion(spec),
				PURL:      PURLFor("npm", name),
			})
		}
	}
	return out, nil
}

// ---- go.mod ----

func parseGoMod(data []byte, res *Result) ([]Component, error) {
	var out []Component
	block := "" // current block directive, e.g. "require", "replace"
	add := func(fields []string, line string) {
		if len(fields) < 2 {
			res.Skipped = append(res.Skipped, "go.mod: cannot parse "+strconvQuote(line))
			return
		}
		mod := strings.Trim(fields[0], "\"`")
		ver := strings.Trim(fields[1], "\"`")
		if mod == "" {
			return
		}
		out = append(out, Component{
			Ecosystem: "Go",
			Name:      mod,
			Version:   version.Normalize(ver),
			PURL:      PURLFor("Go", mod),
		})
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := raw
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if block != "" {
			if line == ")" {
				block = ""
				continue
			}
			if block == "require" {
				add(strings.Fields(line), line)
			}
			continue
		}
		f := strings.Fields(line)
		directive := f[0]
		if len(f) >= 2 && f[1] == "(" {
			block = directive
			continue
		}
		if strings.HasSuffix(directive, "(") { // "require("
			block = strings.TrimSuffix(directive, "(")
			continue
		}
		if directive == "require" {
			add(f[1:], line)
		}
	}
	return out, nil
}

func strconvQuote(s string) string { return fmt.Sprintf("%q", s) }

// ---- requirements.txt ----

var reqDirectRefRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?\s*@`)

var reqNameRe = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$`)

func parseRequirements(data []byte, res *Result) ([]Component, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\\\n", " ") // line continuations
	var out []Component
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.HasPrefix(line, "-") {
			res.Skipped = append(res.Skipped, "requirements: option line skipped: "+line)
			continue
		}
		// drop per-requirement options such as --hash=...
		if i := strings.Index(line, " --"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.Contains(line, "://") && !reqDirectRefRe.MatchString(line) ||
			strings.HasPrefix(line, ".") || strings.HasPrefix(line, "/") {
			res.Skipped = append(res.Skipped, "requirements: URL or path requirement skipped: "+line)
			continue
		}
		m := reqNameRe.FindStringSubmatch(line)
		if m == nil {
			res.Skipped = append(res.Skipped, "requirements: cannot parse: "+line)
			continue
		}
		name := NormalizePyPIName(m[1])
		spec := strings.TrimSpace(m[3])
		ver := ""
		switch {
		case strings.HasPrefix(spec, "@"):
			// direct reference "name @ https://..."
		case spec != "":
			ver = pinnedVersion(spec)
		}
		out = append(out, Component{Ecosystem: "PyPI", Name: name, Version: ver, PURL: PURLFor("PyPI", name)})
	}
	return out, nil
}

// pinnedVersion returns the version from an exact "==" / "===" specifier
// (without wildcards), else "".
func pinnedVersion(spec string) string {
	spec = strings.Trim(spec, "()")
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		var v string
		switch {
		case strings.HasPrefix(part, "==="):
			v = part[3:]
		case strings.HasPrefix(part, "=="):
			v = part[2:]
		default:
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" || strings.Contains(v, "*") {
			return ""
		}
		return version.Normalize(v)
	}
	return ""
}
