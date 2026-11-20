package importer

import (
	"net/url"
	"strings"
)

// ParsePURL parses a package URL ("pkg:type/namespace/name@version?qualifiers#subpath").
// Namespace and name are percent-decoded; namespace may contain "/".
// Qualifiers and subpath are dropped. ok is false when p is not a purl
// with at least a type and a name.
func ParsePURL(p string) (typ, namespace, name, version string, ok bool) {
	p = strings.TrimSpace(p)
	if len(p) < 4 || !strings.EqualFold(p[:4], "pkg:") {
		return "", "", "", "", false
	}
	rest := strings.TrimLeft(p[4:], "/")
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", "", "", "", false
	}
	typ = strings.ToLower(rest[:slash])
	rest = strings.Trim(rest[slash+1:], "/")
	last := strings.LastIndexByte(rest, '/')
	if at := strings.LastIndexByte(rest, '@'); at > last {
		version = unescape(rest[at+1:])
		rest = rest[:at]
	}
	segs := strings.Split(rest, "/")
	var clean []string
	for _, s := range segs {
		if s != "" {
			clean = append(clean, unescape(s))
		}
	}
	if len(clean) == 0 || typ == "" {
		return "", "", "", "", false
	}
	name = clean[len(clean)-1]
	namespace = strings.Join(clean[:len(clean)-1], "/")
	if name == "" {
		return "", "", "", "", false
	}
	return typ, namespace, name, version, true
}

func unescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// escapeSeg percent-encodes a purl path segment (everything except
// unreserved characters).
func escapeSeg(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlnum(c) || c == '.' || c == '-' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// buildPURL assembles "pkg:type/ns.../name" (no version, no qualifiers).
func buildPURL(typ, namespace, name string) string {
	if typ == "" || name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	for _, s := range strings.Split(namespace, "/") {
		if s != "" {
			b.WriteByte('/')
			b.WriteString(escapeSeg(s))
		}
	}
	b.WriteByte('/')
	b.WriteString(escapeSeg(name))
	return b.String()
}

// ecosystemBase strips an OSV ecosystem suffix ("Debian:12" -> "Debian").
func ecosystemBase(eco string) string {
	eco = strings.TrimSpace(eco)
	if i := strings.IndexByte(eco, ':'); i >= 0 {
		eco = eco[:i]
	}
	return eco
}

// PURLFor returns the versionless purl for a package in an OSV ecosystem,
// e.g. PURLFor("npm", "@scope/pkg") == "pkg:npm/%40scope/pkg",
// PURLFor("Maven", "org.apache:commons") == "pkg:maven/org.apache/commons".
// It returns "" for unknown ecosystems or names that do not fit the
// ecosystem (e.g. a Maven name without "group:").
func PURLFor(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	splitLast := func(n string) (string, string) {
		n = strings.Trim(n, "/")
		if i := strings.LastIndexByte(n, '/'); i >= 0 {
			return n[:i], n[i+1:]
		}
		return "", n
	}
	switch strings.ToLower(ecosystemBase(ecosystem)) {
	case "npm":
		ns, n := splitLast(name)
		return buildPURL("npm", ns, n)
	case "go":
		ns, n := splitLast(name)
		return buildPURL("golang", ns, n)
	case "pypi":
		return buildPURL("pypi", "", NormalizePyPIName(name))
	case "maven":
		g, a, ok := strings.Cut(name, ":")
		if !ok || g == "" || a == "" {
			return ""
		}
		return buildPURL("maven", g, a)
	case "crates.io":
		return buildPURL("cargo", "", name)
	case "nuget":
		return buildPURL("nuget", "", name)
	case "packagist":
		ns, n := splitLast(name)
		return buildPURL("composer", ns, n)
	case "rubygems":
		return buildPURL("gem", "", name)
	case "hex":
		return buildPURL("hex", "", name)
	case "pub":
		return buildPURL("pub", "", name)
	case "debian":
		return buildPURL("deb", "debian", name)
	case "alpine":
		return buildPURL("apk", "alpine", name)
	}
	return ""
}

// ecosystemForPURLType maps a purl type to an OSV ecosystem ("" if unknown).
func ecosystemForPURLType(typ string) string {
	switch typ {
	case "npm":
		return "npm"
	case "golang":
		return "Go"
	case "pypi":
		return "PyPI"
	case "maven":
		return "Maven"
	case "cargo":
		return "crates.io"
	case "nuget":
		return "NuGet"
	case "composer":
		return "Packagist"
	case "gem":
		return "RubyGems"
	case "deb":
		return "Debian"
	case "apk":
		return "Alpine"
	case "hex":
		return "Hex"
	case "pub":
		return "Pub"
	}
	return ""
}

// NormalizePyPIName normalizes a Python package name per PEP 503:
// lowercase, runs of "-", "_" and "." replaced by a single "-".
func NormalizePyPIName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	var b strings.Builder
	sep := false
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c == '-' || c == '_' || c == '.' {
			sep = true
			continue
		}
		if sep && b.Len() > 0 {
			b.WriteByte('-')
		}
		sep = false
		b.WriteByte(c)
	}
	return b.String()
}

// componentFromPURL builds a component from a purl. ok is false if the purl
// cannot be parsed.
func componentFromPURL(p string) (c Component, ok bool) {
	typ, ns, name, ver, ok := ParsePURL(p)
	if !ok {
		return Component{}, false
	}
	c.Ecosystem = ecosystemForPURLType(typ)
	c.Version = ver
	switch typ {
	case "npm":
		if ns != "" {
			if !strings.HasPrefix(ns, "@") {
				ns = "@" + ns
			}
			c.Name = ns + "/" + name
		} else {
			c.Name = name
		}
	case "golang", "composer":
		if ns != "" {
			c.Name = ns + "/" + name
		} else {
			c.Name = name
		}
	case "maven":
		if ns != "" {
			c.Name = ns + ":" + name
		} else {
			c.Name = name
		}
	case "pypi":
		c.Name = NormalizePyPIName(name)
	default:
		c.Name = name
	}
	switch typ {
	case "deb", "apk", "rpm":
		// keep the distro namespace from the SBOM
		c.PURL = buildPURL(typ, ns, name)
	default:
		if c.Ecosystem != "" {
			c.PURL = PURLFor(c.Ecosystem, c.Name)
		}
		if c.PURL == "" {
			c.PURL = buildPURL(typ, ns, name)
		}
	}
	return c, true
}

// cpePrefix reduces a CPE 2.3 (or 2.2 URI) string to
// "cpe:2.3:<part>:<vendor>:<product>". It returns "" if vendor or product
// is missing or a wildcard.
func cpePrefix(cpe string) string {
	cpe = strings.TrimSpace(cpe)
	var fields []string
	switch {
	case strings.HasPrefix(strings.ToLower(cpe), "cpe:2.3:"):
		fields = splitCPE(cpe[len("cpe:2.3:"):])
	case strings.HasPrefix(strings.ToLower(cpe), "cpe:/"):
		fields = strings.Split(cpe[len("cpe:/"):], ":")
		for i := range fields {
			fields[i] = unescape(fields[i])
		}
	default:
		return ""
	}
	if len(fields) < 3 {
		return ""
	}
	part, vendor, product := strings.ToLower(fields[0]), strings.ToLower(fields[1]), strings.ToLower(fields[2])
	if part == "" || part == "*" {
		part = "a"
	}
	if vendor == "" || vendor == "*" || vendor == "-" || product == "" || product == "*" || product == "-" {
		return ""
	}
	return "cpe:2.3:" + part + ":" + vendor + ":" + product
}

// splitCPE splits on ':' honouring backslash escapes (kept in output).
func splitCPE(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if c == ':' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	return append(out, cur.String())
}
