// Package version implements version comparison for several versioning
// schemes (SemVer, Debian dpkg, RPM, PEP 440 and a generic fallback) and
// range containment checks used for CVE matching.
package version

import (
	"strings"
)

// Scheme identifies a version comparison algorithm.
type Scheme string

const (
	SemVer  Scheme = "semver"
	Debian  Scheme = "deb"
	RPM     Scheme = "rpm"
	PEP440  Scheme = "pep440"
	Generic Scheme = "generic"
)

// SchemeForEcosystem maps an OSV ecosystem name (optionally with a ":suffix"
// such as "Debian:12") to a comparison scheme. Matching is case-insensitive.
// Unknown ecosystems, "cpe" and "" map to Generic.
func SchemeForEcosystem(eco string) Scheme {
	base := strings.TrimSpace(eco)
	if i := strings.IndexByte(base, ':'); i >= 0 {
		base = base[:i]
	}
	switch strings.ToLower(strings.TrimSpace(base)) {
	case "npm", "go", "golang", "crates.io", "cargo", "packagist", "nuget", "hex", "pub":
		return SemVer
	case "debian", "ubuntu":
		return Debian
	case "red hat", "redhat", "almalinux", "rocky linux", "rocky", "opensuse", "suse", "suse linux enterprise", "fedora", "centos", "oracle linux", "mageia":
		return RPM
	case "pypi":
		return PEP440
	default:
		return Generic
	}
}

// Compare compares a and b according to scheme s and returns -1, 0 or 1.
// It never panics; input that cannot be parsed by the requested scheme is
// compared with the Generic algorithm. Unknown schemes use Generic.
func Compare(s Scheme, a, b string) (res int) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == b {
		return 0
	}
	defer func() {
		if r := recover(); r != nil {
			res = compareGenericSafe(a, b)
		}
	}()
	switch s {
	case SemVer:
		return compareSemVer(a, b)
	case Debian:
		return compareDebian(a, b)
	case RPM:
		return compareRPM(a, b)
	case PEP440:
		return comparePEP440(a, b)
	default:
		return compareGeneric(a, b)
	}
}

func compareGenericSafe(a, b string) (res int) {
	defer func() {
		if r := recover(); r != nil {
			res = sign(strings.Compare(a, b))
		}
	}()
	return compareGeneric(a, b)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// Range is one affected range. Empty strings mean unbounded. Versions is a
// list of exact affected versions.
type Range struct {
	StartIncluding string   `json:"start_including,omitempty"`
	StartExcluding string   `json:"start_excluding,omitempty"`
	EndIncluding   string   `json:"end_including,omitempty"`
	EndExcluding   string   `json:"end_excluding,omitempty"`
	Versions       []string `json:"versions,omitempty"`
}

func (r Range) hasBounds() bool {
	return strings.TrimSpace(r.StartIncluding) != "" || strings.TrimSpace(r.StartExcluding) != "" ||
		strings.TrimSpace(r.EndIncluding) != "" || strings.TrimSpace(r.EndExcluding) != ""
}

// IsEmpty reports whether the range has neither bounds nor exact versions
// (and therefore contains nothing).
func (r Range) IsEmpty() bool {
	if r.hasBounds() {
		return false
	}
	for _, v := range r.Versions {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}

// Contains reports whether version v is inside the range under scheme s.
//
//   - A range with no bounds and no Versions contains nothing.
//   - v == "" (caller wants all versions) matches every non-empty range.
//   - v matching any entry of Versions (Compare == 0) is contained.
//   - Otherwise, if bounds are set, v must satisfy all of them. A
//     StartIncluding of "0" is treated as unbounded (OSV convention).
func (r Range) Contains(s Scheme, v string) bool {
	if r.IsEmpty() {
		return false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	for _, x := range r.Versions {
		if strings.TrimSpace(x) != "" && Compare(s, v, x) == 0 {
			return true
		}
	}
	if !r.hasBounds() {
		return false
	}
	if si := strings.TrimSpace(r.StartIncluding); si != "" && si != "0" {
		if Compare(s, v, si) < 0 {
			return false
		}
	}
	if se := strings.TrimSpace(r.StartExcluding); se != "" {
		if Compare(s, v, se) <= 0 {
			return false
		}
	}
	if ei := strings.TrimSpace(r.EndIncluding); ei != "" {
		if Compare(s, v, ei) > 0 {
			return false
		}
	}
	if ee := strings.TrimSpace(r.EndExcluding); ee != "" {
		if Compare(s, v, ee) >= 0 {
			return false
		}
	}
	return true
}

// IsAll reports whether v means "all versions": "", "*", "all", "any", "-".
func IsAll(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "*", "all", "any", "-":
		return true
	}
	return false
}

// Normalize cleans user or manifest input into a concrete version string.
// It trims whitespace, takes the first alternative of "||" ranges, strips
// range operators (^ ~ >= <= > < = == ~= !=) and takes the first concrete
// version, strips a leading "v"/"V" followed by a digit, and returns "" for
// wildcards ("*", "x", "latest", "all", "any") or versions containing a
// wildcard segment such as "1.2.x".
func Normalize(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "||"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.TrimLeft(v, "^~>=<!= \t")
	if f := strings.Fields(v); len(f) > 0 {
		v = f[0]
	} else {
		return ""
	}
	// "1.0,<2" style (PEP 440 compound specifiers)
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	switch strings.ToLower(v) {
	case "", "*", "x", "latest", "all", "any", "-":
		return ""
	}
	core := v
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	for _, seg := range strings.Split(core, ".") {
		if seg == "*" || seg == "x" || seg == "X" {
			return ""
		}
	}
	return v
}
