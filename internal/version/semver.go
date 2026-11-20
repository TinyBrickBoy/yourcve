package version

import (
	"strings"
)

type semver struct {
	nums []string // numeric core components, leading zeros stripped
	pre  []string // prerelease identifiers, nil if none
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func trimZeros(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// cmpNumStr compares two non-negative decimal strings of arbitrary length.
func cmpNumStr(a, b string) int {
	a, b = trimZeros(a), trimZeros(b)
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return sign(strings.Compare(a, b))
}

// parseSemVer is tolerant: optional leading "v", 1..n numeric core
// components ("1.24" == "1.24.0"), optional "-prerelease", optional
// "+build" (ignored, e.g. Go's "+incompatible").
func parseSemVer(s string) (semver, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 1 && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) == 0 {
		return semver{}, false
	}
	var v semver
	for _, p := range parts {
		if !isDigits(p) {
			return semver{}, false
		}
		v.nums = append(v.nums, trimZeros(p))
	}
	if hasPre {
		if pre == "" {
			return semver{}, false
		}
		for _, id := range strings.Split(pre, ".") {
			if id == "" {
				return semver{}, false
			}
			for i := 0; i < len(id); i++ {
				c := id[i]
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
					return semver{}, false
				}
			}
			v.pre = append(v.pre, id)
		}
	}
	return v, true
}

func compareSemVer(a, b string) int {
	va, oka := parseSemVer(a)
	vb, okb := parseSemVer(b)
	if !oka || !okb {
		return compareGeneric(a, b)
	}
	n := max(len(va.nums), len(vb.nums))
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(va.nums) {
			x = va.nums[i]
		}
		if i < len(vb.nums) {
			y = vb.nums[i]
		}
		if c := cmpNumStr(x, y); c != 0 {
			return c
		}
	}
	switch {
	case va.pre == nil && vb.pre == nil:
		return 0
	case va.pre == nil:
		return 1
	case vb.pre == nil:
		return -1
	}
	for i := 0; i < len(va.pre) && i < len(vb.pre); i++ {
		x, y := va.pre[i], vb.pre[i]
		xn, yn := isDigits(x), isDigits(y)
		var c int
		switch {
		case xn && yn:
			c = cmpNumStr(x, y)
		case xn:
			c = -1
		case yn:
			c = 1
		default:
			c = sign(strings.Compare(x, y))
		}
		if c != 0 {
			return c
		}
	}
	return sign(len(va.pre) - len(vb.pre))
}
