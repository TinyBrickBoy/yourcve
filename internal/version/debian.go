package version

import "strings"

// parseDebian splits a Debian version into epoch, upstream and revision.
func parseDebian(s string) (epoch, upstream, revision string) {
	epoch = "0"
	if i := strings.IndexByte(s, ':'); i >= 0 && isDigits(s[:i]) {
		epoch, s = s[:i], s[i+1:]
	}
	upstream = s
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		upstream, revision = s[:i], s[i+1:]
	}
	return
}

func debOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// verrevcmp is dpkg's version segment comparison.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) && !isDigit(a[i]) {
				ac = debOrder(a[i])
			}
			if j < len(b) && !isDigit(b[j]) {
				bc = debOrder(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			if i < len(a) && !isDigit(a[i]) {
				i++
			}
			if j < len(b) && !isDigit(b[j]) {
				j++
			}
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func compareDebian(a, b string) int {
	if a == "" || b == "" {
		return compareGeneric(a, b)
	}
	ea, ua, ra := parseDebian(a)
	eb, ub, rb := parseDebian(b)
	if c := cmpNumStr(ea, eb); c != 0 {
		return c
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}
