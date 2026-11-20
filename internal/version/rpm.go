package version

import "strings"

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlnum(c byte) bool { return isAlpha(c) || isDigit(c) }

// rpmvercmp implements RPM's segment comparison including '~' (sorts before
// everything) and '^' (sorts after the base version but before any
// further segment).
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ca, cb := at(a, i), at(b, j)
		if ca == '~' || cb == '~' {
			if ca != '~' {
				return 1
			}
			if cb != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if ca == '^' || cb == '^' {
			if ca == 0 {
				return -1
			}
			if cb == 0 {
				return 1
			}
			if ca != '^' {
				return 1
			}
			if cb != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if ca == 0 || cb == 0 {
			break
		}
		si, sj := i, j
		isNum := isDigit(ca)
		if isNum {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		segA, segB := a[si:i], b[sj:j]
		if segB == "" {
			// segment types differ: numeric is newer than alpha
			if isNum {
				return 1
			}
			return -1
		}
		if isNum {
			if c := cmpNumStr(segA, segB); c != 0 {
				return c
			}
		} else if c := strings.Compare(segA, segB); c != 0 {
			return sign(c)
		}
	}
	ea, eb := i >= len(a), j >= len(b)
	switch {
	case ea && eb:
		return 0
	case ea:
		return -1
	default:
		return 1
	}
}

// parseRPM splits [epoch:]version[-release].
func parseRPM(s string) (epoch, ver, rel string) {
	epoch = "0"
	if i := strings.IndexByte(s, ':'); i >= 0 && isDigits(s[:i]) {
		epoch, s = s[:i], s[i+1:]
	}
	ver = s
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		ver, rel = s[:i], s[i+1:]
	}
	return
}

func compareRPM(a, b string) int {
	if a == "" || b == "" {
		return compareGeneric(a, b)
	}
	ea, va, ra := parseRPM(a)
	eb, vb, rb := parseRPM(b)
	if c := cmpNumStr(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	if ra == "" || rb == "" {
		// a missing release matches any release
		return 0
	}
	return rpmvercmp(ra, rb)
}
