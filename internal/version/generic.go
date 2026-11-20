package version

import "strings"

type genSeg struct {
	s   string
	num bool
}

// splitGeneric splits a version into alternating numeric and alphabetic
// segments, using any non-alphanumeric character as a separator.
func splitGeneric(v string) []genSeg {
	v = strings.ToLower(v)
	var segs []genSeg
	i := 0
	for i < len(v) {
		c := v[i]
		switch {
		case isDigit(c):
			j := i
			for j < len(v) && isDigit(v[j]) {
				j++
			}
			segs = append(segs, genSeg{s: v[i:j], num: true})
			i = j
		case isAlpha(c):
			j := i
			for j < len(v) && isAlpha(v[j]) {
				j++
			}
			segs = append(segs, genSeg{s: v[i:j]})
			i = j
		default:
			i++
		}
	}
	return segs
}

// preRank returns the ordering rank of common prerelease words (all of
// which sort below a missing segment), or -1 if w is not one.
func preRank(w string) int {
	switch w {
	case "dev", "snapshot", "nightly":
		return 0
	case "alpha":
		return 1
	case "beta":
		return 2
	case "pre", "preview", "milestone":
		return 3
	case "rc", "cr":
		return 4
	}
	return -1
}

// compareGeneric compares numeric segments numerically and alphabetic
// segments lexically. Prerelease words sort below a missing segment and
// below numbers; other words sort above a missing segment but below
// numbers. A missing segment equals a numeric zero ("1.2" == "1.2.0").
func compareGeneric(a, b string) int {
	sa, sb := splitGeneric(a), splitGeneric(b)
	if len(sa) == 0 && len(sb) == 0 {
		return sign(strings.Compare(a, b))
	}
	n := max(len(sa), len(sb))
	for i := 0; i < n; i++ {
		var x, y *genSeg
		if i < len(sa) {
			x = &sa[i]
		}
		if i < len(sb) {
			y = &sb[i]
		}
		if c := cmpGenSeg(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func cmpGenSeg(x, y *genSeg) int {
	switch {
	case x == nil && y == nil:
		return 0
	case x == nil:
		return -cmpGenSeg(y, x)
	case y == nil:
		if x.num {
			if trimZeros(x.s) == "0" {
				return 0
			}
			return 1
		}
		if preRank(x.s) >= 0 {
			return -1
		}
		return 1
	}
	switch {
	case x.num && y.num:
		return cmpNumStr(x.s, y.s)
	case x.num:
		return 1
	case y.num:
		return -1
	}
	rx, ry := preRank(x.s), preRank(y.s)
	switch {
	case rx >= 0 && ry >= 0:
		if rx != ry {
			return sign(rx - ry)
		}
		return 0 // synonyms such as "pre"/"preview"
	case rx >= 0:
		return -1
	case ry >= 0:
		return 1
	}
	return sign(strings.Compare(x.s, y.s))
}
