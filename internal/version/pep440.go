package version

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

var pep440Re = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d+)?)?` +
	`(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d+)?))?` +
	`(?:[-_.]?(dev)[-_.]?(\d+)?)?` +
	`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

type pep440 struct {
	epoch   int64
	release []string
	pre     [2]int64 // phase, number; phase math.MaxInt64 = none, MinInt64 = dev-only
	post    int64    // MinInt64 = none
	dev     int64    // MaxInt64 = none
}

func atoi64(s string) int64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return math.MaxInt64 - 1
	}
	return n
}

func parsePEP440(s string) (pep440, bool) {
	m := pep440Re.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pep440{}, false
	}
	var v pep440
	v.epoch = atoi64(m[1])
	rel := strings.Split(m[2], ".")
	for len(rel) > 1 && trimZeros(rel[len(rel)-1]) == "0" {
		rel = rel[:len(rel)-1]
	}
	for _, r := range rel {
		v.release = append(v.release, trimZeros(r))
	}
	v.post = math.MinInt64
	if m[5] != "" {
		v.post = atoi64(m[5])
	} else if m[6] != "" {
		v.post = atoi64(m[7])
	}
	v.dev = math.MaxInt64
	if m[8] != "" {
		v.dev = atoi64(m[9])
	}
	switch m[3] {
	case "":
		if v.dev != math.MaxInt64 && v.post == math.MinInt64 {
			v.pre = [2]int64{math.MinInt64, 0}
		} else {
			v.pre = [2]int64{math.MaxInt64, 0}
		}
	case "a", "alpha":
		v.pre = [2]int64{0, atoi64(m[4])}
	case "b", "beta":
		v.pre = [2]int64{1, atoi64(m[4])}
	default: // c, rc, pre, preview
		v.pre = [2]int64{2, atoi64(m[4])}
	}
	return v, true
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func comparePEP440(a, b string) int {
	va, oka := parsePEP440(a)
	vb, okb := parsePEP440(b)
	if !oka || !okb {
		return compareGeneric(a, b)
	}
	if c := cmpInt(va.epoch, vb.epoch); c != 0 {
		return c
	}
	n := max(len(va.release), len(vb.release))
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(va.release) {
			x = va.release[i]
		}
		if i < len(vb.release) {
			y = vb.release[i]
		}
		if c := cmpNumStr(x, y); c != 0 {
			return c
		}
	}
	if c := cmpInt(va.pre[0], vb.pre[0]); c != 0 {
		return c
	}
	if c := cmpInt(va.pre[1], vb.pre[1]); c != 0 {
		return c
	}
	if c := cmpInt(va.post, vb.post); c != 0 {
		return c
	}
	return cmpInt(va.dev, vb.dev)
}
