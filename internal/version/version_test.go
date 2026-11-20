package version

import (
	"testing"
)

type cmpCase struct {
	a, b string
	want int
}

func runCompare(t *testing.T, s Scheme, cases []cmpCase) {
	t.Helper()
	for _, c := range cases {
		if got := Compare(s, c.a, c.b); got != c.want {
			t.Errorf("Compare(%s, %q, %q) = %d, want %d", s, c.a, c.b, got, c.want)
		}
		// antisymmetry
		if got := Compare(s, c.b, c.a); got != -c.want {
			t.Errorf("Compare(%s, %q, %q) = %d, want %d (reverse)", s, c.b, c.a, got, -c.want)
		}
	}
}

func TestSchemeForEcosystem(t *testing.T) {
	cases := map[string]Scheme{
		"npm": SemVer, "Go": SemVer, "crates.io": SemVer, "Packagist": SemVer, "NuGet": SemVer,
		"Hex": SemVer, "Pub": SemVer, "go": SemVer,
		"Debian": Debian, "Debian:12": Debian, "Ubuntu": Debian, "Ubuntu:22.04:LTS": Debian,
		"Red Hat": RPM, "AlmaLinux": RPM, "AlmaLinux:9": RPM, "Rocky Linux": RPM, "openSUSE": RPM, "SUSE": RPM,
		"PyPI": PEP440, "pypi": PEP440,
		"Maven": Generic, "RubyGems": Generic, "cpe": Generic, "": Generic, "Alpine": Generic, "weird": Generic,
	}
	for eco, want := range cases {
		if got := SchemeForEcosystem(eco); got != want {
			t.Errorf("SchemeForEcosystem(%q) = %q, want %q", eco, got, want)
		}
	}
}

func TestCompareSemVer(t *testing.T) {
	runCompare(t, SemVer, []cmpCase{
		{"1.0.0", "1.0.0", 0},
		{"1.24", "1.24.0", 0},
		{"1", "1.0.0", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.0", 1},
		{"2.0.0", "1.99.99", 1},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-beta.2", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-beta.11", "1.0.0-rc.1", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0+build.1", "1.0.0+build.2", 0},
		{"v2.0.0+incompatible", "2.0.0", 0},
		{"v2.1.0+incompatible", "v2.0.9", 1},
		// Go pseudo versions
		{"v0.0.0-20210101000000-abcdef123456", "v0.0.0-20220101000000-abcdef123456", -1},
		{"v0.0.0-20210101000000-abcdef123456", "v0.0.1", -1},
		{"v1.2.4-0.20210101000000-abcdef123456", "v1.2.3", 1},
		{"v1.2.4-0.20210101000000-abcdef123456", "v1.2.4", -1},
		{"1.2.3.4", "1.2.3", 1},
		{"18446744073709551616.0.0", "18446744073709551615.0.0", 1},
		// garbage falls back to generic
		{"1.2.3rc1", "1.2.3", -1},
		{"foo", "foo", 0},
		{"", "1.0.0", -1},
	})
}

func TestCompareDebian(t *testing.T) {
	runCompare(t, Debian, []cmpCase{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1:1.0", "2.0", 1},
		{"0:1.0", "1.0", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0+", -1},
		{"1.0+dfsg-1", "1.0-1", 1},
		{"2.4.58-1+deb12u1", "2.4.58-1", 1},
		{"2.4.58-1+deb12u1", "2.4.58-1+deb12u2", -1},
		{"1.10", "1.9", 1},
		{"1.001", "1.1", 0},
		{"7.88.1-10+deb12u5", "7.88.1-10+deb12u12", -1},
		{"1.2.3", "1.2.3-0", 0},
		{"3.0.11-1~deb12u2", "3.0.11-1", -1},
	})
}

func TestCompareRPM(t *testing.T) {
	runCompare(t, RPM, []cmpCase{
		{"1.0", "1.0", 0},
		{"1.0", "1.0.1", -1},
		{"1.0-1.el9", "1.0-2.el9", -1},
		{"1:1.0-1", "2.0-1", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.0.1", -1},
		{"1.0^git1", "1.0^git2", -1},
		{"1.0a", "1.0", 1},
		{"1.0a", "1.0.1", -1},
		{"2.0", "2_0", 0},
		{"1.010", "1.10", 0},
		{"5.14.0-362.8.1.el9_3", "5.14.0-362.13.1.el9_3", -1},
		{"1.0-1", "1.0", 0}, // missing release matches
		{"1.0a", "1.01", -1},
	})
}

func TestComparePEP440(t *testing.T) {
	runCompare(t, PEP440, []cmpCase{
		{"1.0", "1.0.0", 0},
		{"1.0.dev1", "1.0a1", -1},
		{"1.0a1", "1.0a2", -1},
		{"1.0a2", "1.0b1", -1},
		{"1.0b1", "1.0rc1", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0c1", "1.0rc1", 0},
		{"1.0", "1.0.post1", -1},
		{"1.0-1", "1.0.post1", 0},
		{"1.0.post1.dev1", "1.0.post1", -1},
		{"1.0.post1", "1.1.dev1", -1},
		{"1!0.5", "2.0", 1},
		{"1.0+local.1", "1.0", 0},
		{"v1.0", "1.0", 0},
		{"1.0a1.dev1", "1.0a1", -1},
		{"2.31.0", "2.4.0", 1},
		{"1.0.0RC1", "1.0.0rc1", 0},
		{"1.0-alpha-2", "1.0a2", 0},
		{"not a version", "1.0", -1},
	})
}

func TestCompareGeneric(t *testing.T) {
	runCompare(t, Generic, []cmpCase{
		{"1.2.0", "1.2.0rc1", 1},
		{"1.10", "1.9", 1},
		{"2.4.58", "2.4.9", 1},
		{"1.0.2k", "1.0.2j", 1},
		{"1.0.2", "1.0.2a", -1},
		{"1.0.2zh", "1.1.0", -1},
		{"1.2", "1.2.0", 0},
		{"1.2", "1.2.1", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-rc1", -1},
		{"1.0.0-dev", "1.0.0-alpha", -1},
		{"1.0.0-rc1", "1.0.0-rc2", -1},
		{"1.0.0-RC1", "1.0.0-rc1", 0},
		{"1.0-preview1", "1.0", -1},
		{"5.2.1.Final", "5.2.1", 1},
		{"8.0.36", "8.0.36-debian-12-r1", -1},
		{"1_2_3", "1.2.3", 0},
		{"abc", "abd", -1},
		{"", "0.1", -1},
		{"!!!", "???", -1},
		{"99999999999999999999999", "1", 1},
	})
	if got := Compare(Scheme("bogus"), "1.10", "1.9"); got != 1 {
		t.Errorf("unknown scheme should use generic, got %d", got)
	}
}

func TestCompareNeverPanics(t *testing.T) {
	inputs := []string{"", ":", "-", "~", "^", "1:", ":1", "1:-", "v", "+", "1..2", "1.-.2", "\x00\xff", "1!", "!1", "1-", "-1", "~~~^^^", "1.0+", "999999999999999999999999999999!1"}
	for _, s := range []Scheme{SemVer, Debian, RPM, PEP440, Generic} {
		for _, a := range inputs {
			for _, b := range inputs {
				c := Compare(s, a, b)
				if c < -1 || c > 1 {
					t.Fatalf("Compare(%s,%q,%q) = %d out of range", s, a, b, c)
				}
			}
		}
	}
}

func TestRangeContains(t *testing.T) {
	cases := []struct {
		name string
		r    Range
		s    Scheme
		v    string
		want bool
	}{
		{"empty range", Range{}, SemVer, "1.0.0", false},
		{"empty range all", Range{}, SemVer, "", false},
		{"empty versions entries", Range{Versions: []string{"", " "}}, SemVer, "", false},
		{"all versions nonempty", Range{EndExcluding: "2.0.0"}, SemVer, "", true},
		{"exact match", Range{Versions: []string{"1.0.0", "1.1.0"}}, SemVer, "1.1.0", true},
		{"exact match normalized", Range{Versions: []string{"1.1"}}, SemVer, "v1.1.0", true},
		{"exact no match", Range{Versions: []string{"1.0.0"}}, SemVer, "1.0.1", false},
		{"end excl inside", Range{StartIncluding: "1.0.0", EndExcluding: "1.2.0"}, SemVer, "1.1.9", true},
		{"end excl boundary", Range{StartIncluding: "1.0.0", EndExcluding: "1.2.0"}, SemVer, "1.2.0", false},
		{"start incl boundary", Range{StartIncluding: "1.0.0", EndExcluding: "1.2.0"}, SemVer, "1.0.0", true},
		{"below start", Range{StartIncluding: "1.0.0", EndExcluding: "1.2.0"}, SemVer, "0.9.0", false},
		{"start excl boundary", Range{StartExcluding: "1.0.0"}, SemVer, "1.0.0", false},
		{"start excl above", Range{StartExcluding: "1.0.0"}, SemVer, "1.0.1", true},
		{"end incl boundary", Range{EndIncluding: "2.4.58"}, Generic, "2.4.58", true},
		{"end incl above", Range{EndIncluding: "2.4.58"}, Generic, "2.4.59", false},
		{"generic apache", Range{StartIncluding: "2.4.0", EndExcluding: "2.4.58"}, Generic, "2.4.9", true},
		{"openssl letters", Range{StartIncluding: "1.0.2", EndExcluding: "1.0.2k"}, Generic, "1.0.2j", true},
		{"openssl letters fixed", Range{StartIncluding: "1.0.2", EndExcluding: "1.0.2k"}, Generic, "1.0.2k", false},
		{"start zero osv", Range{StartIncluding: "0", EndExcluding: "1.0.0"}, Generic, "abc", true},
		{"prerelease before fix", Range{StartIncluding: "0", EndExcluding: "1.0.0"}, SemVer, "1.0.0-rc.1", true},
		{"version list plus range", Range{EndExcluding: "1.0", Versions: []string{"2.0"}}, SemVer, "2.0.0", true},
		{"deb fixed", Range{StartIncluding: "0", EndExcluding: "2.4.58-1+deb12u1"}, Debian, "2.4.58-1", true},
		{"deb fixed equal", Range{StartIncluding: "0", EndExcluding: "2.4.58-1+deb12u1"}, Debian, "2.4.58-1+deb12u1", false},
		{"rpm", Range{EndExcluding: "1.0-2.el9"}, RPM, "1.0-1.el9", true},
		{"pypi", Range{StartIncluding: "2.0", EndExcluding: "2.31.0"}, PEP440, "2.4.0", true},
		{"pypi rc", Range{EndExcluding: "2.31.0"}, PEP440, "2.31.0rc1", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.Contains(c.s, c.v); got != c.want {
				t.Errorf("%+v.Contains(%s, %q) = %v, want %v", c.r, c.s, c.v, got, c.want)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"  1.2.3 ":           "1.2.3",
		"v1.2.3":             "1.2.3",
		"V2":                 "2",
		"version":            "version",
		"^1.2.3":             "1.2.3",
		"~1.2.3":             "1.2.3",
		">=1.0.0":            "1.0.0",
		">= 1.0.0 <2.0.0":    "1.0.0",
		"=1.0.0":             "1.0.0",
		"==2.0":              "2.0",
		"~=2.0":              "2.0",
		"^v1.4.0":            "1.4.0",
		"1.2.3 - 2.0.0":      "1.2.3",
		"^1.0.0 || ^2.0.0":   "1.0.0",
		"*":                  "",
		"x":                  "",
		"latest":             "",
		"LATEST":             "",
		"all":                "",
		"":                   "",
		"   ":                "",
		"1.x":                "",
		"1.2.*":              "",
		"1.0.0-beta.1":       "1.0.0-beta.1",
		"2.0.0+incompatible": "2.0.0+incompatible",
		"1:2.3-4":            "1:2.3-4",
		">=1.0,<2":           "1.0",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsAll(t *testing.T) {
	for _, v := range []string{"", " ", "*", "all", "ALL", "any", "-"} {
		if !IsAll(v) {
			t.Errorf("IsAll(%q) = false", v)
		}
	}
	for _, v := range []string{"1.0", "x", "latest", "0"} {
		if IsAll(v) {
			t.Errorf("IsAll(%q) = true", v)
		}
	}
}
