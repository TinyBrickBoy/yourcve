package matcher

import (
	"testing"

	"github.com/tinybrickboy/yourcve/internal/version"
)

func f(v float64) *float64 { return &v }

func TestEvaluate(t *testing.T) {
	a := affect{productName: "nginx", ecosystem: "cpe", source: "nvd", confirmed: true,
		rng: version.Range{StartIncluding: "1.0.0", EndExcluding: "1.25.4"}}
	if ok, _ := evaluate(item{version: "1.24.0"}, a); !ok {
		t.Fatal("1.24.0 should match")
	}
	if ok, _ := evaluate(item{version: "1.25.4"}, a); ok {
		t.Fatal("1.25.4 is fixed")
	}
	if ok, r := evaluate(item{version: ""}, a); !ok || r == "" {
		t.Fatal("all versions should match")
	}
	npm := affect{productName: "lodash", ecosystem: "npm", source: "osv", rng: version.Range{EndExcluding: "4.17.21"}}
	if ok, _ := evaluate(item{version: "4.17.20"}, npm); !ok {
		t.Fatal("lodash 4.17.20")
	}
}

func TestRulePasses(t *testing.T) {
	if RulePasses(7, false, 0, true, f(5), false, nil, true, "new") {
		t.Fatal("below min cvss")
	}
	if !RulePasses(7, false, 0, true, f(5), true, nil, true, "kev_added") {
		t.Fatal("kev addition passes thresholds")
	}
	if RulePasses(0, true, 0, true, f(9), false, nil, true, "new") {
		t.Fatal("kev only")
	}
	if RulePasses(0, false, 0.1, true, f(9), false, f(0.01), true, "new") {
		t.Fatal("epss")
	}
	if RulePasses(0, false, 0, false, f(9), false, nil, false, "new") {
		t.Fatal("unconfirmed excluded")
	}
	if !RulePasses(0, false, 0, true, nil, false, nil, false, "new") {
		t.Fatal("defaults pass")
	}
}
