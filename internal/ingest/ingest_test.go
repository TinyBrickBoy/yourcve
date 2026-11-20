package ingest

import (
	"testing"
	"time"
)

func TestRecordPath(t *testing.T) {
	for id, want := range map[string]string{
		"CVE-2024-6387":   "cves/2024/6xxx/CVE-2024-6387.json",
		"CVE-2026-129086": "cves/2026/129xxx/CVE-2026-129086.json",
		"CVE-2021-0001":   "cves/2021/0xxx/CVE-2021-0001.json",
		"CVE-1999-0123":   "cves/1999/0xxx/CVE-1999-0123.json",
	} {
		if got, _ := RecordPath(id); got != want {
			t.Errorf("%s: %s", id, got)
		}
	}
}

func TestPktLines(t *testing.T) {
	b := []byte("003dd95c4c98054eb7370f6dac551ca1bf2d8bfe52fa refs/heads/main\n0000")
	l := parsePktLines(b)
	if len(l) != 1 || l[0] != "d95c4c98054eb7370f6dac551ca1bf2d8bfe52fa refs/heads/main" {
		t.Fatal(l)
	}
	if pktLine("command=ls-refs\n") != "0014command=ls-refs\n" {
		t.Fatal(pktLine("command=ls-refs\n"))
	}
}

func TestDecodeDeltaPrefix(t *testing.T) {
	full := `[{"fetchTime":"2026-11-20T11:14:40.669Z","new":[{"cveId":"CVE-2026-1"}]},{"fetchTime":"2026-11-20T11:07:00Z","updated":[{"cveId":"CVE-2026-2"}]}]`
	e, ok := decodeDeltaPrefix([]byte(full[:len(full)-30]))
	if len(e) != 1 || ok {
		t.Fatal(len(e), ok)
	}
	e, ok = decodeDeltaPrefix([]byte(full))
	if len(e) != 2 || !ok || e[1].Updated[0].CVEID != "CVE-2026-2" {
		t.Fatal(e, ok)
	}
}

func TestCPESplit(t *testing.T) {
	p := splitCPE23(`cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*`)
	if p[3] != "openbsd" || p[4] != "openssh" || p[5] != "8.5" || p[6] != "p1" {
		t.Fatal(p)
	}
	p = splitCPE23(`cpe:2.3:a:vendor:prod\:x:1.0:*:*:*:*:*:*:*`)
	if p[4] != "prod:x" {
		t.Fatal(p)
	}
	v, pr, part, ok := parseAnyCPE("cpe:/o:redhat:enterprise_linux:9::baseos")
	if !ok || v != "redhat" || pr != "enterprise_linux" || part != "o" {
		t.Fatal(v, pr, part)
	}
}

func TestNVDTime(t *testing.T) {
	if s := nvdTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)); s != "2026-01-02T03:04:05.000+00:00" {
		t.Fatal(s)
	}
}
