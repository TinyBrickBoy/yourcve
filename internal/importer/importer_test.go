package importer

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParsePURL(t *testing.T) {
	cases := []struct {
		in                 string
		typ, ns, name, ver string
		ok                 bool
	}{
		{"pkg:npm/%40scope/pkg@1.2.3", "npm", "@scope", "pkg", "1.2.3", true},
		{"pkg:npm/@scope/pkg@1.2.3?foo=bar#sub/path", "npm", "@scope", "pkg", "1.2.3", true},
		{"pkg:npm/lodash", "npm", "", "lodash", "", true},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "golang", "github.com/foo", "bar", "v1.2.3", true},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", "maven", "org.apache.logging.log4j", "log4j-core", "2.14.1", true},
		{"pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12", "deb", "debian", "openssl", "3.0.11-1~deb12u2", true},
		{"PKG:PyPI/Django@4.2", "pypi", "", "Django", "4.2", true},
		{"pkg://cargo/serde@1.0.0", "cargo", "", "serde", "1.0.0", true},
		{"pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386", "rpm", "fedora", "curl", "7.50.3-1.fc25", true},
		{"pkg:npm/", "", "", "", "", false},
		{"pkg:npm", "", "", "", "", false},
		{"npm/lodash", "", "", "", "", false},
		{"", "", "", "", "", false},
		{"pkg:/x", "", "", "", "", false},
	}
	for _, c := range cases {
		typ, ns, name, ver, ok := ParsePURL(c.in)
		if typ != c.typ || ns != c.ns || name != c.name || ver != c.ver || ok != c.ok {
			t.Errorf("ParsePURL(%q) = %q %q %q %q %v, want %q %q %q %q %v", c.in, typ, ns, name, ver, ok, c.typ, c.ns, c.name, c.ver, c.ok)
		}
	}
}

func TestPURLFor(t *testing.T) {
	cases := []struct{ eco, name, want string }{
		{"npm", "@scope/pkg", "pkg:npm/%40scope/pkg"},
		{"npm", "lodash", "pkg:npm/lodash"},
		{"Go", "github.com/foo/bar", "pkg:golang/github.com/foo/bar"},
		{"PyPI", "Django_REST.framework", "pkg:pypi/django-rest-framework"},
		{"Maven", "org.apache:commons-text", "pkg:maven/org.apache/commons-text"},
		{"Maven", "commons-text", ""},
		{"crates.io", "serde", "pkg:cargo/serde"},
		{"NuGet", "Newtonsoft.Json", "pkg:nuget/Newtonsoft.Json"},
		{"Packagist", "symfony/http-kernel", "pkg:composer/symfony/http-kernel"},
		{"RubyGems", "rails", "pkg:gem/rails"},
		{"Hex", "plug", "pkg:hex/plug"},
		{"Pub", "http", "pkg:pub/http"},
		{"Debian", "openssl", "pkg:deb/debian/openssl"},
		{"Debian:12", "openssl", "pkg:deb/debian/openssl"},
		{"Alpine:v3.18", "musl", "pkg:apk/alpine/musl"},
		{"Unknown", "x", ""},
		{"", "x", ""},
		{"npm", "", ""},
	}
	for _, c := range cases {
		if got := PURLFor(c.eco, c.name); got != c.want {
			t.Errorf("PURLFor(%q, %q) = %q, want %q", c.eco, c.name, got, c.want)
		}
	}
}

func TestCPEPrefix(t *testing.T) {
	cases := map[string]string{
		"cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*": "cpe:2.3:a:apache:http_server",
		"cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*":    "cpe:2.3:o:linux:linux_kernel",
		"cpe:/a:openssl:openssl:1.0.2k":                     "cpe:2.3:a:openssl:openssl",
		`cpe:2.3:a:foo\:bar:baz:1:*:*:*:*:*:*:*`:            `cpe:2.3:a:foo\:bar:baz`,
		"cpe:2.3:a:*:*:*:*:*:*:*:*:*:*":                     "",
		"cpe:2.3:a:vendor":                                  "",
		"not a cpe":                                         "",
	}
	for in, want := range cases {
		if got := cpePrefix(in); got != want {
			t.Errorf("cpePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetect(t *testing.T) {
	cases := []struct {
		file string
		data string
		want string
	}{
		{"package.json", `{}`, FormatPackageJSON},
		{"some/dir/package.json", `{}`, FormatPackageJSON},
		{"go.mod", "", FormatGoMod},
		{"requirements.txt", "", FormatRequirements},
		{"requirements-dev.txt", "", FormatRequirements},
		{"docker-compose.yml", "", FormatDockerCompose},
		{"docker-compose.prod.yaml", "", FormatDockerCompose},
		{"compose.yaml", "", FormatDockerCompose},
		{"app.cdx.json", "{}", FormatCycloneDX},
		{"bom.json", "{}", FormatCycloneDX},
		{"BOM.JSON", "{}", FormatCycloneDX},
		{"bom.json", `{"spdxVersion":"SPDX-2.3"}`, FormatSPDX},
		{"x.spdx.json", "{}", FormatSPDX},
		{"upload.json", `{"bomFormat":"CycloneDX","specVersion":"1.5"}`, FormatCycloneDX},
		{"upload.json", `{"spdxVersion":"SPDX-2.3"}`, FormatSPDX},
		{"", `{"name":"x","dependencies":{}}`, FormatPackageJSON},
		{"upload", "// comment\nmodule example.com/x\n", FormatGoMod},
		{"stack.yml", "services:\n  web:\n    image: nginx\n", FormatDockerCompose},
	}
	for _, c := range cases {
		got, err := Detect(c.file, []byte(c.data))
		if err != nil || got != c.want {
			t.Errorf("Detect(%q) = %q, %v; want %q", c.file, got, err, c.want)
		}
	}
	for _, c := range []struct{ file, data string }{
		{"README.md", "hello"},
		{"data.json", `{"foo":1}`},
		{"x.json", `[1,2]`},
		{"", ""},
	} {
		if f, err := Detect(c.file, []byte(c.data)); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Detect(%q) = %q, %v; want ErrUnsupported", c.file, f, err)
		}
	}
}

func mustParse(t *testing.T, file, data string) *Result {
	t.Helper()
	r, err := Parse(file, []byte(data))
	if err != nil {
		t.Fatalf("Parse(%q): %v", file, err)
	}
	return r
}

func checkComponents(t *testing.T, got, want []Component) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		var b strings.Builder
		fmt.Fprintf(&b, "components mismatch\n got:\n")
		for _, c := range got {
			fmt.Fprintf(&b, "  %+v\n", c)
		}
		fmt.Fprintf(&b, " want:\n")
		for _, c := range want {
			fmt.Fprintf(&b, "  %+v\n", c)
		}
		t.Error(b.String())
	}
}

func TestParsePackageJSON(t *testing.T) {
	data := `{
  "name": "myapp", "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "@scope/pkg": "~1.2.3",
    "lodash": "4.17.21",
    "local": "file:../local",
    "ws": "workspace:*",
    "gitdep": "git+https://github.com/a/b.git",
    "gh": "user/repo",
    "anything": "*",
    "newest": "latest",
    "range": ">=1.0.0 <2.0.0",
    "vpref": "v2.0.0",
    "alias": "npm:other@1.0.0",
    "bad": 5
  },
  "devDependencies": { "jest": "^29.7.0", "lodash": "4.17.21" },
  "optionalDependencies": { "fsevents": "2.3.3" },
  "peerDependencies": { "react": "^18.0.0" }
}`
	r := mustParse(t, "package.json", data)
	if r.Format != FormatPackageJSON {
		t.Fatalf("format = %q", r.Format)
	}
	npm := func(n, v string) Component { return Component{"npm", n, v, PURLFor("npm", n), ""} }
	checkComponents(t, r.Components, []Component{
		npm("@scope/pkg", "1.2.3"),
		npm("alias", ""),
		npm("anything", ""),
		npm("express", "4.18.2"),
		npm("gh", ""),
		npm("gitdep", ""),
		npm("local", ""),
		npm("lodash", "4.17.21"),
		npm("newest", ""),
		npm("range", "1.0.0"),
		npm("vpref", "2.0.0"),
		npm("ws", ""),
		npm("jest", "29.7.0"),
		npm("fsevents", "2.3.3"),
	})
	if r.Components[0].PURL != "pkg:npm/%40scope/pkg" {
		t.Errorf("scoped purl = %q", r.Components[0].PURL)
	}
	if len(r.Skipped) != 1 || !strings.Contains(r.Skipped[0], "bad") {
		t.Errorf("skipped = %v", r.Skipped)
	}
	if _, err := Parse("package.json", []byte("{not json")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseGoMod(t *testing.T) {
	data := `module github.com/me/app

go 1.22

toolchain go1.22.1

require github.com/single/dep v1.0.0

require (
	github.com/foo/bar v1.2.3
	golang.org/x/text v0.14.0 // indirect
	github.com/old/thing v2.0.0+incompatible
	github.com/pseudo/mod v0.0.0-20210101000000-abcdef123456 // indirect
	"github.com/quoted/mod" v1.1.1
)

replace github.com/foo/bar => github.com/fork/bar v1.2.4

replace (
	github.com/x/y => ../y
)

exclude github.com/foo/bar v1.2.2
retract v1.0.1
`
	r := mustParse(t, "go.mod", data)
	g := func(n, v string) Component { return Component{"Go", n, v, "pkg:golang/" + n, ""} }
	checkComponents(t, r.Components, []Component{
		g("github.com/single/dep", "1.0.0"),
		g("github.com/foo/bar", "1.2.3"),
		g("golang.org/x/text", "0.14.0"),
		g("github.com/old/thing", "2.0.0+incompatible"),
		g("github.com/pseudo/mod", "0.0.0-20210101000000-abcdef123456"),
		g("github.com/quoted/mod", "1.1.1"),
	})
}

func TestParseRequirements(t *testing.T) {
	data := `# comment
Django==4.2.7
requests>=2.0
Flask[async]==3.0.0 ; python_version >= "3.8"
numpy == 1.26.2  # inline comment
PyYAML===6.0.1
typing_extensions~=4.0
celery==5.*
urllib3==2.0.7 \
    --hash=sha256:abc \
    --hash=sha256:def
zope.interface==6.1 --hash=sha256:123
pkg @ https://example.com/pkg-1.0.tar.gz
-r other.txt
-e git+https://github.com/a/b.git#egg=b
--index-url https://pypi.example.com/simple
git+https://github.com/a/c.git@v1.0#egg=c
./local/path
compound>=1.0,==1.5
Django==4.2.7
`
	r := mustParse(t, "requirements-dev.txt", data)
	py := func(n, v string) Component { return Component{"PyPI", n, v, "pkg:pypi/" + n, ""} }
	checkComponents(t, r.Components, []Component{
		py("django", "4.2.7"),
		py("requests", ""),
		py("flask", "3.0.0"),
		py("numpy", "1.26.2"),
		py("pyyaml", "6.0.1"),
		py("typing-extensions", ""),
		py("celery", ""),
		py("urllib3", "2.0.7"),
		py("zope-interface", "6.1"),
		py("pkg", ""),
		py("compound", "1.5"),
	})
	if len(r.Skipped) != 5 {
		t.Errorf("skipped = %d %q", len(r.Skipped), r.Skipped)
	}
}

func TestParseCompose(t *testing.T) {
	data := `services:
  web:
    image: nginx:1.24
  db:
    image: bitnami/postgresql:16.2
  cache:
    image: "redis:7.2.3-alpine"
  sidecar:
    image: ghcr.io/foo/bar@sha256:0123456789abcdef
  proxy:
    image: docker.io/library/traefik:v2.10.5
  app:
    build: .
  worker:
    build:
      context: ./worker
  py:
    image: python:3.12-slim-bookworm
  latest:
    image: alpine:latest
  notag:
    image: memcached
  envtag:
    image: "mysql:${MYSQL_VERSION:-8.0.36}"
  registry:
    image: localhost:5000/team/svc:1.0.0
  pinned:
    image: node:20.10.0-bookworm@sha256:abc
`
	r := mustParse(t, "docker-compose.yml", data)
	d := func(n, v string) Component { return Component{Name: n, Version: v} }
	checkComponents(t, r.Components, []Component{
		d("redis", "7.2.3"),
		d("postgresql", "16.2"),
		d("mysql", "8.0.36"),
		d("alpine", ""),
		d("memcached", ""),
		d("node", "20.10.0"),
		d("traefik", "2.10.5"),
		d("python", "3.12"),
		d("svc", "1.0.0"),
		d("bar", ""),
		d("nginx", "1.24"),
	})
	if len(r.Skipped) != 2 {
		t.Errorf("skipped = %q", r.Skipped)
	}
	for _, s := range r.Skipped {
		if !strings.Contains(s, "build") {
			t.Errorf("unexpected skip reason %q", s)
		}
	}
	if _, err := Parse("compose.yaml", []byte("services: [unclosed")); err == nil {
		t.Error("expected YAML error")
	}
}

func TestImageTagVersion(t *testing.T) {
	cases := map[string]string{
		"1.25.3-alpine":       "1.25.3",
		"16.2-bookworm":       "16.2",
		"3.12-slim":           "3.12",
		"8.0.36-debian-12-r1": "8.0.36",
		"v2.10.5":             "2.10.5",
		"1.25.3-1":            "1.25.3",
		"7":                   "7",
		"3.13.0rc1":           "3.13.0-rc1",
		"3.13.0-rc.1-alpine":  "3.13.0-rc.1",
		"latest":              "",
		"alpine":              "",
		"stable-alpine":       "",
		"":                    "",
		"1.24.0_windows":      "1.24.0",
	}
	for in, want := range cases {
		if got := ImageTagVersion(in); got != want {
			t.Errorf("ImageTagVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseImage(t *testing.T) {
	cases := []struct{ in, name, tag string }{
		{"nginx:1.24", "nginx", "1.24"},
		{"bitnami/postgresql:16.2", "postgresql", "16.2"},
		{"ghcr.io/foo/bar@sha256:abc", "bar", ""},
		{"localhost:5000/app", "app", ""},
		{"registry.example.com:443/a/b/C:1.0", "c", "1.0"},
		{"nginx", "nginx", ""},
	}
	for _, c := range cases {
		n, tag := ParseImage(c.in)
		if n != c.name || tag != c.tag {
			t.Errorf("ParseImage(%q) = %q %q, want %q %q", c.in, n, tag, c.name, c.tag)
		}
	}
}

func TestParseCycloneDX(t *testing.T) {
	data := `{
  "bomFormat": "CycloneDX", "specVersion": "1.5",
  "metadata": {"component": {"type": "application", "name": "root"}},
  "components": [
    {"type": "library", "name": "pkg", "group": "@scope", "version": "1.2.3", "purl": "pkg:npm/%40scope/pkg@1.2.3"},
    {"type": "library", "name": "log4j-core", "group": "org.apache.logging.log4j", "version": "2.14.1",
     "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
     "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
     "components": [
       {"type": "library", "name": "inner", "purl": "pkg:golang/github.com/a/inner@v0.3.0"},
       {"type": "library", "name": "deeper", "components": [
         {"type": "library", "name": "Requests", "version": "2.31.0", "purl": "pkg:pypi/Requests@2.31.0"}
       ]}
     ]},
    {"type": "library", "name": "openssl", "version": "1.0.2k", "cpe": "cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*"},
    {"type": "library", "name": "serde", "purl": "pkg:cargo/serde@1.0.190"},
    {"type": "library", "name": "Newtonsoft.Json", "purl": "pkg:nuget/Newtonsoft.Json@13.0.1"},
    {"type": "library", "name": "http-kernel", "purl": "pkg:composer/symfony/http-kernel@v6.3.0"},
    {"type": "library", "name": "rails", "purl": "pkg:gem/rails@7.1.0"},
    {"type": "library", "name": "openssl", "version": "3.0.11-1~deb12u2", "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64"},
    {"type": "library", "name": "curl", "version": "7.76.1-26.el9", "purl": "pkg:rpm/redhat/curl@7.76.1-26.el9?arch=x86_64"},
    {"type": "library", "name": "musl", "version": "1.2.4-r2", "purl": "pkg:apk/alpine/musl@1.2.4-r2"},
    {"type": "library", "name": "thing", "version": "1.0", "purl": "pkg:github/foo/thing@1.0"},
    {"type": "file", "name": "README"},
    {"type": "library", "name": "pkg", "version": "1.2.3", "purl": "pkg:npm/@scope/pkg@1.2.3"}
  ]
}`
	r := mustParse(t, "bom.json", data)
	checkComponents(t, r.Components, []Component{
		{"npm", "@scope/pkg", "1.2.3", "pkg:npm/%40scope/pkg", ""},
		{"Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core", "cpe:2.3:a:apache:log4j"},
		{"Go", "github.com/a/inner", "0.3.0", "pkg:golang/github.com/a/inner", ""},
		{"PyPI", "requests", "2.31.0", "pkg:pypi/requests", ""},
		{"", "openssl", "1.0.2k", "", "cpe:2.3:a:openssl:openssl"},
		{"crates.io", "serde", "1.0.190", "pkg:cargo/serde", ""},
		{"NuGet", "Newtonsoft.Json", "13.0.1", "pkg:nuget/Newtonsoft.Json", ""},
		{"Packagist", "symfony/http-kernel", "6.3.0", "pkg:composer/symfony/http-kernel", ""},
		{"RubyGems", "rails", "7.1.0", "pkg:gem/rails", ""},
		{"Debian", "openssl", "3.0.11-1~deb12u2", "pkg:deb/debian/openssl", ""},
		{"", "curl", "7.76.1-26.el9", "pkg:rpm/redhat/curl", ""},
		{"Alpine", "musl", "1.2.4-r2", "pkg:apk/alpine/musl", ""},
		{"", "thing", "1.0", "pkg:github/foo/thing", ""},
	})
	if len(r.Skipped) != 2 {
		t.Errorf("skipped = %q", r.Skipped)
	}
}

func TestParseSPDX(t *testing.T) {
	data := `{
  "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "doc",
  "documentDescribes": ["SPDXRef-root"],
  "packages": [
    {"SPDXID": "SPDXRef-root", "name": "my-image", "versionInfo": "NOASSERTION"},
    {"SPDXID": "SPDXRef-1", "name": "express", "versionInfo": "4.18.2",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/express@4.18.2"}]},
    {"SPDXID": "SPDXRef-2", "name": "httpd", "versionInfo": "2.4.58",
     "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"}]},
    {"SPDXID": "SPDXRef-3", "name": "zlib", "versionInfo": "NOASSERTION",
     "externalRefs": [
       {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:zlib:zlib:1.3:*:*:*:*:*:*:*"},
       {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:apk/alpine/zlib@1.3-r2"}
     ]},
    {"SPDXID": "SPDXRef-4", "name": "express", "versionInfo": "4.18.2",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/express@4.18.2"}]}
  ]
}`
	r := mustParse(t, "sbom.spdx.json", data)
	checkComponents(t, r.Components, []Component{
		{"npm", "express", "4.18.2", "pkg:npm/express", ""},
		{"", "httpd", "2.4.58", "", "cpe:2.3:a:apache:http_server"},
		{"Alpine", "zlib", "1.3-r2", "pkg:apk/alpine/zlib", "cpe:2.3:a:zlib:zlib"},
	})
	if len(r.Skipped) != 1 || !strings.Contains(r.Skipped[0], "my-image") {
		t.Errorf("skipped = %q", r.Skipped)
	}
}

func TestDedupeMergesIdentifiers(t *testing.T) {
	got := dedupe([]Component{
		{Ecosystem: "npm", Name: "a", Version: "1"},
		{Ecosystem: "npm", Name: "a", Version: "1", PURL: "pkg:npm/a", CPE: "cpe:2.3:a:x:a"},
		{Ecosystem: "npm", Name: "a", Version: "2"},
		{Ecosystem: "", Name: ""},
	})
	checkComponents(t, got, []Component{
		{"npm", "a", "1", "pkg:npm/a", "cpe:2.3:a:x:a"},
		{"npm", "a", "2", "", ""},
	})
}

func TestLimits(t *testing.T) {
	big := make([]byte, MaxInputSize+1)
	if _, err := Parse("package.json", big); !errors.Is(err, ErrTooLarge) {
		t.Errorf("want ErrTooLarge, got %v", err)
	}
	var b strings.Builder
	b.WriteString(`{"dependencies":{`)
	for i := 0; i <= MaxComponents; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"p%d":"1.0.0"`, i)
	}
	b.WriteString("}}")
	if _, err := Parse("package.json", []byte(b.String())); !errors.Is(err, ErrTooManyComponents) {
		t.Errorf("want ErrTooManyComponents, got %v", err)
	}
	if _, err := Parse("notes.txt", []byte("hello")); !errors.Is(err, ErrUnsupported) {
		t.Errorf("want ErrUnsupported, got %v", err)
	}
}

func TestEmptyInputs(t *testing.T) {
	for _, f := range []string{"go.mod", "requirements.txt"} {
		r := mustParse(t, f, "")
		if r.Components == nil || len(r.Components) != 0 {
			t.Errorf("%s: want empty non-nil components, got %v", f, r.Components)
		}
	}
}
