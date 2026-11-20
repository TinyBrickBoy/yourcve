package importer

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tinybrickboy/yourcve/internal/version"
)

type composeFile struct {
	Services map[string]struct {
		Image string    `yaml:"image"`
		Build yaml.Node `yaml:"build"`
	} `yaml:"services"`
}

var envVarRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expandEnv replaces ${VAR:-default} / ${VAR-default} with the default and
// other variable references with "" (we do not know the environment).
func expandEnv(s string) string {
	s = strings.ReplaceAll(s, "$$", "\x00")
	s = envVarRe.ReplaceAllStringFunc(s, func(m string) string {
		sm := envVarRe.FindStringSubmatch(m)
		if sm[2] == ":-" || sm[2] == "-" {
			return sm[3]
		}
		return ""
	})
	return strings.ReplaceAll(s, "\x00", "$")
}

func parseCompose(data []byte, res *Result) ([]Component, error) {
	var cf composeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cf.Services))
	for n := range cf.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Component
	for _, svc := range names {
		s := cf.Services[svc]
		img := strings.TrimSpace(expandEnv(s.Image))
		if img == "" {
			if !s.Build.IsZero() {
				res.Skipped = append(res.Skipped, fmt.Sprintf("service %q: built locally (build:), no image", svc))
			} else {
				res.Skipped = append(res.Skipped, fmt.Sprintf("service %q: no image", svc))
			}
			continue
		}
		name, tag := ParseImage(img)
		if name == "" {
			res.Skipped = append(res.Skipped, fmt.Sprintf("service %q: cannot parse image %q", svc, img))
			continue
		}
		out = append(out, Component{Name: name, Version: ImageTagVersion(tag)})
	}
	return out, nil
}

// ParseImage splits a container image reference into its short name (last
// path element without registry/namespace, lowercased) and tag ("" when
// absent or only a digest is given).
//
//	"nginx:1.24"                  -> "nginx", "1.24"
//	"bitnami/postgresql:16.2"     -> "postgresql", "16.2"
//	"ghcr.io/foo/bar@sha256:abc"  -> "bar", ""
//	"localhost:5000/app:1.0"      -> "app", "1.0"
func ParseImage(ref string) (name, tag string) {
	ref = strings.TrimSpace(ref)
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	ref = strings.Trim(ref, "/")
	last := ref
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		last = ref[i+1:]
	}
	if i := strings.LastIndexByte(last, ':'); i >= 0 {
		last, tag = last[:i], last[i+1:]
	}
	return strings.ToLower(last), tag
}

var tagVersionRe = regexp.MustCompile(`^[vV]?(\d+(?:\.\d+)*)(?:[-.]?((?:rc|beta|alpha|pre)\.?\d*))?(?:$|[-_.+]?[A-Za-z])`)

// ImageTagVersion extracts the leading version from an image tag, dropping
// variant suffixes: "1.25.3-alpine" -> "1.25.3", "16.2-bookworm" -> "16.2",
// "3.12-slim" -> "3.12", "8.0.36-debian-12-r1" -> "8.0.36". Tags without a
// leading version ("latest", "alpine", "stable") yield "".
func ImageTagVersion(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" || strings.EqualFold(tag, "latest") {
		return ""
	}
	m := tagVersionRe.FindStringSubmatch(tag)
	if m == nil {
		// e.g. "1.25.3-1" keep version before first '-'
		if i := strings.IndexAny(tag, "-_"); i > 0 {
			if mm := tagVersionRe.FindStringSubmatch(tag[:i]); mm != nil {
				return mm[1]
			}
		}
		return ""
	}
	v := m[1]
	if m[2] != "" {
		v += "-" + m[2]
	}
	return version.Normalize(v)
}
