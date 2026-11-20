package importer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tinybrickboy/yourcve/internal/version"
)

// ---- CycloneDX JSON (1.4 - 1.6) ----

type cdxComponent struct {
	Type       string         `json:"type"`
	Group      string         `json:"group"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	CPE        string         `json:"cpe"`
	Components []cdxComponent `json:"components"`
}

type cdxBOM struct {
	BOMFormat  string         `json:"bomFormat"`
	Components []cdxComponent `json:"components"`
}

const maxNesting = 64

func parseCycloneDX(data []byte, res *Result) ([]Component, error) {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}
	var out []Component
	var walk func(cs []cdxComponent, depth int)
	walk = func(cs []cdxComponent, depth int) {
		if depth > maxNesting {
			res.Skipped = append(res.Skipped, "cyclonedx: nesting too deep, remaining components skipped")
			return
		}
		for _, c := range cs {
			if comp, ok := sbomComponent(c.Name, c.Version, c.PURL, c.CPE); ok {
				out = append(out, comp)
			} else if c.Name != "" {
				res.Skipped = append(res.Skipped, fmt.Sprintf("cyclonedx: %q has neither purl nor cpe", displayName(c.Group, c.Name)))
			}
			if len(c.Components) > 0 {
				walk(c.Components, depth+1)
			}
		}
	}
	walk(bom.Components, 0)
	return out, nil
}

func displayName(group, name string) string {
	if group != "" {
		return group + "/" + name
	}
	return name
}

// sbomComponent builds a component from SBOM fields. It returns false when
// neither a usable purl nor cpe is present.
func sbomComponent(name, ver, purl, cpe string) (Component, bool) {
	var c Component
	hasPURL := false
	if strings.TrimSpace(purl) != "" {
		if pc, ok := componentFromPURL(purl); ok {
			c = pc
			hasPURL = true
		}
	}
	c.CPE = cpePrefix(cpe)
	if !hasPURL && c.CPE == "" {
		return Component{}, false
	}
	if !hasPURL {
		c.Name = strings.TrimSpace(name)
		if c.Name == "" {
			// fall back to the CPE product
			parts := strings.Split(c.CPE, ":")
			c.Name = parts[len(parts)-1]
		}
	}
	switch strings.ToUpper(strings.TrimSpace(ver)) {
	case "NOASSERTION", "NONE", "UNKNOWN":
		ver = ""
	}
	if v := version.Normalize(ver); v != "" {
		c.Version = v
	} else {
		c.Version = version.Normalize(c.Version)
	}
	return c, true
}

// ---- SPDX JSON 2.2 / 2.3 ----

type spdxDoc struct {
	SPDXVersion string `json:"spdxVersion"`
	Packages    []struct {
		SPDXID       string `json:"SPDXID"`
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceCategory string `json:"referenceCategory"`
			ReferenceType     string `json:"referenceType"`
			ReferenceLocator  string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

func parseSPDX(data []byte, res *Result) ([]Component, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Component
	for _, p := range doc.Packages {
		var purl, cpe string
		for _, r := range p.ExternalRefs {
			switch strings.ToLower(r.ReferenceType) {
			case "purl":
				if purl == "" {
					purl = r.ReferenceLocator
				}
			case "cpe23type", "cpe22type":
				if cpe == "" || cpePrefix(cpe) == "" {
					cpe = r.ReferenceLocator
				}
			}
		}
		c, ok := sbomComponent(p.Name, p.VersionInfo, purl, cpe)
		if !ok {
			n := p.Name
			if n == "" {
				n = p.SPDXID
			}
			res.Skipped = append(res.Skipped, fmt.Sprintf("spdx: %q has neither purl nor cpe", n))
			continue
		}
		out = append(out, c)
	}
	return out, nil
}
