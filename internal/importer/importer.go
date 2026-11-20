// Package importer parses dependency manifests and SBOMs (package.json,
// go.mod, requirements.txt, docker-compose, CycloneDX JSON, SPDX JSON)
// into a flat list of components for vulnerability matching.
package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

// Component is one package found in a manifest or SBOM.
type Component struct {
	Ecosystem string `json:"ecosystem"` // OSV ecosystem name, "" if unknown
	Name      string `json:"name"`
	Version   string `json:"version"` // concrete version or ""
	PURL      string `json:"purl"`    // versionless purl or ""
	CPE       string `json:"cpe"`     // "cpe:2.3:a:vendor:product" or ""
}

// Result is the outcome of Parse.
type Result struct {
	Format     string      `json:"format"`
	Components []Component `json:"components"`
	Skipped    []string    `json:"skipped"` // human readable
}

// Supported formats.
const (
	FormatPackageJSON   = "package.json"
	FormatGoMod         = "go.mod"
	FormatRequirements  = "requirements.txt"
	FormatDockerCompose = "docker-compose"
	FormatCycloneDX     = "cyclonedx"
	FormatSPDX          = "spdx"
)

// Limits.
const (
	MaxInputSize  = 5 << 20
	MaxComponents = 5000
)

var (
	ErrUnsupported       = errors.New("importer: unsupported or unrecognized file format")
	ErrTooLarge          = fmt.Errorf("importer: input exceeds %d bytes", MaxInputSize)
	ErrTooManyComponents = fmt.Errorf("importer: more than %d components", MaxComponents)
)

// Detect determines the format by file name first, then by content
// sniffing. It returns ErrUnsupported if nothing matches.
func Detect(filename string, data []byte) (string, error) {
	if len(data) > MaxInputSize {
		return "", ErrTooLarge
	}
	base := strings.ToLower(path.Base(strings.ReplaceAll(strings.TrimSpace(filename), "\\", "/")))
	isYAML := strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")
	switch {
	case base == "package.json":
		return FormatPackageJSON, nil
	case base == "go.mod":
		return FormatGoMod, nil
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return FormatRequirements, nil
	case isYAML && (strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose")):
		return FormatDockerCompose, nil
	case strings.HasSuffix(base, ".cdx.json") || base == "bom.json":
		if f := sniffJSON(data); f == FormatSPDX {
			return f, nil
		}
		return FormatCycloneDX, nil
	case strings.HasSuffix(base, ".spdx.json"):
		if f := sniffJSON(data); f == FormatCycloneDX {
			return f, nil
		}
		return FormatSPDX, nil
	}
	if f := sniffJSON(data); f != "" {
		return f, nil
	}
	if f := sniffText(data); f != "" {
		return f, nil
	}
	return "", ErrUnsupported
}

func sniffJSON(data []byte) string {
	t := bytes.TrimSpace(data)
	if len(t) == 0 || t[0] != '{' {
		return ""
	}
	var probe struct {
		BOMFormat       string          `json:"bomFormat"`
		SPDXVersion     string          `json:"spdxVersion"`
		Dependencies    json.RawMessage `json:"dependencies"`
		DevDependencies json.RawMessage `json:"devDependencies"`
	}
	if json.Unmarshal(t, &probe) != nil {
		return ""
	}
	switch {
	case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
		return FormatCycloneDX
	case probe.SPDXVersion != "":
		return FormatSPDX
	case probe.Dependencies != nil || probe.DevDependencies != nil:
		return FormatPackageJSON
	}
	return ""
}

func sniffText(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "module ") {
			return FormatGoMod
		}
		if line == "services:" || strings.HasPrefix(line, "services:") || strings.HasPrefix(line, "version:") {
			return FormatDockerCompose
		}
		return ""
	}
	return ""
}

// Parse detects the format and parses data into components.
func Parse(filename string, data []byte) (*Result, error) {
	if len(data) > MaxInputSize {
		return nil, ErrTooLarge
	}
	format, err := Detect(filename, data)
	if err != nil {
		return nil, err
	}
	res := &Result{Format: format}
	var comps []Component
	switch format {
	case FormatPackageJSON:
		comps, err = parsePackageJSON(data, res)
	case FormatGoMod:
		comps, err = parseGoMod(data, res)
	case FormatRequirements:
		comps, err = parseRequirements(data, res)
	case FormatDockerCompose:
		comps, err = parseCompose(data, res)
	case FormatCycloneDX:
		comps, err = parseCycloneDX(data, res)
	case FormatSPDX:
		comps, err = parseSPDX(data, res)
	default:
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, fmt.Errorf("importer: parse %s: %w", format, err)
	}
	res.Components = dedupe(comps)
	if len(res.Components) > MaxComponents {
		return nil, ErrTooManyComponents
	}
	if res.Components == nil {
		res.Components = []Component{}
	}
	return res, nil
}

// dedupe removes duplicates (same ecosystem+name+version), keeping the
// first occurrence and filling in missing PURL/CPE from later ones.
func dedupe(in []Component) []Component {
	idx := make(map[string]int, len(in))
	var out []Component
	for _, c := range in {
		if c.Name == "" {
			continue
		}
		k := c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version
		if i, ok := idx[k]; ok {
			if out[i].PURL == "" {
				out[i].PURL = c.PURL
			}
			if out[i].CPE == "" {
				out[i].CPE = c.CPE
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, c)
	}
	return out
}
