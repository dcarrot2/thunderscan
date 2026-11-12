package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var sevNames = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
var sevWeights = []int{0, 1, 4, 15, 50}

func (s Severity) String() string { return sevNames[s] }

func (s Severity) MarshalJSON() ([]byte, error) { return []byte(`"` + s.String() + `"`), nil }

func parseSeverity(s string) (Severity, bool) {
	for i, n := range sevNames {
		if strings.EqualFold(n, s) {
			return Severity(i), true
		}
	}
	return 0, false
}

type Finding struct {
	Severity Severity `json:"severity"`
	Rule     string   `json:"rule"`
	File     string   `json:"file,omitempty"`
	Title    string   `json:"title"`
	Why      string   `json:"why,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

type VTResult struct {
	Found      bool   `json:"found"`
	Malicious  int    `json:"malicious"`
	Suspicious int    `json:"suspicious"`
	Harmless   int    `json:"undetected"`
	Link       string `json:"link"`
	Error      string `json:"error,omitempty"`
}

type FileInfo struct {
	Path   string    `json:"path"`
	Size   int64     `json:"size"`
	SHA256 string    `json:"sha256"`
	Kind   string    `json:"kind,omitempty"`
	VT     *VTResult `json:"virustotal,omitempty"`
}

type PackageMeta struct {
	FullName       string   `json:"full_name"`
	Owner          string   `json:"owner"`
	Version        string   `json:"version"`
	LatestVersion  string   `json:"latest_version"`
	PackageURL     string   `json:"package_url"`
	WebsiteURL     string   `json:"website_url"`
	Created        string   `json:"package_created"`
	VersionCreated string   `json:"version_created"`
	Downloads      int      `json:"version_downloads"`
	Deprecated     bool     `json:"deprecated"`
	Reviews        []string `json:"review_status"`
	Dependencies   []string `json:"dependencies"`

	Name      string `json:"-"`
	Namespace string `json:"-"`

	pkgCreatedRaw, verCreatedRaw string
	reviewCounts                 map[string]int
}

type Manifest struct {
	Name          string   `json:"name"`
	VersionNumber string   `json:"version_number"`
	WebsiteURL    string   `json:"website_url"`
	Description   string   `json:"description"`
	Dependencies  []string `json:"dependencies"`
}

type Report struct {
	Target   string       `json:"target"`
	Package  *PackageMeta `json:"thunderstore,omitempty"`
	Manifest *Manifest    `json:"manifest,omitempty"`
	Files    []FileInfo   `json:"files"`
	Findings []Finding    `json:"findings"`
	URLs     []string     `json:"urls,omitempty"`
	Score    int          `json:"risk_score"`
	Max      Severity     `json:"max_severity"`
	Verdict  string       `json:"verdict"`

	expectManifest bool
	looseGroup     bool
	seen           map[string]bool
	urlSeen        map[string]bool
}

func newReport(target string) *Report {
	return &Report{Target: target, seen: map[string]bool{}, urlSeen: map[string]bool{}}
}

func (r *Report) add(sev Severity, rule, file, title, why string, ev ...string) {
	key := rule + "\x00" + file
	if r.seen[key] {
		return
	}
	r.seen[key] = true
	r.Findings = append(r.Findings, Finding{sev, rule, file, title, why, ev})
}

func (r *Report) addURL(u string) {
	if len(u) > 200 {
		u = u[:200] + "…"
	}
	if !r.urlSeen[u] {
		r.urlSeen[u] = true
		r.URLs = append(r.URLs, u)
	}
}

func (r *Report) finalize() {
	applyTrust(r)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].Severity != r.Findings[j].Severity {
			return r.Findings[i].Severity > r.Findings[j].Severity
		}
		return r.Findings[i].File < r.Findings[j].File
	})
	r.Score, r.Max = 0, Info
	for _, f := range r.Findings {
		r.Score += sevWeights[f.Severity]
		if f.Severity > r.Max {
			r.Max = f.Severity
		}
	}
	switch r.Max {
	case Critical:
		r.Verdict = "DANGEROUS – strong malware indicators. Do not install unless you can verify every critical finding is benign."
	case High:
		r.Verdict = "SUSPICIOUS – review the HIGH findings (decompile with dnSpy/ILSpy) before installing."
	case Medium:
		r.Verdict = "CAUTION – some capabilities worth a quick look, but nothing strongly malicious."
	default:
		r.Verdict = "No obvious red flags found by static analysis."
	}
	sort.Strings(r.URLs)
}

// ---- text output ----

type painter struct{ on bool }

func (p painter) c(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

var sevColor = []string{"90", "36", "33", "91", "1;97;41"}

func printReport(w io.Writer, r *Report, p painter, verbose bool) {
	fmt.Fprintln(w, p.c("1", "══════ "+r.Target+" ══════"))
	if m := r.Package; m != nil {
		fmt.Fprintf(w, "Thunderstore: %s  (owner %s, v%s", m.PackageURL, m.Owner, m.Version)
		if m.LatestVersion != "" && m.LatestVersion != m.Version {
			fmt.Fprintf(w, ", latest v%s", m.LatestVersion)
		}
		fmt.Fprintf(w, ")\n  version downloads: %d   package created: %s   version uploaded: %s\n", m.Downloads, m.Created, m.VersionCreated)
		if len(m.Reviews) > 0 {
			fmt.Fprintf(w, "  review status: %s\n", strings.Join(m.Reviews, ", "))
		}
		if m.WebsiteURL != "" {
			fmt.Fprintf(w, "  website/source: %s\n", m.WebsiteURL)
		}
	} else if r.Manifest != nil {
		fmt.Fprintf(w, "Manifest: %s v%s  %s\n", r.Manifest.Name, r.Manifest.VersionNumber, r.Manifest.WebsiteURL)
	}

	managed, native := 0, 0
	for _, f := range r.Files {
		switch {
		case strings.HasPrefix(f.Kind, ".NET"):
			managed++
		case strings.HasPrefix(f.Kind, "native"):
			native++
		}
	}
	fmt.Fprintf(w, "Files: %d  (.NET assemblies: %d, native binaries: %d)\n", len(r.Files), managed, native)
	for _, f := range r.Files {
		if f.Kind == "" {
			continue
		}
		line := fmt.Sprintf("  %-14s %s  sha256:%s", f.Kind, f.Path, f.SHA256)
		if f.VT != nil {
			switch {
			case f.VT.Error != "":
				line += "  VT: error " + f.VT.Error
			case !f.VT.Found:
				line += "  VT: unknown file"
			default:
				line += fmt.Sprintf("  VT: %d malicious / %d suspicious", f.VT.Malicious, f.VT.Suspicious)
			}
		}
		fmt.Fprintln(w, p.c("90", line))
	}
	fmt.Fprintln(w)

	shown := 0
	for _, f := range r.Findings {
		if f.Severity == Info && !verbose {
			continue
		}
		shown++
		tag := fmt.Sprintf("[%s]", f.Severity)
		fmt.Fprintf(w, "%s %s  %s\n", p.c(sevColor[f.Severity], tag), p.c("1", f.Title), p.c("90", "("+f.Rule+")"))
		if f.File != "" {
			fmt.Fprintf(w, "    file: %s\n", f.File)
		}
		if f.Why != "" && (verbose || f.Severity >= Medium) {
			fmt.Fprintf(w, "    why:  %s\n", f.Why)
		}
		for _, e := range f.Evidence {
			fmt.Fprintf(w, "    → %s\n", e)
		}
	}
	if shown == 0 {
		fmt.Fprintln(w, p.c("32", "No findings."))
	}

	if len(r.URLs) > 0 {
		fmt.Fprintln(w, "\nURLs embedded in binaries (check these are expected):")
		limit := 25
		if verbose {
			limit = len(r.URLs)
		}
		for i, u := range r.URLs {
			if i == limit {
				fmt.Fprintf(w, "  … and %d more (use -v)\n", len(r.URLs)-limit)
				break
			}
			fmt.Fprintf(w, "  %s\n", u)
		}
	}

	col := map[Severity]string{Critical: "1;97;41", High: "1;91", Medium: "1;33"}[r.Max]
	if col == "" {
		col = "1;32"
	}
	fmt.Fprintf(w, "\nVerdict: %s  (risk score %d)\n\n", p.c(col, r.Verdict), r.Score)
}
