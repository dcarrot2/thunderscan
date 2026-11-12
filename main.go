// thunderscan – static security vetting for Thunderstore (BepInEx / MelonLoader) mods.
//
// Run with no arguments to open the built-in web UI, or pass targets on the
// command line:  thunderscan [flags] <Owner-Name[-1.2.3] | thunderstore URL | mod.zip | folder | file.dll> ...
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type options struct {
	jsonOut  bool
	noColor  bool
	deps     bool
	vt       bool
	vtKey    string
	vtDelay  time.Duration
	failOn   Severity
	maxBytes int64
	verbose  bool
	ui       bool
	port     int
	noOpen   bool
	logf     func(format string, a ...any)
}

func main() { os.Exit(run()) }

func run() int {
	opts := &options{}
	fs := flag.NewFlagSet("thunderscan", flag.ContinueOnError)
	fs.BoolVar(&opts.jsonOut, "json", false, "print machine-readable JSON instead of text")
	fs.BoolVar(&opts.noColor, "no-color", false, "disable colored output")
	fs.BoolVar(&opts.deps, "deps", false, "also download and scan dependencies of Thunderstore packages")
	fs.BoolVar(&opts.vt, "vt", false, "look up binary hashes on VirusTotal (needs VT_API_KEY env var; only hashes are sent)")
	fs.DurationVar(&opts.vtDelay, "vt-delay", 15*time.Second, "delay between VirusTotal requests (public API allows 4/min)")
	failOn := fs.String("fail-on", "high", "exit code 1 if any finding is at least this severe (low|medium|high|critical)")
	maxMB := fs.Int64("max-mb", 512, "maximum size of a single file to scan, in MB")
	fs.BoolVar(&opts.verbose, "v", false, "verbose: show INFO findings, explanations and all URLs")
	fs.BoolVar(&opts.ui, "ui", false, "open the web UI (default when run with no arguments)")
	fs.IntVar(&opts.port, "port", 0, "port for the web UI (default: random free port)")
	fs.BoolVar(&opts.noOpen, "no-browser", false, "don't open the browser automatically in UI mode")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "thunderscan – static security checks for Thunderstore mods\n\nUsage:\n  thunderscan                      (opens the web UI)\n  thunderscan [flags] <target> ...\n\nTargets:\n  Owner-Name, Owner-Name-1.2.3     download from thunderstore.io\n  https://thunderstore.io/c/<game>/p/Owner/Name/\n  path\\to\\mod.zip | path\\to\\folder | path\\to\\file.dll\n\nFlags:")
		fs.PrintDefaults()
	}

	// Allow flags and targets in any order.
	var targets []string
	rest := os.Args[1:]
	for {
		if err := fs.Parse(rest); err != nil {
			if err == flag.ErrHelp {
				return 0
			}
			return 2
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		targets = append(targets, rest[0])
		rest = rest[1:]
	}

	sev, ok := parseSeverity(*failOn)
	if !ok {
		fmt.Fprintln(os.Stderr, "invalid -fail-on value:", *failOn)
		return 2
	}
	opts.failOn = sev
	opts.maxBytes = *maxMB << 20
	if opts.vt {
		opts.vtKey = os.Getenv("VT_API_KEY")
		if opts.vtKey == "" {
			fmt.Fprintln(os.Stderr, "-vt requires the VT_API_KEY environment variable (free key at virustotal.com)")
			return 2
		}
	}
	color := enableVT() && !opts.noColor && os.Getenv("NO_COLOR") == ""

	if opts.ui || (len(targets) == 0 && !opts.jsonOut) {
		return runUI(opts)
	}
	if len(targets) == 0 {
		fs.Usage()
		return 2
	}

	opts.logf = func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
	reports, errs := scanAll(targets, opts)
	if opts.vt {
		opts.logf("Querying VirusTotal…")
		vtLookup(reports, opts.vtKey, opts.vtDelay)
	}

	code := 0
	if opts.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]any{"reports": reports, "errors": errs})
	} else {
		for _, r := range reports {
			printReport(os.Stdout, r, painter{color}, opts.verbose)
		}
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "error:", e)
		}
		if len(reports) > 1 {
			fmt.Println("Summary:")
			for _, r := range reports {
				fmt.Printf("  %-9s %s\n", r.Max, r.Target)
			}
		}
		fmt.Println("Note: static analysis can't prove a mod is safe — it highlights what to review.")
	}
	for _, r := range reports {
		if r.Max >= opts.failOn && r.Max > Info {
			code = 1
		}
	}
	if len(errs) > 0 && code == 0 {
		code = 2
	}
	if shouldPause() {
		fmt.Print("\nPress Enter to close…")
		fmt.Scanln()
	}
	return code
}

// scanAll is shared by the CLI and the web UI.
func scanAll(targets []string, opts *options) ([]*Report, []string) {
	s := &scanner{opts: opts}
	logf := opts.logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var reports []*Report
	var errs []string
	visited := map[string]bool{}

	var scanPkg func(ns, name, ver string, depOf string)
	scanPkg = func(ns, name, ver, depOf string) {
		key := strings.ToLower(ns + "-" + name)
		if visited[key] {
			return
		}
		visited[key] = true
		logf("Downloading %s-%s %s…", ns, name, strings.TrimSpace(ver))
		meta, data, err := fetchPackage(ns, name, ver, opts.maxBytes)
		if err != nil {
			errs = append(errs, err.Error())
			return
		}
		target := meta.FullName
		if depOf != "" {
			target += "  (dependency of " + depOf + ")"
		}
		r, err := s.scanZipBytes(target, data, meta)
		if err != nil {
			errs = append(errs, err.Error())
			return
		}
		r.finalize()
		reports = append(reports, r)
		if opts.deps {
			for _, d := range meta.Dependencies {
				if m := specRe.FindStringSubmatch(d); m != nil {
					scanPkg(m[1], m[2], m[3], meta.FullName)
				}
			}
		}
	}

	for _, t := range targets {
		t = strings.TrimSpace(strings.Trim(strings.TrimSpace(t), `"`))
		if t == "" {
			continue
		}
		if st, err := os.Stat(t); err == nil {
			logf("Scanning %s…", t)
			switch {
			case st.IsDir():
				rs, err := s.scanDir(t)
				if err != nil {
					errs = append(errs, err.Error())
				}
				for _, r := range rs {
					r.finalize()
				}
				reports = append(reports, rs...)
			case strings.EqualFold(filepath.Ext(t), ".zip"):
				r, err := s.scanZipFile(t)
				if err != nil {
					errs = append(errs, err.Error())
					continue
				}
				r.finalize()
				reports = append(reports, r)
			default:
				r, err := s.scanSingleFile(t)
				if err != nil {
					errs = append(errs, err.Error())
					continue
				}
				r.finalize()
				reports = append(reports, r)
			}
			continue
		}
		if ns, name, ver, ok := parseSpec(t); ok {
			scanPkg(ns, name, ver, "")
			continue
		}
		errs = append(errs, fmt.Sprintf("%q is not an existing file/folder, a Thunderstore package name (Owner-Name) or a thunderstore.io URL", t))
	}
	return reports, errs
}
