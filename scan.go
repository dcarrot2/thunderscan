package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// entry is one file inside a package, whether from a zip or a folder.
type entry struct {
	Name     string // forward-slash path relative to package root
	RawName  string // original zip name (for traversal checks); empty for folders
	Size     int64
	CompSize int64 // 0 if not applicable
	Open     func() (io.ReadCloser, error)
}

type scanner struct{ opts *options }

var (
	peExts   = set(".dll", ".exe", ".scr", ".sys", ".com", ".pif", ".ocx", ".cpl", ".drv", ".efi", ".mui")
	textExts = set(".cfg", ".json", ".txt", ".xml", ".yml", ".yaml", ".ini", ".md", ".lua", ".cs", ".ps1", ".psm1",
		".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".sh", ".hta", ".wsf", ".reg", ".url", ".toml", ".csv")
	decoyExts   = set(".txt", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".doc", ".docx", ".mp3", ".mp4", ".wav", ".zip", ".json", ".cfg", ".md", ".html")
	archiveExts = set(".rar", ".7z", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".cab", ".iso", ".img")
	proxyDLLs   = set("winhttp.dll", "version.dll", "winmm.dll", "dinput8.dll", "d3d11.dll", "d3d9.dll", "dxgi.dll",
		"dsound.dll", "xinput1_3.dll", "xinput1_4.dll", "winspool.drv", "iphlpapi.dll", "dbghelp.dll", "msacm32.dll")
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	verRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	depRe  = regexp.MustCompile(`^[A-Za-z0-9_]+-[A-Za-z0-9_]+-\d+\.\d+\.\d+$`)
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func zipEntries(zr *zip.Reader) []entry {
	var out []entry
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		f := f
		out = append(out, entry{
			Name:     strings.TrimLeft(strings.ReplaceAll(f.Name, "\\", "/"), "/"),
			RawName:  f.Name,
			Size:     int64(f.UncompressedSize64),
			CompSize: int64(f.CompressedSize64),
			Open:     f.Open,
		})
	}
	return out
}

func checkZipPath(r *Report, prefix, raw string) {
	n := strings.ReplaceAll(raw, "\\", "/")
	bad := strings.HasPrefix(n, "/") || (len(n) > 1 && n[1] == ':') || strings.Contains(n, "\x00")
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			bad = true
		}
	}
	if bad {
		r.add(Critical, "PATH_TRAVERSAL", prefix+raw, "Archive entry escapes the install folder (zip-slip)",
			"Entries with '..' or absolute paths can overwrite files anywhere on disk when extracted by a mod manager.", raw)
	}
}

func (s *scanner) scanEntries(r *Report, entries []entry, prefix string, depth int) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for _, e := range entries {
		s.scanEntry(r, e, prefix, depth)
	}
	if depth == 0 && r.expectManifest && r.Manifest == nil {
		r.add(Medium, "NO_MANIFEST", "", "No manifest.json at package root",
			"Every Thunderstore package has a root manifest.json. This may not be a genuine Thunderstore package.")
	}
}

func (s *scanner) scanEntry(r *Report, e entry, prefix string, depth int) {
	name := prefix + e.Name
	if e.RawName != "" {
		checkZipPath(r, prefix, e.RawName)
	}
	ext := strings.ToLower(path.Ext(e.Name))
	base := strings.ToLower(path.Base(e.Name))

	if e.Size > s.opts.maxBytes {
		r.add(High, "OVERSIZED_FILE", name, "File too large to scan", fmt.Sprintf("Over the -max-mb limit (%d MB); not analysed.", s.opts.maxBytes>>20))
		r.Files = append(r.Files, FileInfo{Path: name, Size: e.Size})
		return
	}
	if e.CompSize > 0 && e.Size > 50<<20 && e.Size/e.CompSize > 200 {
		r.add(High, "ZIP_BOMB", name, "Extreme compression ratio (possible zip bomb)", "", fmt.Sprintf("%d bytes → %d bytes", e.CompSize, e.Size))
		r.Files = append(r.Files, FileInfo{Path: name, Size: e.Size})
		return
	}

	rc, err := e.Open()
	if err != nil {
		r.add(Medium, "UNREADABLE", name, "Could not read file", err.Error())
		return
	}
	defer rc.Close()
	br := bufio.NewReaderSize(rc, 64<<10)
	head, _ := br.Peek(8)
	isPE := len(head) >= 2 && head[0] == 'M' && head[1] == 'Z'
	isZip := bytes.HasPrefix(head, []byte("PK\x03\x04"))
	isText := textExts[ext] && e.Size < 4<<20 && !isPE && !isZip

	// ---- file type / extension checks ----
	if isPE && !peExts[ext] {
		r.add(Critical, "DISGUISED_EXECUTABLE", name, "Windows executable disguised with a non-executable extension",
			"The file starts with an 'MZ' PE header but is named like a '"+ext+"' file. Hiding binaries is a malware trick.")
	}
	switch ext {
	case ".exe":
		r.add(High, "EXECUTABLE_FILE", name, "Ships a standalone .exe",
			"Thunderstore mods are loaded by BepInEx/MelonLoader as DLLs; a bundled .exe is unusual and runs outside the game sandbox if launched.")
	case ".scr", ".pif", ".com", ".sys", ".drv", ".efi":
		r.add(Critical, "DANGEROUS_BINARY_TYPE", name, "Screensaver/driver/legacy executable type", "This file type is essentially never legitimate in a game mod.")
	case ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sh":
		r.add(High, "SCRIPT_FILE", name, "Ships a script file", "Scripts are not loaded by mod loaders; check what it does and whether you are told to run it.")
	case ".lnk", ".url", ".reg", ".msi", ".msix", ".appx", ".jar", ".cpl", ".ocx", ".application", ".appref-ms":
		r.add(High, "RISKY_FILE_TYPE", name, "Risky Windows file type ("+ext+")", "Shortcuts, registry imports and installers can execute code or change the system when opened.")
	}
	if archiveExts[ext] {
		r.add(Medium, "NESTED_ARCHIVE", name, "Nested archive that this tool cannot open", "Its contents were NOT scanned.")
	}
	if inner := strings.ToLower(path.Ext(strings.TrimSuffix(base, ext))); peExts[ext] && decoyExts[inner] {
		r.add(High, "DOUBLE_EXTENSION", name, "Executable disguised with a double extension",
			"Names like 'readme.txt.exe' trick users into running a program they think is a document.")
	}
	if e.Size == 0 {
		return
	}

	h := sha256.New()
	var data []byte
	if isPE || isZip || isText {
		data, err = io.ReadAll(io.LimitReader(br, s.opts.maxBytes+1))
		h.Write(data)
	} else {
		_, err = io.Copy(h, br)
	}
	if err != nil {
		r.add(Medium, "UNREADABLE", name, "Error while reading file (corrupt archive?)", err.Error())
	}
	fi := FileInfo{Path: name, Size: e.Size, SHA256: hex.EncodeToString(h.Sum(nil))}

	switch {
	case isPE:
		s.analyzePE(r, &fi, data, base)
		if strings.Contains(strings.ToLower(name), "/patchers/") || strings.HasPrefix(strings.ToLower(name), "patchers/") {
			r.add(Info, "PRELOADER_PATCHER", name, "BepInEx preloader patcher", "Runs before the game's own code — review with extra care.")
		}
	case isZip:
		fi.Kind = "zip"
		if depth >= 3 {
			r.add(Medium, "DEEP_NESTING", name, "Deeply nested archive not scanned", "")
			break
		}
		zr, zerr := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if zerr != nil {
			r.add(Medium, "BAD_NESTED_ZIP", name, "Nested zip could not be opened", zerr.Error())
			break
		}
		r.add(Low, "NESTED_ZIP", name, "Contains a nested zip (scanned recursively)", "")
		s.scanEntries(r, zipEntries(zr), name+"!/", depth+1)
	case isText:
		sg := newSignals()
		sg.addStrings([]string{string(data)})
		applyRules(r, name, sg, true)
		if base == "manifest.json" && depth == 0 && !strings.Contains(e.Name, "/") {
			s.checkManifest(r, data)
		}
	}
	r.Files = append(r.Files, fi)
}

func (s *scanner) checkManifest(r *Report, data []byte) {
	data = bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF"))
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		r.add(Medium, "INVALID_MANIFEST", "manifest.json", "manifest.json is not valid JSON", err.Error())
		return
	}
	r.Manifest = &m
	if !nameRe.MatchString(m.Name) {
		r.add(Low, "MANIFEST_NAME", "manifest.json", "Manifest name is not a valid Thunderstore name", "", m.Name)
	}
	if !verRe.MatchString(m.VersionNumber) {
		r.add(Low, "MANIFEST_VERSION", "manifest.json", "Manifest version is not Major.Minor.Patch", "", m.VersionNumber)
	}
	for _, d := range m.Dependencies {
		if !depRe.MatchString(d) {
			r.add(Low, "MANIFEST_DEPENDENCY", "manifest.json", "Malformed dependency string", "", d)
		}
	}
	if p := r.Package; p != nil {
		want := p.Name
		if !strings.EqualFold(m.Name, want) || m.VersionNumber != p.Version {
			r.add(High, "MANIFEST_MISMATCH", "manifest.json", "manifest.json does not match the Thunderstore listing",
				"Could indicate a repackaged/impersonating upload.", fmt.Sprintf("manifest: %s %s, listing: %s %s", m.Name, m.VersionNumber, want, p.Version))
		}
	}
}

func (s *scanner) analyzePE(r *Report, fi *FileInfo, data []byte, base string) {
	s.analyzePEAt(r, fi, data, base, 0)
}

// analyzePEAt is analyzePE with the nesting depth of embedded assemblies.
func (s *scanner) analyzePEAt(r *Report, fi *FileInfo, data []byte, base string, depth int) {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		fi.Kind = "PE(malformed)"
		r.add(Medium, "MALFORMED_PE", fi.Path, "Malformed Windows binary", "Could not be parsed; may be corrupt or deliberately mangled to resist analysis.", err.Error())
		return
	}
	defer f.Close()

	sg := newSignals()
	var nativeImports []string
	if syms, err := f.ImportedSymbols(); err == nil {
		for _, sym := range syms {
			fn, dll := sym, ""
			if i := strings.IndexByte(sym, ':'); i >= 0 {
				fn, dll = sym[:i], strings.ToLower(sym[i+1:])
			}
			sg.pinvoke = append(sg.pinvoke, fn)
			if dll != "mscoree.dll" {
				nativeImports = append(nativeImports, sym)
			}
		}
	}

	meta, merr := parseCLR(f, data)
	if meta == nil && merr == nil {
		fi.Kind = "native"
		why := "Unmanaged code can do anything and cannot be decompiled to C#. Some mods legitimately ship native libraries (audio, physics); make sure you trust the author."
		if proxyDLLs[base] {
			r.add(High, "PROXY_DLL", fi.Path, "DLL named to be auto-loaded by the game ("+base+")",
				"Windows loads this DLL from the game folder automatically at launch (DLL hijacking). Expected ONLY from the mod loader itself (e.g. BepInEx's Doorstop winhttp.dll).")
		}
		r.add(High, "NATIVE_BINARY", fi.Path, "Native (non-.NET) binary", why)
		sg.addStrings(extractStrings(data, 6))
		applyRules(r, fi.Path, sg, false)
		s.checkEmbedded(r, fi.Path, data)
		return
	}

	fi.Kind = ".NET"
	if merr != nil {
		r.add(Medium, "METADATA_UNREADABLE", fi.Path, ".NET metadata could not be parsed",
			"Often caused by obfuscators/protectors that corrupt headers to break decompilers.", merr.Error())
	}
	if meta != nil {
		if meta.ParseErr != nil {
			r.add(Medium, "METADATA_TABLES_UNREADABLE", fi.Path, ".NET metadata tables could not be parsed",
				"Only string heaps were analysed. Can be a sign of anti-analysis tampering.", meta.ParseErr.Error())
		}
		for _, t := range meta.TypeRefs {
			sg.types[t] = true
		}
		for _, m := range meta.MemberRefs {
			sg.members[m] = true
			if i := strings.Index(m, "::"); i >= 0 {
				sg.types[m[:i]] = true
			}
		}
		for _, id := range meta.StringHeap {
			sg.idents[id] = true
		}
		sg.pinvoke = append(sg.pinvoke, meta.PInvokes...)
		sg.addStrings(meta.UserStrings)
		sg.addStrings(decodeHidden(meta.UserStrings))
		for k := range meta.ILFacts {
			sg.il[k] = true
		}
		if len(meta.PInvokes) > 0 {
			mods := uniq(meta.ModuleRefs)
			r.add(Info, "PINVOKE", fi.Path, "Calls native Windows/library functions (P/Invoke)", "", "modules: "+strings.Join(mods, ", "))
		}
		obfuscationHeuristics(r, fi.Path, meta)
		if len(meta.ResourcesData) > 256<<10 {
			if e := entropy(meta.ResourcesData); e > 7.95 {
				r.add(Low, "OPAQUE_RESOURCES", fi.Path, "Large compressed/encrypted embedded resources",
					"Usually bundled assets (asset bundles, images, sounds). Contents can't be inspected statically; only a concern alongside DYNAMIC_ASSEMBLY_LOAD or decoding findings.",
					fmt.Sprintf("%d KB, entropy %.2f bits/byte", len(meta.ResourcesData)>>10, e))
			}
		}
		costura := false
		for _, id := range meta.StringHeap {
			if strings.HasPrefix(strings.ToLower(id), "costura") {
				costura = true
				break
			}
		}
		found := s.scanResources(r, fi.Path, meta.ResourcesData, depth)
		switch {
		case costura && found > 0:
			r.add(Info, "COSTURA", fi.Path, "Bundles embedded dependency DLLs (Costura.Fody)", fmt.Sprintf("%d embedded binaries were unpacked and scanned (listed as %s!/resource#N).", found, path.Base(fi.Path)))
		case costura:
			r.add(Low, "COSTURA", fi.Path, "Bundles embedded dependency DLLs (Costura.Fody), but none could be unpacked",
				"The embedded DLLs may use a format this tool doesn't read (e.g. encrypted), so they were NOT scanned.")
		}
	}
	if len(nativeImports) > 0 {
		fi.Kind = ".NET(mixed)"
		r.add(Medium, "MIXED_MODE", fi.Path, "Mixed-mode assembly (contains native code)", "Part of this DLL is native code that decompilers can't show.")
	}
	applyRules(r, fi.Path, sg, false)
	s.checkEmbedded(r, fi.Path, data)
}

// scanResources walks a .NET assembly's managed resources (each stored as a
// 4-byte length + bytes) and scans any that are, or inflate/gunzip to, a PE
// file — this is how Costura.Fody and many loaders embed DLLs. It returns how
// many embedded binaries were scanned.
func (s *scanner) scanResources(r *Report, owner string, res []byte, depth int) int {
	if depth >= 2 || len(res) == 0 {
		return 0
	}
	found := 0
	for i, p := 0, 0; p+4 <= len(res) && i < 4096; i++ {
		n := int(binary.LittleEndian.Uint32(res[p:]))
		p += 4
		if n < 0 || n > len(res)-p {
			break
		}
		chunk := res[p : p+n]
		p += n
		bin, how := s.unpackPE(chunk)
		if bin == nil {
			continue
		}
		found++
		name := fmt.Sprintf("%s!/resource#%d", owner, i)
		sum := sha256.Sum256(bin)
		fi := FileInfo{Path: name, Size: int64(len(bin)), SHA256: hex.EncodeToString(sum[:])}
		r.add(Info, "EMBEDDED_PE_SCANNED", name, "Embedded binary unpacked and scanned", "Stored "+how+" inside "+path.Base(owner)+".")
		s.analyzePEAt(r, &fi, bin, path.Base(name), depth+1)
		r.Files = append(r.Files, fi)
	}
	return found
}

func (s *scanner) unpackPE(chunk []byte) ([]byte, string) {
	isPE := func(b []byte) bool { return len(b) > 64 && b[0] == 'M' && b[1] == 'Z' }
	if isPE(chunk) {
		return chunk, "uncompressed"
	}
	limit := s.opts.maxBytes
	if limit > 64<<20 { // embedded DLLs are small; don't let a hostile stream inflate to the full file limit
		limit = 64 << 20
	}
	read := func(rc io.Reader) []byte {
		b, err := io.ReadAll(io.LimitReader(rc, limit))
		if err != nil && len(b) < 64 {
			return nil
		}
		return b
	}
	if len(chunk) > 2 && chunk[0] == 0x1F && chunk[1] == 0x8B {
		if zr, err := gzip.NewReader(bytes.NewReader(chunk)); err == nil {
			if b := read(zr); isPE(b) {
				return b, "gzip-compressed"
			}
		}
	}
	if b := read(flate.NewReader(bytes.NewReader(chunk))); isPE(b) {
		return b, "deflate-compressed"
	}
	return nil, ""
}

func (s *scanner) checkEmbedded(r *Report, file string, data []byte) {
	if n := bytes.Count(data, []byte("This program cannot be run in DOS mode")); n > 1 {
		r.add(High, "EMBEDDED_EXECUTABLE", file, "Contains embedded executable(s)",
			"Another PE file is stored inside this binary and could be dropped to disk or loaded from memory.", fmt.Sprintf("%d PE headers found", n))
	}
}

func obfuscationHeuristics(r *Report, file string, m *clrMeta) {
	total, weird := 0, 0
	var examples []string
	for _, n := range m.DefNames {
		if n == "" || n == ".ctor" || n == ".cctor" || strings.HasPrefix(n, "<") {
			continue
		}
		total++
		if isWeirdName(n) {
			weird++
			if len(examples) < 4 {
				examples = append(examples, fmt.Sprintf("%q", n))
			}
		}
	}
	if total >= 20 && float64(weird)/float64(total) > 0.15 {
		r.add(High, "OBFUSCATED_NAMES", file, "Identifiers look obfuscated",
			"A large share of type/method/field names contain invisible, control or private-use characters — typical of ConfuserEx-style obfuscation.",
			append([]string{fmt.Sprintf("%d of %d names", weird, total)}, examples...)...)
	}
}

func isWeirdName(n string) bool {
	if !utf8.ValidString(n) {
		return true
	}
	for _, c := range n {
		if unicode.Is(unicode.Cf, c) || unicode.Is(unicode.Co, c) || unicode.IsControl(c) || c == utf8.RuneError || (c >= 0xD800 && c <= 0xDFFF) {
			return true
		}
	}
	return false
}

func entropy(b []byte) float64 {
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	e, n := 0.0, float64(len(b))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// extractStrings pulls printable ASCII and UTF-16LE runs out of a native binary.
func extractStrings(b []byte, min int) []string {
	var out []string
	start := -1
	for i := 0; i <= len(b); i++ {
		if i < len(b) && b[i] >= 0x20 && b[i] < 0x7F {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= min {
			out = append(out, string(b[start:i]))
		}
		start = -1
	}
	var sb []byte
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] >= 0x20 && b[i] < 0x7F && b[i+1] == 0 {
			sb = append(sb, b[i])
			continue
		}
		if len(sb) >= min {
			out = append(out, string(sb))
		}
		sb = sb[:0]
	}
	if len(sb) >= min {
		out = append(out, string(sb))
	}
	return out
}

func uniq(xs []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x != "" && !m[strings.ToLower(x)] {
			m[strings.ToLower(x)] = true
			out = append(out, x)
		}
	}
	return out
}

// ---- input sources ----

func (s *scanner) scanZipBytes(target string, data []byte, meta *PackageMeta) (*Report, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%s: not a valid zip: %w", target, err)
	}
	r := newReport(target)
	r.Package = meta
	r.expectManifest = true
	if meta != nil {
		packageMetaFindings(r, meta)
	}
	s.scanEntries(r, zipEntries(zr), "", 0)
	return r, nil
}

func (s *scanner) scanZipFile(p string) (*Report, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.Size() > s.opts.maxBytes*2 {
		return nil, fmt.Errorf("%s: archive larger than limit", p)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return s.scanZipBytes(filepath.Base(p), data, nil)
}

func fileEntry(full, rel string, size int64) entry {
	return entry{Name: rel, Size: size, Open: func() (io.ReadCloser, error) { return os.Open(full) }}
}

func (s *scanner) scanSingleFile(p string) (*Report, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	r := newReport(filepath.Base(p))
	s.scanEntries(r, []entry{fileEntry(p, filepath.Base(p), st.Size())}, "", 0)
	return r, nil
}

// scanDir treats every folder containing a manifest.json as a package (the way
// r2modman / Thunderstore Mod Manager lay out BepInEx/plugins). Files not under
// any package are grouped into one extra report.
func (s *scanner) scanDir(root string) ([]*Report, error) {
	root, _ = filepath.Abs(root)
	type file struct {
		full string
		size int64
	}
	var files []file
	pkgRoots := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		files = append(files, file{p, info.Size()})
		if strings.EqualFold(d.Name(), "manifest.json") {
			pkgRoots[filepath.Dir(p)] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	groups := map[string][]entry{}
	const loose = "\x00loose"
	for _, f := range files {
		best := ""
		for dir := filepath.Dir(f.full); ; dir = filepath.Dir(dir) {
			if pkgRoots[dir] {
				best = dir
				break
			}
			if dir == root || dir == filepath.Dir(dir) {
				break
			}
		}
		key, base := best, best
		if best == "" {
			key, base = loose, root
		}
		rel, _ := filepath.Rel(base, f.full)
		groups[key] = append(groups[key], fileEntry(f.full, filepath.ToSlash(rel), f.size))
	}

	var keys []string
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var reports []*Report
	for _, k := range keys {
		var r *Report
		if k == loose {
			r = newReport(filepath.Base(root) + " (files not inside any mod package)")
			r.looseGroup = true
		} else {
			rel, _ := filepath.Rel(filepath.Dir(root), k)
			r = newReport(rel)
			r.expectManifest = true
		}
		s.scanEntries(r, groups[k], "", 0)
		reports = append(reports, r)
	}
	return reports, nil
}
