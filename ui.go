package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed ui.html
var uiHTML []byte

// runUI serves a single-page UI on 127.0.0.1 only. A random per-run token is
// required on every API call so other websites open in the browser can't
// drive the scanner (CSRF / DNS-rebinding protection).
func runUI(base *options) int {
	tokb := make([]byte, 16)
	rand.Read(tokb)
	token := hex.EncodeToString(tokb)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base.port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not start UI:", err)
		return 2
	}
	addr := ln.Addr().String()
	url := "http://" + addr + "/?t=" + token

	var mu sync.Mutex // one scan at a time
	done := make(chan struct{})
	mux := http.NewServeMux()

	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Host != addr {
				http.Error(w, "bad host", http.StatusForbidden)
				return
			}
			if r.URL.Path != "/" {
				if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(token)) != 1 {
					http.Error(w, "bad token", http.StatusForbidden)
					return
				}
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			h(w, r)
		}
	}

	mux.HandleFunc("/", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:")
		w.Write(uiHTML)
	}))

	mux.HandleFunc("/api/scan", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, base.maxBytes*2)
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()

		opts := *base
		opts.deps = r.FormValue("deps") == "1"
		opts.logf = func(f string, a ...any) { fmt.Printf(f+"\n", a...) }

		var targets []string
		for _, line := range strings.Split(r.FormValue("targets"), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		reports, errs := scanAll(targets, &opts)

		s := &scanner{opts: &opts}
		if r.MultipartForm != nil {
			for _, fh := range r.MultipartForm.File["files"] {
				f, err := fh.Open()
				if err != nil {
					errs = append(errs, fh.Filename+": "+err.Error())
					continue
				}
				data, err := io.ReadAll(io.LimitReader(f, opts.maxBytes+1))
				f.Close()
				if err != nil {
					errs = append(errs, fh.Filename+": "+err.Error())
					continue
				}
				rep, err := s.scanUpload(fh.Filename, data)
				if err != nil {
					errs = append(errs, err.Error())
					continue
				}
				rep.finalize()
				reports = append(reports, rep)
			}
		}

		if key := strings.TrimSpace(r.FormValue("vtkey")); key != "" {
			vtLookup(reports, key, opts.vtDelay)
		}
		if reports == nil {
			reports = []*Report{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"reports": reports, "errors": errs})
	}))

	mux.HandleFunc("/api/quit", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		w.Write([]byte("bye"))
		go func() { time.Sleep(200 * time.Millisecond); close(done) }()
	}))

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)

	fmt.Println("thunderscan UI running at:")
	fmt.Println("  " + url)
	fmt.Println("Close this window (or press Quit in the page) to stop.")
	if !base.noOpen {
		if err := openBrowser(url); err != nil {
			fmt.Println("Open the address above in your browser.")
		}
	}
	<-done
	srv.Close()
	return 0
}

// scanUpload handles a file dropped into the UI: zips are scanned as
// packages, anything else as a single file.
func (s *scanner) scanUpload(name string, data []byte) (*Report, error) {
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return s.scanZipBytes(name, data, nil)
	}
	r := newReport(name)
	e := entry{Name: name, Size: int64(len(data)), Open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}}
	s.scanEntries(r, []entry{e}, "", 0)
	return r, nil
}
