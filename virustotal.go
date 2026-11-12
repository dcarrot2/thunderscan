package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// vtLookup checks file hashes (never the files themselves) against VirusTotal.
func vtLookup(reports []*Report, key string, delay time.Duration) {
	cache := map[string]*VTResult{}
	first := true
	for _, r := range reports {
		for i := range r.Files {
			f := &r.Files[i]
			if f.SHA256 == "" || !(strings.HasPrefix(f.Kind, ".NET") || strings.HasPrefix(f.Kind, "native") || strings.HasPrefix(f.Kind, "PE")) {
				continue
			}
			res, ok := cache[f.SHA256]
			if !ok {
				if !first {
					time.Sleep(delay)
				}
				first = false
				res = vtQuery(f.SHA256, key)
				cache[f.SHA256] = res
			}
			f.VT = res
			switch {
			case res.Malicious >= 3:
				r.add(Critical, "VT_DETECTED", f.Path, "Flagged as malicious by VirusTotal engines", "", fmt.Sprintf("%d malicious, %d suspicious — %s", res.Malicious, res.Suspicious, res.Link))
			case res.Malicious > 0 || res.Suspicious > 0:
				r.add(High, "VT_SOME_DETECTIONS", f.Path, "A few VirusTotal engines flag this file", "1–2 detections are often false positives for mods, but check the names.", fmt.Sprintf("%d malicious, %d suspicious — %s", res.Malicious, res.Suspicious, res.Link))
			case res.Found:
				r.add(Info, "VT_CLEAN", f.Path, "Known to VirusTotal with no detections", "")
			}
		}
		r.finalize()
	}
}

func vtQuery(sha, key string) *VTResult {
	res := &VTResult{Link: "https://www.virustotal.com/gui/file/" + sha}
	req, _ := http.NewRequest("GET", "https://www.virustotal.com/api/v3/files/"+sha, nil)
	req.Header.Set("x-apikey", key)
	resp, err := httpClient.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 404:
		return res
	case 200:
	default:
		res.Error = resp.Status
		return res
	}
	var body struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&body); err != nil {
		res.Error = err.Error()
		return res
	}
	st := body.Data.Attributes.Stats
	res.Found, res.Malicious, res.Suspicious, res.Harmless = true, st.Malicious, st.Suspicious, st.Undetected
	return res
}
