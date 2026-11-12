package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const tsAPI = "https://thunderstore.io/api/experimental/package/"

var httpClient = &http.Client{Timeout: 5 * time.Minute}

type tsVersion struct {
	Namespace     string   `json:"namespace"`
	Name          string   `json:"name"`
	VersionNumber string   `json:"version_number"`
	FullName      string   `json:"full_name"`
	Dependencies  []string `json:"dependencies"`
	DownloadURL   string   `json:"download_url"`
	Downloads     int      `json:"downloads"`
	DateCreated   string   `json:"date_created"`
	WebsiteURL    string   `json:"website_url"`
}

type tsPackage struct {
	Namespace         string    `json:"namespace"`
	Name              string    `json:"name"`
	FullName          string    `json:"full_name"`
	Owner             string    `json:"owner"`
	PackageURL        string    `json:"package_url"`
	DateCreated       string    `json:"date_created"`
	IsDeprecated      bool      `json:"is_deprecated"`
	Latest            tsVersion `json:"latest"`
	CommunityListings []struct {
		Community    string `json:"community"`
		ReviewStatus string `json:"review_status"`
	} `json:"community_listings"`
}

var specRe = regexp.MustCompile(`^([A-Za-z0-9_]+)-([A-Za-z0-9_]+)(?:-(\d+\.\d+\.\d+))?$`)

// parseSpec accepts "Owner-Name", "Owner-Name-1.2.3" or a thunderstore.io URL.
func parseSpec(s string) (ns, name, ver string, ok bool) {
	s = strings.TrimSpace(s)
	if m := specRe.FindStringSubmatch(s); m != nil {
		return m[1], m[2], m[3], true
	}
	u, err := url.Parse(s)
	if err != nil || !strings.HasSuffix(strings.ToLower(u.Hostname()), "thunderstore.io") {
		return "", "", "", false
	}
	segs := strings.FieldsFunc(u.Path, func(r rune) bool { return r == '/' })
	for i, seg := range segs {
		if (seg == "p" || seg == "package" || seg == "download") && i+2 < len(segs) {
			if seg == "package" && segs[i+1] == "download" {
				continue
			}
			ns, name = segs[i+1], segs[i+2]
			if i+3 < len(segs) && verRe.MatchString(segs[i+3]) {
				ver = segs[i+3]
			} else if i+4 < len(segs) && segs[i+3] == "v" {
				ver = segs[i+4]
			}
			return ns, name, ver, nameRe.MatchString(ns) && nameRe.MatchString(name)
		}
	}
	return "", "", "", false
}

func getJSON(u string, v any) error {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "thunderscan/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return fmt.Errorf("package not found on Thunderstore")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("thunderstore API: %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
}

// fetchPackage downloads a package zip into memory along with its listing metadata.
func fetchPackage(ns, name, ver string, maxBytes int64) (*PackageMeta, []byte, error) {
	var pkg tsPackage
	if err := getJSON(tsAPI+url.PathEscape(ns)+"/"+url.PathEscape(name)+"/", &pkg); err != nil {
		return nil, nil, fmt.Errorf("%s-%s: %w", ns, name, err)
	}
	v := pkg.Latest
	if ver != "" && ver != v.VersionNumber {
		if err := getJSON(tsAPI+url.PathEscape(ns)+"/"+url.PathEscape(name)+"/"+url.PathEscape(ver)+"/", &v); err != nil {
			return nil, nil, fmt.Errorf("%s-%s-%s: %w", ns, name, ver, err)
		}
	}
	meta := &PackageMeta{
		FullName: v.FullName, Owner: pkg.Owner, Version: v.VersionNumber, LatestVersion: pkg.Latest.VersionNumber,
		PackageURL: pkg.PackageURL, WebsiteURL: v.WebsiteURL, Created: day(pkg.DateCreated), VersionCreated: day(v.DateCreated),
		Downloads: v.Downloads, Deprecated: pkg.IsDeprecated, Dependencies: v.Dependencies,
	}
	meta.Name, meta.Namespace = pkg.Name, pkg.Namespace
	counts := map[string]int{}
	for _, l := range pkg.CommunityListings {
		counts[l.ReviewStatus]++
		if len(pkg.CommunityListings) <= 3 {
			meta.Reviews = append(meta.Reviews, l.Community+": "+l.ReviewStatus)
		}
	}
	if len(pkg.CommunityListings) > 3 {
		for _, st := range []string{"approved", "unreviewed", "rejected"} {
			if counts[st] > 0 {
				meta.Reviews = append(meta.Reviews, fmt.Sprintf("%s in %d communities", st, counts[st]))
			}
		}
	}
	meta.reviewCounts = counts

	dl := v.DownloadURL
	if dl == "" {
		dl = fmt.Sprintf("https://thunderstore.io/package/download/%s/%s/%s/", ns, name, v.VersionNumber)
	}
	req, _ := http.NewRequest("GET", dl, nil)
	req.Header.Set("User-Agent", "thunderscan/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("download %s: %s", v.FullName, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes*2+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maxBytes*2 {
		return nil, nil, fmt.Errorf("%s: download exceeds size limit", v.FullName)
	}
	meta.pkgCreatedRaw, meta.verCreatedRaw = pkg.DateCreated, v.DateCreated
	return meta, data, nil
}

func day(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

func packageMetaFindings(r *Report, m *PackageMeta) {
	c := m.reviewCounts
	switch {
	case c["rejected"] > 0 && c["approved"] == 0 && c["unreviewed"] == 0:
		r.add(High, "LISTING_REJECTED", "", "Thunderstore moderators rejected this listing", "", strings.Join(m.Reviews, ", "))
	case c["rejected"] > 0:
		r.add(Info, "LISTING_PARTLY_REJECTED", "", "Rejected in some game communities (usually just 'wrong game')", "", strings.Join(m.Reviews, ", "))
	case c["approved"] == 0 && c["unreviewed"] > 0:
		r.add(Info, "LISTING_UNREVIEWED", "", "Listing not yet reviewed by Thunderstore moderators", "", strings.Join(m.Reviews, ", "))
	}
	if m.Deprecated {
		r.add(Medium, "DEPRECATED", "", "Package is marked deprecated", "Deprecated packages are often abandoned, broken, or were pulled for a reason.")
	}
	if t, err := time.Parse(time.RFC3339Nano, m.pkgCreatedRaw); err == nil {
		if age := time.Since(t); age < 7*24*time.Hour {
			r.add(Medium, "NEW_PACKAGE", "", "Brand-new package (under 7 days old)",
				"Most malicious uploads are new accounts/packages that get removed within days.", "created "+m.Created)
		}
	}
	if t, err := time.Parse(time.RFC3339Nano, m.verCreatedRaw); err == nil && time.Since(t) < 48*time.Hour {
		r.add(Low, "NEW_VERSION", "", "This version was uploaded in the last 48 hours",
			"Compromised accounts push malicious updates to popular mods; the community may not have noticed yet.", "uploaded "+m.VersionCreated)
	}
	if m.Downloads < 200 {
		r.add(Low, "LOW_DOWNLOADS", "", "Very few downloads", "Little community exposure — problems are less likely to have been reported.", fmt.Sprintf("%d downloads", m.Downloads))
	}
	if m.WebsiteURL == "" {
		r.add(Low, "NO_SOURCE_LINK", "", "No website/source link", "Open-source mods are much easier to trust.")
	}
	if m.LatestVersion != "" && m.LatestVersion != m.Version {
		r.add(Info, "NOT_LATEST", "", "Not the latest version", "", "latest is "+m.LatestVersion)
	}
}
