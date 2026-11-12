package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func xorB64(s string, k byte) string {
	b := []byte(s)
	for i := range b {
		b[i] ^= k
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestDecodeHiddenPicksReadableXorKey(t *testing.T) {
	url := "https://discord.com/api/webhooks/000/placeholder"
	got := decodeHidden([]string{xorB64(url, 0x2A)})
	if len(got) != 1 || !strings.Contains(got[0], url) {
		t.Fatalf("want decoded %q, got %q", url, got)
	}
	plain := decodeHidden([]string{base64.StdEncoding.EncodeToString([]byte(url))})
	if len(plain) != 1 || !strings.HasPrefix(plain[0], "[base64] ") {
		t.Fatalf("plain base64 not decoded: %q", plain)
	}
	if n := decodeHidden([]string{"NotBase64 at all, has spaces", "short"}); len(n) != 0 {
		t.Fatalf("decoded junk: %q", n)
	}
}

func TestStartupFolderIL(t *testing.T) {
	tok := map[uint32]bool{0x0A000005: true}
	call := []byte{0x28, 0x05, 0x00, 0x00, 0x0A}
	cases := []struct {
		name string
		code []byte
		want bool
	}{
		{"ldc.i4.7", append([]byte{0x00, 0x1D}, call...), true},
		{"ldc.i4.s 24", append([]byte{0x1F, 24}, call...), true},
		{"ldc.i4 7", append([]byte{0x20, 7, 0, 0, 0}, call...), true},
		{"(7, option 0)", append([]byte{0x1D, 0x16}, call...), true},
		{"ApplicationData=26", append([]byte{0x1F, 26}, call...), false},
		{"Desktop=0", append([]byte{0x16}, call...), false},
		{"other token", []byte{0x1D, 0x28, 0x06, 0x00, 0x00, 0x0A}, false},
	}
	for _, c := range cases {
		if got := callsWithStartupFolder(c.code, tok); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestShellStringsWholeWord(t *testing.T) {
	var r *rule
	for i := range rules {
		if rules[i].ID == "SHELL_STRINGS" {
			r = &rules[i]
		}
	}
	hit := []string{`C:\Windows\System32\cmd.exe`, "cscript //nologo x.vbs", `\WindowsPowerShell\v1.0\powershell.exe`, "run pwsh -c"}
	miss := []string{"CodeRebirth.src.MiscScripts.WeatherController:Start", "WindowsPowerShellHelper", "rundll32x"}
	for _, x := range hit {
		s := newSignals()
		s.addStrings([]string{x})
		if len(matchRule(r, s, false)) == 0 {
			t.Errorf("should match: %q", x)
		}
	}
	for _, x := range miss {
		s := newSignals()
		s.addStrings([]string{x})
		if ev := matchRule(r, s, false); len(ev) > 0 {
			t.Errorf("false positive on %q: %v", x, ev)
		}
	}
}

func TestSplitAndExactMatchers(t *testing.T) {
	s := newSignals()
	s.addStrings([]string{"discord", "Local Storage", "leveldb", "WebClient, System", "updater.exe"})
	for _, id := range []string{"CREDENTIAL_PATH_PARTS", "SENSITIVE_NAME_PARTS", "EXECUTABLE_NAME"} {
		var r *rule
		for i := range rules {
			if rules[i].ID == id {
				r = &rules[i]
			}
		}
		if r == nil || len(matchRule(r, s, false)) == 0 {
			t.Errorf("%s did not fire", id)
		}
	}
	// "Processing..." must not count as the bare name "Process".
	s2 := newSignals()
	s2.addStrings([]string{"Processing items", "Local Storage only"})
	for i := range rules {
		if id := rules[i].ID; (id == "SENSITIVE_NAME_PARTS" || id == "CREDENTIAL_PATH_PARTS") && len(matchRule(&rules[i], s2, false)) > 0 {
			t.Errorf("%s false positive", id)
		}
	}
}
