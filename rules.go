package main

import (
	"regexp"
	"sort"
	"strings"
)

// signals is everything extracted from one file that rules can match on.
type signals struct {
	types   map[string]bool // referenced type full names
	members map[string]bool // "Type::Member"
	idents  map[string]bool // raw #Strings heap entries
	pinvoke []string        // P/Invoke + native import function names
	strs    []string        // user strings / extracted literals
	lower   []string
}

func newSignals() *signals {
	return &signals{types: map[string]bool{}, members: map[string]bool{}, idents: map[string]bool{}}
}

func (s *signals) addStrings(xs []string) {
	for _, x := range xs {
		s.strs = append(s.strs, x)
		s.lower = append(s.lower, strings.ToLower(x))
	}
}

type rule struct {
	ID      string
	Sev     Severity
	Title   string
	Why     string
	Types   []string // exact referenced type
	Members []string // exact "Type::Member"
	PInvoke []string // native function, A/W/Ex suffix-insensitive
	Strings []string // case-insensitive substring of string literals
	Idents  []string // exact identifier in the #Strings heap
	TextToo bool     // also apply Strings to plain-text files (configs, scripts)
}

var rules = []rule{
	// ---- execution ----
	{ID: "PROCESS_START", Sev: High, Title: "Can launch external programs",
		Why:     "Calls Process.Start. Game mods almost never need to run other programs; malware uses this to run droppers or shell commands. (Occasionally used to open a URL or folder.)",
		Members: []string{"System.Diagnostics.Process::Start"}, Types: []string{"System.Diagnostics.ProcessStartInfo"}},
	{ID: "SHELL_STRINGS", Sev: High, Title: "References Windows shells / LOLBins",
		Why:     "Contains command-line tool names commonly abused to run payloads.",
		Strings: []string{"cmd.exe", "cmd /c", "powershell", "pwsh", "-encodedcommand", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "schtasks", "vssadmin", "wmic ", "reg add", "Add-MpPreference", "Set-MpPreference"}},
	{ID: "NATIVE_EXEC", Sev: High, Title: "Native process execution API",
		Why:     "Imports Win32 functions that start processes directly.",
		PInvoke: []string{"WinExec", "ShellExecute", "CreateProcess", "CreateProcessAsUser"}},
	{ID: "NATIVE_DOWNLOAD", Sev: Critical, Title: "Native file download API",
		Why:     "URLDownloadToFile is a classic dropper primitive.",
		PInvoke: []string{"URLDownloadToFile", "URLDownloadToCacheFile", "InternetOpenUrl", "WinHttpOpen"}},

	// ---- code loading ----
	{ID: "DYNAMIC_ASSEMBLY_LOAD", Sev: Medium, Title: "Loads .NET code at runtime",
		Why:     "Assembly.Load* can run code that is not visible in this file. Legit for some dependency loaders; dangerous combined with downloads or decoding.",
		Members: []string{"System.Reflection.Assembly::Load", "System.Reflection.Assembly::LoadFile", "System.Reflection.Assembly::LoadFrom", "System.Reflection.Assembly::UnsafeLoadFrom", "System.AppDomain::Load", "System.Reflection.Assembly::LoadWithPartialName"}},
	{ID: "BASE64_DECODE", Sev: Low, Title: "Decodes Base64",
		Why:     "Common and usually harmless, but also used to hide payloads/URLs.",
		Members: []string{"System.Convert::FromBase64String"}},
	{ID: "CRYPTO", Sev: Low, Title: "Uses symmetric encryption",
		Why:   "Unusual in game mods; can be used to decrypt hidden payloads.",
		Types: []string{"System.Security.Cryptography.RijndaelManaged", "System.Security.Cryptography.Aes", "System.Security.Cryptography.AesManaged", "System.Security.Cryptography.AesCryptoServiceProvider", "System.Security.Cryptography.DESCryptoServiceProvider", "System.Security.Cryptography.TripleDESCryptoServiceProvider", "System.Security.Cryptography.RC2CryptoServiceProvider"}},
	{ID: "REFLECTION_EVASION", Sev: High, Title: "Sensitive APIs named in string literals",
		Why:     "Dangerous type/DLL names appearing as strings suggests they are resolved via reflection to hide them from scanners.",
		Strings: []string{"System.Diagnostics.Process", "System.Net.WebClient", "System.Net.Http.HttpClient", "System.Reflection.Assembly", "Microsoft.Win32.Registry", "kernel32", "ntdll", "advapi32", "urlmon"}},

	// ---- memory / injection ----
	{ID: "PROCESS_INJECTION", Sev: Critical, Title: "Process injection APIs",
		Why:     "These functions write into or create threads in other processes — standard malware injection technique.",
		PInvoke: []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "NtCreateThreadEx", "RtlCreateUserThread", "NtWriteVirtualMemory"}},
	{ID: "SHELLCODE_APIS", Sev: High, Title: "Executable-memory APIs",
		Why:     "VirtualAlloc/VirtualProtect/CreateThread from a mod can indicate in-memory shellcode execution.",
		PInvoke: []string{"VirtualAlloc", "VirtualProtect", "CreateThread"}},
	{ID: "DYNAMIC_NATIVE_LOAD", Sev: Medium, Title: "Resolves native functions dynamically",
		Why:     "LoadLibrary/GetProcAddress hide which native functions are used.",
		PInvoke: []string{"LoadLibrary", "GetProcAddress", "LdrLoadDll"}},

	// ---- spying ----
	{ID: "KEYLOG_SPY", Sev: High, Title: "Keyboard hook / global key polling",
		Why:     "Global hooks and GetAsyncKeyState are keylogger primitives; Unity mods use Unity's Input system instead.",
		PInvoke: []string{"SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState", "RegisterRawInputDevices"}},
	{ID: "SCREEN_CAPTURE", Sev: Medium, Title: "Captures the screen",
		Why:     "Desktop screenshots are a common stealer feature.",
		Members: []string{"System.Drawing.Graphics::CopyFromScreen"}, PInvoke: []string{"BitBlt", "GetDesktopWindow"}},
	{ID: "CLIPBOARD", Sev: Low, Title: "Accesses the clipboard",
		Why:     "Usually copy/paste features; crypto 'clippers' also do this.",
		Members: []string{"UnityEngine.GUIUtility::get_systemCopyBuffer", "System.Windows.Forms.Clipboard::GetText", "System.Windows.Forms.Clipboard::SetText"},
		PInvoke: []string{"GetClipboardData", "SetClipboardData"}},
	{ID: "PROCESS_ENUM", Sev: Medium, Title: "Enumerates or kills other processes",
		Why:     "Used by malware to find AV / analysis tools or target processes.",
		Members: []string{"System.Diagnostics.Process::GetProcesses", "System.Diagnostics.Process::GetProcessesByName", "System.Diagnostics.Process::GetProcessById"},
		PInvoke: []string{"CreateToolhelp32Snapshot", "Process32First", "OpenProcess", "TerminateProcess"}},
	{ID: "ANTI_DEBUG", Sev: Medium, Title: "Anti-debugging checks",
		Why:     "Legit mods have no reason to detect debuggers.",
		Members: []string{"System.Diagnostics.Debugger::get_IsAttached"},
		PInvoke: []string{"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "NtSetInformationThread"}},
	{ID: "WMI", Sev: Medium, Title: "WMI queries (system fingerprinting)",
		Why:     "WMI is used to fingerprint machines, detect VMs/AV and execute commands.",
		Types:   []string{"System.Management.ManagementObjectSearcher", "System.Management.ManagementClass"},
		Strings: []string{"Win32_Process", "Win32_ComputerSystem", "AntiVirusProduct", "Win32_VideoController", "root\\SecurityCenter"}},
	{ID: "USER_IDENTITY", Sev: Low, Title: "Reads user/machine identity",
		Why:     "Collecting user name / machine name is fingerprinting; harmless alone.",
		Members: []string{"System.Environment::get_UserName", "System.Environment::get_MachineName", "System.Security.Principal.WindowsIdentity::GetCurrent", "System.Environment::get_UserDomainName"}},

	// ---- system modification ----
	{ID: "REGISTRY", Sev: Medium, Title: "Reads/writes the Windows registry",
		Why:   "Mods rarely need the registry; malware uses it for persistence and to read stored secrets.",
		Types: []string{"Microsoft.Win32.Registry", "Microsoft.Win32.RegistryKey"}},
	{ID: "PERSISTENCE", Sev: Critical, Title: "Persistence locations",
		Why:     "References autorun registry keys, the Startup folder or scheduled tasks.",
		Strings: []string{"CurrentVersion\\Run", "CurrentVersion\\RunOnce", "Start Menu\\Programs\\Startup", "schtasks /create", "Winlogon\\Shell", "Winlogon\\Userinit", "Image File Execution Options"},
		TextToo: true},
	{ID: "DEFENDER_TAMPER", Sev: Critical, Title: "Windows Defender tampering",
		Why:     "Disabling or excluding paths from Defender is a strong malware indicator.",
		Strings: []string{"Add-MpPreference", "Set-MpPreference", "DisableRealtimeMonitoring", "ExclusionPath", "Windows Defender\\Exclusions"},
		TextToo: true},

	// ---- credential theft / exfiltration ----
	{ID: "CREDENTIAL_PATHS", Sev: Critical, Title: "References browser / Discord / Steam / wallet secrets",
		Why: "Paths to saved passwords, cookies, Discord tokens, Steam session files or crypto wallets are the hallmark of info-stealers.",
		Strings: []string{"Local Storage\\leveldb", "Local Storage/leveldb", "\\Login Data", "Login Data For Account", "\\Network\\Cookies", "Local State", "User Data\\Default",
			"Mozilla\\Firefox\\Profiles", "logins.json", "key4.db", "loginusers.vdf", "\\ssfn", "config\\config.vdf",
			"wallet.dat", "Exodus\\exodus.wallet", "\\Electrum\\wallets", "nkbihfbeogaeaoehlefnkodbefgpgknn", "Atomic\\Local Storage", "discordcanary", "discordptb", "dQw4w9WgXcQ:"}},
	{ID: "DPAPI_DECRYPT", Sev: Critical, Title: "Decrypts DPAPI-protected secrets",
		Why:     "CryptUnprotectData / ProtectedData.Unprotect is how stealers decrypt browser passwords and cookies.",
		Members: []string{"System.Security.Cryptography.ProtectedData::Unprotect"}, PInvoke: []string{"CryptUnprotectData", "BCryptDecrypt"}},
	{ID: "EXFIL_WEBHOOK", Sev: Critical, Title: "Discord webhook / Telegram bot endpoint",
		Why:     "Hard-coded webhook or bot URLs are the most common exfiltration channel for stolen data.",
		Strings: []string{"discord.com/api/webhooks", "discordapp.com/api/webhooks", "canary.discord.com/api/webhooks", "ptb.discord.com/api/webhooks", "api.telegram.org/bot"},
		TextToo: true},
	{ID: "IP_LOOKUP", Sev: High, Title: "Public-IP / geolocation lookup services",
		Why:     "Stealers and loggers look up the victim's IP; game mods have no need to.",
		Strings: []string{"api.ipify.org", "ipinfo.io", "ip-api.com", "icanhazip", "checkip.amazonaws", "ifconfig.me", "iplogger", "grabify", "ipwho.is", "myexternalip"},
		TextToo: true},
	{ID: "PAYLOAD_HOSTS", Sev: Medium, Title: "File-sharing / paste / tunnel hosts",
		Why:     "Often used to host second-stage payloads.",
		Strings: []string{"pastebin.com", "hastebin", "paste.ee", "rentry.co", "transfer.sh", "anonfiles", "gofile.io", "ngrok", "cdn.discordapp.com/attachments", "mediafire.com", "mega.nz", "bit.ly/", "tinyurl.com", "catbox.moe", "filebin"}},

	// ---- network ----
	{ID: "NETWORK_RAW", Sev: Medium, Title: "General-purpose network access",
		Why:   "WebClient/HttpClient/sockets can download or upload anything. Some mods use them for update checks or online features.",
		Types: []string{"System.Net.WebClient", "System.Net.Http.HttpClient", "System.Net.HttpWebRequest", "System.Net.WebRequest", "System.Net.FtpWebRequest", "System.Net.Sockets.TcpClient", "System.Net.Sockets.Socket", "System.Net.Sockets.UdpClient", "System.Net.Mail.SmtpClient"}},
	{ID: "NETWORK_UNITY", Sev: Low, Title: "Unity web requests",
		Why:   "Common for update checks / downloading assets; check where it connects (see URLs).",
		Types: []string{"UnityEngine.Networking.UnityWebRequest", "UnityEngine.WWW"}},

	// ---- obfuscation ----
	{ID: "OBFUSCATOR", Sev: High, Title: "Commercial/known obfuscator detected",
		Why:    "Thunderstore mods are normally plain, decompilable C#. Obfuscation hides intent and is a frequent trait of malicious uploads.",
		Idents: []string{"ConfusedByAttribute", "DotfuscatorAttribute", "SmartAssembly.Attributes", "PoweredByAttribute", "BabelObfuscatorAttribute", "BabelAttribute", "ObfuscatedByGoliath", "YanoAttribute", "CryptoObfuscator", "NineRays.Obfuscator", "ZYXDNGuarder", "DNGuard", "Xenocode.Client.Attributes.AssemblyAttributes", "ObfuscatedByAgileDotNetAttribute", "SecureTeam.Attributes.ObfuscatedByAgileDotNetAttribute", "EMyPID_8234_", "MaxtoCodeObfuscator", "Macrobject.Obfuscator", "BabelObfuscator", "SpicesObfuscator", "NETGuard", "ArmDot", "ObfuscatorAttribute"}},
}

var urlRe = regexp.MustCompile(`(?i)\b(?:https?|ftp|wss?)://[^\s"'<>{}|\\^` + "`" + `]{3,}`)
var ipRe = regexp.MustCompile(`\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(:\d{2,5})?\b`)

func pinvokeMatch(name, target string) bool {
	n, t := strings.ToLower(name), strings.ToLower(target)
	if !strings.HasPrefix(n, t) {
		return false
	}
	switch n[len(t):] {
	case "", "a", "w", "ex", "exa", "exw":
		return true
	}
	return false
}

// matchRule returns evidence strings if the rule fires.
func matchRule(r *rule, s *signals, textOnly bool) []string {
	var ev []string
	add := func(x string) {
		for _, e := range ev {
			if e == x {
				return
			}
		}
		if len(ev) < 6 {
			ev = append(ev, x)
		}
	}
	if !textOnly {
		for _, t := range r.Types {
			if s.types[t] {
				add(t)
			}
		}
		for _, mm := range r.Members {
			if s.members[mm] {
				add(mm)
			}
		}
		for _, id := range r.Idents {
			if s.idents[id] {
				add(id)
			}
		}
		for _, p := range r.PInvoke {
			for _, name := range s.pinvoke {
				if pinvokeMatch(name, p) {
					add(name)
				}
			}
		}
	}
	if !textOnly || r.TextToo {
		for _, needle := range r.Strings {
			nl := strings.ToLower(needle)
			for i, l := range s.lower {
				if strings.Contains(l, nl) {
					add(snippet(s.strs[i], strings.Index(l, nl), len(nl)))
					break
				}
			}
		}
	}
	return ev
}

func snippet(s string, at, n int) string {
	start, end := at-30, at+n+30
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	out := strings.Join(strings.Fields(s[start:end]), " ")
	if start > 0 {
		out = "…" + out
	}
	if end < len(s) {
		out += "…"
	}
	return "\"" + out + "\""
}

type combo struct {
	ID, Title, Why string
	Sev            Severity
	All            [][]string // each inner slice: at least one of these rule IDs must have fired
}

var combos = []combo{
	{ID: "DOWNLOAD_AND_EXECUTE", Sev: Critical, Title: "Downloads from the internet AND launches programs",
		Why: "Network access combined with process execution is the signature of a dropper/loader.",
		All: [][]string{{"NETWORK_RAW", "NETWORK_UNITY", "NATIVE_DOWNLOAD"}, {"PROCESS_START", "NATIVE_EXEC"}}},
	{ID: "NETWORK_CODE_LOADER", Sev: Critical, Title: "Downloads data AND loads assemblies at runtime",
		Why: "Can fetch and run code that was never uploaded to Thunderstore.",
		All: [][]string{{"NETWORK_RAW", "NETWORK_UNITY"}, {"DYNAMIC_ASSEMBLY_LOAD"}}},
	{ID: "SHELL_EXECUTION", Sev: Critical, Title: "Launches a Windows shell / LOLBin",
		Why: "Process.Start together with cmd/powershell/etc. strings.",
		All: [][]string{{"PROCESS_START", "NATIVE_EXEC"}, {"SHELL_STRINGS"}}},
	{ID: "DECODE_AND_LOAD", Sev: High, Title: "Decodes/decrypts data AND loads assemblies",
		Why: "Hidden embedded payload pattern.",
		All: [][]string{{"BASE64_DECODE", "CRYPTO"}, {"DYNAMIC_ASSEMBLY_LOAD"}}},
	{ID: "FINGERPRINT_AND_SEND", Sev: High, Title: "Collects identity info AND has network access",
		Why: "May be sending user/machine info to a remote server.",
		All: [][]string{{"USER_IDENTITY", "WMI", "IP_LOOKUP"}, {"NETWORK_RAW", "NETWORK_UNITY"}}},
}

func applyRules(rep *Report, file string, s *signals, textOnly bool) {
	fired := map[string]bool{}
	for i := range rules {
		r := &rules[i]
		if ev := matchRule(r, s, textOnly); len(ev) > 0 {
			fired[r.ID] = true
			rep.add(r.Sev, r.ID, file, r.Title, r.Why, ev...)
		}
	}
	for _, c := range combos {
		ok := true
		var parts []string
		for _, group := range c.All {
			hit := ""
			for _, id := range group {
				if fired[id] {
					hit = id
					break
				}
			}
			if hit == "" {
				ok = false
				break
			}
			parts = append(parts, hit)
		}
		if ok {
			rep.add(c.Sev, c.ID, file, c.Title, c.Why, "combination of: "+strings.Join(parts, " + "))
		}
	}
	if textOnly {
		return
	}
	// URLs and hard-coded IPs
	seen := map[string]bool{}
	var ips []string
	for _, x := range s.strs {
		for _, u := range urlRe.FindAllString(x, -1) {
			u = strings.TrimRight(u, ".,);")
			rep.addURL(u)
		}
		for _, m := range ipRe.FindAllStringSubmatch(x, -1) {
			ip := m[1]
			if seen[ip] || boringIP(ip, m[2] != "", x) {
				continue
			}
			seen[ip] = true
			ips = append(ips, m[0])
		}
	}
	if len(ips) > 0 {
		sort.Strings(ips)
		if len(ips) > 6 {
			ips = ips[:6]
		}
		rep.add(Medium, "HARDCODED_IP", file, "Hard-coded IP address(es)",
			"Direct IP connections bypass DNS and are common for C2 servers. Could also be a game server address.", ips...)
	}
}

func boringIP(ip string, hasPort bool, ctx string) bool {
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "0.") || strings.HasPrefix(ip, "255.") ||
		strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "224.") {
		return true
	}
	if hasPort || strings.Contains(ctx, "://"+ip) {
		return false
	}
	// Looks like a version number ("5.4.21.0") rather than an address?
	first := ip[:strings.IndexByte(ip, '.')]
	if len(first) < 2 || strings.HasSuffix(ip, ".0") {
		return true
	}
	return false
}
