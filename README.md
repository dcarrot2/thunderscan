# thunderscan

Static security checks for Thunderstore mods (BepInEx / MelonLoader). One `.exe`, no dependencies, and it never runs or installs the mod it inspects.

## Use it

**Double-click `thunderscan.exe`.** A small page opens in your browser (served only on `127.0.0.1`). On that page you can:

- paste package names, thunderstore.io links, or local paths, one per line
- drop `.zip` or `.dll` files onto it
- tick **Also scan dependencies**, and optionally add a VirusTotal key (only file hashes are sent)

Press **Quit** on the page, or close the console window, to stop it.

**Command line:**

```bash
thunderscan.exe notnotnotswipez-MoreCompany
```

```bash
thunderscan.exe -deps Owner-ModName-1.2.3 https://thunderstore.io/c/lethal-company/p/Owner/Other/
```

```bash
thunderscan.exe "%APPDATA%\r2modmanPlus-local\LethalCompany\profiles\Default\BepInEx\plugins"
```

```bash
thunderscan.exe -json -fail-on medium mod.zip > report.json
```

You can also drag a zip onto `thunderscan.exe` in Explorer. The window stays open until you press Enter.

| Flag | Meaning |
|---|---|
| `-deps` | also download and scan each package's dependencies |
| `-vt` | look up binary SHA-256 hashes on VirusTotal (set `VT_API_KEY`) |
| `-json` | machine-readable output |
| `-fail-on high` | exit code 1 if any finding is ≥ this severity (exit code 2 means errors) |
| `-v` | also show INFO findings, all explanations, all URLs |
| `-ui`, `-port`, `-no-browser` | UI options |
| `-max-mb 512` | per-file size limit |

## What it checks

- **.NET DLLs:** parses the metadata tables to find which APIs are actually referenced. It flags:
  - running programs (Process.Start, shells and LOLBins)
  - loading code at runtime, including combined with downloading or decoding
  - process injection and shellcode APIs, keyloggers, screen capture
  - registry access, persistence, Defender tampering
  - paths to browser, Discord, Steam and crypto-wallet secrets, DPAPI decryption
  - Discord webhooks, Telegram bots, IP-lookup services, paste and file-sharing hosts
  - known obfuscators and ConfuserEx-style invisible names
  - embedded executables, mixed-mode native code
  - embedded URLs and hard-coded IP addresses
  - code written to dodge the rules above:
    - Startup-folder persistence via `Environment.GetFolderPath(SpecialFolder.Startup)`, found by scanning method bodies (IL), so no path string is needed
    - stealer paths split into pieces (`Path.Combine("Local Storage", "leveldb")`)
    - strings hidden with Base64 or Base64 + single-byte XOR (decoded, then checked by every rule)
    - `Type.GetType` + `Invoke`/`CreateInstance` with API-name fragments like `"Process"` or `"WebClient"`
    - file writes combined with launching programs or executable file names
  - embedded DLLs (Costura.Fody and similar: raw, deflate or gzip resources) are unpacked and scanned like any other DLL
- **Native DLLs:** imports and strings, plus DLL-hijack names like `winhttp.dll` or `version.dll`.
- **Package structure:**
  - zip-slip (`..`) paths, zip bombs, nested archives
  - executables disguised as other file types (e.g. `icon.png` that's really an EXE), double extensions
  - bundled `.exe`, `.bat`, `.ps1` or `.lnk` files
  - webhooks and persistence strings in config files
- **Thunderstore listing:**
  - manifest that doesn't match the listing
  - rejected or deprecated listings
  - brand-new packages, low download counts, no source link

Findings for the official `BepInEx` / `LavaGang` packages, and for known BepInEx core files in a profile folder, are capped at LOW, because loaders legitimately do loader things. Hard indicators are never downgraded: credential theft, webhooks, persistence, injection, obfuscation and VirusTotal hits.

## Limits

This is static analysis. A clean result means no known red flags were found, not that the mod is safe. Code can be encrypted inside resources, downloaded later, or written to dodge these rules (for example multi-byte XOR, strings built character by character, or a custom packer). For anything rated HIGH or CRITICAL, open the DLL in [ILSpy](https://github.com/icsharpcode/ILSpy) or dnSpy and read the flagged code before installing.

## Build

Requires Go 1.21+.

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o thunderscan.exe .
```
