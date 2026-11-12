package main

import (
	"path"
	"strings"
)

// Mod loaders (BepInEx, Harmony, MonoMod, MelonLoader) legitimately do
// loader-like things: native hooks, VirtualProtect, a winhttp.dll proxy,
// Assembly.Load. Their findings are downgraded to LOW – but only when the
// package comes from the official Thunderstore namespace, or the file is a
// known core file installed by the mod manager outside any mod package.
var trustedNamespaces = set("bepinex", "lavagang")

var coreFileNames = set("0harmony.dll", "0harmony20.dll", "bepinex.dll", "bepinex.preloader.dll", "bepinex.harmony.dll",
	"harmonyxinterop.dll", "mono.cecil.dll", "mono.cecil.mdb.dll", "mono.cecil.pdb.dll", "mono.cecil.rocks.dll",
	"monomod.runtimedetour.dll", "monomod.utils.dll", "bepinex.core.dll", "bepinex.unity.mono.dll",
	"bepinex.unity.mono.preloader.dll", "bepinex.preloader.core.dll", "bepinex.unity.common.dll", "il2cppinterop.runtime.dll")

// These are never downgraded, no matter who published the file.
var hardRules = set("CREDENTIAL_PATHS", "DPAPI_DECRYPT", "EXFIL_WEBHOOK", "PERSISTENCE", "DEFENDER_TAMPER", "IP_LOOKUP",
	"PATH_TRAVERSAL", "DISGUISED_EXECUTABLE", "DOUBLE_EXTENSION", "VT_DETECTED", "VT_SOME_DETECTIONS", "OBFUSCATOR",
	"OBFUSCATED_NAMES", "PROCESS_INJECTION", "NATIVE_DOWNLOAD", "SHELL_EXECUTION", "SHELL_STRINGS", "KEYLOG_SPY",
	"MANIFEST_MISMATCH", "LISTING_REJECTED", "EXECUTABLE_FILE", "SCRIPT_FILE", "DANGEROUS_BINARY_TYPE", "ZIP_BOMB",
	"STARTUP_FOLDER", "STARTUP_DROP", "CREDENTIAL_PATH_PARTS")

func isKnownCoreFile(p string) bool {
	lp := strings.ToLower(p)
	base := path.Base(lp)
	if strings.Contains("/"+lp, "/bepinex/core/") && coreFileNames[base] {
		return true
	}
	// Doorstop proxy at the game root (or one folder down in the BepInExPack zip layout).
	return base == "winhttp.dll" && strings.Count(lp, "/") <= 1
}

func applyTrust(r *Report) {
	trustedPkg := r.Package != nil && trustedNamespaces[strings.ToLower(r.Package.Namespace)]
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Severity <= Low || f.File == "" || hardRules[f.Rule] {
			continue
		}
		note := ""
		switch {
		case trustedPkg:
			note = "official " + r.Package.Namespace + " mod-loader package"
		case r.looseGroup && isKnownCoreFile(f.File):
			note = "known BepInEx core file — compare its SHA-256 with the official BepInExPack if unsure"
		}
		if note != "" {
			f.Severity = Low
			f.Title += "  [expected: " + note + "]"
		}
	}
}
