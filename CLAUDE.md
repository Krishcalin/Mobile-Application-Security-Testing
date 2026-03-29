# CLAUDE.md -- MAST Scanner

## Project Overview

Single-file Mobile Application Security Testing (MAST) scanner that performs static
analysis of Android APK and iOS IPA files. Maps findings to OWASP Mobile Top 10
2024, MASVS v2 (Mobile Application Security Verification Standard), and CWE.

## Repository Structure

```
Mobile-Application-Security-Testing/
├── mast_scanner.py              # Main scanner (single file, ~2,800 lines)
├── banner.svg                   # Project banner
├── CLAUDE.md                    # This file
├── LICENSE                      # MIT License
├── README.md                    # Documentation
├── .gitignore                   # Python gitignore
└── tests/
    ├── sample_manifest.xml      # Intentionally vulnerable AndroidManifest
    └── sample_plist.xml         # Intentionally vulnerable iOS Info.plist
```

## Architecture

- **File**: `mast_scanner.py` (~2,800 lines)
- **Version**: 2.1.0
- **Dependencies**: Python 3.8+ stdlib only (zero external packages)
- **Platforms**: Android APK, iOS IPA

### Key Classes

| Class | Purpose |
|-------|---------|
| `Finding` | Dataclass: rule_id, name, category, severity, platform, file_path, evidence, description, recommendation, cwe, owasp_mobile, masvs |
| `APKAnalyzer` | Extract and parse Android APK (manifest, DEX strings, native libs) |
| `IPAAnalyzer` | Extract and parse iOS IPA (Info.plist, entitlements, Mach-O strings) |
| `MASTScanner` | Orchestrator: detect platform, analyze, run checks, report |

### Binary Parsers

| Parser | Purpose |
|--------|---------|
| `parse_android_binary_xml()` | Decode Android compiled binary XML (AndroidManifest.xml) |
| `extract_dex_strings()` | Extract string constants from classes.dex |
| `extract_macho_strings()` | Extract printable strings from Mach-O binaries |

### Check Modules (24 modules, ~130 SAST rules + 39 dependency CVEs)

| Module | Rule IDs | Count | Platform | MASVS |
|--------|----------|-------|----------|-------|
| `check_android_manifest` | MAST-MANIFEST-001 to 012 | 12 | Android | PLATFORM, STORAGE, NETWORK, CODE, RESILIENCE, PRIVACY |
| `check_android_secrets` | MAST-SECRET-001 to 008 | 8 | Android | CRYPTO-1 |
| `check_android_crypto` | MAST-CRYPTO-001 to 005 | 5 | Android | CRYPTO-2 |
| `check_android_network` | MAST-NET-001 to 007 | 7 | Android | NETWORK-1, NETWORK-2 |
| `check_android_storage` | MAST-STORAGE-001 to 008 | 8 | Android | STORAGE-1, STORAGE-2 |
| `check_android_webview` | MAST-WEBVIEW-001 to 005 | 5 | Android | PLATFORM-2 |
| `check_android_components` | MAST-COMP-001 to 005 | 5 | Android | PLATFORM-1, CODE-2 |
| `check_android_auth` | MAST-AUTH-001 to 005 | 5 | Android | AUTH-1, AUTH-3, STORAGE-1 |
| `check_android_resilience` | MAST-RESIL-001 to 006 | 6 | Android | RESILIENCE-1 to 4 |
| `check_android_code` | MAST-CODE-001 to 005 | 5 | Android | CODE-2, CODE-4, PLATFORM-1, PLATFORM-2 |
| `check_android_privacy` | MAST-PRIV-001 to 005 | 5 | Android | PRIVACY-1, PRIVACY-3 |
| `check_ios_plist` | MAST-IOS-PLIST-001 to 008 | 8 | iOS | NETWORK-1, PLATFORM-1, CODE-3, STORAGE-1, PRIVACY-1, PRIVACY-3 |
| `check_ios_secrets` | MAST-IOS-SECRET-001 to 004 | 4 | iOS | CRYPTO-1 |
| `check_ios_binary` | MAST-IOS-BIN-001 to 004 | 4 | iOS | RESILIENCE-1, CODE-4 |
| `check_ios_transport` | MAST-IOS-NET-001 to 004 | 4 | iOS | NETWORK-1, NETWORK-2 |
| `check_ios_auth` | MAST-IOS-AUTH-001 to 004 | 4 | iOS | AUTH-1, AUTH-3 |
| `check_ios_resilience` | MAST-IOS-RES-001 to 005 | 5 | iOS | RESILIENCE-1 to 4 |
| `check_ios_code` | MAST-IOS-CODE-001 to 004 | 4 | iOS | CODE-1, CODE-2, CODE-4, STORAGE-2 |
| `check_ios_privacy` | MAST-IOS-PRIV-001 to 004 | 4 | iOS | PRIVACY-1, PRIVACY-2 |
| `check_common_secrets` | MAST-COMMON-SEC-001 to 006 | 6 | Common | CRYPTO-1 |
| `check_common_urls` | MAST-COMMON-URL-001 to 004 | 4 | Common | NETWORK-1, CODE-2 |
| `check_common_crypto` | MAST-COMMON-CRYPTO-001 to 005 | 5 | Common | CRYPTO-2 |
| `check_android_deps` | DEP-ANDROID-CVE-*, DEP-NATIVE-CVE-* | 19+11 | Android | CODE-1 |
| `check_ios_deps` | DEP-IOS-CVE-*, DEP-NATIVE-CVE-* | 9+11 | iOS | CODE-1 |

### Rule ID Format

`MAST-{CATEGORY}-{NNN}` (e.g., MAST-MANIFEST-001, MAST-IOS-PLIST-003, MAST-COMMON-SEC-002)

### Dependency CVE Databases

| Database | Libraries | CVEs | Detection Method |
|----------|-----------|------|-----------------|
| `ANDROID_LIB_CVES` | 14 (OkHttp, Retrofit, Gson, Jackson, Bouncy Castle, Log4j, Glide, Lottie, ExoPlayer, Facebook SDK, Apache HTTP, Conscrypt, Fresco, Kotlinx) | 19 | DEX string version patterns |
| `IOS_LIB_CVES` | 8 (AFNetworking, Alamofire, SDWebImage, Firebase, Realm, SVProgressHUD, Kingfisher, Moya) | 9 | Mach-O string version patterns |
| `NATIVE_LIB_CVES` | 7 (OpenSSL, libcurl, SQLite, libwebp, libpng, zlib, libjpeg-turbo) | 11 | Native binary version strings |

**Version scanning**: `_parse_ver()` + `_version_in_range()` — same pattern as other SAST scanners. Supports `<`, `<=`, `>`, `>=`, comma-separated ranges.

**Rule ID format**: `DEP-ANDROID-CVE{YYYY}{NNNNN}`, `DEP-IOS-CVE{YYYY}{NNNNN}`, `DEP-NATIVE-CVE{YYYY}{NNNNN}`

### MASVS v2 Control Coverage

| MASVS Group | Controls Hit | Scanner Modules |
|-------------|-------------|-----------------|
| MASVS-STORAGE | STORAGE-1, STORAGE-2 | storage, manifest, plist, ios_code |
| MASVS-CRYPTO | CRYPTO-1, CRYPTO-2 | secrets, crypto, common_secrets, common_crypto |
| MASVS-AUTH | AUTH-1, AUTH-3 | android_auth, ios_auth |
| MASVS-NETWORK | NETWORK-1, NETWORK-2 | network, transport, manifest, plist, common_urls |
| MASVS-PLATFORM | PLATFORM-1, PLATFORM-2, PLATFORM-3 | manifest, components, webview, code, plist |
| MASVS-CODE | CODE-1, CODE-2, CODE-3, CODE-4 | android_code, ios_code, components, manifest, plist |
| MASVS-RESILIENCE | RESILIENCE-1 to 4 | android_resilience, ios_resilience, ios_binary, manifest |
| MASVS-PRIVACY | PRIVACY-1, PRIVACY-2, PRIVACY-3 | android_privacy, ios_privacy, plist |

### OWASP Mobile Top 10 2024 Coverage

| Category | Our Coverage |
|----------|-------------|
| M1: Improper Credential Usage | Secrets checks, hardcoded passwords, credential storage |
| M2: Inadequate Supply Chain Security | Dynamic code loading, deprecated UIWebView, min SDK |
| M3: Insecure Authentication/Authorization | Exported components, biometric bypass, session mgmt |
| M4: Insufficient Input/Output Validation | WebView JavaScript, intent filters, format strings |
| M5: Insecure Communication | ATS, cleartext, cert pinning, TrustManager, weak TLS |
| M6: Inadequate Privacy Controls | Permissions, tracking SDKs, IDFA, fingerprinting, ATT |
| M7: Insufficient Binary Protections | PIE, ARC, canaries, obfuscation, root/jailbreak detect |
| M8: Security Misconfiguration | Manifest flags, backup, debuggable, min SDK |
| M9: Insecure Data Storage | SharedPrefs, external storage, SQLite, clipboard, screenshots |
| M10: Insufficient Cryptography | Weak algorithms, ECB, hardcoded keys/IVs, insecure random |

## CLI

```bash
python mast_scanner.py <APK_OR_IPA_FILE>
    [--json FILE] [--html FILE] [--sarif FILE]
    [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
    [-v/--verbose] [--version]
    [--platform {auto,android,ios}]
```

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | *(default)* | Coloured summary with severity counts + MASVS refs |
| JSON | `--json FILE` | Machine-readable full detail with MASVS mapping |
| HTML | `--html FILE` | Interactive dark-themed report with MASVS coverage |
| SARIF | `--sarif FILE` | SARIF v2.1.0 for GitHub/GitLab CI with MASVS properties |

## Testing

```bash
# Scan an Android APK
python mast_scanner.py app-debug.apk --verbose --html report.html --json report.json

# Scan an iOS IPA
python mast_scanner.py MyApp.ipa --severity HIGH --sarif results.sarif
```

## Conventions

- Single-file scanner, zero external dependencies
- Check functions return `List[Finding]` (not generators)
- Check function signature: `(apk_data|ipa_data: dict) -> List[Finding]`
- Exit code: `1` if CRITICAL or HIGH findings, `0` otherwise
- HTML theme: dark background (#0f172a), same palette as DAST scanner
- String searches limited to 50,000 strings for performance
- Evidence strings truncated to 200 chars
- Binary XML parser handles malformed APKs gracefully
- Every finding maps to MASVS v2 control via `masvs` field
- IMPORTANT: Only analyse apps you own or have authorisation to test
