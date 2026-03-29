# CLAUDE.md -- MAST Scanner

## Project Overview

Single-file Mobile Application Security Testing (MAST) scanner that performs static
analysis of Android APK and iOS IPA files. Maps findings to OWASP Mobile Top 10
2024 and MASVS (Mobile Application Security Verification Standard).

## Repository Structure

```
Mobile-Application-Security-Testing/
├── mast_scanner.py              # Main scanner (single file, ~3,000 lines)
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

- **File**: `mast_scanner.py` (~3,000 lines)
- **Version**: 1.0.0
- **Dependencies**: Python 3.8+ stdlib only (zero external packages)
- **Platforms**: Android APK, iOS IPA

### Key Classes

| Class | Purpose |
|-------|---------|
| `Finding` | Dataclass: rule_id, name, category, severity, platform, file_path, evidence, description, recommendation, cwe, owasp_mobile |
| `APKAnalyzer` | Extract and parse Android APK (manifest, DEX strings, native libs) |
| `IPAAnalyzer` | Extract and parse iOS IPA (Info.plist, entitlements, Mach-O strings) |
| `MASTScanner` | Orchestrator: detect platform, analyze, run checks, report |

### Binary Parsers

| Parser | Purpose |
|--------|---------|
| `parse_android_binary_xml()` | Decode Android compiled binary XML (AndroidManifest.xml) |
| `extract_dex_strings()` | Extract string constants from classes.dex |
| `extract_macho_strings()` | Extract printable strings from Mach-O binaries |

### Check Modules (14 modules, ~80 rules)

| Module | Rule IDs | Count | Platform |
|--------|----------|-------|----------|
| `check_android_manifest` | MAST-MANIFEST-001 to 012 | 12 | Android |
| `check_android_secrets` | MAST-SECRET-001 to 008 | 8 | Android |
| `check_android_crypto` | MAST-CRYPTO-001 to 005 | 5 | Android |
| `check_android_network` | MAST-NET-001 to 005 | 5 | Android |
| `check_android_storage` | MAST-STORAGE-001 to 005 | 5 | Android |
| `check_android_webview` | MAST-WEBVIEW-001 to 005 | 5 | Android |
| `check_android_components` | MAST-COMP-001 to 005 | 5 | Android |
| `check_ios_plist` | MAST-IOS-PLIST-001 to 008 | 8 | iOS |
| `check_ios_secrets` | MAST-IOS-SECRET-001 to 004 | 4 | iOS |
| `check_ios_binary` | MAST-IOS-BIN-001 to 004 | 4 | iOS |
| `check_ios_transport` | MAST-IOS-NET-001 to 004 | 4 | iOS |
| `check_common_secrets` | MAST-COMMON-SEC-001 to 006 | 6 | Common |
| `check_common_urls` | MAST-COMMON-URL-001 to 004 | 4 | Common |
| `check_common_crypto` | MAST-COMMON-CRYPTO-001 to 005 | 5 | Common |

### Rule ID Format

`MAST-{CATEGORY}-{NNN}` (e.g., MAST-MANIFEST-001, MAST-IOS-PLIST-003, MAST-COMMON-SEC-002)

### OWASP Mobile Top 10 2024 Coverage

| Category | Our Coverage |
|----------|-------------|
| M1: Improper Credential Usage | Secrets checks, hardcoded passwords |
| M2: Inadequate Supply Chain Security | Min SDK, third-party lib detection |
| M3: Insecure Authentication/Authorization | Exported components, permissions |
| M4: Insufficient Input/Output Validation | WebView JavaScript, intent filters |
| M5: Insecure Communication | ATS, cleartext, cert pinning, TrustManager |
| M6: Inadequate Privacy Controls | Permissions (camera, contacts, SMS, location) |
| M7: Insufficient Binary Protections | PIE, ARC, stack canaries, debug |
| M8: Security Misconfiguration | Manifest flags, backup, debuggable |
| M9: Insecure Data Storage | SharedPrefs, external storage, SQLite |
| M10: Insufficient Cryptography | Weak algorithms, ECB, hardcoded keys |

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
| Console | *(default)* | Coloured summary with severity counts |
| JSON | `--json FILE` | Machine-readable full detail |
| HTML | `--html FILE` | Interactive dark-themed report |
| SARIF | `--sarif FILE` | SARIF v2.1.0 for GitHub/GitLab CI |

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
- IMPORTANT: Only analyse apps you own or have authorisation to test
