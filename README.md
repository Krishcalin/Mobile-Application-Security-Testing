<p align="center">
  <img src="banner.svg" alt="MAST Scanner Banner" width="100%"/>
</p>

# Mobile Application Security Testing (MAST) Scanner

An open-source, single-file Python-based **Mobile Application Security Testing** scanner that performs static analysis of **Android APK** and **iOS IPA** files. Detects security misconfigurations, hardcoded secrets, insecure cryptography, vulnerable dependencies, authentication flaws, reverse engineering gaps, and privacy issues.

Maps every finding to **OWASP Mobile Top 10 2024**, **MASVS v2** (22 of 24 controls), and **CWE**.

**Zero external dependencies** -- runs on Python 3.8+ using only the standard library.

---

## Features

- **130+ SAST rules** across 24 check modules for Android and iOS
- **39 dependency CVEs** across 29 libraries (Android, iOS, and native)
- **MASVS v2 mapping** -- 22 of 24 controls across all 8 groups (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY)
- **Android APK analysis** -- binary XML manifest parsing, DEX string extraction, native lib scanning
- **iOS IPA analysis** -- Info.plist parsing, Mach-O binary analysis, entitlements extraction
- **Hardcoded secret detection** -- AWS, Google, Stripe, Twilio, SendGrid, Firebase, OAuth, private keys
- **Vulnerable dependency scanning** -- OkHttp, Retrofit, Gson, Jackson, Log4j, Bouncy Castle, AFNetworking, Alamofire, OpenSSL, libcurl, libwebp, and more
- **Authentication & resilience checks** -- biometric bypass, root/jailbreak detection, obfuscation, anti-debug, tamper detection
- **Privacy analysis** -- tracking SDKs, advertising IDs, device fingerprinting, ATT compliance
- **4 output formats** -- coloured console, JSON, HTML (dark theme with MASVS coverage), SARIF (CI/CD)
- **Zero dependencies** -- Python 3.8+ stdlib only
- **Exit codes** -- returns `1` if CRITICAL or HIGH findings (CI/CD pipeline gating)

---

## Quick Start

```bash
# Scan an Android APK
python mast_scanner.py app-debug.apk --html report.html --json report.json

# Scan an iOS IPA
python mast_scanner.py MyApp.ipa --severity HIGH --sarif results.sarif

# Verbose scan
python mast_scanner.py app-release.apk -v
```

---

## Security Checks

### Android Manifest (12 Rules)

| Rule ID | Name | Severity | MASVS |
|---------|------|----------|-------|
| MAST-MANIFEST-001 | Application is debuggable | CRITICAL | RESILIENCE-2 |
| MAST-MANIFEST-002 | Application allows backup | HIGH | STORAGE-1 |
| MAST-MANIFEST-003 | Exported activity without permission | HIGH | PLATFORM-1 |
| MAST-MANIFEST-004 | Exported service without permission | HIGH | PLATFORM-1 |
| MAST-MANIFEST-005 | Exported broadcast receiver | MEDIUM | PLATFORM-1 |
| MAST-MANIFEST-006 | Exported content provider | HIGH | PLATFORM-1 |
| MAST-MANIFEST-007 | Cleartext traffic allowed | HIGH | NETWORK-1 |
| MAST-MANIFEST-008 | Low minimum SDK version | MEDIUM | CODE-3 |
| MAST-MANIFEST-009 | Dangerous permissions | MEDIUM | PLATFORM-3 |
| MAST-MANIFEST-010 | SYSTEM_ALERT_WINDOW permission | MEDIUM | PLATFORM-3 |
| MAST-MANIFEST-011 | Missing network security config | MEDIUM | NETWORK-2 |
| MAST-MANIFEST-012 | Custom task affinity | LOW | PLATFORM-1 |

### Android Secrets (8 Rules)

| Rule ID | Name | Severity | MASVS |
|---------|------|----------|-------|
| MAST-SECRET-001 | AWS Access Key ID | CRITICAL | CRYPTO-1 |
| MAST-SECRET-002 | AWS Secret Key | CRITICAL | CRYPTO-1 |
| MAST-SECRET-003 | Google API Key | HIGH | CRYPTO-1 |
| MAST-SECRET-004 | Firebase Database URL | MEDIUM | CRYPTO-1 |
| MAST-SECRET-005 | Generic API Key/Token | MEDIUM | CRYPTO-1 |
| MAST-SECRET-006 | Hardcoded Password | HIGH | CRYPTO-1 |
| MAST-SECRET-007 | Private Key | CRITICAL | CRYPTO-1 |
| MAST-SECRET-008 | OAuth Client Secret | HIGH | CRYPTO-1 |

### Android Crypto (5), Network (7), Storage (8), WebView (5), Components (5)

30 rules covering: weak algorithms (MD5/SHA1/DES/ECB), insecure random, hardcoded keys/IVs, TrustManager bypass, hostname verifier bypass, cleartext HTTP, cert pinning absence, weak TLS versions, custom SSLSocketFactory, world-accessible files, external storage, SQLite without encryption, clipboard data, screenshot prevention, keyboard cache, WebView JavaScript/file access/debugging, PendingIntent mutability, dynamic code loading, and URI permission grants.

### Android Authentication (5 Rules)

| Rule ID | Name | Severity | MASVS |
|---------|------|----------|-------|
| MAST-AUTH-001 | BiometricPrompt without CryptoObject | HIGH | AUTH-3 |
| MAST-AUTH-002 | Deprecated FingerprintManager | MEDIUM | AUTH-3 |
| MAST-AUTH-003 | Auth state in SharedPreferences | HIGH | AUTH-1 |
| MAST-AUTH-004 | No session timeout | MEDIUM | AUTH-1 |
| MAST-AUTH-005 | Credentials in SharedPreferences | CRITICAL | STORAGE-1 |

### Android Resilience (6 Rules)

| Rule ID | Name | Severity | MASVS |
|---------|------|----------|-------|
| MAST-RESIL-001 | No code obfuscation (ProGuard/R8) | MEDIUM | RESILIENCE-1 |
| MAST-RESIL-002 | No root detection | MEDIUM | RESILIENCE-3 |
| MAST-RESIL-003 | No debugger detection | LOW | RESILIENCE-2 |
| MAST-RESIL-004 | No emulator detection | LOW | RESILIENCE-2 |
| MAST-RESIL-005 | No app integrity / tamper detection | MEDIUM | RESILIENCE-4 |
| MAST-RESIL-006 | Hooking framework reference | INFO | RESILIENCE-2 |

### Android Code Quality (5 Rules)

| Rule ID | Name | Severity | MASVS |
|---------|------|----------|-------|
| MAST-CODE-001 | Unsafe reflection | MEDIUM | CODE-4 |
| MAST-CODE-002 | Raw SQL query | HIGH | CODE-2 |
| MAST-CODE-003 | Exception stack trace exposure | LOW | CODE-4 |
| MAST-CODE-004 | Implicit Intent for sensitive action | MEDIUM | PLATFORM-1 |
| MAST-CODE-005 | WebView loadUrl with dynamic input | HIGH | PLATFORM-2 |

### Android Privacy (5 Rules)

| Rule ID | Name | Severity | MASVS |
|---------|------|----------|-------|
| MAST-PRIV-001 | Advertising ID usage | MEDIUM | PRIVACY-1 |
| MAST-PRIV-002 | Analytics/tracking SDKs | INFO | PRIVACY-1 |
| MAST-PRIV-003 | Device fingerprinting | MEDIUM | PRIVACY-3 |
| MAST-PRIV-004 | Background location tracking | HIGH | PRIVACY-1 |
| MAST-PRIV-005 | Third-party ad SDK data sharing | MEDIUM | PRIVACY-1 |

### iOS Plist (8 Rules)

| Rule ID | Name | Severity | MASVS |
|---------|------|----------|-------|
| MAST-IOS-PLIST-001 | ATS disabled (NSAllowsArbitraryLoads) | HIGH | NETWORK-1 |
| MAST-IOS-PLIST-002 | ATS exception domains | MEDIUM | NETWORK-1 |
| MAST-IOS-PLIST-003 | Custom URL schemes | INFO | PLATFORM-1 |
| MAST-IOS-PLIST-004 | Excessive queried URL schemes | LOW | PRIVACY-3 |
| MAST-IOS-PLIST-005 | Additional ATS exceptions | MEDIUM | NETWORK-1 |
| MAST-IOS-PLIST-006 | Low minimum iOS version | MEDIUM | CODE-3 |
| MAST-IOS-PLIST-007 | Background modes | INFO | PRIVACY-1 |
| MAST-IOS-PLIST-008 | Multiple Keychain access groups | INFO | STORAGE-1 |

### iOS Secrets (4), Binary (4), Transport (4)

12 rules: hardcoded keys/tokens in binary, Firebase URLs, private keys, PIE flag, ARC detection, stack canaries, debug symbols, HTTP URLs, cert pinning absence, custom SSL handling, weak TLS in ATS exceptions.

### iOS Authentication (4 Rules)

| Rule ID | Name | Severity | MASVS |
|---------|------|----------|-------|
| MAST-IOS-AUTH-001 | Biometric auth without Keychain binding | HIGH | AUTH-3 |
| MAST-IOS-AUTH-002 | Keychain items without access control | MEDIUM | AUTH-1 |
| MAST-IOS-AUTH-003 | Auth state in UserDefaults | HIGH | AUTH-1 |
| MAST-IOS-AUTH-004 | No biometric enrollment change detection | MEDIUM | AUTH-3 |

### iOS Resilience (5 Rules)

| Rule ID | Name | Severity | MASVS |
|---------|------|----------|-------|
| MAST-IOS-RES-001 | No jailbreak detection | MEDIUM | RESILIENCE-3 |
| MAST-IOS-RES-002 | No anti-debug protection (ptrace) | LOW | RESILIENCE-2 |
| MAST-IOS-RES-003 | No runtime integrity verification | MEDIUM | RESILIENCE-4 |
| MAST-IOS-RES-004 | Hooking framework reference | INFO | RESILIENCE-2 |
| MAST-IOS-RES-005 | Dynamic library injection risk | MEDIUM | RESILIENCE-1 |

### iOS Code Quality (4), Privacy (4)

8 rules: deprecated UIWebView, NSLog with sensitive data, format string vulnerabilities, pasteboard usage, IDFA tracking, analytics frameworks, missing PrivacyInfo.xcprivacy, missing ATT.

### Common Checks (15 Rules)

| Category | Rules | Checks |
|----------|------:|--------|
| Secrets | 6 | AWS, Google Cloud, Stripe, Twilio, SendGrid, Bearer tokens |
| URLs | 4 | HTTP endpoints, staging URLs, localhost, hardcoded IPs |
| Crypto | 5 | Hardcoded keys, MD5 usage, insecure random, hardcoded IVs, Base64 pseudo-encryption |

### Dependency CVE Scanning (39 CVEs)

| Database | Libraries | CVEs | Detection |
|----------|-----------|------|-----------|
| Android libs | 14 (OkHttp, Retrofit, Gson, Jackson, Bouncy Castle, Log4j, Glide, Lottie, ExoPlayer, Facebook SDK, Apache HTTP, Conscrypt, Fresco, Kotlinx) | 19 | DEX string version patterns |
| iOS frameworks | 8 (AFNetworking, Alamofire, SDWebImage, Firebase, Realm, SVProgressHUD, Kingfisher, Moya) | 9 | Mach-O string version patterns |
| Native libs | 7 (OpenSSL, libcurl, SQLite, libwebp, libpng, zlib, libjpeg-turbo) | 11 | Binary version strings |

---

## MASVS v2 Coverage (22 of 24 Controls)

| MASVS Group | Controls | Scanner Modules |
|-------------|----------|-----------------|
| **STORAGE** | STORAGE-1, STORAGE-2 | storage, manifest, plist, ios_code |
| **CRYPTO** | CRYPTO-1, CRYPTO-2 | secrets, crypto, common_secrets, common_crypto |
| **AUTH** | AUTH-1, AUTH-3 | android_auth, ios_auth |
| **NETWORK** | NETWORK-1, NETWORK-2 | network, transport, manifest, plist, common_urls |
| **PLATFORM** | PLATFORM-1, PLATFORM-2, PLATFORM-3 | manifest, components, webview, code, plist |
| **CODE** | CODE-1, CODE-2, CODE-3, CODE-4 | android_code, ios_code, android_deps, ios_deps |
| **RESILIENCE** | RESILIENCE-1, RESILIENCE-2, RESILIENCE-3, RESILIENCE-4 | android_resilience, ios_resilience, ios_binary |
| **PRIVACY** | PRIVACY-1, PRIVACY-2, PRIVACY-3 | android_privacy, ios_privacy, plist |

---

## OWASP Mobile Top 10 2024 Coverage

| Category | Coverage |
|----------|---------|
| M1: Improper Credential Usage | Secrets checks, hardcoded passwords, credential storage |
| M2: Inadequate Supply Chain Security | 39 dependency CVEs, dynamic code loading, deprecated frameworks |
| M3: Insecure Authentication/Authorization | Exported components, biometric bypass, session management |
| M4: Insufficient Input/Output Validation | WebView JavaScript, URL schemes, format strings, raw SQL |
| M5: Insecure Communication | ATS, cleartext, cert pinning, TrustManager, weak TLS |
| M6: Inadequate Privacy Controls | Tracking SDKs, IDFA, fingerprinting, ATT, background location |
| M7: Insufficient Binary Protections | PIE, ARC, canaries, obfuscation, root/jailbreak detection |
| M8: Security Misconfiguration | Manifest flags, backup, debuggable, min SDK |
| M9: Insecure Data Storage | SharedPrefs, external storage, SQLite, clipboard, screenshots |
| M10: Insufficient Cryptography | Weak algorithms, ECB, hardcoded keys/IVs, insecure random |

---

## CLI Reference

```
usage: mast_scanner.py [-h] [--json FILE] [--html FILE] [--sarif FILE]
                       [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
                       [-v] [--platform {auto,android,ios}] [--version]
                       target

positional arguments:
  target                Path to APK or IPA file

options:
  --json FILE           Save JSON report to FILE
  --html FILE           Save HTML report to FILE
  --sarif FILE          Save SARIF report for CI/CD
  --severity SEV        Minimum severity (default: INFO)
  -v, --verbose         Verbose output with descriptions
  --platform PLAT       Force platform (default: auto-detect)
  --version             Show scanner version
```

---

## Requirements

- Python **3.8+**
- No external dependencies

---

## Legal & Ethical Use

This tool is designed **exclusively for authorised security testing**:

- **Your own applications** -- test apps you develop
- **Authorised assessments** -- pentest engagements with written permission
- **Bug bounty programs** -- within scope of published rules
- **Training / CTF** -- practice mobile security analysis

> **Important:** Only analyse applications you own or have explicit authorisation to test.

---

## License

MIT -- see [LICENSE](LICENSE) for details.
