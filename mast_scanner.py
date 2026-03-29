#!/usr/bin/env python3
"""
Mobile Application Security Testing (MAST) Scanner
Version : 1.0.0
License : MIT
Requires: Python 3.8+ (no external dependencies)

Static analysis scanner for Android APK and iOS IPA files.
Detects security misconfigurations, hardcoded secrets, insecure
cryptography, network security issues, and more.

Maps findings to OWASP Mobile Top 10 2024 and MASVS.

IMPORTANT: Only analyse applications you own or have explicit
authorisation to test.
"""
from __future__ import annotations

import argparse
import base64
import collections
import datetime
import hashlib
import io
import json
import os
import plistlib
import re
import struct
import sys
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree

__version__ = "1.0.0"

# ════════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m",
    "LOW": "\033[92m", "INFO": "\033[97m",
}
RESET = "\033[0m"
BOLD = "\033[1m"

MAX_STRINGS = 50000
MAX_EVIDENCE = 200


# ════════════════════════════════════════════════════════════════════════════════
#  FINDING DATACLASS
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    rule_id: str
    name: str
    category: str
    severity: str
    platform: str
    file_path: str
    evidence: str
    description: str
    recommendation: str
    cwe: str
    owasp_mobile: str


# ════════════════════════════════════════════════════════════════════════════════
#  ANDROID BINARY XML PARSER
# ════════════════════════════════════════════════════════════════════════════════

# Chunk types
_CHUNK_STRINGPOOL = 0x001C0001
_CHUNK_RESOURCEIDS = 0x00080180
_CHUNK_XML_START_NS = 0x00100100
_CHUNK_XML_END_NS = 0x00100101
_CHUNK_XML_START_TAG = 0x00100102
_CHUNK_XML_END_TAG = 0x00100103
_CHUNK_XML_TEXT = 0x00100104

# Android resource namespace
_ANDROID_NS = "http://schemas.android.com/apk/res/android"


def parse_android_binary_xml(data: bytes) -> Optional[ElementTree.Element]:
    """Parse Android compiled binary XML into an ElementTree Element."""
    if not data:
        return None

    # If it's already text XML, parse directly
    try:
        text = data.decode("utf-8", errors="ignore").strip()
        if text.startswith("<?xml") or text.startswith("<manifest") or text.startswith("<"):
            return ElementTree.fromstring(text)
    except Exception:
        pass

    # Binary XML parsing
    try:
        return _parse_binary_xml(data)
    except Exception:
        return None


def _parse_binary_xml(data: bytes) -> Optional[ElementTree.Element]:
    """Internal binary XML parser."""
    if len(data) < 8:
        return None

    magic, file_size = struct.unpack_from("<HH I", data, 0)
    if magic != 0x0003:  # RES_XML_TYPE
        return None

    strings: List[str] = []
    ns_map: Dict[str, str] = {}
    root = None
    stack: List[ElementTree.Element] = []
    offset = 8

    while offset < len(data) - 8:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HH I", data, offset)

        if chunk_type == 0x0001 and (data[offset + 2:offset + 4] == b'\x1c\x00' or header_size >= 0x1C):
            # String pool
            strings = _read_string_pool(data, offset)

        elif chunk_type == 0x0102 or chunk_type == (_CHUNK_XML_START_TAG & 0xFFFF):
            # Start tag
            try:
                ns_idx, name_idx = struct.unpack_from("<i i", data, offset + 16)
                attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, offset + 24)

                tag_name = strings[name_idx] if 0 <= name_idx < len(strings) else f"unknown_{name_idx}"

                elem = ElementTree.Element(tag_name)

                for i in range(attr_count):
                    attr_off = offset + 36 + (i * 20)
                    if attr_off + 20 > len(data):
                        break
                    a_ns, a_name, a_raw, a_type, a_val = struct.unpack_from("<i i i HH i", data, attr_off)

                    attr_name = strings[a_name] if 0 <= a_name < len(strings) else f"attr_{a_name}"
                    # Resolve value
                    if a_raw >= 0 and a_raw < len(strings):
                        attr_val = strings[a_raw]
                    elif (a_type >> 8) == 0x10:  # TYPE_INT_DEC
                        attr_val = str(a_val)
                    elif (a_type >> 8) == 0x12:  # TYPE_INT_BOOLEAN
                        attr_val = "true" if a_val != 0 else "false"
                    else:
                        attr_val = str(a_val) if a_val is not None else ""

                    # Prefix with android: namespace
                    if a_ns >= 0 and a_ns < len(strings) and "android" in strings[a_ns]:
                        attr_name = f"android:{attr_name}"

                    elem.set(attr_name, attr_val)

                if root is None:
                    root = elem
                elif stack:
                    stack[-1].append(elem)
                stack.append(elem)
            except Exception:
                pass

        elif chunk_type == 0x0103 or chunk_type == (_CHUNK_XML_END_TAG & 0xFFFF):
            # End tag
            if stack:
                stack.pop()

        offset += max(chunk_size, 8)

    return root


def _read_string_pool(data: bytes, offset: int) -> List[str]:
    """Read the string pool chunk."""
    strings: List[str] = []
    try:
        header_size = struct.unpack_from("<H", data, offset + 2)[0]
        string_count, style_count, flags, string_start, style_start = struct.unpack_from(
            "<I I I I I", data, offset + 8
        )
        is_utf8 = bool(flags & (1 << 8))

        offsets = []
        for i in range(min(string_count, 10000)):
            off = struct.unpack_from("<I", data, offset + 28 + i * 4)[0]
            offsets.append(off)

        pool_start = offset + string_start

        for off in offsets:
            try:
                pos = pool_start + off
                if is_utf8:
                    # UTF-8: 2 length bytes (chars), 2 length bytes (bytes), then string
                    char_len = data[pos]
                    if char_len & 0x80:
                        char_len = ((char_len & 0x7F) << 8) | data[pos + 1]
                        pos += 2
                    else:
                        pos += 1
                    byte_len = data[pos]
                    if byte_len & 0x80:
                        byte_len = ((byte_len & 0x7F) << 8) | data[pos + 1]
                        pos += 2
                    else:
                        pos += 1
                    s = data[pos:pos + byte_len].decode("utf-8", errors="replace")
                else:
                    # UTF-16
                    str_len = struct.unpack_from("<H", data, pos)[0]
                    if str_len & 0x8000:
                        str_len = ((str_len & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos + 2)[0]
                        pos += 4
                    else:
                        pos += 2
                    s = data[pos:pos + str_len * 2].decode("utf-16-le", errors="replace")
                strings.append(s)
            except Exception:
                strings.append("")
    except Exception:
        pass
    return strings


# ════════════════════════════════════════════════════════════════════════════════
#  DEX STRING EXTRACTOR
# ════════════════════════════════════════════════════════════════════════════════

def extract_dex_strings(data: bytes) -> List[str]:
    """Extract string constants from a DEX file."""
    strings: List[str] = []
    if len(data) < 112 or data[:4] not in (b"dex\n", b"cdex"):
        return strings

    try:
        string_ids_size = struct.unpack_from("<I", data, 56)[0]
        string_ids_off = struct.unpack_from("<I", data, 60)[0]

        for i in range(min(string_ids_size, MAX_STRINGS)):
            str_data_off = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
            if str_data_off >= len(data):
                continue
            # Read ULEB128 length
            pos = str_data_off
            size = 0
            shift = 0
            while pos < len(data):
                b = data[pos]
                pos += 1
                size |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            if size > 0 and pos + size <= len(data):
                try:
                    s = data[pos:pos + size].decode("utf-8", errors="replace")
                    if s and len(s) >= 4:
                        strings.append(s)
                except Exception:
                    pass
    except Exception:
        pass
    return strings


# ════════════════════════════════════════════════════════════════════════════════
#  MACH-O STRING EXTRACTOR
# ════════════════════════════════════════════════════════════════════════════════

_MACHO_MAGIC_32 = 0xFEEDFACE
_MACHO_MAGIC_64 = 0xFEEDFACF
_MACHO_FAT = 0xCAFEBABE
_MH_PIE = 0x200000


def extract_macho_strings(data: bytes, min_len: int = 8) -> List[str]:
    """Extract printable ASCII strings from a Mach-O binary."""
    strings: List[str] = []
    current: List[str] = []

    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))

    return strings[:MAX_STRINGS]


def check_macho_pie(data: bytes) -> bool:
    """Check if Mach-O binary has PIE flag set."""
    try:
        if len(data) < 28:
            return True  # Can't determine, assume safe
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic == _MACHO_MAGIC_64:
            flags = struct.unpack_from("<I", data, 24)[0]
            return bool(flags & _MH_PIE)
        elif magic == _MACHO_MAGIC_32:
            flags = struct.unpack_from("<I", data, 24)[0]
            return bool(flags & _MH_PIE)
        elif magic == _MACHO_FAT:
            # FAT binary — check first arch
            nfat = struct.unpack_from(">I", data, 4)[0]
            if nfat > 0:
                offset = struct.unpack_from(">I", data, 12)[0]
                return check_macho_pie(data[offset:])
    except Exception:
        pass
    return True


# ════════════════════════════════════════════════════════════════════════════════
#  APK ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class APKAnalyzer:
    """Extract and parse Android APK files."""

    def __init__(self, path: str) -> None:
        self.path = path

    def analyze(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "manifest": None,
            "package_name": "",
            "dex_strings": [],
            "all_strings": [],
            "file_list": [],
            "has_native_libs": False,
            "cert_info": {},
        }

        try:
            with zipfile.ZipFile(self.path, "r") as zf:
                result["file_list"] = zf.namelist()

                # Parse AndroidManifest.xml
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_data = zf.read("AndroidManifest.xml")
                    result["manifest"] = parse_android_binary_xml(manifest_data)
                    if result["manifest"] is not None:
                        result["package_name"] = result["manifest"].get("package", "")

                # Extract DEX strings
                for name in zf.namelist():
                    if name.endswith(".dex"):
                        try:
                            dex_data = zf.read(name)
                            dex_strings = extract_dex_strings(dex_data)
                            result["dex_strings"].extend(dex_strings)
                        except Exception:
                            pass

                # Extract native lib strings
                for name in zf.namelist():
                    if name.endswith(".so"):
                        result["has_native_libs"] = True
                        try:
                            so_data = zf.read(name)
                            so_strings = extract_macho_strings(so_data, min_len=10)
                            result["all_strings"].extend(so_strings[:5000])
                        except Exception:
                            pass

                # Combine all strings
                result["all_strings"].extend(result["dex_strings"])
                result["all_strings"] = result["all_strings"][:MAX_STRINGS]

        except (zipfile.BadZipFile, Exception) as e:
            print(f"[ERROR] Failed to open APK: {e}", file=sys.stderr)

        return result


# ════════════════════════════════════════════════════════════════════════════════
#  IPA ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class IPAAnalyzer:
    """Extract and parse iOS IPA files."""

    def __init__(self, path: str) -> None:
        self.path = path

    def analyze(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "plist": {},
            "entitlements": {},
            "binary_strings": [],
            "binary_data": b"",
            "file_list": [],
            "app_name": "",
            "has_pie": True,
        }

        try:
            with zipfile.ZipFile(self.path, "r") as zf:
                result["file_list"] = zf.namelist()

                # Find .app directory
                app_dir = ""
                for name in zf.namelist():
                    if name.startswith("Payload/") and name.endswith(".app/"):
                        app_dir = name
                        break
                if not app_dir:
                    for name in zf.namelist():
                        if name.startswith("Payload/") and ".app/" in name:
                            app_dir = name[:name.index(".app/") + 5]
                            break

                if not app_dir:
                    return result

                result["app_name"] = app_dir.split("/")[-2].replace(".app", "")

                # Parse Info.plist
                plist_path = app_dir + "Info.plist"
                if plist_path in zf.namelist():
                    try:
                        plist_data = zf.read(plist_path)
                        result["plist"] = plistlib.loads(plist_data)
                    except Exception:
                        # Try as text XML
                        try:
                            text = plist_data.decode("utf-8", errors="ignore")
                            result["plist"] = plistlib.loads(text.encode("utf-8"))
                        except Exception:
                            pass

                # Parse embedded.mobileprovision for entitlements
                prov_path = app_dir + "embedded.mobileprovision"
                if prov_path in zf.namelist():
                    try:
                        prov_data = zf.read(prov_path)
                        # Extract plist from provisioning profile
                        start = prov_data.find(b"<?xml")
                        end = prov_data.find(b"</plist>")
                        if start >= 0 and end >= 0:
                            plist_xml = prov_data[start:end + 8]
                            prov_plist = plistlib.loads(plist_xml)
                            result["entitlements"] = prov_plist.get("Entitlements", {})
                    except Exception:
                        pass

                # Extract main binary
                exec_name = result["plist"].get("CFBundleExecutable", result["app_name"])
                bin_path = app_dir + exec_name
                if bin_path in zf.namelist():
                    try:
                        bin_data = zf.read(bin_path)
                        result["binary_data"] = bin_data
                        result["binary_strings"] = extract_macho_strings(bin_data)
                        result["has_pie"] = check_macho_pie(bin_data)
                    except Exception:
                        pass

                # Extract framework strings
                for name in zf.namelist():
                    if ".framework/" in name and not name.endswith("/"):
                        try:
                            fw_data = zf.read(name)
                            if len(fw_data) > 1000:
                                fw_strings = extract_macho_strings(fw_data, min_len=12)
                                result["binary_strings"].extend(fw_strings[:2000])
                        except Exception:
                            pass

                result["binary_strings"] = result["binary_strings"][:MAX_STRINGS]

        except (zipfile.BadZipFile, Exception) as e:
            print(f"[ERROR] Failed to open IPA: {e}", file=sys.stderr)

        return result


# ════════════════════════════════════════════════════════════════════════════════
#  ANDROID CHECK MODULES
# ════════════════════════════════════════════════════════════════════════════════

def _manifest_attr(elem, attr: str, default: str = "") -> str:
    """Get an android: namespaced attribute from a manifest element."""
    if elem is None:
        return default
    for key in (f"android:{attr}", f"{{{_ANDROID_NS}}}{attr}", attr):
        val = elem.get(key)
        if val is not None:
            return val
    return default


def check_android_manifest(apk: Dict) -> List[Finding]:
    """Check AndroidManifest.xml for security misconfigurations."""
    findings: List[Finding] = []
    manifest = apk.get("manifest")
    if manifest is None:
        return findings

    app = manifest.find("application") or manifest.find(".//application")
    pkg = apk.get("package_name", "")

    # MAST-MANIFEST-001: debuggable
    if app is not None and _manifest_attr(app, "debuggable").lower() == "true":
        findings.append(Finding(
            rule_id="MAST-MANIFEST-001", name="Application is debuggable",
            category="Manifest", severity="CRITICAL", platform="android",
            file_path="AndroidManifest.xml", evidence='android:debuggable="true"',
            description="Application has debugging enabled, allowing attackers to attach debuggers and inspect runtime data.",
            recommendation='Set android:debuggable="false" in release builds.',
            cwe="CWE-215", owasp_mobile="M8:2024 Security Misconfiguration",
        ))

    # MAST-MANIFEST-002: allowBackup
    if app is not None and _manifest_attr(app, "allowBackup", "true").lower() == "true":
        findings.append(Finding(
            rule_id="MAST-MANIFEST-002", name="Application allows backup",
            category="Manifest", severity="HIGH", platform="android",
            file_path="AndroidManifest.xml", evidence='android:allowBackup="true"',
            description="Application data can be backed up via ADB, potentially exposing sensitive data.",
            recommendation='Set android:allowBackup="false" or use android:fullBackupContent with encryption.',
            cwe="CWE-530", owasp_mobile="M9:2024 Insecure Data Storage",
        ))

    # MAST-MANIFEST-003 to 006: Exported components
    component_checks = [
        ("activity", ".//activity", "MAST-MANIFEST-003", "Activity"),
        ("service", ".//service", "MAST-MANIFEST-004", "Service"),
        ("receiver", ".//receiver", "MAST-MANIFEST-005", "Broadcast Receiver"),
        ("provider", ".//provider", "MAST-MANIFEST-006", "Content Provider"),
    ]
    for comp_type, xpath, rule_id, label in component_checks:
        severity = "HIGH" if comp_type in ("activity", "service", "provider") else "MEDIUM"
        for elem in manifest.findall(xpath):
            exported = _manifest_attr(elem, "exported")
            permission = _manifest_attr(elem, "permission")
            name = _manifest_attr(elem, "name", "unknown")
            # Exported without permission protection
            if exported.lower() == "true" and not permission:
                # Skip launcher activities
                has_launcher = any("LAUNCHER" in (ic.text or "") for ic in elem.iter()
                                   if ic.tag in ("category", "action"))
                intent_filters = elem.findall("intent-filter")
                if has_launcher and comp_type == "activity":
                    continue
                findings.append(Finding(
                    rule_id=rule_id, name=f"Exported {label} without permission",
                    category="Manifest", severity=severity, platform="android",
                    file_path="AndroidManifest.xml",
                    evidence=f'{name} exported="true" without permission',
                    description=f"{label} '{name}' is exported without permission protection, accessible by other apps.",
                    recommendation=f"Add android:permission to restrict access or set exported=\"false\".",
                    cwe="CWE-926", owasp_mobile="M3:2024 Insecure Authentication/Authorization",
                ))

    # MAST-MANIFEST-007: usesCleartextTraffic
    if app is not None and _manifest_attr(app, "usesCleartextTraffic").lower() == "true":
        findings.append(Finding(
            rule_id="MAST-MANIFEST-007", name="Cleartext traffic allowed",
            category="Manifest", severity="HIGH", platform="android",
            file_path="AndroidManifest.xml", evidence='usesCleartextTraffic="true"',
            description="Application allows cleartext HTTP traffic, exposing data to network interception.",
            recommendation='Set usesCleartextTraffic="false" and use HTTPS exclusively.',
            cwe="CWE-319", owasp_mobile="M5:2024 Insecure Communication",
        ))

    # MAST-MANIFEST-008: minSdkVersion
    for sdk in manifest.findall(".//uses-sdk"):
        min_sdk = _manifest_attr(sdk, "minSdkVersion", "0")
        try:
            if int(min_sdk) < 23:
                findings.append(Finding(
                    rule_id="MAST-MANIFEST-008", name=f"Low minimum SDK version ({min_sdk})",
                    category="Manifest", severity="MEDIUM", platform="android",
                    file_path="AndroidManifest.xml", evidence=f"minSdkVersion={min_sdk}",
                    description=f"App supports Android SDK {min_sdk} (< 23/Android 6.0), missing runtime permission model.",
                    recommendation="Increase minSdkVersion to 23+ for runtime permissions and modern security features.",
                    cwe="CWE-693", owasp_mobile="M8:2024 Security Misconfiguration",
                ))
        except ValueError:
            pass

    # MAST-MANIFEST-009: Dangerous permissions
    dangerous_perms = {
        "android.permission.CAMERA": "Camera access",
        "android.permission.READ_SMS": "SMS read access",
        "android.permission.SEND_SMS": "SMS send access",
        "android.permission.READ_CONTACTS": "Contacts access",
        "android.permission.ACCESS_FINE_LOCATION": "Fine location access",
        "android.permission.RECORD_AUDIO": "Microphone access",
        "android.permission.READ_PHONE_STATE": "Phone state access",
        "android.permission.READ_CALL_LOG": "Call log access",
        "android.permission.WRITE_EXTERNAL_STORAGE": "External storage write",
    }
    for perm_elem in manifest.findall(".//uses-permission"):
        perm_name = _manifest_attr(perm_elem, "name", "")
        if perm_name in dangerous_perms:
            findings.append(Finding(
                rule_id="MAST-MANIFEST-009", name=f"Dangerous permission: {dangerous_perms[perm_name]}",
                category="Manifest", severity="MEDIUM", platform="android",
                file_path="AndroidManifest.xml", evidence=perm_name,
                description=f"App requests dangerous permission '{perm_name}' ({dangerous_perms[perm_name]}).",
                recommendation="Verify this permission is necessary. Request at runtime with clear user justification.",
                cwe="CWE-250", owasp_mobile="M6:2024 Inadequate Privacy Controls",
            ))

    # MAST-MANIFEST-010: SYSTEM_ALERT_WINDOW
    for perm_elem in manifest.findall(".//uses-permission"):
        if _manifest_attr(perm_elem, "name") == "android.permission.SYSTEM_ALERT_WINDOW":
            findings.append(Finding(
                rule_id="MAST-MANIFEST-010", name="SYSTEM_ALERT_WINDOW permission",
                category="Manifest", severity="MEDIUM", platform="android",
                file_path="AndroidManifest.xml", evidence="android.permission.SYSTEM_ALERT_WINDOW",
                description="App can draw over other apps, potentially used for tapjacking/overlay attacks.",
                recommendation="Remove unless essential. Google Play restricts this permission.",
                cwe="CWE-1021", owasp_mobile="M8:2024 Security Misconfiguration",
            ))

    # MAST-MANIFEST-011: Missing network security config
    if app is not None and not _manifest_attr(app, "networkSecurityConfig"):
        findings.append(Finding(
            rule_id="MAST-MANIFEST-011", name="Missing network security config",
            category="Manifest", severity="MEDIUM", platform="android",
            file_path="AndroidManifest.xml", evidence="networkSecurityConfig not set",
            description="No custom network security configuration. Relying on platform defaults.",
            recommendation="Add a network_security_config.xml to enforce certificate pinning and cleartext restrictions.",
            cwe="CWE-295", owasp_mobile="M5:2024 Insecure Communication",
        ))

    # MAST-MANIFEST-012: Task affinity
    if app is not None:
        affinity = _manifest_attr(app, "taskAffinity")
        if affinity and affinity != pkg:
            findings.append(Finding(
                rule_id="MAST-MANIFEST-012", name="Custom task affinity set",
                category="Manifest", severity="LOW", platform="android",
                file_path="AndroidManifest.xml", evidence=f"taskAffinity={affinity}",
                description="Custom task affinity may enable task hijacking attacks (StrandHogg).",
                recommendation="Remove taskAffinity or set to empty string to use default.",
                cwe="CWE-269", owasp_mobile="M3:2024 Insecure Authentication/Authorization",
            ))

    return findings


# ── Secret patterns for string scanning ──────────────────────────────────────

_SECRET_PATTERNS = [
    ("MAST-SECRET-001", r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "CRITICAL"),
    ("MAST-SECRET-002", r"(?:aws_secret|secret_key|AWS_SECRET)['\"\s:=]+[A-Za-z0-9/+=]{40}", "AWS Secret Key", "CRITICAL"),
    ("MAST-SECRET-003", r"AIzaSy[0-9A-Za-z\-_]{33}", "Google API Key", "HIGH"),
    ("MAST-SECRET-004", r"https?://[\w-]+\.firebaseio\.com", "Firebase Database URL", "MEDIUM"),
    ("MAST-SECRET-005", r"(?:api[_-]?key|apikey|token)['\"\s:=]+['\"][A-Za-z0-9\-_]{20,}['\"]", "Generic API Key/Token", "MEDIUM"),
    ("MAST-SECRET-006", r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "Hardcoded Password", "HIGH"),
    ("MAST-SECRET-007", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key", "CRITICAL"),
    ("MAST-SECRET-008", r"(?:client_secret|oauth_secret)\s*[=:]\s*['\"][A-Za-z0-9\-_]{10,}['\"]", "OAuth Client Secret", "HIGH"),
]


def check_android_secrets(apk: Dict) -> List[Finding]:
    """Detect hardcoded secrets in APK strings."""
    findings: List[Finding] = []
    all_strings = apk.get("all_strings", [])

    for s in all_strings:
        for rule_id, pattern, name, severity in _SECRET_PATTERNS:
            m = re.search(pattern, s, re.I)
            if m:
                findings.append(Finding(
                    rule_id=rule_id, name=name,
                    category="Secrets", severity=severity, platform="android",
                    file_path="classes.dex / resources",
                    evidence=m.group()[:MAX_EVIDENCE],
                    description=f"Hardcoded {name.lower()} found in application strings.",
                    recommendation="Remove hardcoded secrets. Use Android Keystore or environment-based configuration.",
                    cwe="CWE-798", owasp_mobile="M1:2024 Improper Credential Usage",
                ))
                break  # One finding per string per pattern
    return findings


def check_android_crypto(apk: Dict) -> List[Finding]:
    """Detect insecure cryptographic patterns."""
    findings: List[Finding] = []
    strings = apk.get("dex_strings", [])
    joined = "\n".join(strings[:MAX_STRINGS])

    checks = [
        ("MAST-CRYPTO-001", r"MessageDigest\.getInstance\([\"'](?:MD5|SHA-?1)[\"']\)", "Weak hash algorithm (MD5/SHA1)", "MEDIUM", "CWE-328"),
        ("MAST-CRYPTO-002", r"Cipher\.getInstance\([\"'](?:DES|DESede|RC4|RC2|Blowfish)", "Weak cipher algorithm", "HIGH", "CWE-327"),
        ("MAST-CRYPTO-003", r"(?:AES|DES|DESede)/ECB", "ECB mode encryption", "HIGH", "CWE-327"),
        ("MAST-CRYPTO-004", r"java\.util\.Random\b", "Insecure random (java.util.Random)", "MEDIUM", "CWE-330"),
        ("MAST-CRYPTO-005", r"(?:SecretKeySpec|IvParameterSpec)\([\"'][^\"']{8,}[\"']", "Hardcoded key/IV", "HIGH", "CWE-321"),
    ]
    for rule_id, pattern, name, severity, cwe in checks:
        m = re.search(pattern, joined)
        if m:
            findings.append(Finding(
                rule_id=rule_id, name=name,
                category="Cryptography", severity=severity, platform="android",
                file_path="classes.dex",
                evidence=m.group()[:MAX_EVIDENCE],
                description=f"Insecure cryptographic pattern detected: {name}.",
                recommendation="Use AES-256-GCM, SHA-256+, and java.security.SecureRandom.",
                cwe=cwe, owasp_mobile="M10:2024 Insufficient Cryptography",
            ))
    return findings


def check_android_network(apk: Dict) -> List[Finding]:
    """Detect network security issues."""
    findings: List[Finding] = []
    strings = apk.get("dex_strings", [])
    joined = "\n".join(strings[:MAX_STRINGS])

    checks = [
        ("MAST-NET-001", r"(?:TrustAllCertificates|AllTrustManager|checkServerTrusted.*\{\s*\}|X509TrustManager.*return\b)", "TrustManager accepts all certificates", "CRITICAL", "CWE-295"),
        ("MAST-NET-002", r"(?:ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|verify.*return\s+true)", "Hostname verification disabled", "CRITICAL", "CWE-297"),
        ("MAST-NET-003", r"http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|0\.0\.0\.0)[^\s\"']{5,}", "Cleartext HTTP URL", "MEDIUM", "CWE-319"),
        ("MAST-NET-005", r"MIXED_CONTENT_ALWAYS_ALLOW", "WebView mixed content allowed", "MEDIUM", "CWE-319"),
    ]
    for rule_id, pattern, name, severity, cwe in checks:
        matches = re.findall(pattern, joined)
        if matches:
            for m_text in matches[:3]:
                findings.append(Finding(
                    rule_id=rule_id, name=name,
                    category="Network", severity=severity, platform="android",
                    file_path="classes.dex",
                    evidence=m_text[:MAX_EVIDENCE],
                    description=f"Network security issue: {name}.",
                    recommendation="Use HTTPS only. Implement proper certificate validation and pinning.",
                    cwe=cwe, owasp_mobile="M5:2024 Insecure Communication",
                ))
            break  # One set per pattern

    # MAST-NET-004: No cert pinning
    pinning_indicators = ["CertificatePinner", "TrustManagerFactory", "network_security_config", "pinning"]
    has_pinning = any(ind.lower() in joined.lower() for ind in pinning_indicators)
    if not has_pinning and len(strings) > 100:
        findings.append(Finding(
            rule_id="MAST-NET-004", name="No certificate pinning detected",
            category="Network", severity="LOW", platform="android",
            file_path="classes.dex", evidence="No pinning references found in code",
            description="No certificate pinning implementation found. App may be vulnerable to MitM attacks.",
            recommendation="Implement certificate pinning via OkHttp CertificatePinner or network_security_config.xml.",
            cwe="CWE-295", owasp_mobile="M5:2024 Insecure Communication",
        ))
    return findings


def check_android_storage(apk: Dict) -> List[Finding]:
    """Detect insecure data storage patterns."""
    findings: List[Finding] = []
    joined = "\n".join(apk.get("dex_strings", [])[:MAX_STRINGS])

    checks = [
        ("MAST-STORAGE-001", r"MODE_WORLD_(?:READ|WRIT)ABLE", "World-accessible file mode", "CRITICAL", "CWE-276"),
        ("MAST-STORAGE-002", r"getExternal(?:Storage|FilesDir|CacheDir)", "External storage usage", "MEDIUM", "CWE-922"),
        ("MAST-STORAGE-003", r"SQLiteDatabase\.openOrCreateDatabase|openDatabase", "SQLite without encryption", "MEDIUM", "CWE-312"),
        ("MAST-STORAGE-004", r"/(?:data|sdcard|storage)/[^\s\"']{5,}\.(?:db|sqlite)", "Hardcoded database path", "LOW", "CWE-798"),
        ("MAST-STORAGE-005", r"Log\.(?:d|v|i)\([^)]*(?:password|token|secret|key|credential)", "Logging sensitive data", "MEDIUM", "CWE-532"),
    ]
    for rule_id, pattern, name, severity, cwe in checks:
        m = re.search(pattern, joined, re.I)
        if m:
            findings.append(Finding(
                rule_id=rule_id, name=name,
                category="Data Storage", severity=severity, platform="android",
                file_path="classes.dex", evidence=m.group()[:MAX_EVIDENCE],
                description=f"Insecure data storage: {name}.",
                recommendation="Use EncryptedSharedPreferences, SQLCipher, or Android Keystore for sensitive data.",
                cwe=cwe, owasp_mobile="M9:2024 Insecure Data Storage",
            ))
    return findings


def check_android_webview(apk: Dict) -> List[Finding]:
    """Detect WebView security issues."""
    findings: List[Finding] = []
    joined = "\n".join(apk.get("dex_strings", [])[:MAX_STRINGS])

    checks = [
        ("MAST-WEBVIEW-001", r"setJavaScriptEnabled\(\s*true\s*\)", "WebView JavaScript enabled", "MEDIUM", "CWE-79"),
        ("MAST-WEBVIEW-002", r"setAllowFileAccess\(\s*true\s*\)", "WebView file access enabled", "HIGH", "CWE-200"),
        ("MAST-WEBVIEW-003", r"setAllowUniversalAccessFromFileURLs\(\s*true\s*\)", "WebView universal file access", "CRITICAL", "CWE-200"),
        ("MAST-WEBVIEW-004", r"addJavascriptInterface\(", "WebView JavaScript interface", "HIGH", "CWE-749"),
        ("MAST-WEBVIEW-005", r"setWebContentsDebuggingEnabled\(\s*true\s*\)", "WebView remote debugging enabled", "HIGH", "CWE-215"),
    ]
    for rule_id, pattern, name, severity, cwe in checks:
        m = re.search(pattern, joined)
        if m:
            findings.append(Finding(
                rule_id=rule_id, name=name,
                category="WebView", severity=severity, platform="android",
                file_path="classes.dex", evidence=m.group()[:MAX_EVIDENCE],
                description=f"WebView security issue: {name}.",
                recommendation="Disable unnecessary WebView features. Use setJavaScriptEnabled(false) unless required.",
                cwe=cwe, owasp_mobile="M4:2024 Insufficient Input/Output Validation",
            ))
    return findings


def check_android_components(apk: Dict) -> List[Finding]:
    """Detect component security issues."""
    findings: List[Finding] = []
    joined = "\n".join(apk.get("dex_strings", [])[:MAX_STRINGS])

    checks = [
        ("MAST-COMP-001", r"PendingIntent\.get(?:Activity|Service|Broadcast)\([^)]*FLAG_MUTABLE", "PendingIntent with FLAG_MUTABLE", "HIGH", "CWE-927"),
        ("MAST-COMP-002", r"(?:putExtra|setAction)\([^)]*(?:password|token|secret|credential)", "Sensitive data in Intent", "MEDIUM", "CWE-927"),
        ("MAST-COMP-003", r"sendBroadcast\([^)]*(?!,\s*[\"'])", "Broadcast without permission", "MEDIUM", "CWE-927"),
    ]
    for rule_id, pattern, name, severity, cwe in checks:
        m = re.search(pattern, joined, re.I)
        if m:
            findings.append(Finding(
                rule_id=rule_id, name=name,
                category="Components", severity=severity, platform="android",
                file_path="classes.dex", evidence=m.group()[:MAX_EVIDENCE],
                description=f"Component security issue: {name}.",
                recommendation="Use FLAG_IMMUTABLE for PendingIntents. Avoid putting secrets in Intents.",
                cwe=cwe, owasp_mobile="M3:2024 Insecure Authentication/Authorization",
            ))
    return findings


# ════════════════════════════════════════════════════════════════════════════════
#  iOS CHECK MODULES
# ════════════════════════════════════════════════════════════════════════════════

def check_ios_plist(ipa: Dict) -> List[Finding]:
    """Check Info.plist for security misconfigurations."""
    findings: List[Finding] = []
    plist = ipa.get("plist", {})
    if not plist:
        return findings

    # MAST-IOS-PLIST-001: ATS disabled
    ats = plist.get("NSAppTransportSecurity", {})
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads"):
        findings.append(Finding(
            rule_id="MAST-IOS-PLIST-001", name="App Transport Security disabled",
            category="Plist", severity="HIGH", platform="ios",
            file_path="Info.plist", evidence="NSAllowsArbitraryLoads = true",
            description="ATS is disabled, allowing cleartext HTTP and insecure TLS connections.",
            recommendation="Enable ATS. Only add exceptions for specific domains that require them.",
            cwe="CWE-319", owasp_mobile="M5:2024 Insecure Communication",
        ))

    # MAST-IOS-PLIST-002: ATS exception domains
    exceptions = ats.get("NSExceptionDomains", {}) if isinstance(ats, dict) else {}
    for domain, config in exceptions.items():
        if isinstance(config, dict) and config.get("NSExceptionAllowsInsecureHTTPLoads"):
            findings.append(Finding(
                rule_id="MAST-IOS-PLIST-002", name=f"ATS exception: {domain}",
                category="Plist", severity="MEDIUM", platform="ios",
                file_path="Info.plist", evidence=f"{domain}: NSExceptionAllowsInsecureHTTPLoads=true",
                description=f"ATS exception allows insecure HTTP for domain '{domain}'.",
                recommendation=f"Ensure {domain} supports HTTPS and remove the ATS exception.",
                cwe="CWE-319", owasp_mobile="M5:2024 Insecure Communication",
            ))

    # MAST-IOS-PLIST-003: URL schemes
    url_types = plist.get("CFBundleURLTypes", [])
    for ut in url_types:
        schemes = ut.get("CFBundleURLSchemes", [])
        for scheme in schemes:
            findings.append(Finding(
                rule_id="MAST-IOS-PLIST-003", name=f"Custom URL scheme: {scheme}",
                category="Plist", severity="INFO", platform="ios",
                file_path="Info.plist", evidence=f"URL scheme: {scheme}://",
                description=f"App registers custom URL scheme '{scheme}://'. Ensure input validation on deep link handlers.",
                recommendation="Validate all parameters received via URL schemes. Use Universal Links instead where possible.",
                cwe="CWE-939", owasp_mobile="M4:2024 Insufficient Input/Output Validation",
            ))

    # MAST-IOS-PLIST-005: Additional ATS exceptions
    if isinstance(ats, dict):
        for key in ("NSAllowsArbitraryLoadsForMedia", "NSAllowsArbitraryLoadsInWebContent", "NSAllowsLocalNetworking"):
            if ats.get(key):
                findings.append(Finding(
                    rule_id="MAST-IOS-PLIST-005", name=f"ATS exception: {key}",
                    category="Plist", severity="MEDIUM", platform="ios",
                    file_path="Info.plist", evidence=f"{key} = true",
                    description=f"ATS exception '{key}' weakens transport security.",
                    recommendation=f"Remove {key} unless absolutely necessary.",
                    cwe="CWE-319", owasp_mobile="M5:2024 Insecure Communication",
                ))

    # MAST-IOS-PLIST-006: Low minimum OS version
    min_os = plist.get("MinimumOSVersion", "")
    if min_os:
        try:
            major = int(min_os.split(".")[0])
            if major < 14:
                findings.append(Finding(
                    rule_id="MAST-IOS-PLIST-006", name=f"Low minimum iOS version ({min_os})",
                    category="Plist", severity="MEDIUM", platform="ios",
                    file_path="Info.plist", evidence=f"MinimumOSVersion = {min_os}",
                    description=f"App supports iOS {min_os} (< 14.0), missing modern security features.",
                    recommendation="Increase minimum deployment target to iOS 14.0+ for latest security APIs.",
                    cwe="CWE-693", owasp_mobile="M8:2024 Security Misconfiguration",
                ))
        except ValueError:
            pass

    # MAST-IOS-PLIST-008: Keychain access groups
    kc_groups = plist.get("keychain-access-groups", [])
    if len(kc_groups) > 1:
        findings.append(Finding(
            rule_id="MAST-IOS-PLIST-008", name="Multiple Keychain access groups",
            category="Plist", severity="INFO", platform="ios",
            file_path="Info.plist", evidence=f"Keychain groups: {', '.join(str(g) for g in kc_groups[:5])}",
            description="App shares Keychain access with multiple groups. Verify data isolation.",
            recommendation="Review Keychain access groups to ensure sensitive data is not shared unnecessarily.",
            cwe="CWE-922", owasp_mobile="M9:2024 Insecure Data Storage",
        ))

    return findings


def check_ios_secrets(ipa: Dict) -> List[Finding]:
    """Detect hardcoded secrets in iOS binary strings."""
    findings: List[Finding] = []
    all_strings = ipa.get("binary_strings", [])

    secret_patterns = [
        ("MAST-IOS-SECRET-001", r"AIzaSy[0-9A-Za-z\-_]{33}", "Google API Key", "HIGH"),
        ("MAST-IOS-SECRET-001", r"AKIA[0-9A-Z]{16}", "AWS Access Key", "CRITICAL"),
        ("MAST-IOS-SECRET-002", r"https?://[\w-]+\.firebaseio\.com", "Firebase URL", "MEDIUM"),
        ("MAST-IOS-SECRET-003", r"(?:Bearer|token|authorization)\s+[A-Za-z0-9\-_.]{20,}", "Bearer/OAuth Token", "HIGH"),
        ("MAST-IOS-SECRET-004", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key", "CRITICAL"),
    ]
    for s in all_strings:
        for rule_id, pattern, name, severity in secret_patterns:
            m = re.search(pattern, s)
            if m:
                findings.append(Finding(
                    rule_id=rule_id, name=name,
                    category="Secrets", severity=severity, platform="ios",
                    file_path="binary", evidence=m.group()[:MAX_EVIDENCE],
                    description=f"Hardcoded {name.lower()} found in iOS binary.",
                    recommendation="Remove hardcoded secrets. Use iOS Keychain or server-side configuration.",
                    cwe="CWE-798", owasp_mobile="M1:2024 Improper Credential Usage",
                ))
                break
    return findings


def check_ios_binary(ipa: Dict) -> List[Finding]:
    """Check iOS binary for security protections."""
    findings: List[Finding] = []
    bin_strings = ipa.get("binary_strings", [])
    joined = "\n".join(bin_strings[:10000])

    # MAST-IOS-BIN-001: PIE
    if not ipa.get("has_pie", True):
        findings.append(Finding(
            rule_id="MAST-IOS-BIN-001", name="PIE not enabled",
            category="Binary", severity="HIGH", platform="ios",
            file_path="binary", evidence="MH_PIE flag not set in Mach-O header",
            description="Binary is not compiled as Position Independent Executable, weakening ASLR protection.",
            recommendation="Enable PIE in Xcode build settings (Position Independent Code = YES).",
            cwe="CWE-119", owasp_mobile="M7:2024 Insufficient Binary Protections",
        ))

    # MAST-IOS-BIN-002: ARC
    if "objc_release" not in joined and "objc_retain" not in joined and len(bin_strings) > 100:
        findings.append(Finding(
            rule_id="MAST-IOS-BIN-002", name="ARC may not be enabled",
            category="Binary", severity="MEDIUM", platform="ios",
            file_path="binary", evidence="No objc_release/objc_retain references found",
            description="Binary may not use Automatic Reference Counting, increasing memory corruption risk.",
            recommendation="Enable ARC in Xcode (Objective-C Automatic Reference Counting = YES).",
            cwe="CWE-119", owasp_mobile="M7:2024 Insufficient Binary Protections",
        ))

    # MAST-IOS-BIN-003: Stack canaries
    if "__stack_chk_fail" not in joined and "__stack_chk_guard" not in joined and len(bin_strings) > 100:
        findings.append(Finding(
            rule_id="MAST-IOS-BIN-003", name="Stack canaries not detected",
            category="Binary", severity="MEDIUM", platform="ios",
            file_path="binary", evidence="No __stack_chk_fail/__stack_chk_guard references",
            description="Binary may lack stack buffer overflow protection (stack canaries).",
            recommendation="Enable stack protection in Xcode (-fstack-protector-all compiler flag).",
            cwe="CWE-120", owasp_mobile="M7:2024 Insufficient Binary Protections",
        ))

    # MAST-IOS-BIN-004: Debug symbols
    if any("DWARF" in s or ".debug_" in s for s in bin_strings[:5000]):
        findings.append(Finding(
            rule_id="MAST-IOS-BIN-004", name="Debug symbols present",
            category="Binary", severity="LOW", platform="ios",
            file_path="binary", evidence="DWARF debug sections found",
            description="Binary contains debug symbols which aid reverse engineering.",
            recommendation="Strip debug symbols in release builds (Strip Debug Symbols During Copy = YES).",
            cwe="CWE-215", owasp_mobile="M7:2024 Insufficient Binary Protections",
        ))

    return findings


def check_ios_transport(ipa: Dict) -> List[Finding]:
    """Detect iOS transport security issues."""
    findings: List[Finding] = []
    strings = ipa.get("binary_strings", [])
    joined = "\n".join(strings[:MAX_STRINGS])

    # MAST-IOS-NET-001: HTTP URLs
    http_urls = re.findall(r"http://(?!localhost|127\.0\.0\.1)[^\s\"']{5,}", joined)
    if http_urls:
        findings.append(Finding(
            rule_id="MAST-IOS-NET-001", name="HTTP URLs in binary",
            category="Network", severity="MEDIUM", platform="ios",
            file_path="binary", evidence="; ".join(http_urls[:3])[:MAX_EVIDENCE],
            description=f"Found {len(http_urls)} cleartext HTTP URL(s) in binary.",
            recommendation="Use HTTPS for all network communication.",
            cwe="CWE-319", owasp_mobile="M5:2024 Insecure Communication",
        ))

    # MAST-IOS-NET-002: No cert pinning
    pinning_refs = ["TrustKit", "AFSecurityPolicy", "pinning", "PublicKeyPin", "SSLPinning"]
    if not any(ref.lower() in joined.lower() for ref in pinning_refs) and len(strings) > 100:
        findings.append(Finding(
            rule_id="MAST-IOS-NET-002", name="No certificate pinning detected",
            category="Network", severity="LOW", platform="ios",
            file_path="binary", evidence="No pinning framework references found",
            description="No certificate pinning implementation detected in the binary.",
            recommendation="Implement certificate pinning using TrustKit, Alamofire, or NSURLSession delegate.",
            cwe="CWE-295", owasp_mobile="M5:2024 Insecure Communication",
        ))

    # MAST-IOS-NET-003: Custom SSL handling
    if "SecTrustEvaluate" in joined or "SecTrustSetAnchorCertificates" in joined:
        findings.append(Finding(
            rule_id="MAST-IOS-NET-003", name="Custom SSL/TLS trust evaluation",
            category="Network", severity="MEDIUM", platform="ios",
            file_path="binary", evidence="SecTrustEvaluate or custom anchor certs detected",
            description="App implements custom SSL trust evaluation which may weaken security if incorrect.",
            recommendation="Review SecTrust implementation to ensure proper certificate chain validation.",
            cwe="CWE-295", owasp_mobile="M5:2024 Insecure Communication",
        ))

    return findings


# ════════════════════════════════════════════════════════════════════════════════
#  COMMON CHECK MODULES (Android + iOS)
# ════════════════════════════════════════════════════════════════════════════════

_COMMON_SECRET_PATTERNS = [
    ("MAST-COMMON-SEC-001", r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "CRITICAL"),
    ("MAST-COMMON-SEC-002", r"AIzaSy[0-9A-Za-z\-_]{33}", "Google Cloud API Key", "HIGH"),
    ("MAST-COMMON-SEC-003", r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key", "CRITICAL"),
    ("MAST-COMMON-SEC-004", r"SK[0-9a-fA-F]{32}", "Twilio Auth Token", "HIGH"),
    ("MAST-COMMON-SEC-005", r"SG\.[0-9A-Za-z\-_]{22,}", "SendGrid API Key", "HIGH"),
    ("MAST-COMMON-SEC-006", r"Bearer\s+[A-Za-z0-9\-_.]{20,}", "Generic Bearer Token", "MEDIUM"),
]


def check_common_secrets(all_strings: List[str], platform: str) -> List[Finding]:
    """Detect common secrets across platforms."""
    findings: List[Finding] = []
    seen: Set[str] = set()

    for s in all_strings:
        for rule_id, pattern, name, severity in _COMMON_SECRET_PATTERNS:
            m = re.search(pattern, s)
            if m:
                val = m.group()[:50]
                if val not in seen:
                    seen.add(val)
                    findings.append(Finding(
                        rule_id=rule_id, name=name,
                        category="Secrets", severity=severity, platform="common",
                        file_path="strings", evidence=m.group()[:MAX_EVIDENCE],
                        description=f"Hardcoded {name.lower()} found in application.",
                        recommendation="Remove secrets from code. Use platform-specific secure storage.",
                        cwe="CWE-798", owasp_mobile="M1:2024 Improper Credential Usage",
                    ))
    return findings


def check_common_urls(all_strings: List[str], platform: str) -> List[Finding]:
    """Detect insecure URL patterns."""
    findings: List[Finding] = []
    seen_types: Set[str] = set()

    for s in all_strings:
        # MAST-COMMON-URL-001: HTTP URLs
        if "MAST-COMMON-URL-001" not in seen_types:
            http = re.findall(r"http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.)[^\s\"'<>]{5,}", s)
            if http:
                seen_types.add("MAST-COMMON-URL-001")
                findings.append(Finding(
                    rule_id="MAST-COMMON-URL-001", name="Cleartext HTTP endpoint",
                    category="URLs", severity="MEDIUM", platform="common",
                    file_path="strings", evidence=http[0][:MAX_EVIDENCE],
                    description="Application contains cleartext HTTP URLs.",
                    recommendation="Use HTTPS for all network endpoints.",
                    cwe="CWE-319", owasp_mobile="M5:2024 Insecure Communication",
                ))

        # MAST-COMMON-URL-002: Staging/internal URLs
        if "MAST-COMMON-URL-002" not in seen_types:
            staging = re.search(r"https?://(?:staging|dev|test|internal|qa|uat)\.", s, re.I)
            if staging:
                seen_types.add("MAST-COMMON-URL-002")
                findings.append(Finding(
                    rule_id="MAST-COMMON-URL-002", name="Staging/internal URL found",
                    category="URLs", severity="MEDIUM", platform="common",
                    file_path="strings", evidence=staging.group()[:MAX_EVIDENCE],
                    description="Application contains staging or internal URLs that should not be in production.",
                    recommendation="Remove all staging/dev/test URLs from production builds.",
                    cwe="CWE-200", owasp_mobile="M8:2024 Security Misconfiguration",
                ))

        # MAST-COMMON-URL-003: Localhost
        if "MAST-COMMON-URL-003" not in seen_types:
            if re.search(r"https?://(?:localhost|127\.0\.0\.1)(?::\d+)?/", s):
                seen_types.add("MAST-COMMON-URL-003")
                findings.append(Finding(
                    rule_id="MAST-COMMON-URL-003", name="Localhost reference",
                    category="URLs", severity="LOW", platform="common",
                    file_path="strings", evidence=re.search(r"https?://(?:localhost|127\.0\.0\.1)[^\s]*", s).group()[:MAX_EVIDENCE],
                    description="Localhost/127.0.0.1 reference found — likely debug leftover.",
                    recommendation="Remove localhost references from production builds.",
                    cwe="CWE-200", owasp_mobile="M8:2024 Security Misconfiguration",
                ))

        # MAST-COMMON-URL-004: Hardcoded IPs
        if "MAST-COMMON-URL-004" not in seen_types:
            ip_match = re.search(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?/", s)
            if ip_match and ip_match.group(1) not in ("127.0.0.1", "0.0.0.0"):
                seen_types.add("MAST-COMMON-URL-004")
                findings.append(Finding(
                    rule_id="MAST-COMMON-URL-004", name="Hardcoded IP address",
                    category="URLs", severity="LOW", platform="common",
                    file_path="strings", evidence=ip_match.group()[:MAX_EVIDENCE],
                    description="Hardcoded IP address found — makes infrastructure changes difficult.",
                    recommendation="Use domain names instead of hardcoded IP addresses.",
                    cwe="CWE-798", owasp_mobile="M8:2024 Security Misconfiguration",
                ))

    return findings


def check_common_crypto(all_strings: List[str], platform: str) -> List[Finding]:
    """Detect common cryptographic issues across platforms."""
    findings: List[Finding] = []
    joined = "\n".join(all_strings[:MAX_STRINGS])

    checks = [
        ("MAST-COMMON-CRYPTO-001", r"(?:encryption_key|aes_key|secret_key)\s*[=:]\s*['\"][A-Za-z0-9+/=]{16,}['\"]", "Hardcoded encryption key", "HIGH", "CWE-321"),
        ("MAST-COMMON-CRYPTO-002", r"(?:MD5|md5)\s*\(", "MD5 hash usage", "LOW", "CWE-328"),
        ("MAST-COMMON-CRYPTO-003", r"(?:Math\.random|arc4random\b(?!_uniform))", "Insecure random", "MEDIUM", "CWE-330"),
    ]
    for rule_id, pattern, name, severity, cwe in checks:
        m = re.search(pattern, joined, re.I)
        if m:
            findings.append(Finding(
                rule_id=rule_id, name=name,
                category="Cryptography", severity=severity, platform="common",
                file_path="strings", evidence=m.group()[:MAX_EVIDENCE],
                description=f"Cryptographic issue: {name}.",
                recommendation="Use platform-provided secure cryptographic APIs.",
                cwe=cwe, owasp_mobile="M10:2024 Insufficient Cryptography",
            ))
    return findings


# ════════════════════════════════════════════════════════════════════════════════
#  MAST SCANNER ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════

class MASTScanner:
    """Mobile Application Security Testing Scanner."""

    def __init__(self, path: str, verbose: bool = False, platform: str = "auto"):
        self.path = path
        self.verbose = verbose
        self.requested_platform = platform
        self.findings: List[Finding] = []
        self.platform: str = ""
        self.app_info: Dict[str, Any] = {}

    def scan(self) -> List[Finding]:
        """Run the full scan."""
        if not os.path.isfile(self.path):
            print(f"[ERROR] File not found: {self.path}", file=sys.stderr)
            return []

        # Detect platform
        self.platform = self._detect_platform()
        if not self.platform:
            print("[ERROR] Cannot determine platform. Use --platform android|ios", file=sys.stderr)
            return []

        print(f"[*] Platform : {self.platform.upper()}")
        print(f"[*] File     : {os.path.basename(self.path)}")
        print(f"[*] Size     : {os.path.getsize(self.path):,} bytes")

        if self.platform == "android":
            self._scan_android()
        elif self.platform == "ios":
            self._scan_ios()

        # Sort by severity
        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 5))

        # Deduplicate
        seen: Set[str] = set()
        deduped: List[Finding] = []
        for f in self.findings:
            key = f"{f.rule_id}:{f.evidence[:80]}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        self.findings = deduped

        print(f"\n[+] Analysis complete: {len(self.findings)} finding(s)")
        return self.findings

    def _detect_platform(self) -> str:
        if self.requested_platform != "auto":
            return self.requested_platform
        ext = os.path.splitext(self.path)[1].lower()
        if ext == ".apk":
            return "android"
        elif ext == ".ipa":
            return "ios"
        # Try ZIP inspection
        try:
            with zipfile.ZipFile(self.path, "r") as zf:
                names = zf.namelist()
                if any("AndroidManifest.xml" in n for n in names):
                    return "android"
                if any("Payload/" in n and ".app/" in n for n in names):
                    return "ios"
        except Exception:
            pass
        return ""

    def _scan_android(self) -> None:
        print("[*] Analysing Android APK...")
        analyzer = APKAnalyzer(self.path)
        apk = analyzer.analyze()
        self.app_info = {"package": apk.get("package_name", ""), "files": len(apk.get("file_list", []))}

        if self.verbose:
            print(f"    Package  : {apk.get('package_name', 'unknown')}")
            print(f"    Files    : {len(apk.get('file_list', []))}")
            print(f"    DEX str  : {len(apk.get('dex_strings', []))}")

        # Run Android checks
        self.findings.extend(check_android_manifest(apk))
        self.findings.extend(check_android_secrets(apk))
        self.findings.extend(check_android_crypto(apk))
        self.findings.extend(check_android_network(apk))
        self.findings.extend(check_android_storage(apk))
        self.findings.extend(check_android_webview(apk))
        self.findings.extend(check_android_components(apk))

        # Common checks
        all_strings = apk.get("all_strings", [])
        self.findings.extend(check_common_secrets(all_strings, "android"))
        self.findings.extend(check_common_urls(all_strings, "android"))
        self.findings.extend(check_common_crypto(all_strings, "android"))

    def _scan_ios(self) -> None:
        print("[*] Analysing iOS IPA...")
        analyzer = IPAAnalyzer(self.path)
        ipa = analyzer.analyze()
        self.app_info = {"app_name": ipa.get("app_name", ""), "files": len(ipa.get("file_list", []))}

        if self.verbose:
            print(f"    App name : {ipa.get('app_name', 'unknown')}")
            print(f"    Files    : {len(ipa.get('file_list', []))}")
            print(f"    Strings  : {len(ipa.get('binary_strings', []))}")

        # Run iOS checks
        self.findings.extend(check_ios_plist(ipa))
        self.findings.extend(check_ios_secrets(ipa))
        self.findings.extend(check_ios_binary(ipa))
        self.findings.extend(check_ios_transport(ipa))

        # Common checks
        all_strings = ipa.get("binary_strings", [])
        self.findings.extend(check_common_secrets(all_strings, "ios"))
        self.findings.extend(check_common_urls(all_strings, "ios"))
        self.findings.extend(check_common_crypto(all_strings, "ios"))

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity: str) -> None:
        min_level = SEVERITY_ORDER.get(min_severity, 4)
        self.findings = [f for f in self.findings if SEVERITY_ORDER.get(f.severity, 5) <= min_level]

    def print_report(self) -> None:
        s = self.summary()
        total = sum(s.values())
        print(f"\n{'='*60}")
        print(f"  MAST Scanner v{__version__} — {self.platform.upper()} Analysis Report")
        print(f"{'='*60}")
        print(f"  Total findings: {total}")
        for sev in SEVERITY_ORDER:
            c = s[sev]
            if c > 0:
                print(f"  {SEVERITY_COLOR[sev]}{sev:<10}{RESET} {c}")
        print(f"{'='*60}\n")

        for f in self.findings:
            sc = SEVERITY_COLOR.get(f.severity, "")
            print(f"  {sc}[{f.severity}]{RESET} {BOLD}{f.rule_id}{RESET}: {f.name}")
            print(f"           File: {f.file_path}")
            print(f"           Evidence: {f.evidence[:100]}")
            if self.verbose:
                print(f"           {f.description}")
                print(f"           Fix: {f.recommendation}")
            print()

    def save_json(self, path: str) -> None:
        report = {
            "scanner": "MAST Scanner",
            "version": __version__,
            "platform": self.platform,
            "file": os.path.basename(self.path),
            "scan_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "app_info": self.app_info,
            "summary": self.summary(),
            "findings": [asdict(f) for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"  JSON report: {path}")

    def save_html(self, path: str) -> None:
        s = self.summary()
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
                      "LOW": "#0891b2", "INFO": "#6b7280"}

        rows = ""
        for f in self.findings:
            sc = sev_colors.get(f.severity, "#6b7280")
            esc = lambda t: (t or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            rows += f"""<tr>
<td><span style="color:{sc};font-weight:700">{f.severity}</span></td>
<td><code>{f.rule_id}</code></td>
<td>{esc(f.name)}</td>
<td>{f.platform}</td>
<td><code>{esc(f.file_path)}</code></td>
<td style="font-size:.85em">{esc(f.evidence[:120])}</td>
<td style="font-size:.85em">{esc(f.description[:200])}</td>
<td>{f.cwe}</td>
</tr>\n"""

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>MAST Scanner Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0f172a;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}}
h1{{font-size:1.8rem;margin-bottom:.5rem}}
.meta{{color:#94a3b8;margin-bottom:2rem}}
.cards{{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}}
.card{{background:#1e293b;border-radius:8px;padding:1rem 1.5rem;min-width:120px;text-align:center}}
.card .num{{font-size:2rem;font-weight:800}}
.card .label{{font-size:.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:1px}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{text-align:left;padding:.6rem;background:#1e293b;color:#94a3b8;border-bottom:1px solid #334155}}
td{{padding:.6rem;border-bottom:1px solid #1e293b;vertical-align:top}}
tr:hover{{background:#1e293b40}}
code{{background:#334155;padding:1px 5px;border-radius:3px;font-size:.82rem}}
</style></head><body>
<h1>MAST Scanner Report</h1>
<div class="meta">Platform: {self.platform.upper()} | File: {os.path.basename(self.path)} | {now} | v{__version__}</div>
<div class="cards">
<div class="card"><div class="num" style="color:#dc2626">{s.get('CRITICAL',0)}</div><div class="label">Critical</div></div>
<div class="card"><div class="num" style="color:#ea580c">{s.get('HIGH',0)}</div><div class="label">High</div></div>
<div class="card"><div class="num" style="color:#ca8a04">{s.get('MEDIUM',0)}</div><div class="label">Medium</div></div>
<div class="card"><div class="num" style="color:#0891b2">{s.get('LOW',0)}</div><div class="label">Low</div></div>
<div class="card"><div class="num" style="color:#6b7280">{s.get('INFO',0)}</div><div class="label">Info</div></div>
</div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Name</th><th>Platform</th><th>File</th><th>Evidence</th><th>Description</th><th>CWE</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"  HTML report: {path}")

    def save_sarif(self, path: str) -> None:
        sev_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                   "LOW": "note", "INFO": "note"}

        seen_rules: Dict[str, Dict] = {}
        for f in self.findings:
            if f.rule_id not in seen_rules:
                cwe_num = f.cwe.split("-")[1] if f.cwe.startswith("CWE-") else ""
                seen_rules[f.rule_id] = {
                    "id": f.rule_id, "name": f.name,
                    "shortDescription": {"text": f.name},
                    "fullDescription": {"text": f.description[:1024]},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html" if cwe_num else "",
                    "properties": {"owasp_mobile": f.owasp_mobile, "cwe": f.cwe},
                }

        results = []
        for f in self.findings:
            results.append({
                "ruleId": f.rule_id,
                "level": sev_map.get(f.severity, "note"),
                "message": {"text": f"{f.name}: {f.description}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file_path}}}],
                "properties": {"severity": f.severity, "platform": f.platform, "evidence": f.evidence[:500]},
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {
                "name": "MAST Scanner", "version": __version__,
                "informationUri": "https://github.com/Krishcalin/Mobile-Application-Security-Testing",
                "rules": list(seen_rules.values()),
            }}, "results": results}],
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2, default=str)
        print(f"  SARIF report: {path}")


# ════════════════════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════════════════════

BANNER = f"""{BOLD}
  __  __    _    ____ _____   ____
 |  \\/  |  / \\  / ___|_   _| / ___|  ___ __ _ _ __  _ __   ___ _ __
 | |\\/| | / _ \\ \\___ \\ | |   \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
 | |  | |/ ___ \\ ___) || |    ___) | (_| (_| | | | | | | |  __/ |
 |_|  |_/_/   \\_\\____/ |_|   |____/ \\___\\__,_|_| |_|_| |_|\\___|_|
                                                          v{__version__}
  Mobile Application Security Testing Scanner
  Android APK | iOS IPA | OWASP Mobile Top 10 2024
{RESET}"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mast_scanner.py",
        description="Mobile Application Security Testing (MAST) Scanner -- "
                    "static analysis of Android APK and iOS IPA files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
  Scan an Android APK with all reports:
      python mast_scanner.py app-debug.apk --json report.json --html report.html

  Scan an iOS IPA with severity filter:
      python mast_scanner.py MyApp.ipa --severity HIGH --sarif results.sarif

  Verbose scan:
      python mast_scanner.py app-release.apk -v
        """,
    )
    p.add_argument("target", help="Path to APK or IPA file")
    p.add_argument("--json", metavar="FILE", help="Save JSON report to FILE")
    p.add_argument("--html", metavar="FILE", help="Save HTML report to FILE")
    p.add_argument("--sarif", metavar="FILE", help="Save SARIF report to FILE (CI/CD)")
    p.add_argument("--severity", default="INFO",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                   help="Minimum severity to report (default: INFO)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--platform", choices=["auto", "android", "ios"], default="auto",
                   help="Target platform (default: auto-detect)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main() -> int:
    print(BANNER)
    parser = _build_parser()
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"[ERROR] File not found: {args.target}", file=sys.stderr)
        return 1

    scanner = MASTScanner(args.target, verbose=args.verbose, platform=args.platform)
    scanner.scan()

    if args.severity != "INFO":
        scanner.filter_severity(args.severity)

    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)
    if args.sarif:
        scanner.save_sarif(args.sarif)

    s = scanner.summary()
    return 1 if s.get("CRITICAL", 0) + s.get("HIGH", 0) > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
