#!/usr/bin/env python3
"""
Generate a synthetic vulnerable APK for MAST scanner testing.
This creates a fake .apk file (ZIP archive) containing:
  - An AndroidManifest.xml with security misconfigurations
  - A fake .so file with embedded vulnerable string patterns
  - Resource files with secrets

Usage:
    python create_test_apk.py
    python mast_scanner.py test_vulnerable.apk --json mast_report.json --html mast_report.html -v
"""

import os
import zipfile

APK_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_vulnerable.apk")

# ── AndroidManifest.xml with many misconfigurations ──────────────────────────
MANIFEST = '''\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.vulnerable.app">

    <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="33" />

    <!-- Dangerous permissions -->
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.READ_CALL_LOG" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />

    <application
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true"
        android:taskAffinity="com.other.hijack.app">

        <!-- Exported components without permission protection -->
        <activity android:name=".ExportedActivity"
            android:exported="true">
        </activity>

        <service android:name=".ExportedService"
            android:exported="true">
        </service>

        <receiver android:name=".ExportedReceiver"
            android:exported="true">
        </receiver>

        <provider android:name=".ExportedProvider"
            android:exported="true"
            android:authorities="com.test.vulnerable.provider">
        </provider>

        <!-- Launcher activity (should NOT trigger exported warning) -->
        <activity android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
'''

# ── Vulnerable strings that mimic DEX/native library content ─────────────────
# These patterns match the regex rules in the MAST scanner's check functions.
# Embedded in a fake .so file so APKAnalyzer extracts them via extract_macho_strings.
VULNERABLE_STRINGS = '''\
AKIAIOSFODNN7EXAMPLE1
aws_secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AIzaSyA1234567890abcdefghijklmnopqrstuvw
https://staging.example.com/api/v1
https://dev.internal-api.example.com/data
http://api.example.com/users/login
http://cdn.example.com/static/assets/v2
password = "SuperSecret123!"
api_key = "sk_test_FAKE_DO_NOT_USE_abcdefgh"
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w
client_secret = "my-oauth-client-secret-value"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn
-----END RSA PRIVATE KEY-----
encryption_key = "SGVsbG9Xb3JsZDEyMzQ1Njc4"
MessageDigest.getInstance("MD5")
Cipher.getInstance("DES/ECB/PKCS5Padding")
AES/ECB/PKCS5Padding
java.util.Random
SecretKeySpec("MyHardcodedKey12345678")
IvParameterSpec("1234567890abcdef")
MODE_WORLD_READABLE
getExternalStorageDirectory
SQLiteDatabase.openOrCreateDatabase
/sdcard/myapp/data.db
Log.d(TAG, "password=" + userPassword)
Log.v(TAG, "token=" + authToken)
TrustAllCertificates
AllowAllHostnameVerifier
MIXED_CONTENT_ALWAYS_ALLOW
SSLSocketFactory
createSocket(
TLSv1.0
SSLv3
http://192.168.1.100:8080/api
https://localhost:3000/debug
SK1234567890abcdef1234567890abcd
SG.abcdefghijklmnopqrstuv.wxyz1234
MD5(input)
Math.random()
base64.encode(password)
okhttp/3.10.0
com.squareup.okhttp3
com.google.firebase
https://test-project.firebaseio.com
addJavascriptInterface
setJavaScriptEnabled(true)
WebView.loadUrl
evaluateJavascript
setAllowFileAccess
setAllowUniversalAccessFromFileURLs
BiometricPrompt
FingerprintManager
KeyguardManager
getDeviceId
getSubscriberId
getMacAddress
getSimSerialNumber
Runtime.getRuntime().exec
ProcessBuilder
DexClassLoader
PathClassLoader
System.loadLibrary
'''

# ── Additional resource strings ──────────────────────────────────────────────
STRINGS_XML = '''\
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="api_key">AIzaSyB1234567890abcdefghijklmnopqrstuv</string>
    <string name="firebase_url">https://my-project.firebaseio.com</string>
    <string name="debug_url">http://staging.mycompany.com/api</string>
    <string name="secret">sk_test_FAKE_DO_NOT_USE_12345678</string>
</resources>
'''


def main():
    print(f"[*] Creating synthetic vulnerable APK: {APK_PATH}")

    with zipfile.ZipFile(APK_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        # AndroidManifest.xml (text XML -- scanner handles both binary and text)
        zf.writestr("AndroidManifest.xml", MANIFEST)

        # Fake native library with vulnerable strings
        # The APKAnalyzer extracts strings from .so files via extract_macho_strings
        # which reads printable ASCII strings >= 8 chars
        zf.writestr("lib/arm64-v8a/libvulnerable.so", VULNERABLE_STRINGS.encode("ascii"))
        zf.writestr("lib/armeabi-v7a/libcompat.so", VULNERABLE_STRINGS.encode("ascii"))

        # Resource files
        zf.writestr("res/values/strings.xml", STRINGS_XML)

        # Fake classes.dex (empty -- no real DEX, but .so strings cover everything)
        # We add a minimal file so the file_list is populated
        zf.writestr("classes.dex", b"\x00" * 16)

        # Additional files to populate the file list
        zf.writestr("res/xml/network_security_config.xml", "<network-security-config/>")
        zf.writestr("assets/config.json", '{"debug": true, "api_url": "http://staging.example.com"}')

    size = os.path.getsize(APK_PATH)
    print(f"[+] Created {APK_PATH} ({size:,} bytes)")
    print()
    print("Run the MAST scanner:")
    print(f'  python mast_scanner.py "{APK_PATH}" --json mast_report.json --html mast_report.html -v')


if __name__ == "__main__":
    main()
