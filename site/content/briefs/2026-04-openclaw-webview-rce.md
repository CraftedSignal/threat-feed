---
title: OpenClaw WebView JavascriptInterface Vulnerability (CVE-2026-35643)
slug: 2026-04-openclaw-webview-rce
description: OpenClaw before 2026.3.22 is vulnerable to arbitrary code execution due to an unvalidated WebView JavascriptInterface, allowing attackers to inject malicious instructions by invoking the canvas bridge from untrusted pages.
date: "2026-04-10T17:17:04Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-35643
  - rce
  - android
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35643
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35643
  - https://github.com/openclaw/openclaw/commit/630f1479c44f78484dfa21bb407cbe6f171dac87
  - https://github.com/openclaw/openclaw/commit/8b02ef133275be96d8aac2283100016c8a7f32e5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-cxmw-p77q-wchg
  - https://www.vulncheck.com/advisories/openclaw-arbitrary-code-execution-via-unvalidated-webview-javascriptinterface
rules:
  - title: Detect Suspicious WebView Bridge Usage
    description: Detects suspicious process creations originating from the WebView's JavascriptInterface bridge, indicative of potential RCE attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - android
  - title: Detect WebView Loading Untrusted URLs
    description: Detects WebView loading potentially malicious URLs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - android
rules_count: 2
---

OpenClaw versions prior to 2026.3.22 are susceptible to a critical vulnerability (CVE-2026-35643) stemming from an unvalidated WebView JavascriptInterface. This flaw enables attackers to inject arbitrary instructions and execute malicious code within the context of the Android application. The vulnerability arises because untrusted web pages can exploit the canvas bridge, a component responsible for communication between the WebView and the native Android code. Successful exploitation allows an attacker to gain control over the application's resources and potentially the device itself. This is a severe risk for any application using OpenClaw, as it could lead to data theft, malware installation, or other malicious activities.

## Attack Chain

1. An attacker identifies an application utilizing a vulnerable version of OpenClaw (prior to 2026.3.22).
2. The attacker crafts a malicious web page containing JavaScript code designed to exploit the unvalidated WebView JavascriptInterface.
3. The victim unknowingly navigates to the attacker-controlled web page, likely through social engineering or malicious advertising.
4. The malicious JavaScript code on the page interacts with the vulnerable canvas bridge within the OpenClaw WebView.
5. The attacker injects arbitrary instructions through the canvas bridge, leveraging the lack of input validation.
6. These injected instructions are then executed within the Android application context, bypassing security restrictions.
7. The attacker gains unauthorized access to the application's resources, such as user data or device functionalities.
8. The attacker executes arbitrary code, potentially leading to data exfiltration, malware installation, or complete device compromise.

## Impact

The successful exploitation of CVE-2026-35643 in OpenClaw can lead to complete compromise of the Android application and potentially the device it is running on. This can result in data theft, unauthorized access to sensitive information, installation of malware, and other malicious activities. While the exact number of vulnerable applications is unknown, the widespread use of OpenClaw could potentially affect a large number of users. The vulnerability is particularly dangerous because it can be exploited remotely through a simple web page, making it easily accessible to attackers.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.22 or later to patch CVE-2026-35643, as mentioned in the overview.
*   Implement input validation and sanitization on all data received through the WebView JavascriptInterface to prevent arbitrary code injection.
*   Deploy the Sigma rule to detect attempts to exploit the canvas bridge within OpenClaw (see "Detect Suspicious WebView Bridge Usage" rule).
*   Monitor web traffic for access to untrusted URLs from applications utilizing OpenClaw to identify potential exploitation attempts.
