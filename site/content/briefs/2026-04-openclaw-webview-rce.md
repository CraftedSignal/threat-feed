---
title: OpenClaw WebView JavascriptInterface Vulnerability (CVE-2026-35643)
slug: 2026-04-openclaw-webview-rce
description: OpenClaw before 2026.3.22 is vulnerable to arbitrary code execution due to an unvalidated WebView JavascriptInterface, allowing attackers to inject malicious instructions by invoking the canvas bridge from untrusted pages.
date: "2026-04-10T17:17:04Z"
severities:
  - critical
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

OpenClaw versions prior to 2026.3.22 are susceptible to a critical vulnerability (CVE-2026-35643) stemming from an unvalidated WebView JavascriptInterface. This flaw enables attackers to inject arbitrary instructions and execute malicious code within the context of the Android application. The vulnerability arises because untrusted web pages can exploit the canvas bridge, a component responsible for communication between the WebView and the native Android code. Successful exploitation allows an…
