---
title: OpenClaw Android App Vulnerable to Arbitrary Code Execution via WebView JavascriptInterface
slug: 2024-01-openclaw-webview-rce
description: The openclaw npm package before version 2026.3.22 is vulnerable to arbitrary code execution, where an attacker could inject instructions into the app by invoking the JavascriptInterface bridge from untrusted origins within Android Canvas WebView pages.
date: "2024-01-11T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - android
  - webview
  - rce
vendors:
  - OpenClaw
products:
  - OpenClaw Android application
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://github.com/advisories/GHSA-cxmw-p77q-wchg
rules:
  - title: Detect Untrusted Origin in OpenClaw CanvasScreen.kt
    description: Detects attempts to load untrusted origins in the CanvasScreen.kt file based on modified code.
    platform: sigma
    severity: medium
    tactics:
      - execution
    data_sources:
      - file_event
      - linux
  - title: Detect Centralized Validation in OpenClaw CanvasActionTrust.kt
    description: Detects modification of CanvasActionTrust.kt for centralized validation, which might be part of exploit mitigation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The OpenClaw Android application, specifically versions prior to 2026.3.22, contains a vulnerability that allows for arbitrary code execution. This flaw stems from insufficient validation of the origin of requests made to the JavascriptInterface bridge within Android Canvas WebView pages. An attacker could potentially exploit this by serving malicious content via a compromised or untrusted website loaded in the WebView. This allows the attacker to bypass security restrictions and inject arbitrary instructions directly into the application's context. The vulnerability was reported by @cyjhhh and a fix was implemented in version 2026.3.22. Defenders should ensure all OpenClaw Android applications are updated to version 2026.3.22 or later.

## Attack Chain

1. An attacker hosts a malicious webpage containing JavaScript code designed to exploit the WebView's JavascriptInterface.
2. The user opens the OpenClaw Android application and navigates to the CanvasScreen, which loads the attacker's malicious webpage within a WebView.
3. The malicious JavaScript code within the WebView attempts to invoke methods exposed through the JavascriptInterface bridge.
4. Due to the lack of sufficient origin validation in versions prior to 2026.3.22, the JavascriptInterface bridge incorrectly processes the attacker's commands.
5. The attacker crafts specific instructions through the bridge to execute arbitrary code within the OpenClaw application's context.
6. This could lead to the installation of malware, data exfiltration, or other malicious actions depending on the permissions granted to the OpenClaw application.
7. The application executes the attacker-injected code, granting the attacker control within the app's sandbox.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code within the OpenClaw Android application. This could lead to data theft, credential compromise, or potentially lateral movement to other applications or systems accessible from the compromised device. The number of affected users depends on the adoption rate of vulnerable OpenClaw versions, but the impact is high due to the potential for complete compromise of the application and its data.

## Recommendation

*   Immediately update the OpenClaw npm package to version 2026.3.22 or later to patch the vulnerability.
*   Monitor for unexpected network activity originating from devices running older versions of OpenClaw, as this may indicate exploitation attempts.
*   Consider implementing network-level restrictions to prevent the OpenClaw application from accessing untrusted or known malicious websites.
