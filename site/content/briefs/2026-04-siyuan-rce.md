---
title: SiYuan Knowledge Management System RCE via Malicious Website
slug: 2026-04-siyuan-rce
description: SiYuan versions prior to 3.6.2 are vulnerable to remote code execution (RCE) via a malicious website exploiting a permissive CORS policy to inject a JavaScript snippet, leading to arbitrary code execution within the application's Node.js context.
date: "2026-03-31T22:17:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-34449
  - rce
  - siyuan
  - cors
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34449
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34449
rules:
  - title: Detect Suspicious SiYuan API Access from Web Browser
    description: Detects network connections to the SiYuan API originating from web browsers, potentially indicating an exploitation attempt of CVE-2026-34449.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - network_connection
      - windows
  - title: Detect Processes Spawned from SiYuan Indicating RCE
    description: Detects the creation of unusual processes spawned directly from the SiYuan application, which could indicate successful remote code execution (RCE).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

SiYuan is a personal knowledge management system. Versions prior to 3.6.2 contain a critical vulnerability (CVE-2026-34449) that allows a malicious website to execute arbitrary code on any desktop running the application. This is achieved by exploiting an overly permissive Cross-Origin Resource Sharing (CORS) policy ("Access-Control-Allow-Origin: *" combined with "Access-Control-Allow-Private-Network: true"). An attacker can inject a JavaScript snippet into the application via its API. This injected code then executes in the context of Electron's Node.js environment, granting the attacker full operating system access. The vulnerability is triggered simply by a user visiting a malicious website while SiYuan is running. The issue has been addressed and patched in version 3.6.2 of SiYuan. This RCE can allow attackers to steal data, install malware, or perform other malicious activities on the victim's machine.

## Attack Chain

1. Victim launches the SiYuan application on their desktop (Windows, Linux, or macOS).
2. Victim visits a malicious website in a web browser while SiYuan is running.
3. The malicious website leverages the permissive CORS policy of SiYuan.
4. The malicious website sends an API request to the running SiYuan instance.
5. This API request injects a malicious JavaScript payload into SiYuan.
6. The injected JavaScript code is stored within SiYuan's data.
7. The next time the user opens SiYuan's UI, the injected JavaScript code executes within Electron's Node.js context.
8. The attacker gains full OS access and can perform arbitrary actions.

## Impact

Successful exploitation of CVE-2026-34449 allows for complete compromise of the user's system. The attacker can steal sensitive data, install persistent backdoors, or deploy ransomware. Given SiYuan's purpose as a knowledge management system, it likely holds valuable and sensitive personal or business information. The impact is significant due to the ease of exploitation requiring no user interaction beyond visiting a malicious website.

## Recommendation

*   Immediately upgrade SiYuan to version 3.6.2 or later to patch CVE-2026-34449.
*   Monitor network connections for unusual API requests originating from web browsers, as this could indicate exploitation attempts. Deploy the Sigma rule `title: "Detect Suspicious SiYuan API Access from Web Browser"` to detect this behavior.
*   Implement strict CORS policies for web applications to prevent unauthorized cross-origin requests.
*   Enable process creation logging and monitor for unexpected processes spawned from SiYuan, as this could be a sign of successful RCE. Deploy the Sigma rule `title: "Detect Processes Spawned from SiYuan Indicating RCE"` to detect this.
