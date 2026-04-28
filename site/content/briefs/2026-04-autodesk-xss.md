---
title: Autodesk Fusion Stored XSS Vulnerability (CVE-2026-4344)
slug: 2026-04-autodesk-xss
description: CVE-2026-4344 is a stored cross-site scripting (XSS) vulnerability in the Autodesk Fusion desktop application where a malicious HTML payload in a component name, when displayed during the delete confirmation dialog and clicked by a user, can lead to arbitrary code execution.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - xss
  - autodesk
  - cve-2026-4344
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Local Account
cves:
  - id: CVE-2026-4344
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4344
  - https://www.autodesk.com/trust/security-advisories/adsk-sa-2026-0005
iocs:
  - type: url
    value: https://dl.appstreaming.autodesk.com/production/installers/Fusion%20Client%20Downloader.dmg
  - type: url
    value: https://dl.appstreaming.autodesk.com/production/installers/Fusion%20Client%20Downloader.exe
  - type: url
    value: https://www.autodesk.com/trust/security-advisories/adsk-sa-2026-0005
ioc_counts:
  url: 3
rules:
  - title: Detect Process Creation from Autodesk Fusion with Suspicious Arguments
    description: Detects suspicious process creation originating from the Autodesk Fusion application that could indicate exploitation of CVE-2026-4344.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Autodesk Fusion Executing PowerShell with Obfuscated Commands
    description: Detects PowerShell execution from Autodesk Fusion with obfuscated commands.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-4344, affects the Autodesk Fusion desktop application. The vulnerability occurs due to insufficient sanitization of component names. A malicious actor can inject a crafted HTML payload into a component's name. When a user attempts to delete the component, the malicious payload is displayed within the delete confirmation dialog. If the user interacts with the crafted HTML, the XSS vulnerability is triggered, potentially leading to local file reads or arbitrary code execution within the context of the Autodesk Fusion process. This vulnerability poses a significant risk as it could allow attackers to compromise a user's system through a seemingly benign action within the application.

## Attack Chain

1.  The attacker crafts a malicious HTML payload.
2.  The attacker injects the crafted HTML payload into a component name within Autodesk Fusion.
3.  A user attempts to delete the component with the malicious name.
4.  The Autodesk Fusion application displays a delete confirmation dialog containing the malicious HTML payload.
5.  The user clicks or interacts with the malicious HTML payload within the delete confirmation dialog.
6.  The XSS vulnerability is triggered, allowing the attacker to execute arbitrary JavaScript code.
7.  The attacker uses the XSS vulnerability to read local files or execute arbitrary code within the context of the Autodesk Fusion process.
8.  The attacker gains unauthorized access or control over the user's system.

## Impact

Successful exploitation of CVE-2026-4344 allows a malicious actor to execute arbitrary code within the context of the Autodesk Fusion application. This could lead to the attacker reading local files, modifying sensitive data, or even gaining complete control over the user's system. Due to the widespread use of Autodesk Fusion in engineering and design sectors, this vulnerability could potentially impact a large number of users and organizations.

## Recommendation

*   Monitor process creations originating from the Autodesk Fusion process (process_creation, product: windows/macos) for suspicious command-line arguments that may indicate exploitation.
*   Inspect Autodesk Fusion application logs (if available) for events related to component deletion and HTML rendering, searching for unusual or potentially malicious HTML tags (webserver, product: linux/windows).
*   Block the download URLs for Autodesk Fusion installers (iocs, type: url) at the network level to prevent attackers from distributing malicious versions of the software.
