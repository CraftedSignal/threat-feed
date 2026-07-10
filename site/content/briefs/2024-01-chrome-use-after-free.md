---
title: Google Chrome Use-After-Free Vulnerability in Video Component (CVE-2026-6359)
slug: 2024-01-chrome-use-after-free
description: CVE-2026-6359 is a use-after-free vulnerability in the Video component of Google Chrome on Windows prior to version 147.0.7727.101, allowing a remote attacker who has compromised the renderer process to achieve out-of-bounds memory access via a crafted HTML page.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-6359
  - chrome
  - use-after-free
  - windows
vendors:
  - Google
products:
  - Google Chrome
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6359
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6359
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/490251701
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Chrome Use-After-Free via HTML
    description: Detects attempts to exploit Chrome use-after-free vulnerabilities by monitoring for suspicious HTML pages being accessed.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Chrome Renderer Process Exploitation
    description: Detects potential exploitation of Chrome renderer processes by monitoring for unusual spawned processes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-6359 is a high-severity vulnerability affecting Google Chrome on Windows. Specifically, a use-after-free flaw exists in the Video component of Chrome versions prior to 147.0.7727.101. The vulnerability can be exploited by a remote attacker who has already achieved compromise of the renderer process. By crafting a malicious HTML page, the attacker can trigger the use-after-free condition, leading to out-of-bounds memory access. This could potentially allow the attacker to execute arbitrary code or cause a denial-of-service condition. The Chromium security team has rated this vulnerability as "High" severity. This vulnerability was patched in the stable channel update released on April 15, 2026.

## Attack Chain

1.  Attacker crafts a malicious HTML page designed to trigger the use-after-free vulnerability in Chrome's video processing component.
2.  The attacker compromises the renderer process, potentially through a separate vulnerability or social engineering.
3.  The compromised renderer process navigates to the malicious HTML page.
4.  The HTML page attempts to access a video object that has already been freed from memory.
5.  The use-after-free condition triggers, leading to memory corruption.
6.  The attacker leverages the memory corruption to gain out-of-bounds memory access.
7.  The attacker can potentially use this out-of-bounds access to execute arbitrary code within the context of the renderer process.
8.  The attacker pivots from the renderer process to further compromise the system, potentially exfiltrating data or installing malware.

## Impact

Successful exploitation of CVE-2026-6359 allows a remote attacker to perform out-of-bounds memory access. While the initial vulnerability requires a compromised renderer process, successful exploitation could lead to arbitrary code execution, data exfiltration, or denial of service. The impact is significant for organizations relying on Chrome for Windows, potentially affecting all users who have not updated to version 147.0.7727.101 or later. The scope of impact depends on the attacker's objectives after gaining code execution, and could range from stealing credentials to deploying ransomware.

## Recommendation

*   Upgrade Google Chrome on Windows to version 147.0.7727.101 or later to patch CVE-2026-6359.
*   Deploy the Sigma rule `Detect Chrome Use-After-Free via HTML` to your SIEM to detect potential exploitation attempts.
*   Monitor network traffic for suspicious activity originating from Chrome processes using network connection logs, potentially indicating post-exploitation behavior.
*   Enable process creation logging via Sysmon to capture details of spawned processes from Chrome, assisting in identifying potential exploit payloads.
