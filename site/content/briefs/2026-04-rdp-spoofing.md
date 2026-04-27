---
title: Windows Remote Desktop Spoofing Vulnerability (CVE-2026-26151)
slug: 2026-04-rdp-spoofing
description: CVE-2026-26151 is a spoofing vulnerability in Windows Remote Desktop due to an insufficient UI warning for dangerous operations, allowing an unauthorized attacker to perform spoofing over a network.
date: "2026-04-15T12:00:00Z"
severities:
  - medium
tags:
  - cve-2026-26151
  - rdp
  - spoofing
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
cves:
  - id: CVE-2026-26151
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26151
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26151
rules:
  - title: Detect Suspicious RDP Clipboard Activity
    description: Detects large data transfers via RDP clipboard, which may indicate data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1113
    data_sources:
      - network_connection
      - windows
  - title: Detect Multiple Failed RDP Login Attempts
    description: Detects multiple failed RDP login attempts from the same source IP, indicating a possible brute-force attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - auth
      - windows
rules_count: 2
---

CVE-2026-26151 is a security vulnerability affecting Windows Remote Desktop (RDP). The vulnerability stems from an insufficient UI warning mechanism when dangerous operations are about to be performed within an RDP session. An attacker could potentially exploit this to spoof legitimate actions or elements within the RDP interface, misleading the user into performing unintended actions. This vulnerability could be exploited by an attacker positioned on the same network as the victim, or through…
