---
title: JetBrains YouTrack RCE via Sandbox Bypass (CVE-2026-33392)
slug: 2026-04-jetbrains-rce
description: A high privileged user can achieve remote code execution via sandbox bypass in JetBrains YouTrack before version 2025.3.131383, identified as CVE-2026-33392, potentially leading to complete system compromise.
date: "2026-04-17T08:16:17Z"
severities:
  - critical
tags:
  - cve-2026-33392
  - rce
  - jetbrains
  - youtrack
  - sandbox-bypass
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33392
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33392
  - https://www.jetbrains.com/privacy-security/issues-fixed/
rules:
  - title: Detect Potential YouTrack Sandbox Bypass Attempts
    description: Detects suspicious HTTP requests that may indicate an attempt to exploit a sandbox bypass vulnerability in JetBrains YouTrack.  Looks for potentially malicious characters and keywords commonly associated with code injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
  - title: Detect YouTrack Process Creation from Suspicious Web Paths
    description: Detects process creation events originating from common web server directories, potentially indicating code execution originating from a compromised YouTrack installation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-33392 describes a remote code execution (RCE) vulnerability affecting JetBrains YouTrack servers before version 2025.3.131383. This vulnerability allows a high privileged user to bypass the application's sandbox and execute arbitrary code on the underlying system. While the specific exploitation details are not provided in the source, successful exploitation would grant the attacker complete control over the YouTrack server and potentially the entire network. Given the potential for…
