---
title: Dell AppSync 4.6.0 UNIX Symbolic Link Following Vulnerability (CVE-2026-22767)
slug: 2026-04-dell-appsync-symlink
description: Dell AppSync version 4.6.0 is vulnerable to a UNIX Symbolic Link (Symlink) Following vulnerability (CVE-2026-22767) that allows a low-privileged local attacker to tamper with information.
date: "2026-04-01T13:16:33Z"
severities:
  - medium
tags:
  - symlink
  - dell
  - appsync
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-22767
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22767
  - https://www.dell.com/support/kbdoc/en-us/000446965/dsa-2026-163-security-update-for-dell-appsync-vulnerabilities
rules:
  - title: Detect Suspicious Symlink Creation
    description: Detects the creation of symbolic links by low-privileged users to potentially sensitive locations, indicative of potential exploitation of symlink vulnerabilities like CVE-2026-22767.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Sensitive File Tampering via Symlink
    description: Detects modifications to sensitive files (e.g., /etc/shadow) potentially achieved through a symlink vulnerability like CVE-2026-22767.
    platform: sigma
    severity: high
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Dell AppSync version 4.6.0 contains a UNIX Symbolic Link (Symlink) Following vulnerability, identified as CVE-2026-22767. This vulnerability enables a low-privileged attacker with local access to exploit the system and potentially tamper with sensitive information. The vulnerability was disclosed on April 1, 2026. Defenders should be aware of the potential for local privilege escalation and information tampering due to this vulnerability. Addressing this vulnerability is critical to maintaining…
