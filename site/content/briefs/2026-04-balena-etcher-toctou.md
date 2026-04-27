---
title: Balena Etcher for Windows TOCTOU Vulnerability
slug: 2026-04-balena-etcher-toctou
description: A Time-of-Check to Time-of-Use (TOCTOU) race condition vulnerability in Balena Etcher for Windows prior to v2.1.4 allows attackers to escalate privileges and execute arbitrary code by replacing a legitimate script with a crafted payload during the flashing process.
date: "2026-04-02T16:16:22Z"
severities:
  - high
tags:
  - privilege-escalation
  - toctou
  - balena-etcher
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-30332
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-30332
  - https://github.com/B1tBreaker/CVE-2026-30332
  - https://github.com/balena-io/etcher/issues/4500
  - https://www.balena.io/security
rules:
  - title: Detect Suspicious Balena Etcher Child Processes
    description: Detects suspicious child processes spawned by Balena Etcher, indicating potential privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect File Replacement in Balena Etcher Directory
    description: Detects file creation events in Balena Etcher directory indicating potential TOCTOU exploit
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Balena Etcher for Windows versions prior to 2.1.4 are susceptible to a Time-of-Check to Time-of-Use (TOCTOU) race condition vulnerability (CVE-2026-30332). This flaw arises during the flashing process where a legitimate script can be replaced with a malicious payload. An attacker with local access and the ability to influence the file system can exploit this vulnerability to escalate privileges and execute arbitrary code. The successful exploitation of this issue can lead to a complete…
