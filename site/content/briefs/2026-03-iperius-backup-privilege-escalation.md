---
title: Iperius Backup Improper Privilege Management Vulnerability (CVE-2026-4824)
slug: 2026-03-iperius-backup-privilege-escalation
description: CVE-2026-4824 is a vulnerability in Enter Software Iperius Backup up to version 8.7.3, where manipulating the Backup Job Configuration File Handler allows for improper privilege management by a local attacker, requiring an upgrade to version 8.7.4 to resolve the issue.
date: "2026-03-25T22:16:19Z"
severities:
  - medium
tags:
  - privilege-escalation
  - vulnerability
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4824
rules:
  - title: Detect Suspicious Iperius Backup Process Execution
    description: Detects suspicious process executions potentially related to Iperius Backup exploitation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Iperius Backup Configuration File Modification
    description: Detects modifications to the Iperius Backup configuration file, which could indicate an attempt to exploit CVE-2026-4824.
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

A privilege management vulnerability, tracked as CVE-2026-4824, has been identified in Enter Software Iperius Backup software, affecting versions up to 8.7.3. The vulnerability resides within the Backup Job Configuration File Handler. Successful exploitation of this vulnerability allows a local attacker to perform actions with elevated privileges. The vendor was promptly notified and released a patched version, 8.7.4, to address the reported security flaw. Due to the local attack vector and the…
