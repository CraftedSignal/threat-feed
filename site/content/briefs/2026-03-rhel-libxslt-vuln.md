---
title: Red Hat Enterprise Linux libxslt Vulnerability Allows Code Execution or File Manipulation
slug: 2026-03-rhel-libxslt-vuln
description: A local attacker can exploit a vulnerability in libxslt in Red Hat Enterprise Linux to execute arbitrary program code or manipulate files.
date: "2026-03-24T10:16:03Z"
severities:
  - high
tags:
  - libxslt
  - rhel
  - code-execution
  - file-manipulation
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0626
rules:
  - title: Detect Suspicious Libxslt Process Execution
    description: Detects suspicious process execution involving libxslt, potentially indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious File Modification via Libxslt
    description: Detects file modifications by processes related to libxslt that may indicate malicious activity.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists within the libxslt library in Red Hat Enterprise Linux (RHEL) that could be exploited by a local attacker. While specific details regarding the vulnerability (CVE number, affected versions) are not provided in this advisory, the potential impact includes arbitrary code execution or manipulation of files on the affected system. Due to the lack of specific details, the scope of targeting remains unknown, but any RHEL system utilizing libxslt is potentially vulnerable. It is…
