---
title: doslib Memory Buffer Overflow Vulnerability (CVE-2026-33851)
slug: 2026-03-doslib-buffer-overflow
description: An Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability exists in joncampbell123's doslib before version doslib-20250729, potentially leading to arbitrary code execution.
date: "2026-03-24T06:16:22Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-33851
  - buffer-overflow
  - doslib
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33851
  - https://github.com/joncampbell123/doslib/pull/65
rules:
  - title: Potential doslib Buffer Overflow Attempt
    description: Detects potential exploitation attempts of doslib buffer overflow vulnerabilities by monitoring for suspicious process arguments or behaviors.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
  - title: Suspicious File Creation in doslib related directories
    description: Detects suspicious file creation events in directories commonly associated with doslib applications, which could indicate malicious activity following a buffer overflow.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-33851 describes a memory buffer overflow vulnerability within the doslib library developed by joncampbell123. This vulnerability exists in versions of doslib prior to doslib-20250729. The vulnerability is due to improper restriction of operations within the bounds of a memory buffer, a classic coding error that can lead to exploitable conditions. While specific exploitation details are not provided in the source, the nature of the vulnerability (CWE-119) indicates the potential for…
