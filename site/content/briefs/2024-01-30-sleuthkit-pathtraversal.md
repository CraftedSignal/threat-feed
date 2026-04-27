---
title: Sleuth Kit Path Traversal Vulnerability (CVE-2026-40024)
slug: 2024-01-30-sleuthkit-pathtraversal
description: A path traversal vulnerability exists in The Sleuth Kit through 4.14.0 (tsk_recover), enabling attackers to write files to arbitrary locations via crafted filenames with path traversal sequences in a filesystem image, potentially leading to code execution.
date: "2026-04-08T22:16:22Z"
severities:
  - high
tags:
  - path traversal
  - code execution
  - privilege escalation
  - sleuth kit
  - CVE-2026-40024
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1553
    technique_name: Subvert Trust Relationships
cves:
  - id: CVE-2026-40024
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40024
rules:
  - title: Detect Sleuth Kit Path Traversal
    description: Detects attempts to write files outside the intended recovery directory using tsk_recover, indicating potential path traversal exploitation.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-40024
      - persistence
      - privilege_escalation
    techniques:
      - T1553
    data_sources:
      - process_creation
      - linux
  - title: Detect File Creation in Suspicious Paths by tsk_recover
    description: Detects file creation events in sensitive directories by the tsk_recover process. This can indicate a path traversal attack where the tool is writing files outside of its intended directory.
    platform: sigma
    severity: critical
    tactics:
      - cve-2026-40024
      - persistence
      - privilege_escalation
    techniques:
      - T1553
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Sleuth Kit, a collection of command-line tools for forensic analysis of disk images, is susceptible to a path traversal vulnerability (CVE-2026-40024) affecting versions up to 4.14.0. This vulnerability resides within the `tsk_recover` utility, which is designed to recover files from disk images. An attacker can exploit this flaw by crafting a malicious filesystem image containing filenames or directory paths with path traversal sequences (e.g., `../`). When `tsk_recover` processes this…
