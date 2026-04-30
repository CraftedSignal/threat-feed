---
title: InstructLab Path Traversal Vulnerability (CVE-2026-6855)
slug: 2026-04-instructlab-path-traversal
description: A local attacker can exploit a path traversal vulnerability in InstructLab by manipulating the `logs_dir` parameter, leading to arbitrary file creation and modification.
date: "2026-04-22T13:16:22Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - instructlab
  - cve-2026-6855
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
cves:
  - id: CVE-2026-6855
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6855
  - https://access.redhat.com/security/cve/CVE-2026-6855
  - https://bugzilla.redhat.com/show_bug.cgi?id=2460013
rules:
  - title: Detect Suspicious Directory Creation with Path Traversal
    description: Detects attempts to create directories with path traversal sequences (../) which could indicate exploitation of CVE-2026-6855.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1553
    data_sources:
      - file_event
      - linux
  - title: Detect File Writes in Unusual Locations via InstructLab
    description: Detects file writes in unusual system locations originating from the InstructLab process, suggesting successful exploitation of CVE-2026-6855.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1553
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-6855 describes a path traversal vulnerability found in InstructLab, a tool or platform that allows for interactive instruction or learning sessions. A local attacker can exploit this vulnerability by manipulating the `logs_dir` parameter within the chat session handler. This manipulation allows the attacker to bypass intended directory restrictions and gain the ability to create new directories and write files to arbitrary locations on the affected system. The vulnerability was…
