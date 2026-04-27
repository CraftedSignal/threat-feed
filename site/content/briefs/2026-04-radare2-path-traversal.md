---
title: Radare2 Path Traversal Vulnerability in Project Deletion
slug: 2026-04-radare2-path-traversal
description: Radare2 versions prior to 6.1.4 are vulnerable to a path traversal in project deletion, allowing local attackers to recursively delete arbitrary directories by escaping the 'dir.projects' root, leading to integrity and availability loss.
date: "2026-04-23T21:16:06Z"
severities:
  - high
tags:
  - path-traversal
  - radare2
  - local-privilege-escalation
vendors:
  - radare
products:
  - radare2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-6940
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6940
rules:
  - title: Detect Radare2 Project Deletion with Absolute Path
    description: Detects radare2 process execution attempting to delete projects using absolute paths, indicating potential path traversal exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Radare2 Process Executing with Suspicious Arguments
    description: Detects radare2 process executing potentially malicious commands indicative of exploitation attempts.
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

Radare2, a reverse engineering framework, is susceptible to a path traversal vulnerability (CVE-2026-6940) affecting versions prior to 6.1.4. This flaw allows a local attacker to delete arbitrary directories outside of the intended project storage location. By crafting project marker files with absolute paths that escape the configured `dir.projects` root directory, an attacker can trick the radare2 process into recursively deleting directories they should not have access to. This vulnerability…
