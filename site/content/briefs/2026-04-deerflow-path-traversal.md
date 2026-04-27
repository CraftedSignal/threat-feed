---
title: ByteDance DeerFlow Path Traversal and Arbitrary File Write Vulnerability
slug: 2026-04-deerflow-path-traversal
description: ByteDance DeerFlow before commit 2176b2b contains a path traversal and arbitrary file write vulnerability in bootstrap-mode custom-agent creation where the agent name validation is bypassed, allowing attackers to write files outside the intended custom-agent directory.
date: "2026-04-17T17:17:09Z"
severities:
  - high
tags:
  - path-traversal
  - file-write
  - bytedance
  - deerflow
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Controls
cves:
  - id: CVE-2026-40518
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40518
  - https://github.com/bytedance/deer-flow/commit/2176b2bbfccfce25ceee08318813f96d843a13fd
  - https://github.com/bytedance/deer-flow/pull/2274
  - https://www.vulncheck.com/advisories/bytedance-deerflow-path-traversal-and-arbitrary-file-write-via-bootstrap-mode
rules:
  - title: Detect Suspicious DeerFlow Agent Creation
    description: Detects the creation of custom agents with suspicious names indicative of path traversal attempts in ByteDance DeerFlow
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1553.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Arbitrary File Writes via DeerFlow
    description: Detects file writes outside the standard custom agent directory.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1553.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

ByteDance DeerFlow, a software of unknown purpose, prior to commit 2176b2b, is vulnerable to path traversal and arbitrary file write. The vulnerability lies within the bootstrap-mode custom-agent creation process, specifically due to insufficient validation of the agent name. This flaw allows attackers to bypass intended directory restrictions and write files to arbitrary locations on the system, provided they have the necessary filesystem permissions. The vulnerability was reported on April…
