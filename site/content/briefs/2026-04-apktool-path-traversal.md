---
title: Apktool Path Traversal Vulnerability (CVE-2026-39973)
slug: 2026-04-apktool-path-traversal
description: A path traversal vulnerability in Apktool versions 3.0.0 and 3.0.1 allows a malicious APK file to write arbitrary files to the filesystem during decoding, potentially leading to remote code execution.
date: "2026-04-21T02:16:07Z"
severities:
  - critical
tags:
  - apktool
  - path-traversal
  - android
  - cve-2026-39973
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1566
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-39973
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39973
rules:
  - title: Detect Apktool Path Traversal Attempt
    description: Detects potential path traversal attempts when using apktool by monitoring command-line arguments containing '../' sequences.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1566
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Writes via Apktool Vulnerability
    description: Detects file writes to sensitive locations potentially exploited by the Apktool path traversal vulnerability (CVE-2026-39973).
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

Apktool, a tool used for reverse engineering Android APK files, is vulnerable to a path traversal issue in versions 3.0.0 and 3.0.1 (CVE-2026-39973). This vulnerability resides within the `brut/androlib/res/decoder/ResFileDecoder.java` component. A maliciously crafted APK can exploit this flaw during standard decoding (`apktool d`) to write arbitrary files to the filesystem. The vulnerability is a security regression introduced by commit e10a045 (PR #4041, December 12, 2025), which…
