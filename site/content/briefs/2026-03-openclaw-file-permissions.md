---
title: OpenClaw Insufficient File Permissions Vulnerability (CVE-2026-33572)
slug: 2026-03-openclaw-file-permissions
description: OpenClaw before 2026.2.17 creates session transcript JSONL files with overly broad default permissions, allowing local users to read transcript contents and extract sensitive information.
date: "2026-03-29T13:17:02Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-33572
  - file-permissions
  - credential-access
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33572
  - https://github.com/openclaw/openclaw/commit/095d522099653367e1b76fa5bb09d4ddf7c8a57c
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-vr7j-g7jv-h5mp
  - https://www.vulncheck.com/advisories/openclaw-insufficient-file-permissions-in-session-transcript-files
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Detect Unauthorized Access to OpenClaw Session Transcripts
    description: Detects unauthorized processes accessing OpenClaw session transcript files, indicating potential exploitation of CVE-2026-33572.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - linux
  - title: Detect File Creation With Overly Permissive Permissions
    description: Detects files created with overly permissive permissions (world-readable) which may expose sensitive information.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw before version 2026.2.17 is vulnerable to an insufficient file permissions issue. The application creates session transcript JSONL files with overly permissive default access controls. This vulnerability allows local users to read these transcript files, potentially exposing sensitive information such as secrets, API keys, passwords, or other confidential data that might be present in tool outputs or commands executed during a session. The vulnerability is identified as CVE-2026-33572…
