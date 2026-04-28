---
title: OpenClaw Symlink Vulnerability in SSH Sandbox Tar Upload (CVE-2026-41364)
slug: 2026-04-openclaw-symlink
description: OpenClaw before 2026.3.31 contains a symlink following vulnerability in SSH sandbox tar upload that allows remote attackers to write arbitrary files by uploading a malicious tar archive containing symlinks, leading to arbitrary file write on the remote host.
date: "2026-04-28T00:16:25Z"
severities:
  - high
tags:
  - symlink
  - file-write
  - sandbox-escape
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41364
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41364
  - https://github.com/openclaw/openclaw/commit/3d5af14984ac1976c747a8e11581d697bd0829dc
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-fv94-qvg8-xqpw
  - https://www.vulncheck.com/advisories/openclaw-arbitrary-file-write-via-symlink-following-in-ssh-sandbox-tar-upload
rules:
  - title: Detect Suspicious Tar Archive Upload with Symlinks
    description: Detects the upload of tar archives containing symlinks, which can be indicative of a sandbox escape attempt via CVE-2026-41364 in OpenClaw.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious File Overwrite via Tar Extraction
    description: Detects the modification of system files outside of normal user directories during tar extraction, indicating potential exploitation of CVE-2026-41364.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw versions before 2026.3.31 are vulnerable to a symlink following issue within the SSH sandbox tar upload functionality. This vulnerability, identified as CVE-2026-41364, allows a remote attacker with the ability to upload tar archives to the OpenClaw instance to potentially escape the intended sandbox environment. By crafting a malicious tar archive containing carefully constructed symbolic links, an attacker can overwrite arbitrary files on the remote host, leading to a compromise of…
