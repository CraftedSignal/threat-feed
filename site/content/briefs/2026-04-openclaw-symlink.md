---
title: OpenClaw Symlink Traversal Vulnerability (CVE-2026-35632)
slug: 2026-04-openclaw-symlink
description: OpenClaw through 2026.2.22 is vulnerable to symlink traversal, allowing attackers with workspace access to inject malicious content into arbitrary files via IDENTITY.md, leading to potential remote code execution and unauthorized access.
date: "2026-04-09T22:16:32Z"
severities:
  - high
tags:
  - symlink
  - traversal
  - rce
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35632
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35632
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-7xr2-q9vf-x4r5
  - https://www.vulncheck.com/advisories/openclaw-symlink-traversal-via-identity-md-appendfile-in-agents-create-update
rules:
  - title: Detect Crontab Modification via OpenClaw
    description: Detects modifications to /etc/crontab by OpenClaw processes, indicating potential cronjob injection.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect Symlink Creation to Sensitive Files
    description: Detects the creation of symlinks pointing to sensitive files, potentially indicating symlink traversal exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw, up to version 2026.2.22, suffers from a symlink traversal vulnerability identified as CVE-2026-35632. This flaw exists in the `agents.create` and `agents.update` handlers, where the `fs.appendFile` function is used on `IDENTITY.md` without proper symlink containment checks. An attacker with workspace access can exploit this vulnerability by planting symlinks that allow them to append arbitrary content to system files. Successful exploitation could lead to remote code execution via…
