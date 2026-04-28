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

OpenClaw, up to version 2026.2.22, suffers from a symlink traversal vulnerability identified as CVE-2026-35632. This flaw exists in the `agents.create` and `agents.update` handlers, where the `fs.appendFile` function is used on `IDENTITY.md` without proper symlink containment checks. An attacker with workspace access can exploit this vulnerability by planting symlinks that allow them to append arbitrary content to system files. Successful exploitation could lead to remote code execution via crontab injection or unauthorized access via SSH key manipulation. Defenders should prioritize patching and implement detections to identify potential exploitation attempts.

## Attack Chain

1. An attacker gains workspace access to a vulnerable OpenClaw instance.
2. The attacker creates a malicious symlink within the workspace, pointing `IDENTITY.md` to a sensitive system file such as `/etc/crontab` or `~/.ssh/authorized_keys`.
3. The attacker triggers the `agents.create` or `agents.update` handler, which calls `fs.appendFile` on `IDENTITY.md`.
4. Due to the symlink, the content intended for `IDENTITY.md` is instead appended to the target system file (e.g., `/etc/crontab`).
5. If the attacker appended a cronjob, it executes according to the cron schedule, resulting in code execution.
6. Alternatively, if the attacker appended an SSH key to `~/.ssh/authorized_keys`, they can gain unauthorized SSH access to the system.

## Impact

Successful exploitation of CVE-2026-35632 allows attackers to inject malicious content into arbitrary files on the OpenClaw server. This can lead to remote code execution if the attacker injects a cronjob or unauthorized access if they inject an SSH key. The impact is significant, as it can compromise the confidentiality, integrity, and availability of the affected system. The severity is further amplified by the potential for lateral movement if the compromised server is used as a pivot point.

## Recommendation

*   Upgrade OpenClaw to a version beyond 2026.2.22 to patch CVE-2026-35632.
*   Implement filesystem monitoring to detect the creation of symlinks within OpenClaw workspaces that point to sensitive system files like `/etc/crontab` or `~/.ssh/authorized_keys` using a `file_event` Sigma rule.
*   Deploy the provided Sigma rule to detect modifications to `/etc/crontab` by processes related to OpenClaw to identify potential cronjob injection attempts.
*   Monitor SSH logs for unauthorized access attempts following exploitation, correlating with suspicious file modifications.
