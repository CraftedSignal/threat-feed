---
title: CodexBar Privilege Escalation Vulnerability (CVE-2026-49134)
slug: 2026-06-codexbar-privesc
description: CodexBar versions prior to 0.32.0 contain a privilege escalation vulnerability (CVE-2026-49134) due to a race condition in the CLI installer's temporary file handling, allowing local attackers to execute arbitrary commands as root.
date: "2026-06-01T21:19:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - local-exploit
  - cve
vendors:
  - CodexBar
products:
  - CodexBar
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-49134
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49134
  - CVE-2026-49134
rules:
  - title: Detect Suspicious Bash Execution from Temp Directory
    description: Detects execution of bash scripts from temporary directories, which may indicate exploitation of CVE-2026-49134
    platform: sigma
    severity: high
    tactics:
      - cve-2026-49134
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect CodexBar Installer Modification
    description: Detects modifications to the CodexBar installer binary, indicating a possible attempt to exploit CVE-2026-49134
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-49134
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CodexBar versions prior to 0.32.0 are vulnerable to a privilege escalation vulnerability (CVE-2026-49134) in the CLI installer. A race condition exists in the temporary file handling. This flaw allows a local attacker with same-user privileges to execute arbitrary commands as root. The vulnerability occurs because the installer uses `mktemp` to create a temporary file, writes a privileged shell payload into it, and then executes the file with administrator privileges via bash. A local process can exploit this by rewriting the installer body before the administrator prompt is approved, leading to the execution of attacker-controlled commands with root privileges. This issue was reported on 2026-06-01 and affects versions prior to 0.32.0.

## Attack Chain

1. A local attacker gains initial access to the system with limited privileges.
2. The attacker executes the vulnerable CodexBar CLI installer.
3. The installer creates a temporary file using `mktemp` to store a privileged shell payload.
4. The installer writes the privileged shell payload to the temporary file.
5. A race condition occurs where the attacker, using a separate local process, attempts to rewrite the installer body.
6. The attacker successfully overwrites the installer body with malicious code before the administrator prompt is approved.
7. The installer executes the modified (attacker-controlled) code with administrator privileges via bash.
8. The attacker gains root privileges and can execute arbitrary commands on the system.

## Impact

Successful exploitation of this vulnerability allows a local attacker to escalate their privileges to root. This can lead to complete system compromise, including data theft, modification, and denial of service. The impact is severe, as it bypasses standard privilege separation mechanisms. The number of potential victims depends on the number of systems running vulnerable versions of CodexBar.

## Recommendation

*   Upgrade CodexBar to version 0.32.0 or later to remediate CVE-2026-49134.
*   Monitor process creation events for execution of bash scripts from temporary directories, as demonstrated in the attack chain. Deploy the Sigma rule `Detect Suspicious Bash Execution from Temp Directory` to identify potential exploitation attempts.
*   Implement file integrity monitoring to detect unauthorized modifications to the CodexBar installer binary, as described in the attack chain.
