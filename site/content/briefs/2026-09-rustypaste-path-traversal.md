---
title: Path Traversal Vulnerability in rustypaste
slug: 2026-09-rustypaste-path-traversal
description: rustypaste versions prior to 0.18.1 contain a path traversal vulnerability that allows attackers to write files to arbitrary locations by manipulating the custom filename HTTP header.
date: "2026-09-13T11:26:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rustypaste:rustypaste:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - vulnerability
  - remote-code-execution
vendors:
  - rustypaste
products:
  - rustypaste (< 0.18.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: rustypaste before 0.18.1 validates the destination path before applying the optional custom filename HTTP header, allowing attackers to bypass directory-escape checks.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can supply path traversal sequences in the filename header to write files outside the configured upload directory to arbitrary locations.
    confidence_band: med
cves:
  - id: CVE-2026-90774
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90774
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade rustypaste to version 0.18.1 or later
      owner: IT Operations
      addresses: CVE-2026-90774
      evidence: Source states rustypaste before 0.18.1 is vulnerable
---

rustypaste versions prior to 0.18.1 are affected by a path traversal vulnerability (CVE-2026-90774) stemming from improper input validation. The application validates the destination path before processing the optional custom filename header, which creates a race condition or logic flaw where the custom filename can contain directory traversal sequences (such as ../). This allows an attacker to bypass intended directory restrictions and write files outside of the configured upload directory. An unauthenticated attacker can exploit this to overwrite critical system configuration files or place malicious scripts (e.g., web shells) in executable directories, potentially leading to remote code execution or complete system compromise. This issue affects all rustypaste deployments using versions earlier than 0.18.1.

## Impact

Successful exploitation allows for arbitrary file write outside the designated upload directory. This could lead to a full system compromise if an attacker overwrites sensitive files or uploads malicious payloads to a location that is subsequently executed by the server or system processes.

## Recommendation

- Upgrade all rustypaste instances to version 0.18.1 or later to remediate CVE-2026-90774.
- Review server-side upload directory permissions to ensure the application runs with the least privilege necessary, minimizing the impact of potential file-write vulnerabilities.
- Audit access logs for suspicious HTTP requests containing directory traversal sequences (e.g., '../') within custom headers or filename parameters.
