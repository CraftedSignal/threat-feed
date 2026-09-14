---
title: Path Traversal Vulnerability in DevSpace In-Pod Sync
slug: 2026-09-devspace-tar-traversal
description: DevSpace versions 6.3.21 and earlier are vulnerable to a path traversal flaw during the in-pod sync process that allows arbitrary file writes on developer workstations.
date: "2026-09-14T23:37:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:loft:devspace:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - path-traversal
  - devspace
vendors:
  - DevSpace
products:
  - DevSpace (<= 6.3.21)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers operating a malicious container can stream tar entries with traversal sequences to write arbitrary files on the developer workstation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: enabling code execution.
    confidence_band: med
cves:
  - id: CVE-2026-91200
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91200
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade DevSpace CLI to the latest version post-6.3.21
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-91200 advisory
  mitigation_plan:
    - priority: immediate
      action: Enforce policy to use only vetted base images in DevSpace configurations
      owner: Security Operations
      addresses: CVE-2026-91200
      evidence: Source describes attack origin from malicious containers
---

DevSpace versions 6.3.21 and earlier contain a security vulnerability, identified as CVE-2026-91200, related to how the application handles tar entries during the in-pod sync process. The software fails to properly sanitize or reject entries containing parent-directory segments (e.g., ../) within the tar stream received from a container. An attacker capable of operating a malicious or compromised container can exploit this oversight to perform directory traversal when syncing files to a developer's workstation. By crafting specific tar entries, an attacker can overwrite critical system files or place malicious executables in startup directories, potentially achieving remote code execution on the host machine. This poses a significant risk to development environments, as the synchronization utility operates with the privileges of the user running the DevSpace CLI.

## Impact

Successful exploitation allows for unauthorized arbitrary file writes on a developer's local workstation. This can lead to full system compromise, exfiltration of sensitive source code or credentials present in the user environment, and the persistent installation of malicious software. The impact is significant given that the affected tool is typically used in trusted development environments where security controls might be relaxed compared to production infrastructure.

## Recommendation

- Upgrade the DevSpace CLI to a version later than 6.3.21 immediately to address the vulnerability in the tar archive extraction logic.
- Audit developer workstations for unauthorized files created by the DevSpace binary within unexpected directories.
- Restrict container access to only authorized and trusted images to mitigate the risk of a malicious container interacting with the sync stream.
