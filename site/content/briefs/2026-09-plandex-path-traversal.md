---
title: Path Traversal Vulnerability in Plandex
slug: 2026-09-plandex-path-traversal
description: Plandex version 2.2.1 contains a path traversal vulnerability in the ApplyFiles function allowing arbitrary file writes via manipulated model outputs, potentially leading to remote code execution.
date: "2026-09-04T15:31:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:plandex:plandex:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - code-execution
vendors:
  - Plandex
products:
  - Plandex (2.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can manipulate model outputs through poisoned repository files or controlled context to write files to arbitrary locations outside the project directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can influence model output through poisoned repository files or attacker-controlled context to write to arbitrary locations like shell rc or cron files, achieving code execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543.001
    technique_name: 'Create or Modify System Process: Launch Agent'
    evidence: Attackers can influence model output to write to arbitrary locations like cron files, achieving code execution.
    confidence_band: high
cves:
  - id: CVE-2026-85690
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85690
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Plandex to a patched version once released.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85690
  mitigation_plan:
    - priority: immediate
      action: Run Plandex within restricted containers to limit filesystem exposure.
      owner: IT Operations
      addresses: CVE-2026-85690
      evidence: Path traversal in ApplyFiles allows writing files outside project directory.
---

Plandex version 2.2.1 contains a critical path traversal vulnerability within its ApplyFiles function. This flaw arises from insufficient validation of file paths during the file application process, which is intended to update or create files within a designated project directory. An attacker who can influence the model's output, either through poisoned repository files or by supplying malicious context to the AI model, can force Plandex to write files to arbitrary locations on the host filesystem. By targeting sensitive directories, such as those containing shell initialization scripts (.bashrc, .zshrc) or cron job configurations, an attacker can achieve unauthorized code execution under the context of the user running the Plandex tool. This vulnerability represents a significant security risk for developers using Plandex in environments where the AI model's context might be influenced by untrusted sources.

## Attack Chain

1. The attacker identifies or creates a malicious repository file or manipulates the Plandex project context.
2. The attacker triggers the Plandex model to generate a file update or creation action involving the ApplyFiles function.
3. The model output is crafted to include path traversal sequences (e.g., ../../../) within the filename parameter.
4. The ApplyFiles function fails to sanitize the provided path, allowing the write operation to escape the target project directory.
5. The Plandex process performs an unauthorized write to a sensitive system or user location, such as ~/.bashrc.
6. The target system or user triggers the malicious file (e.g., upon new shell login or cron execution).
7. Arbitrary code defined by the attacker is executed on the host system.

## Impact

Successful exploitation allows attackers to gain remote code execution on the host machine running Plandex. This can lead to full system compromise, data exfiltration, or the establishment of persistent backdoors. Targeted environments include any developer workstation or server instance where Plandex is used to process code or configuration files.

## Recommendation

1. Upgrade Plandex to a version addressing CVE-2026-85690 immediately once available from the vendor.
2. Review logs for unexpected file write operations originating from the Plandex process.
3. Isolate Plandex operations in a containerized or sandboxed environment with restricted filesystem access to mitigate the impact of path traversal.
