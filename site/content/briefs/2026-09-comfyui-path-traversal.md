---
title: Path Traversal in ComfyUI Dataset Save Nodes
slug: 2026-09-comfyui-path-traversal
description: ComfyUI versions prior to 0.30.0 are vulnerable to path traversal via unsanitized input in dataset save nodes, allowing attackers to write arbitrary files and potentially achieve code execution.
date: "2026-09-16T21:58:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:comfyui:comfyui:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - path-traversal
  - cve-2026-92816
vendors:
  - ComfyUI
products:
  - ComfyUI (< 0.30.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ComfyUI before 0.30.0 fails to sanitize folder_name input in dataset save nodes, allowing attackers to write files to arbitrary paths outside the output directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can load a crafted workflow that writes attacker-controlled content to arbitrary locations, enabling code execution through modified startup files or package initializers.
    confidence_band: high
cves:
  - id: CVE-2026-92816
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92816
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ComfyUI to 0.30.0 or later to patch CVE-2026-92816
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Patch ComfyUI to 0.30.0
      owner: IT Operations
      addresses: CVE-2026-92816
      evidence: NVD
---

ComfyUI versions before 0.30.0 contain a critical path traversal vulnerability (CVE-2026-92816) within its dataset save nodes. The application fails to properly sanitize the 'folder_name' parameter, which is used to define the destination directory for saved files. By providing a crafted 'folder_name' string containing directory traversal sequences, an authenticated or remote attacker can escape the intended output directory and write files to arbitrary locations on the host filesystem. This vulnerability is particularly dangerous in the context of ComfyUI, as an attacker with the ability to write files to the filesystem can overwrite critical startup scripts, configuration files, or package initialization modules. Successful exploitation leads to arbitrary code execution within the security context of the ComfyUI process. Users are advised to upgrade to version 0.30.0 or later to mitigate this risk.

## Attack Chain

1. Attacker identifies a target instance of ComfyUI running a version earlier than 0.30.0.
2. Attacker crafts a malicious workflow containing a dataset save node configuration.
3. Attacker sets the 'folder_name' parameter in the dataset save node to include directory traversal sequences (e.g., ../../../).
4. Attacker uploads or executes the crafted workflow within the ComfyUI interface.
5. ComfyUI backend processes the 'folder_name' input without sanitization.
6. The application performs a file write operation to the destination path specified by the traversal sequences.
7. Attacker overwrites a system-level startup script or Python package initialization file with malicious code.
8. Upon restart of the ComfyUI service or specific process execution, the malicious code is triggered, resulting in code execution.

## Impact

The vulnerability carries a CVSS v3.1 base score of 7.8. Successful exploitation allows for arbitrary file write, which facilitates full system compromise via code execution. This impacts any organization or individual running vulnerable versions of ComfyUI in environments where the service is accessible to untrusted parties.

## Recommendation

Prioritized actions for security teams:
- Patch ComfyUI: Upgrade all instances to version 0.30.0 or later immediately to address CVE-2026-92816.
- Review Audit Logs: Investigate webserver logs for requests involving dataset save nodes that contain non-alphanumeric characters or path traversal sequences like '../'.
- Restrict Access: Ensure ComfyUI instances are not exposed to the public internet and restrict access to authenticated, trusted users only.
- Principle of Least Privilege: Run the ComfyUI service under a dedicated, low-privileged user account to limit the impact of potential code execution scenarios.
