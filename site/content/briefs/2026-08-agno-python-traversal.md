---
title: Path Traversal Vulnerability in Agno PythonTools
slug: 2026-08-agno-python-traversal
description: Agno PythonTools contains a path traversal vulnerability in its read_file, save_to_file, and run_python_file functions that allows attackers to read, write, or execute arbitrary files.
date: "2026-08-19T22:45:25Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Agno
products:
  - PythonTools
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can inject traversal sequences such as '../../../../../../etc/passwd' through direct tool invocation or via prompt injection embedded in agent-processed content.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attacker can achieve arbitrary Python code execution within the process user's authority.
    confidence_band: high
cves:
  - id: CVE-2026-76832
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76832
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Agno PythonTools to resolve CVE-2026-76832
      owner: IT Operations
      due: 48h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Restrict filesystem permissions for agent service accounts
      owner: IT Operations
      addresses: CVE-2026-76832
      evidence: General security hardening for file-system access vulnerabilities
---

Agno's PythonTools component, specifically located in libs/agno/agno/tools/python.py, contains a critical path traversal vulnerability (CVE-2026-76832). This vulnerability stems from improper validation of the file_name argument passed to the tool's core functions: read_file, save_to_file, and run_python_file. 

An attacker can bypass intended directory restrictions by providing parent-directory traversal sequences (e.g., ../../../) within the file_name parameter. This can be exploited through direct invocation of these tools or via prompt injection attacks where an agent processes malicious input containing the traversal payloads. Successful exploitation permits an attacker to escape the base_dir boundary, enabling arbitrary file read access, overwriting sensitive system files, or executing arbitrary Python code with the privileges of the application process. This vulnerability presents a high risk for environments where Agno agents are configured to interface with local filesystems or have broad execution authority.

## Impact

The vulnerability allows unauthorized actors to compromise the integrity and confidentiality of the host environment. By leveraging the save_to_file or run_python_file actions, an attacker can achieve remote code execution (RCE) in the context of the agent process, potentially leading to full system compromise, exfiltration of environment variables or credentials, and persistence within the affected host or container environment.

## Recommendation

* Update the Agno library to the patched version that implements strict path normalization and boundary validation for the file_name argument.
* Implement restrictive filesystem permissions for the service user account running Agno agents to limit the impact of potential traversal attempts.
* Monitor application logs for suspicious tool input patterns containing repeated directory traversal sequences like "../".
* Restrict agent access to unnecessary filesystem paths via environment isolation, such as containerization or chroot jails, where feasible.
