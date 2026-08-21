---
title: Abuse of Python Site-Package Hooks for Persistence
slug: 2026-08-python-site-hooks
description: Adversaries are abusing the Python site module by planting malicious sitecustomize.py or usercustomize.py files in package directories to ensure persistent code execution during Python initialization.
date: "2026-08-21T13:08:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - supply-chain
  - python
  - endpoint-security
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: If an adversary manipulates or plants one of these files, they can hijack the Python environment and execute their payload with every Python invocation, achieving persistence on the victim endpoint.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: This activity is often observed during or immediately following malicious package installation.
    confidence_band: high
rules:
  - title: Detect Python Site Hook Creation During Package Installation
    description: Detects the creation of sitecustomize.py or usercustomize.py in site-packages directories during a process containing 'install' in its command line.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to production SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provided detection logic for this technique.
  hunt_leads:
    - lead: Audit existing site-packages directories for unauthorized .py hook files.
      technique_id: T1546
      data_needed:
        - File system inventory
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Adversaries persist by planting these files.
---

Adversaries are leveraging Python site initialization hooks to establish persistence on compromised Windows, Linux, and macOS endpoints. By planting a 'sitecustomize.py' or 'usercustomize.py' script within 'site-packages' or 'dist-packages' directories, an attacker ensures their malicious code is automatically executed every time the Python interpreter starts. This technique, notably used by the VIPERTUNNEL backdoor to trigger subsequent DLL-based payloads, effectively hides malicious logic within the standard Python environment. Defenders should focus on monitoring for the creation of these specific files in conjunction with software installation processes, as this behavior often indicates a supply chain compromise or the final stage of a malware deployment.

## Attack Chain

1. Attacker identifies a target system with existing Python environments and accessible site-packages or dist-packages directories.
2. Attacker initiates a malicious installation process or abuses legitimate package managers to gain execution context.
3. Attacker writes a malicious script named 'sitecustomize.py' or 'usercustomize.py' to a directory included in the Python 'sys.path'.
4. The malicious hook script contains logic to import malicious libraries or execute shell commands.
5. The attacker completes the package installation or masquerades as a legitimate installation to evade initial detection.
6. A user or system process subsequently invokes the Python interpreter for normal operations.
7. The Python 'site' module automatically detects and executes the planted hook file during initialization.
8. The malicious payload executes in the security context of the user or service running the Python process, achieving persistence.

## Impact

This technique enables persistent arbitrary code execution with the permissions of the invoking Python process. Depending on the target environment, this could lead to full system compromise, data exfiltration, or lateral movement. It has been observed in the wild supporting the VIPERTUNNEL backdoor, which uses this persistence mechanism to facilitate further stages of an attack.

## Recommendation

- Enable Sysmon or equivalent endpoint logging for both process creation (Event ID 1) and file creation (Event ID 11).
- Deploy the provided Sigma rule to monitor the creation of 'sitecustomize.py' or 'usercustomize.py' files during package installation events.
- Investigate any detected files by inspecting the file contents and the parent process that performed the write operation to distinguish between legitimate environment configuration and malicious activity.
