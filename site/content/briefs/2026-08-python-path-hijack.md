---
title: Abuse of PYTHONPATH for Python Module Hijacking and Persistence
slug: 2026-08-python-path-hijack
description: Adversaries are modifying the PYTHONPATH environment variable during Python package installation to redirect module imports, enabling code execution and persistence whenever Python is invoked.
date: "2026-08-21T13:08:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - python
  - persistence
  - registry
  - supply-chain
  - windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574.007
    technique_name: 'Hijack Execution Flow: Path Hijacking'
    evidence: If an adversary is able to control the value of PYTHONPATH, they can point it to an attacker-controlled directory and hijack imported packages, achieving user-level persistence.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Supply Chain Compromise
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: The following analytic detects modification of the PYTHONPATH environment variable in conjunction with a package installation process.
    confidence_band: high
rules:
  - title: Detect PYTHONPATH Modification via Registry
    description: Detects modifications to the PYTHONPATH environment variable registry key, which may indicate an attempt to hijack Python module imports for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1574.007
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable Sysmon Event ID 13 monitoring for the Environment registry hive.
      owner: IT Operations
      due: 48h
      evidence: Source requirement for detection visibility.
  hunt_leads:
    - lead: Search registry logs for any changes to PYTHONPATH occurring alongside pip process execution.
      technique_id: T1574.007
      data_needed:
        - Sysmon Event ID 1 (Process)
        - Sysmon Event ID 13 (Registry)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic detects modification of PYTHONPATH during package installation.
---

Adversaries are targeting Python environments by manipulating the PYTHONPATH environment variable, a mechanism used by the Python interpreter to locate modules for import. By altering this variable - often via registry modifications - an attacker can force Python to load libraries from an attacker-controlled directory instead of legitimate locations. This technique facilitates module hijacking, allowing the attacker to execute arbitrary code with the privileges of the user who invokes the Python interpreter. This activity is frequently observed in conjunction with the installation of malicious Python packages, serving as both a method for initial code execution and a persistent backdoor that activates automatically upon future Python sessions. Defenders should monitor registry modifications affecting environmental paths during package management workflows.

## Attack Chain

1. Attacker delivers a malicious payload or script to the target system.
2. The target user or an automated process executes a Python package installation (e.g., via `pip`).
3. The installer triggers a process that interacts with the Windows environment configuration.
4. The malicious process or installer modifies the `HKCU\Environment\PYTHONPATH` registry key.
5. The attacker places a malicious Python module (e.g., a `.py` file) in the directory specified by the modified PYTHONPATH.
6. The victim executes a standard Python application or script.
7. The Python interpreter traverses the modified PYTHONPATH, prioritizes the malicious directory, and loads the attacker's module.
8. Malicious code within the hijacked module executes, providing the attacker with sustained, user-level persistence.

## Impact

Successful exploitation allows for arbitrary code execution and persistent access to the target host. Because the persistence mechanism relies on the standard Python import lookup process, the attacker's code runs every time the user invokes Python, potentially leading to credential theft, data exfiltration, or further lateral movement within the network.

## Recommendation

* Enable Sysmon Event ID 1 (Process Creation) and Event ID 13 (Registry Value Set) to monitor for unauthorized changes to the `PYTHONPATH` environment variable.
* Deploy the provided Sigma rule to detect registry modifications to the `PYTHONPATH` key performed by processes associated with Python package installation.
* Investigate any process modifying `HKCU\Environment\PYTHONPATH` if it originates from an unexpected parent process or is not part of a known, approved development workflow.
