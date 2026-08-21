---
title: TeamPCP Persistence via Malicious Python .pth Files
slug: 2026-08-python-pth-persistence
description: The threat actor TeamPCP leverages Python path configuration (.pth) files created during package installation to achieve persistent arbitrary code execution.
date: "2026-08-21T13:08:12Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - TeamPCP
tags:
  - persistence
  - supply-chain-compromise
  - python
  - persistence-technique
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Path configuration files placed under site-packages or dist-packages are executed with every subsequent invocation of Python, allowing adversaries to achieve persistence.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: This technique was used by the threat actor group TeamPCP during the supply chain compromise of the litellm package.
    confidence_band: high
rules:
  - title: Detect Python .pth File Creation During Package Installation
    description: Detects the creation of a .pth file by a python.exe process during a package installation event, indicative of potential supply chain persistence.
    platform: sigma
    severity: high
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
    - action: Deploy Sigma rule to identify .pth file creation
      owner: Detection Engineering
      due: 24h
      evidence: Source provides analytic logic for .pth file creation monitoring
  hunt_leads:
    - lead: Search for .pth files in site-packages and dist-packages created in the last 30 days
      technique_id: T1546
      data_needed:
        - File system inventory
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source analytic logic targets these specific directories
---

The threat actor group TeamPCP has been identified exploiting the Python interpreter's behavior regarding path configuration files (.pth). During the supply chain compromise of the 'litellm' package, the actors embedded malicious .pth files within the package distribution. When these packages are installed, the .pth file is placed into the site-packages or dist-packages directory. The Python interpreter automatically processes these files upon every subsequent invocation, leading to persistent, arbitrary code execution on the compromised host. This technique is particularly effective as it bypasses traditional execution controls and remains active regardless of how the Python application is built or distributed. Defenders should monitor for the correlation between Python process execution and the creation of .pth files in sensitive package directories.

## Attack Chain

1. The adversary publishes a malicious version of a legitimate Python package (e.g., 'litellm') to a public repository.
2. A target user installs the malicious package via 'pip' or other standard package managers.
3. The malicious installation script triggers a process (e.g., python.exe) to handle package setup.
4. The installation process writes a malicious .pth file to the target's 'site-packages' or 'dist-packages' directory.
5. The attacker's code inside the .pth file is configured to execute upon Python startup.
6. The victim executes a local Python script or application on the host.
7. The Python interpreter automatically parses the directory, discovers the .pth file, and executes the contained malicious commands.
8. The attacker achieves persistence and potential full control over the compromised environment.

## Impact

Successful exploitation results in persistent arbitrary code execution on the target endpoint. Any host that installs the compromised package, including developers and automated CI/CD build environments, becomes infected. This enables data exfiltration, lateral movement, and long-term access to the internal network.

## Recommendation

- Enable Sysmon logging for Event ID 1 (Process Creation) and Event ID 11 (File Creation) to capture .pth file modifications.
- Deploy the provided Sigma rule to detect the specific correlation between python.exe activity and .pth file creation.
- Review the contents of any .pth files found in site-packages or dist-packages for suspicious imports or command execution scripts.
- Audit Python environments for unauthorized changes to package installation directories.
