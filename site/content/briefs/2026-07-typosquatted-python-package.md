---
title: Detection of Typosquatted Python Package Installation
slug: 2026-07-typosquatted-python-package
description: A detection identifies suspicious installations of Python packages, leveraging Cisco NVM flow telemetry to monitor `pip` or `poetry` commands making outbound connections to public repositories for package names resembling known typosquats, indicating potential malicious software supply chain compromise.
date: "2026-07-27T18:05:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - typosquatting
  - python
  - package-manager
  - supply-chain
  - endpoint
  - network
  - cisco-nvm
  - software-supply-chain-security
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This analytic detects suspicious python package installations where the package name resembles popular Python libraries but may be typosquatted or slightly altered... This detection leverages Cisco NVM flow telemetry and checks for pip or poetry package managers with the 'install' or 'add' flags...
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Typosquatting is a common technique used by attackers to trick users into installing malicious packages that mimic legitimate ones.
    confidence_band: high
references:
  - https://securelist.com/two-more-malicious-python-packages-in-the-pypi/107218/
  - https://blog.checkpoint.com/securing-the-cloud/pypi-inundated-by-malicious-typosquatting-campaign/
  - https://rhisac.org/threat-intelligence/typosquatting-campaign-targets-python-developers-with-hundreds-of-malicious-libraries/
rules:
  - title: Detect Typosquatted Python Package Installation (Windows)
    description: Detects suspicious Python package installations on Windows where 'pip' or 'poetry' commands attempt to install known typosquatted package names. This rule should be correlated with network logs to confirm outbound connections to public package repositories.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Typosquatted Python Package Installation (Linux)
    description: Detects suspicious Python package installations on Linux where 'pip' or 'poetry' commands attempt to install known typosquatted package names. This rule should be correlated with network logs to confirm outbound connections to public package repositories.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1204.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This threat brief details the detection of typosquatted Python package installations, a common technique employed by attackers to compromise software supply chains. Attackers create and publish malicious Python packages with names deliberately misspelled or slightly altered to resemble popular legitimate libraries (e.g., `reqeusts` instead of `requests`). These malicious packages are uploaded to public repositories like PyPI, where unsuspecting developers might inadvertently install them. The detection leverages Cisco Network Visibility Module (NVM) flow telemetry, monitoring for `pip` or `poetry` package manager commands with "install" or "add" flags that make outbound connections to legitimate package repositories (such as `pypi.org`, `pythonhosted.org`, `python-poetry.org`), specifically when the package name matches known or suspected typosquatted identifiers. This analytic was created on 2025-07-01 and last modified on 2026-07-14, highlighting an ongoing risk.

## Attack Chain

1. **Attacker Creates Malicious Package**: Threat actors develop a malicious Python package containing payloads for data exfiltration, system compromise, or other illicit activities.
2. **Typosquatting**: The attacker names the malicious package with a slight variation of a popular, legitimate Python library (e.g., `djanga` instead of `django`, `coloramaa` instead of `colorama`).
3. **Publication to Public Repository**: The typosquatted malicious package is uploaded to public Python package indexes such as PyPI (Python Package Index).
4. **Victim Lured to Install**: A developer or automated system is tricked, perhaps through social engineering, a typo in a development script, or a compromised upstream dependency, into attempting to install the malicious package.
5. **Execution of Installation Command**: The victim executes a package manager command, such as `pip install <typosquatted_package_name>` or `poetry add <typosquatted_package_name>`.
6. **Package Manager Fetches Malicious Code**: The package manager initiates an outbound network connection to a public Python package repository to download the package corresponding to the typosquatted name.
7. **Malicious Code Execution**: Upon download, the malicious package's setup scripts (e.g., `setup.py`) are automatically executed, leading to the attacker achieving initial code execution, persistence, data exfiltration, or further system compromise on the victim's machine.

## Impact

Successful installation of a typosquatted Python package can lead to severe consequences, including full system compromise, remote code execution, sensitive data exfiltration, credential theft, or the establishment of persistent backdoors. Attackers frequently use such methods to gain initial access or escalate privileges within development environments, potentially affecting entire software projects and their downstream users. Multiple malicious typosquatting campaigns have been observed targeting the Python Package Index, indicating a widespread and active threat to developers and organizations utilizing Python. The specific impact depends on the payload within the malicious package, but it consistently results in a breach of system integrity and confidentiality.

## Recommendation

* Deploy the provided Sigma rules to your SIEM and augment the `CommandLine` selections with an up-to-date list of known typosquatted Python package names.
* Ensure Cisco Network Visibility Module (NVM) flow data is being collected and ingested into your SIEM, including `process_arguments`, `dest_hostname`, and `dest_port` for accurate correlation.
* Configure the `typo_squatted_python_packages` lookup table in your environment, referencing external threat intelligence feeds for new typosquatting campaigns, to enhance the effectiveness of detection.
* Monitor for process creation events related to `pip` and `poetry` commands on both Windows and Linux endpoints, especially those involving outbound network connections to package repositories.
