---
title: Compromised PyTorch Lightning Packages on PyPI Steal Developer Credentials
slug: 2026-05-pytorch-lightning-compromise
description: Compromised PyTorch Lightning packages versions 2.6.2 and 2.6.3 on PyPI contain malicious code to steal developer credentials from cloud and developer environments, and republish infected packages.
date: "2026-05-01T00:45:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - pypi
  - credential-theft
  - malware
vendors:
  - GitHub
products:
  - pytorch-lightning
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi
rules:
  - title: Detect Suspicious PyPI Package Installation
    description: Detects the installation of specific malicious PyPI packages by name.
    platform: sigma
    severity: high
    tactics:
      - supply_chain
    techniques:
      - T1195.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Credential Harvesting via Bun
    description: Detects execution of Bun, potentially related to credential harvesting, based on process name.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On April 30, 2026, two malicious versions (2.6.2 and 2.6.3) of the widely used `pytorch-lightning` package were published to the PyPI registry after the publisher account was compromised. These versions contain embedded malicious code designed to steal developer credentials and republish infected versions of repositories to which the stolen tokens have access. The attack is triggered upon importing the package, initiating a background process that silently harvests credentials from a wide array of services, including AWS, Azure, Google Cloud, and GitHub, as well as local environment variables and credential files. Version 2.6.3 was published just 13 minutes after 2.6.2, and was intended to evade detection.

## Attack Chain

1.  Attacker compromises the publisher account for the `pytorch-lightning` package on PyPI.
2.  Attacker publishes malicious versions 2.6.2 and 2.6.3 to PyPI.
3.  A modified `__init__.py` file within the package initiates a background process upon import.
4.  The background process executes silently, without any visible output or indication of compromise to the user.
5.  The malicious package downloads a runtime (Bun) from GitHub.
6.  The package executes a large, obfuscated JavaScript file, targeting AWS, Azure, Google Cloud, GitHub, and local credential stores.
7.  Stolen credentials, including cloud provider keys, API tokens, and secrets, are exfiltrated to attacker-controlled infrastructure.
8.  The malware attempts to download and execute a second-stage payload from attacker-controlled infrastructure, expanding the scope of the attack.

## Impact

Organizations that downloaded and used versions 2.6.2 or 2.6.3 of the `pytorch-lightning` package are at high risk of compromise. The malicious package is designed to steal a wide range of credentials, including cloud provider keys, API tokens, and secrets stored in environment variables. This can lead to unauthorized access to sensitive data and systems, potentially resulting in data breaches, financial losses, and reputational damage. The malware's ability to download and execute secondary payloads further increases the potential impact.

## Recommendation

*   Immediately remove versions 2.6.2 and 2.6.3 of the `lightning` package from all systems where they are installed (see overview).
*   Audit systems for unauthorized processes and review outbound network connections to detect potential compromises (see overview).
*   Rotate all cloud provider keys (AWS, Azure, GCP), API tokens (GitHub, CI/CD systems), and secrets stored in environment variables to prevent further unauthorized access (see Attack Chain).
*   Implement the `Detect Suspicious PyPI Package Installation` Sigma rule to identify potential malicious packages being installed in the future (see rules).
*   Implement the `Detect Credential Harvesting via Bun` Sigma rule to catch execution of the malicious JavaScript payload (see rules).
*   Pin dependencies to known-good versions and verify package integrity before use to prevent future supply chain attacks (see references).
