---
title: Compromise of PyTorch Lightning PyPI Package Versions
slug: 2026-05-pytorch-lightning-compromise
description: Compromised PyTorch Lightning PyPI packages versions 2.6.2 and 2.6.3 contain malicious code related to credential harvesting, requiring immediate credential rotation and system rebuilding.
date: "2026-05-07T00:52:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - credential-theft
  - pypi
vendors:
  - Lightning AI
products:
  - pytorch-lightning (2.6.2)
  - pytorch-lightning (2.6.3)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-w37p-236h-pfx3
iocs:
  - type: email
    value: security@lightning.ai
ioc_counts:
  email: 1
rules:
  - title: Detect Installation of Compromised PyTorch Lightning Package
    description: Detects the installation of the compromised PyTorch Lightning packages based on package name and version.
    platform: sigma
    severity: critical
    tactics:
      - supply_chain
    techniques:
      - T1195
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Network Connection by PyTorch Lightning
    description: Detects suspicious network connections initiated by Python processes associated with PyTorch Lightning, which may indicate credential exfiltration.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

On April 30, 2026, Lightning AI disclosed a security incident affecting the PyTorch Lightning PyPI package. Versions 2.6.2 and 2.6.3 have been identified as compromised and contain malicious code. The ongoing investigation suggests the injected code functions as a credential harvesting mechanism, potentially exposing sensitive information like API keys, access tokens, SSH keys, and service account credentials. The root cause of the compromise is still under investigation, but Lightning AI has taken steps to quarantine the malicious versions and is working to determine the full scope and impact of the breach. Defenders should immediately rotate credentials and rebuild systems affected by these compromised packages.

## Attack Chain

1.  Attacker gains unauthorized access to the PyTorch Lightning PyPI package release process.
2.  Malicious code is injected into the `2.6.2` and `2.6.3` versions of the `pytorch-lightning` package.
3.  Developers unknowingly install the compromised packages using `pip`.
4.  Upon execution, the malicious code begins harvesting credentials from the compromised environment.
5.  Stolen credentials, including API keys, access tokens, SSH keys, and service account credentials, are exfiltrated to an attacker-controlled server.
6.  The attacker uses the stolen credentials to gain unauthorized access to systems and data.
7.  The attacker may escalate privileges within the compromised environment using the acquired credentials.

## Impact

The compromise of PyTorch Lightning versions 2.6.2 and 2.6.3 poses a critical risk to developers and organizations using these packages. Successful credential harvesting can lead to unauthorized access to sensitive data, system compromise, and potential financial loss. The number of affected users is currently unknown, but given the popularity of PyTorch Lightning, the potential impact could be significant across various sectors. Systems running the affected versions should be considered fully compromised until remediated.

## Recommendation

*   Immediately rotate all credentials and secrets that may have been exposed, including API keys, access tokens, SSH keys, and service account credentials, as mentioned in the advisory.
*   Rebuild affected systems from a known clean state to eliminate any residual malicious code as recommended by the advisory.
*   Pin PyTorch Lightning to version `2.6.1` to prevent further installations of the compromised versions, per the advisory.
*   Review logs for any suspicious or unauthorized activity to identify potential breaches resulting from the compromised packages.
*   Monitor network traffic for outbound connections to unusual or suspicious domains/IP addresses, which may indicate credential exfiltration.
