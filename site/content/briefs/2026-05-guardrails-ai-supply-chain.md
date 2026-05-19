---
title: Malicious guardrails-ai 0.10.1 Package Published to PyPI
slug: 2026-05-guardrails-ai-supply-chain
description: A malicious version of the guardrails-ai package (0.10.1) was published to PyPI on May 11, 2026, advising users who installed this version to downgrade and treat the host as potentially compromised, rotating credentials and auditing GitHub accounts, with Snowglobe and Guardrails Hub API keys being invalidated on May 13, 2026.
date: "2026-05-19T15:41:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - pypi
  - malicious-package
vendors:
  - Guardrails AI
products:
  - guardrails-ai (== 0.10.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1608
    technique_name: Stage Capabilities
references:
  - https://github.com/advisories/GHSA-xmpw-2vmm-p4p6
  - https://github.com/guardrails-ai/guardrails/blob/main/SECURITY_ADVISORY.md
  - https://github.com/guardrails-ai/guardrails/issues/1473
rules:
  - title: Detect guardrails-ai Package Installation
    description: Detects installation of the malicious guardrails-ai package version 0.10.1 via pip
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1608
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential Credential Exfiltration by guardrails-ai 0.10.1
    description: Detects suspicious processes spawned by python.exe after the installation of guardrails-ai 0.10.1 that attempt to access or exfiltrate credentials.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 11, 2026, a malicious version (0.10.1) of the `guardrails-ai` package was published to the Python Package Index (PyPI). The compromised package was identified by security researchers within approximately two hours, leading to its subsequent quarantine by PyPI. Any user who installed `guardrails-ai==0.10.1` from PyPI on May 11, 2026, is potentially affected. While Guardrails AI has not observed any data exfiltration through their systems, users are advised to take immediate remediation steps, including downgrading to version 0.10.0 and treating affected hosts as potentially compromised. This supply chain compromise could lead to credential theft and unauthorized access to sensitive resources. The incident highlights the risks associated with relying on third-party packages and the importance of verifying package integrity.

## Attack Chain

1.  The attacker compromises the PyPI account or infrastructure used to publish the `guardrails-ai` package.
2.  The attacker injects malicious code into the `guardrails-ai` version 0.10.1 package.
3.  The attacker publishes the malicious `guardrails-ai` 0.10.1 package to PyPI.
4.  Developers unknowingly install the compromised `guardrails-ai==0.10.1` package using `pip`.
5.  Upon execution, the malicious code within the installed package attempts to exfiltrate sensitive data, such as credentials (GitHub PATs, cloud provider keys, package registry tokens, API keys) from the compromised host.
6.  The exfiltrated credentials could then be used to gain unauthorized access to GitHub accounts and other cloud resources.
7.  The attacker may create unauthorized workflows or repositories using the stolen credentials.
8.  The attacker leverages the compromised GitHub account or cloud resources to further propagate malicious activity.

## Impact

The malicious `guardrails-ai` 0.10.1 package could lead to the compromise of developer machines and the theft of sensitive credentials, including GitHub Personal Access Tokens (PATs), cloud provider keys, and API keys. If successful, attackers could gain unauthorized access to GitHub accounts, cloud resources, and other sensitive systems. The immediate impact includes potential data breaches, supply chain attacks, and service disruptions. Guardrails AI has invalidated all Snowglobe and Guardrails Hub API keys as a precaution, requiring users to rotate them to avoid service interruptions.

## Recommendation

*   Downgrade immediately to `guardrails-ai==0.10.0` as advised in the overview to mitigate the risk of running the malicious code.
*   Deploy the "Detect guardrails-ai Package Installation" Sigma rule to identify potentially compromised systems that installed the malicious package.
*   Rotate any credentials accessible from machines that installed version 0.10.1, including GitHub PATs, cloud provider keys, and package registry tokens, as described in the overview.
*   Audit your GitHub account for unauthorized workflows or repositories as recommended in the advisory overview.
*   Rotate Snowglobe and Guardrails Hub API keys before May 13, 2026, at 2:00 PM Pacific to avoid service interruptions, as mentioned in the advisory overview.
